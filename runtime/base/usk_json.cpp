#include "usk_json.h"

#include "usk_sha256.h"

#include <cctype>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace usk::json {

Value::Value(bool value) : type_(Type::boolean), boolean_(value) {}
Value::Value(std::uint64_t value) : type_(Type::unsigned_integer), unsigned_(value) {}
Value::Value(std::string value) : type_(Type::string), string_(std::move(value)) {}
Value::Value(const char* value) : Value(std::string(value)) {}
Value::Value(Array value) : type_(Type::array), array_(std::move(value)) {}
Value::Value(Object value) : type_(Type::object), object_(std::move(value)) {}

bool Value::as_boolean() const
{
    if (type_ != Type::boolean) throw std::runtime_error("JSON value is not a boolean");
    return boolean_;
}

std::uint64_t Value::as_unsigned() const
{
    if (type_ != Type::unsigned_integer) throw std::runtime_error("JSON value is not an unsigned integer");
    return unsigned_;
}

const std::string& Value::as_string() const
{
    if (type_ != Type::string) throw std::runtime_error("JSON value is not a string");
    return string_;
}

const Value::Array& Value::as_array() const
{
    if (type_ != Type::array) throw std::runtime_error("JSON value is not an array");
    return array_;
}

const Value::Object& Value::as_object() const
{
    if (type_ != Type::object) throw std::runtime_error("JSON value is not an object");
    return object_;
}

Value::Array& Value::as_array()
{
    if (type_ != Type::array) throw std::runtime_error("JSON value is not an array");
    return array_;
}

Value::Object& Value::as_object()
{
    if (type_ != Type::object) throw std::runtime_error("JSON value is not an object");
    return object_;
}

const Value& Value::at(const std::string& key) const
{
    const Object& object = as_object();
    const auto found = object.find(key);
    if (found == object.end()) throw std::runtime_error("required JSON member is missing: " + key);
    return found->second;
}

bool Value::contains(const std::string& key) const
{
    return type_ == Type::object && object_.find(key) != object_.end();
}

namespace {

bool valid_utf8(const std::string& value)
{
    for (std::size_t index = 0; index < value.size();) {
        const unsigned char first = static_cast<unsigned char>(value[index++]);
        if (first <= 0x7fu) continue;
        std::uint32_t codepoint = 0;
        std::size_t remaining = 0;
        if (first >= 0xc2u && first <= 0xdfu) {
            codepoint = first & 0x1fu;
            remaining = 1;
        } else if (first >= 0xe0u && first <= 0xefu) {
            codepoint = first & 0x0fu;
            remaining = 2;
        } else if (first >= 0xf0u && first <= 0xf4u) {
            codepoint = first & 0x07u;
            remaining = 3;
        } else {
            return false;
        }
        if (remaining > value.size() - index) return false;
        for (std::size_t count = 0; count < remaining; ++count) {
            const unsigned char continuation = static_cast<unsigned char>(value[index++]);
            if ((continuation & 0xc0u) != 0x80u) return false;
            codepoint = (codepoint << 6) | (continuation & 0x3fu);
        }
        if ((remaining == 2 && codepoint < 0x800u) ||
            (remaining == 3 && codepoint < 0x10000u) ||
            codepoint > 0x10ffffu || (codepoint >= 0xd800u && codepoint <= 0xdfffu)) {
            return false;
        }
    }
    return true;
}

void append_utf8(std::string& output, std::uint32_t codepoint)
{
    if (codepoint <= 0x7fu) {
        output.push_back(static_cast<char>(codepoint));
    } else if (codepoint <= 0x7ffu) {
        output.push_back(static_cast<char>(0xc0u | (codepoint >> 6)));
        output.push_back(static_cast<char>(0x80u | (codepoint & 0x3fu)));
    } else if (codepoint <= 0xffffu) {
        output.push_back(static_cast<char>(0xe0u | (codepoint >> 12)));
        output.push_back(static_cast<char>(0x80u | ((codepoint >> 6) & 0x3fu)));
        output.push_back(static_cast<char>(0x80u | (codepoint & 0x3fu)));
    } else {
        output.push_back(static_cast<char>(0xf0u | (codepoint >> 18)));
        output.push_back(static_cast<char>(0x80u | ((codepoint >> 12) & 0x3fu)));
        output.push_back(static_cast<char>(0x80u | ((codepoint >> 6) & 0x3fu)));
        output.push_back(static_cast<char>(0x80u | (codepoint & 0x3fu)));
    }
}

class Parser {
public:
    Parser(const std::string& text, ParseLimits limits) : text_(text), limits_(limits)
    {
        if (text_.size() > limits_.max_bytes) throw std::runtime_error("JSON input exceeds byte budget");
    }

    Value run()
    {
        skip_space();
        Value result = value(0);
        skip_space();
        if (position_ != text_.size()) throw std::runtime_error("JSON has trailing content");
        return result;
    }

private:
    Value value(std::size_t depth)
    {
        if (depth > limits_.max_depth) throw std::runtime_error("JSON exceeds depth budget");
        if (++values_ > limits_.max_values) throw std::runtime_error("JSON exceeds value budget");
        skip_space();
        if (position_ >= text_.size()) throw std::runtime_error("JSON value is truncated");
        const char ch = text_[position_];
        if (ch == 'n') { literal("null"); return Value(); }
        if (ch == 't') { literal("true"); return Value(true); }
        if (ch == 'f') { literal("false"); return Value(false); }
        if (ch == '"') return Value(string());
        if (ch == '[') return array(depth + 1);
        if (ch == '{') return object(depth + 1);
        if (ch >= '0' && ch <= '9') return Value(number());
        throw std::runtime_error("JSON contains an unsupported value token");
    }

    void literal(const char* expected)
    {
        const std::string token(expected);
        if (text_.compare(position_, token.size(), token) != 0) {
            throw std::runtime_error("JSON literal is invalid");
        }
        position_ += token.size();
    }

    std::uint64_t number()
    {
        if (text_[position_] == '0' && position_ + 1 < text_.size() &&
            std::isdigit(static_cast<unsigned char>(text_[position_ + 1]))) {
            throw std::runtime_error("JSON integer has a leading zero");
        }
        std::uint64_t result = 0;
        do {
            const unsigned int digit = static_cast<unsigned int>(text_[position_] - '0');
            if (result > (std::numeric_limits<std::uint64_t>::max() - digit) / 10u) {
                throw std::runtime_error("JSON integer overflows uint64");
            }
            result = result * 10u + digit;
            ++position_;
        } while (position_ < text_.size() &&
                 std::isdigit(static_cast<unsigned char>(text_[position_])));
        if (position_ < text_.size() &&
            (text_[position_] == '.' || text_[position_] == 'e' || text_[position_] == 'E')) {
            throw std::runtime_error("JSON floating point numbers are forbidden");
        }
        return result;
    }

    static std::uint32_t hex_digit(char ch)
    {
        if (ch >= '0' && ch <= '9') return static_cast<std::uint32_t>(ch - '0');
        if (ch >= 'a' && ch <= 'f') return static_cast<std::uint32_t>(ch - 'a' + 10);
        if (ch >= 'A' && ch <= 'F') return static_cast<std::uint32_t>(ch - 'A' + 10);
        throw std::runtime_error("JSON Unicode escape is invalid");
    }

    std::uint32_t unicode_escape()
    {
        if (position_ + 4 > text_.size()) throw std::runtime_error("JSON Unicode escape is truncated");
        std::uint32_t result = 0;
        for (int index = 0; index < 4; ++index) result = result * 16u + hex_digit(text_[position_++]);
        return result;
    }

    std::string string()
    {
        ++position_;
        std::string result;
        while (position_ < text_.size()) {
            const unsigned char ch = static_cast<unsigned char>(text_[position_++]);
            if (ch == '"') {
                if (result.size() > limits_.max_string_bytes) throw std::runtime_error("JSON string exceeds budget");
                if (!valid_utf8(result)) throw std::runtime_error("JSON string is not valid UTF-8");
                return result;
            }
            if (ch < 0x20u) throw std::runtime_error("JSON string contains an unescaped control byte");
            if (ch != '\\') {
                result.push_back(static_cast<char>(ch));
                continue;
            }
            if (position_ >= text_.size()) throw std::runtime_error("JSON escape is truncated");
            const char escaped = text_[position_++];
            switch (escaped) {
            case '"': result.push_back('"'); break;
            case '\\': result.push_back('\\'); break;
            case '/': result.push_back('/'); break;
            case 'b': result.push_back('\b'); break;
            case 'f': result.push_back('\f'); break;
            case 'n': result.push_back('\n'); break;
            case 'r': result.push_back('\r'); break;
            case 't': result.push_back('\t'); break;
            case 'u': {
                std::uint32_t codepoint = unicode_escape();
                if (codepoint >= 0xd800u && codepoint <= 0xdbffu) {
                    if (position_ + 2 > text_.size() || text_[position_] != '\\' || text_[position_ + 1] != 'u') {
                        throw std::runtime_error("JSON high surrogate lacks a low surrogate");
                    }
                    position_ += 2;
                    const std::uint32_t low = unicode_escape();
                    if (low < 0xdc00u || low > 0xdfffu) throw std::runtime_error("JSON low surrogate is invalid");
                    codepoint = 0x10000u + ((codepoint - 0xd800u) << 10) + (low - 0xdc00u);
                } else if (codepoint >= 0xdc00u && codepoint <= 0xdfffu) {
                    throw std::runtime_error("JSON contains an unpaired low surrogate");
                }
                append_utf8(result, codepoint);
                break;
            }
            default: throw std::runtime_error("JSON string escape is invalid");
            }
        }
        throw std::runtime_error("JSON string is unterminated");
    }

    Value array(std::size_t depth)
    {
        ++position_;
        Value::Array result;
        skip_space();
        if (consume(']')) return Value(std::move(result));
        for (;;) {
            result.push_back(value(depth));
            skip_space();
            if (consume(']')) return Value(std::move(result));
            require(',');
        }
    }

    Value object(std::size_t depth)
    {
        ++position_;
        Value::Object result;
        skip_space();
        if (consume('}')) return Value(std::move(result));
        for (;;) {
            skip_space();
            if (position_ >= text_.size() || text_[position_] != '"') throw std::runtime_error("JSON object key is invalid");
            std::string key = string();
            skip_space();
            require(':');
            auto inserted = result.emplace(std::move(key), value(depth));
            if (!inserted.second) throw std::runtime_error("JSON object contains a duplicate key");
            skip_space();
            if (consume('}')) return Value(std::move(result));
            require(',');
        }
    }

    void skip_space()
    {
        while (position_ < text_.size() &&
               (text_[position_] == ' ' || text_[position_] == '\t' ||
                text_[position_] == '\r' || text_[position_] == '\n')) ++position_;
    }

    bool consume(char expected)
    {
        if (position_ < text_.size() && text_[position_] == expected) {
            ++position_;
            return true;
        }
        return false;
    }

    void require(char expected)
    {
        skip_space();
        if (!consume(expected)) throw std::runtime_error("JSON punctuation is invalid");
    }

    const std::string& text_;
    ParseLimits limits_;
    std::size_t position_ = 0;
    std::size_t values_ = 0;
};

void append_escaped(std::string& output, const std::string& value)
{
    static const char hex[] = "0123456789abcdef";
    output.push_back('"');
    for (unsigned char ch : value) {
        switch (ch) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\b': output += "\\b"; break;
        case '\f': output += "\\f"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (ch < 0x20u) {
                output += "\\u00";
                output.push_back(hex[ch >> 4]);
                output.push_back(hex[ch & 0x0fu]);
            } else {
                output.push_back(static_cast<char>(ch));
            }
        }
    }
    output.push_back('"');
}

void append_canonical(std::string& output, const Value& value)
{
    switch (value.type()) {
    case Value::Type::null_value: output += "null"; return;
    case Value::Type::boolean: output += value.as_boolean() ? "true" : "false"; return;
    case Value::Type::unsigned_integer: output += std::to_string(value.as_unsigned()); return;
    case Value::Type::string: append_escaped(output, value.as_string()); return;
    case Value::Type::array: {
        output.push_back('[');
        bool first = true;
        for (const Value& item : value.as_array()) {
            if (!first) output.push_back(',');
            first = false;
            append_canonical(output, item);
        }
        output.push_back(']');
        return;
    }
    case Value::Type::object: {
        output.push_back('{');
        bool first = true;
        for (const auto& member : value.as_object()) {
            if (!first) output.push_back(',');
            first = false;
            append_escaped(output, member.first);
            output.push_back(':');
            append_canonical(output, member.second);
        }
        output.push_back('}');
        return;
    }
    }
}

} // namespace

Value parse(const std::string& text, const ParseLimits& limits)
{
    return Parser(text, limits).run();
}

std::string canonical(const Value& value)
{
    std::string result;
    append_canonical(result, value);
    return result;
}

std::string sha256_canonical(const Value& value)
{
    const std::string text = canonical(value);
    usk::base::Sha256 digest;
    digest.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
    return digest.finish();
}

} // namespace usk::json
