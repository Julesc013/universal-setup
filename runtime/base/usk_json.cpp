// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_json.h"

#include "usk_sha256.h"
#include "usk_utf8_path.h"

#include <cctype>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace usk::json {

Value::Value(bool value) : storage_(value) {}
Value::Value(std::uint64_t value) : storage_(value) {}
Value::Value(std::string value) : storage_(std::move(value)) {}
Value::Value(const char* value) : Value(std::string(value)) {}
Value::Value(Array value) : storage_(std::move(value)) {}
Value::Value(Object value) : storage_(std::make_unique<Object>(std::move(value))) {}

Value::Value(const Value& other)
    : storage_(std::visit([](const auto& value) -> Storage {
        using Alternative = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<Alternative, OwnedObject>) {
            return std::make_unique<Object>(*value);
        } else {
            return value;
        }
    }, other.storage_))
{
}

Value::Value(Value&& other) noexcept : storage_(std::move(other.storage_))
{
    static_assert(std::is_nothrow_move_constructible_v<Storage> &&
        std::is_nothrow_move_assignable_v<Storage> && std::is_nothrow_swappable_v<Storage>,
        "owned JSON storage must transfer without becoming valueless");
    // Every successfully constructed object alternative has an owned map.
    // A transferred-from Value remains readable/reusable as JSON null.
    other.storage_.emplace<std::monostate>();
}

Value& Value::operator=(const Value& other)
{
    static_assert(std::is_nothrow_move_constructible_v<Storage> &&
        std::is_nothrow_move_assignable_v<Storage> && std::is_nothrow_swappable_v<Storage>,
        "owned JSON storage must transfer without becoming valueless");
    // Complete the independent copy before replacing the current value. A
    // failed allocation cannot leave a changed discriminator or partial proof.
    if (this != &other) {
        Value replacement(other);
        storage_.swap(replacement.storage_);
    }
    return *this;
}

Value& Value::operator=(Value&& other) noexcept
{
    if (this != &other) {
        // Finish the transfer before destroying this tree, including when
        // other is a descendant of this Value. No source access follows swap.
        Value replacement(std::move(other));
        storage_.swap(replacement.storage_);
    }
    return *this;
}

bool Value::as_boolean() const
{
    if (type() != Type::boolean) throw std::runtime_error("JSON value is not a boolean");
    return std::get<bool>(storage_);
}

std::uint64_t Value::as_unsigned() const
{
    if (type() != Type::unsigned_integer) throw std::runtime_error("JSON value is not an unsigned integer");
    return std::get<std::uint64_t>(storage_);
}

const std::string& Value::as_string() const
{
    if (type() != Type::string) throw std::runtime_error("JSON value is not a string");
    return std::get<std::string>(storage_);
}

const Value::Array& Value::as_array() const
{
    if (type() != Type::array) throw std::runtime_error("JSON value is not an array");
    return std::get<Array>(storage_);
}

const Value::Object& Value::as_object() const
{
    if (type() != Type::object) throw std::runtime_error("JSON value is not an object");
    return *std::get<OwnedObject>(storage_);
}

Value::Array& Value::as_array()
{
    if (type() != Type::array) throw std::runtime_error("JSON value is not an array");
    return std::get<Array>(storage_);
}

Value::Object& Value::as_object()
{
    if (type() != Type::object) throw std::runtime_error("JSON value is not an object");
    return *std::get<OwnedObject>(storage_);
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
    return type() == Type::object && as_object().find(key) != as_object().end();
}

namespace {

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
    Parser(const std::string& text, const ParseLimits& limits) : text_(text), limits_(limits)
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
                if (!usk::base::valid_utf8(result)) {
                    throw std::runtime_error("JSON string is not valid UTF-8");
                }
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
    std::size_t plain = 0;
    for (std::size_t index = 0; index < value.size(); ++index) {
        const auto ch = static_cast<unsigned char>(value[index]);
        if (ch >= 0x20u && ch != '"' && ch != '\\') continue;
        // Transfer each unchanged byte run once. Escapes, embedded NULs and
        // UTF-8 bytes keep exactly the existing canonical representation.
        output.append(value, plain, index - plain);
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
            }
        }
        plain = index + 1;
    }
    output.append(value, plain, value.size() - plain);
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

class CanonicalBudget {
public:
    explicit CanonicalBudget(const ParseLimits& limits) : limits_(limits) {}
    void object(const CanonicalObjectView& fields)
    {
        count_value(0);
        bytes(2); // braces
        bool first = true;
        for (const auto& field : fields) member(field.first, field.second.get(), 0, first);
    }
private:
    void bytes(std::size_t count)
    {
        if (count > limits_.max_bytes - bytes_) throw std::runtime_error("JSON input exceeds byte budget");
        bytes_ += count;
    }
    void count_value(std::size_t depth)
    {
        if (depth > limits_.max_depth) throw std::runtime_error("JSON exceeds depth budget");
        if (values_ == limits_.max_values) throw std::runtime_error("JSON exceeds value budget");
        ++values_;
    }
    void string(const std::string& text)
    {
        if (text.size() > limits_.max_string_bytes) throw std::runtime_error("JSON string exceeds budget");
        if (!usk::base::valid_utf8(text)) throw std::runtime_error("JSON string is not valid UTF-8");
        bytes(2); // quotes; budget measures encoded bytes, not decoded length
        for (const unsigned char ch : text) {
            switch (ch) {
            case '"': case '\\': case '\b': case '\f': case '\n': case '\r': case '\t': bytes(2); break;
            default: bytes(ch < 0x20u ? 6 : 1); break;
            }
        }
    }
    void child(const Value& item, std::size_t depth)
    {
        // Check before incrementing; empty containers need no child depth.
        if (depth >= limits_.max_depth) throw std::runtime_error("JSON exceeds depth budget");
        value(item, depth + 1);
    }
    void member(const std::string& key, const Value& item, std::size_t depth, bool& first)
    {
        if (!first) bytes(1);
        first = false;
        string(key);
        bytes(1); // colon; keys do not count toward the parser's value budget
        child(item, depth);
    }
    void value(const Value& item, std::size_t depth)
    {
        count_value(depth);
        switch (item.type()) {
        case Value::Type::null_value: bytes(4); return;
        case Value::Type::boolean: bytes(item.as_boolean() ? 4 : 5); return;
        case Value::Type::unsigned_integer: {
            auto number = item.as_unsigned();
            std::size_t digits = 1;
            while (number >= 10) { number /= 10; ++digits; }
            bytes(digits); return;
        }
        case Value::Type::string: string(item.as_string()); return;
        case Value::Type::array: {
            bytes(2);
            bool first = true;
            for (const auto& entry : item.as_array()) {
                if (!first) bytes(1);
                first = false;
                child(entry, depth);
            }
            return;
        }
        case Value::Type::object: {
            bytes(2);
            bool first = true;
            for (const auto& entry : item.as_object()) member(entry.first, entry.second, depth, first);
            return;
        }
        }
    }
    const ParseLimits& limits_;
    std::size_t bytes_ = 0, values_ = 0;
};

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

std::string canonical_object(const CanonicalObjectView& fields)
{
    std::string result(1, '{');
    bool first = true;
    for (const auto& field : fields) {
        if (!first) result.push_back(',');
        first = false;
        append_escaped(result, field.first);
        result.push_back(':');
        append_canonical(result, field.second.get());
    }
    result.push_back('}');
    return result;
}

void require_canonical_object_parse_limits(const CanonicalObjectView& fields, const ParseLimits& limits)
{
    CanonicalBudget(limits).object(fields);
}

bool equal_values(const Value& left, const Value& right)
{
    if (left.type() != right.type()) return false;
    switch (left.type()) {
    case Value::Type::null_value: return true;
    case Value::Type::boolean: return left.as_boolean() == right.as_boolean();
    case Value::Type::unsigned_integer: return left.as_unsigned() == right.as_unsigned();
    case Value::Type::string: return left.as_string() == right.as_string();
    case Value::Type::array: {
        const auto& a = left.as_array();
        const auto& b = right.as_array();
        if (a.size() != b.size()) return false;
        for (std::size_t i = 0; i < a.size(); ++i)
            if (!equal_values(a[i], b[i])) return false;
        return true;
    }
    case Value::Type::object: {
        const auto& a = left.as_object();
        const auto& b = right.as_object();
        if (a.size() != b.size()) return false;
        auto other = b.begin();
        for (const auto& member : a) {
            if (member.first != other->first || !equal_values(member.second, other->second)) return false;
            ++other;
        }
        return true;
    }
    }
    return false;
}

std::string sha256_canonical(const Value& value)
{
    const std::string text = canonical(value);
    usk::base::Sha256 digest;
    digest.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
    return digest.finish();
}

} // namespace usk::json
