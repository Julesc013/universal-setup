// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_JSON_H
#define USK_JSON_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace usk::json {

class Value {
public:
    enum class Type { null_value, boolean, unsigned_integer, string, array, object };
    using Array = std::vector<Value>;
    using Object = std::map<std::string, Value>;

    Value() = default;
    explicit Value(bool value);
    explicit Value(std::uint64_t value);
    explicit Value(std::string value);
    explicit Value(const char* value);
    explicit Value(Array value);
    explicit Value(Object value);

    Type type() const noexcept { return type_; }
    bool as_boolean() const;
    std::uint64_t as_unsigned() const;
    const std::string& as_string() const;
    const Array& as_array() const;
    const Object& as_object() const;
    Array& as_array();
    Object& as_object();
    const Value& at(const std::string& key) const;
    bool contains(const std::string& key) const;

private:
    Type type_ = Type::null_value;
    bool boolean_ = false;
    std::uint64_t unsigned_ = 0;
    std::string string_;
    Array array_;
    Object object_;
};

struct ParseLimits {
    std::size_t max_bytes = 4u * 1024u * 1024u;
    std::size_t max_depth = 64;
    std::size_t max_values = 100000;
    std::size_t max_string_bytes = 1024u * 1024u;
};

Value parse(const std::string& text, const ParseLimits& limits = {});
std::string canonical(const Value& value);
std::string sha256_canonical(const Value& value);

} // namespace usk::json

#endif
