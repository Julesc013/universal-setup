// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_JSON_H
#define USK_JSON_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <variant>
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
    Value(const Value&);
    Value(Value&&) noexcept;
    Value& operator=(const Value&);
    Value& operator=(Value&&) noexcept;

    Type type() const noexcept { return static_cast<Type>(storage_.index()); }
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
    // Alternatives follow Type exactly. Only the active owned value is live;
    // copying a scalar need not construct/copy empty string/vector/map members.
    // map's move construction may allocate an empty sentinel on some STLs.
    // An exclusive pointer transfers the active object without that allocation;
    // copy construction explicitly clones it rather than sharing proof trees.
    using OwnedObject = std::unique_ptr<Object>;
    using Storage = std::variant<std::monostate, bool, std::uint64_t, std::string, Array, OwnedObject>;
    Storage storage_;
};

struct ParseLimits {
    std::size_t max_bytes = 4u * 1024u * 1024u;
    std::size_t max_depth = 64;
    std::size_t max_values = 100000;
    std::size_t max_string_bytes = 1024u * 1024u;
};

// Ephemeral fields for encoding an object without copying its value subtrees.
// The caller keeps every referenced value alive through the synchronous call.
using CanonicalObjectView = std::map<std::string, std::reference_wrapper<const Value>>;

Value parse(const std::string& text, const ParseLimits& limits = {});
std::string canonical(const Value& value);
std::string canonical_object(const CanonicalObjectView& fields);
// Exactly the acceptance of parse(canonical_object(fields), limits), without
// materializing another encoding or decoded tree. Keys are unique by construction.
void require_canonical_object_parse_limits(const CanonicalObjectView& fields, const ParseLimits& limits);
// Exact value equality, equivalent to comparing the canonical encodings.
bool equal_values(const Value& left, const Value& right);
std::string sha256_canonical(const Value& value);

} // namespace usk::json

#endif
