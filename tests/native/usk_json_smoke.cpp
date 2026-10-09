// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_json.h"

#include <functional>
#include <cstdlib>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

bool fail_allocations = false;
std::size_t allocations_remaining = 0;

} // namespace

// Only this statically linked smoke executable injects allocation failures.
// Production allocators and JSON exception handling are unchanged.
void* operator new(std::size_t size)
{
    if (fail_allocations) {
        if (allocations_remaining == 0) throw std::bad_alloc();
        --allocations_remaining;
    }
    if (void* memory = std::malloc(size == 0 ? 1 : size)) return memory;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete[](void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }
void operator delete[](void* memory, std::size_t) noexcept { std::free(memory); }

namespace {

bool copy_failure_preserves(const usk::json::Value& source, const usk::json::Value& original)
{
    const auto source_bytes = usk::json::canonical(source);
    const auto original_bytes = usk::json::canonical(original);
    bool saw_failure = false;
    for (std::size_t allowance = 0; allowance < 512; ++allowance) {
        usk::json::Value destination(original);
        bool failed = false;
        allocations_remaining = allowance;
        fail_allocations = true;
        try {
            destination = source;
        } catch (const std::bad_alloc&) {
            failed = true;
        } catch (...) {
            fail_allocations = false;
            return false;
        }
        fail_allocations = false;
        if (usk::json::canonical(source) != source_bytes) return false;
        if (!failed) return saw_failure && usk::json::canonical(destination) == source_bytes;
        saw_failure = true;
        if (destination.type() != original.type() || usk::json::canonical(destination) != original_bytes) return false;
    }
    return false;
}

bool refuses(const std::function<void()>& operation)
{
    try {
        operation();
    } catch (const std::runtime_error&) {
        return true;
    }
    return false;
}

} // namespace

int main()
{
    const std::string source =
        " { \"z\" : [true,null,7,\"line\\n\"], \"a\" : {\"unicode\":\"\\ud83d\\ude80\"} } ";
    const usk::json::Value parsed = usk::json::parse(source);
    const std::string expected =
        "{\"a\":{\"unicode\":\"\xf0\x9f\x9a\x80\"},\"z\":[true,null,7,\"line\\n\"]}";
    if (usk::json::canonical(parsed) != expected ||
        parsed.at("z").as_array().at(2).as_unsigned() != 7) {
        return 1;
    }
    if (!refuses([] { (void)usk::json::parse("{\"a\":1,\"a\":2}"); }) ||
        !refuses([] { (void)usk::json::parse("01"); }) ||
        !refuses([] { (void)usk::json::parse("1.0"); }) ||
        !refuses([] { (void)usk::json::parse("-1"); }) ||
        !refuses([] { (void)usk::json::parse("\"\\ud800\""); }) ||
        !refuses([] { (void)usk::json::parse(std::string("\"") + "\xc0\xaf" + "\""); }) ||
        !refuses([] { (void)usk::json::parse("{} trailing"); })) {
        return 2;
    }
    usk::json::ParseLimits limits;
    limits.max_values = 2;
    if (!refuses([&] { (void)usk::json::parse("[1,2]", limits); })) return 3;
    // Differential equality checks retain the canonical encoder as the oracle.
    // Types, byte escaping, integer precision, key ordering and array ordering
    // must agree without changing either input or the serialized wire format.
    using usk::json::Value;
    std::string controls;
    for (unsigned char ch = 0; ch < 32; ++ch) controls.push_back(static_cast<char>(ch));
    const std::vector<Value> values{
        Value(), Value(false), Value(true), Value(std::uint64_t{0}), Value(std::uint64_t{1}),
        Value(std::uint64_t{9007199254740992ull}), Value(std::uint64_t{9007199254740993ull}),
        Value(std::numeric_limits<std::uint64_t>::max()), Value(""), Value("null"), Value("true"),
        Value("0"), Value(controls), Value("\\u0000"), Value("\"\\\n\t"),
        Value(Value::Array{}), Value(Value::Object{}), parsed, usk::json::parse(expected),
        usk::json::parse("[1,2]"), usk::json::parse("[2,1]"),
        usk::json::parse("{\"z\":1,\"a\":[null,true]}"),
        usk::json::parse("{\"\\u0061\":[null,true],\"z\":1}"),
        usk::json::parse("{\"a\":[null,false],\"z\":1}"),
        usk::json::parse("{\"a\":[null,true],\"z\":2}"),
        usk::json::parse("{\"a\":[null,true],\"zz\":1}")};
    std::vector<std::string> encodings;
    for (const auto& value : values) encodings.push_back(usk::json::canonical(value));
    for (std::size_t i = 0; i < values.size(); ++i) {
        for (std::size_t j = 0; j < values.size(); ++j) {
            if (usk::json::equal_values(values[i], values[j]) != (encodings[i] == encodings[j])) return 5;
            // Exercise every source/destination type pair against independent
            // canonical bytes, including owned nested trees and exact UInt64s.
            Value assigned(values[i]);
            assigned = values[j];
            if (assigned.type() != values[j].type() || usk::json::canonical(assigned) != encodings[j]) return 14;
            assigned = assigned;
            if (usk::json::canonical(assigned) != encodings[j]) return 15;
            Value copied(values[j]);
            Value moved(std::move(copied));
            Value destination(values[i]);
            destination = std::move(moved);
            if (destination.type() != values[j].type() || usk::json::canonical(destination) != encodings[j] ||
                copied.type() != Value::Type::null_value || moved.type() != Value::Type::null_value) return 16;
            // Value's explicit move contract resets both live source objects
            // to monostate. Keep testing their readable canonical null state;
            // Cppcheck's generic moved-argument warning cannot model this API.
            // cppcheck-suppress accessMoved
            if (usk::json::canonical(copied) != "null" || usk::json::canonical(moved) != "null") return 16;
            destination = std::move(destination);
            if (usk::json::canonical(destination) != encodings[j]) return 19;
        }
        if (usk::json::canonical(values[i]) != encodings[i]) return 6;
    }
    Value independent(parsed);
    independent.as_object().at("a").as_object().at("unicode") = Value("changed");
    independent.as_object().at("z").as_array().at(0) = Value(false);
    if (usk::json::canonical(parsed) != expected || usk::json::equal_values(independent, parsed)) return 17;
    independent = Value(std::uint64_t{7});
    if (!refuses([&] { (void)independent.as_object(); }) || independent.contains("a") ||
        independent.as_unsigned() != 7 || usk::json::canonical(parsed) != expected) return 18;
    Value parent(parsed);
    parent = parent.as_object().at("a");
    if (usk::json::canonical(parent) != usk::json::canonical(parsed.at("a"))) return 20;
    parent = parsed;
    parent = std::move(parent.as_object().at("a"));
    if (usk::json::canonical(parent) != usk::json::canonical(parsed.at("a"))) return 21;
    const Value large_string(std::string(256, 'x'));
    const Value copied_array(Value::Array{parsed, large_string});
    const Value copied_object(Value::Object{{"nested", copied_array}, {"text", large_string}});
    for (const auto& original : values) {
        for (const auto& source_value : {large_string, copied_array, copied_object}) {
            if (!copy_failure_preserves(source_value, original)) return 22;
        }
    }
    // Independently decode the old owned encoding as the acceptance oracle for
    // the borrowed packet encoder and its allocation-free budget check.
    const auto agrees = [](const usk::json::CanonicalObjectView& fields,
        const usk::json::ParseLimits& budget) {
        Value::Object owned;
        for (const auto& field : fields) owned.emplace(field.first, field.second.get());
        const auto encoding = usk::json::canonical(Value(std::move(owned)));
        if (usk::json::canonical_object(fields) != encoding) return false;
        return refuses([&] { (void)usk::json::parse(encoding, budget); }) ==
            refuses([&] { usk::json::require_canonical_object_parse_limits(fields, budget); });
    };
    auto corpus = values;
    for (const auto& invalid : {std::string("\xc0\xaf"), std::string("\xed\xa0\x80"),
        std::string("\xf4\x90\x80\x80"), std::string("\xe2\x82")}) {
        corpus.emplace_back(invalid);
        corpus.emplace_back(Value::Object{{invalid, Value(true)}});
    }
    Value nested(Value::Array{});
    for (unsigned depth = 0; depth < 6; ++depth) {
        corpus.push_back(nested);
        nested = Value(Value::Array{nested});
    }
    const Value sequence(std::numeric_limits<std::uint64_t>::max()), binding(std::string(64, 'a'));
    for (const auto& body : corpus) {
        const usk::json::CanonicalObjectView fields{{"sequence", std::cref(sequence)},
            {"binding_sha256", std::cref(binding)}, {"body", std::cref(body)}};
        const auto encoded_bytes = usk::json::canonical_object(fields).size();
        for (std::size_t bound = 0; bound <= encoded_bytes + 1; ++bound) {
            usk::json::ParseLimits budget;
            budget.max_bytes = bound;
            if (!agrees(fields, budget)) return 7;
        }
        for (std::size_t bound = 0; bound <= 70; ++bound) {
            usk::json::ParseLimits budget;
            budget.max_string_bytes = bound;
            if (!agrees(fields, budget)) return 8;
            budget = usk::json::ParseLimits{};
            budget.max_values = bound;
            if (!agrees(fields, budget)) return 9;
        }
        for (std::size_t bound = 0; bound <= 8; ++bound) {
            usk::json::ParseLimits budget;
            budget.max_depth = bound;
            if (!agrees(fields, budget)) return 10;
        }
    }
    // Empty root, invalid key bytes and escaped key lengths also follow the
    // parser's rules: object keys count as strings, but never as values.
    for (const auto& key : {std::string(), controls, std::string("\xc0\xaf"), std::string("\"\\")}) {
        const Value body(true);
        const usk::json::CanonicalObjectView fields{{key, std::cref(body)}};
        for (std::size_t bound = 0; bound <= 40; ++bound) {
            usk::json::ParseLimits budget;
            budget.max_string_bytes = bound;
            budget.max_depth = bound;
            budget.max_values = bound;
            budget.max_bytes = bound;
            if (!agrees(fields, budget)) return 11;
        }
    }
    for (std::size_t bound = 0; bound <= 2; ++bound) {
        usk::json::ParseLimits budget;
        budget.max_bytes = bound;
        budget.max_values = bound;
        budget.max_depth = 0;
        if (!agrees({}, budget)) return 12;
    }
    usk::json::ParseLimits packet_budget;
    packet_budget.max_string_bytes = packet_budget.max_bytes;
    const Value empty_body("");
    const std::size_t overhead = usk::json::canonical_object({{"sequence", std::cref(sequence)},
        {"binding_sha256", std::cref(binding)}, {"body", std::cref(empty_body)}}).size();
    for (const auto extra : {std::size_t{0}, std::size_t{1}}) {
        const Value body(std::string(packet_budget.max_bytes - overhead + extra, 'x'));
        const usk::json::CanonicalObjectView fields{{"sequence", std::cref(sequence)},
            {"binding_sha256", std::cref(binding)}, {"body", std::cref(body)}};
        if (!agrees(fields, packet_budget)) return 13;
    }
    return usk::json::sha256_canonical(usk::json::parse("{}")) ==
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" ? 0 : 4;
}
