// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_json.h"
#include "usk_sha256.h"

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
std::size_t maximum_allocation = std::numeric_limits<std::size_t>::max();

} // namespace

// Only this statically linked smoke executable injects allocation failures.
// Production allocators and JSON exception handling are unchanged.
void* operator new(std::size_t size)
{
    if (fail_allocations) {
        if (allocations_remaining == 0 || size > maximum_allocation) throw std::bad_alloc();
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
    // Independent literal grammar covers every control byte, consecutive
    // escapes, beginning/end boundaries and UTF-8 bytes in unchanged runs.
    const std::string control_encoding =
        "\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007"
        "\\b\\t\\n\\u000b\\f\\r\\u000e\\u000f"
        "\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017"
        "\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f";
    for (const std::size_t length : {0u, 1u, 15u, 16u, 4096u}) {
        const std::string plain = std::string(length, 'p') + "\xf0\x9f\x9a\x80\x7f";
        const std::string text = controls + plain + "\"\\" + plain + controls;
        const std::string encoded = "\"" + control_encoding + plain + "\\\"\\\\" +
            plain + control_encoding + "\"";
        const Value body(text);
        if (usk::json::canonical(body) != encoded ||
            !usk::json::equal_values(usk::json::parse(encoded), body)) return 24;
        const Value object(Value::Object{{text, body}});
        const usk::json::CanonicalObjectView view{{text, std::cref(body)}};
        const std::string expected_object = "{" + encoded + ":" + encoded + "}";
        if (usk::json::canonical(object) != expected_object ||
            usk::json::canonical_object(view) != expected_object) return 25;
    }
    const std::string lookup_key = "required_long_json_member_literal";
    const char nul_literal[] = "member\0with_embedded_nul_and_long_tail";
    const std::string nul_key(nul_literal, sizeof(nul_literal) - 1);
    const std::string storage = "[" + nul_key + "]";
    const Value lookup(Value::Object{{lookup_key, Value(std::uint64_t{42})}, {nul_key, Value(true)}});
    allocations_remaining = 0; fail_allocations = true;
    bool lookup_ok = false;
    try {
        lookup_ok = lookup.at("required_long_json_member_literal").as_unsigned() == 42 &&
            lookup.at(lookup_key).as_unsigned() == 42 && lookup.contains(lookup_key) &&
            lookup.at(std::string_view(storage.data() + 1, nul_key.size())).as_boolean() &&
            lookup.contains(std::string_view(storage.data() + 1, nul_key.size())) &&
            !lookup.contains("absent_long_json_member_literal");
    } catch (...) { lookup_ok = false; }
    fail_allocations = false;
    if (!lookup_ok) return 26;
    if (!refuses([&] { (void)lookup.at(std::string_view("missing")); })) return 27;
    const auto digest_oracle = [](const Value& value) {
        const auto bytes = usk::json::canonical(value);
        usk::base::Sha256 digest;
        digest.update(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
        return digest.finish();
    };
    // Cross digest-buffer boundaries with escapes and plain runs. The oracle
    // hashes the independent complete canonical byte string.
    for (const std::size_t length : {0u, 1u, 4093u, 4094u, 4095u, 4096u, 4097u, 8191u, 65536u}) {
        const Value text(std::string(length, 'x') + controls + "\xf0\x9f\x9a\x80");
        if (usk::json::sha256_canonical(text) != digest_oracle(text)) return 28;
    }
    const Value large_digest_input(Value::Object{{lookup_key, Value(std::string(1024u * 1024u, 'x'))}});
    const auto large_digest_expected = digest_oracle(large_digest_input);
    allocations_remaining = 32; maximum_allocation = 4096; fail_allocations = true;
    bool bounded_digest_ok = false;
    try { bounded_digest_ok = usk::json::sha256_canonical(large_digest_input) == large_digest_expected; }
    catch (...) { bounded_digest_ok = false; }
    fail_allocations = false; maximum_allocation = std::numeric_limits<std::size_t>::max();
    if (!bounded_digest_ok) return 29;
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
    for (const auto& value : values) {
        encodings.push_back(usk::json::canonical(value));
        if (usk::json::sha256_canonical(value) != digest_oracle(value)) return 30;
    }
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
        const auto expected_refusal = refuses([&] { (void)usk::json::parse(encoding, budget); });
        if (expected_refusal != refuses([&] { usk::json::require_canonical_object_parse_limits(fields, budget); })) return false;
        std::size_t object_bytes = 0;
        const auto size_refusal = refuses([&] { object_bytes = usk::json::require_canonical_object_encoded_size(fields, budget); });
        if (size_refusal != expected_refusal || (!size_refusal && object_bytes != encoding.size())) return false;
        if (!refuses([&] { (void)usk::json::require_canonical_object_member_parse_limits(fields, budget, "missing-selector"); })) return false;
        // Check every member, including every varied body type, against the
        // independent encoder while retaining full-envelope parser parity.
        for (const auto& selected : fields) {
            std::size_t count = 0;
            const auto rejected = refuses([&] { count = usk::json::require_canonical_object_member_parse_limits(fields, budget, selected.first); });
            if (rejected != expected_refusal || (!rejected && count != usk::json::canonical(selected.second.get()).size())) return false;
        }
        return true;
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
    // Compare virtual array-object rows against the independent fully owned
    // canonical encoding/parser, including aggregate values and wrapper depth.
    for (const auto& body : {Value(), Value(controls), Value(std::string("\xc0\xaf")),
            Value(Value::Array(15u, Value(true))), usk::json::parse("{\"a\":[[false],{\"z\":\"x\"}]}")}) {
        const Value compact(Value::Array{Value(Value::Object{}), Value(Value::Object{})});
        const Value packet(Value::Object{{"results", compact}, {"tag", Value("shared")}});
        const std::vector<usk::json::CanonicalObjectView> rows{
            {{"left", std::cref(body)}, {"right", std::cref(body)}},
            {{"left", std::cref(body)}, {"right", std::cref(body)}}};
        const Value expanded_row(Value::Object{{"left", body}, {"right", body}});
        const Value expanded(Value::Object{{"results", Value(Value::Array{expanded_row, expanded_row})},
            {"tag", Value("shared")}});
        const usk::json::CanonicalObjectView wrapper{{"sequence", std::cref(sequence)},
            {"binding_sha256", std::cref(binding)}, {"body", std::cref(packet)}};
        const usk::json::CanonicalObjectView oracle{{"sequence", std::cref(sequence)},
            {"binding_sha256", std::cref(binding)}, {"body", std::cref(expanded)}};
        const auto encoded = usk::json::canonical_object(oracle);
        const auto expected_bytes = usk::json::canonical(expanded).size();
        const auto before = usk::json::canonical(packet);
        const auto agrees_array = [&](const usk::json::ParseLimits& limits) {
            bool expected_ok = true, actual_ok = true;
            std::size_t actual_bytes = 0;
            try { (void)usk::json::parse(encoded, limits); } catch (const std::runtime_error&) { expected_ok = false; }
            try { actual_bytes = usk::json::require_canonical_object_array_view_member_parse_limits(
                wrapper, limits, "body", packet.at("results"), rows); }
            catch (const std::runtime_error&) { actual_ok = false; }
            return expected_ok == actual_ok && (!actual_ok || actual_bytes == expected_bytes);
        };
        for (std::size_t bound = 0; bound <= encoded.size() + 1u; ++bound) {
            usk::json::ParseLimits limits; limits.max_bytes = bound;
            if (!agrees_array(limits)) return 31;
        }
        for (std::size_t bound = 0; bound <= 160u; ++bound) {
            usk::json::ParseLimits limits; limits.max_values = bound;
            if (!agrees_array(limits)) return 31;
            limits = {}; limits.max_string_bytes = bound;
            if (!agrees_array(limits)) return 31;
        }
        for (std::size_t bound = 0; bound <= 12u; ++bound) {
            usk::json::ParseLimits limits; limits.max_depth = bound;
            if (!agrees_array(limits)) return 31;
        }
        if (usk::json::canonical(packet) != before) return 32;
    }
    {
        const Value item(true), compact(Value::Array{Value(Value::Object{})});
        const Value packet(Value::Object{{"results", compact}});
        const std::vector<usk::json::CanonicalObjectView> rows{{{"value", std::cref(item)}}};
        const usk::json::CanonicalObjectView wrapper{{"body", std::cref(packet)}};
        allocations_remaining = 0; fail_allocations = true;
        bool no_allocation = false;
        try { no_allocation = usk::json::require_canonical_object_array_view_member_parse_limits(
            wrapper, {}, "body", packet.at("results"), rows) ==
                sizeof("{\"results\":[{\"value\":true}]}") - 1u; }
        catch (...) {}
        fail_allocations = false;
        if (!no_allocation) return 33;
        if (!refuses([&] { (void)usk::json::require_canonical_object_array_view_member_parse_limits(
                wrapper, {}, "body", compact, rows); }) ||
            !refuses([&] { (void)usk::json::require_canonical_object_array_view_member_parse_limits(
                wrapper, {}, "absent", packet.at("results"), rows); }) ||
            !refuses([&] { (void)usk::json::require_canonical_object_array_view_member_parse_limits(
                wrapper, {}, "body", packet.at("results"), {}); })) return 34;
        const usk::json::CanonicalObjectView aliased{{"body", std::cref(packet)}, {"other", std::cref(packet)}};
        if (!refuses([&] { (void)usk::json::require_canonical_object_array_view_member_parse_limits(
                aliased, {}, "body", packet.at("results"), rows); })) return 34;
        const std::vector<usk::json::CanonicalObjectView> recursive{{{"value", std::cref(packet.at("results"))}}};
        if (!refuses([&] { (void)usk::json::require_canonical_object_array_view_member_parse_limits(
                wrapper, {}, "body", packet.at("results"), recursive); })) return 34;
    }
    {
        const Value empty(Value::Array{}), packet(Value::Object{{"results", Value(Value::Array{})}});
        const usk::json::CanonicalObjectView wrapper{{"body", std::cref(packet)}};
        const auto encoded = usk::json::canonical_object(wrapper);
        for (std::size_t bound = 0; bound < 7u; ++bound) {
            for (const bool values : {false, true}) {
                usk::json::ParseLimits limits;
                if (values) limits.max_values = bound; else limits.max_depth = bound;
                bool expected_ok = true, actual_ok = true;
                try { (void)usk::json::parse(encoded, limits); } catch (const std::runtime_error&) { expected_ok = false; }
                try { (void)usk::json::require_canonical_object_array_view_member_parse_limits(
                    wrapper, limits, "body", packet.at("results"), {}); }
                catch (const std::runtime_error&) { actual_ok = false; }
                if (expected_ok != actual_ok) return 35;
            }
        }
        (void)empty;
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
