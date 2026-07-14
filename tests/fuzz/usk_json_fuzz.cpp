// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_json.h"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size > 64u * 1024u) return 0;
    const std::string input(reinterpret_cast<const char*>(data), size);
    usk::json::ParseLimits limits;
    limits.max_bytes = 64u * 1024u;
    limits.max_depth = 32;
    limits.max_values = 4096;
    limits.max_string_bytes = 32u * 1024u;
    try {
        const usk::json::Value parsed = usk::json::parse(input, limits);
        const std::string canonical = usk::json::canonical(parsed);
        const usk::json::Value reparsed = usk::json::parse(canonical, limits);
        if (usk::json::canonical(reparsed) != canonical) __builtin_trap();
    } catch (const std::runtime_error&) {
    }
    return 0;
}
