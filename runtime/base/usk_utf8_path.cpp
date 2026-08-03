// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_utf8_path.h"

#include <cstdint>
#include <stdexcept>

namespace fs = std::filesystem;

namespace {

bool has_unc_or_device_prefix(const std::string& value)
{
    return value.size() >= 2 &&
        ((value[0] == '\\' && value[1] == '\\') ||
         (value[0] == '/' && value[1] == '/'));
}

std::runtime_error path_error(
    const std::string& field_name,
    const std::string& detail)
{
    return std::runtime_error(field_name + " " + detail);
}

} // namespace

namespace usk::base {

bool valid_utf8(const std::string& value) noexcept
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
            const unsigned char continuation =
                static_cast<unsigned char>(value[index++]);
            if ((continuation & 0xc0u) != 0x80u) return false;
            codepoint = (codepoint << 6) | (continuation & 0x3fu);
        }
        if ((remaining == 2 && codepoint < 0x800u) ||
            (remaining == 3 && codepoint < 0x10000u) ||
            codepoint > 0x10ffffu ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu)) {
            return false;
        }
    }
    return true;
}

std::string path_to_utf8(const fs::path& path)
{
    try {
        const std::string result = path.u8string();
        if (!valid_utf8(result)) {
            throw std::runtime_error("native filesystem path is not valid UTF-8");
        }
        if (result.find('\0') != std::string::npos) {
            throw std::runtime_error("native filesystem path contains an embedded NUL");
        }
        const fs::path rebuilt = fs::u8path(result);
        if (rebuilt.native() != path.native() || rebuilt.u8string() != result) {
            throw std::runtime_error(
                "native filesystem path does not round-trip through UTF-8");
        }
        return result;
    } catch (const fs::filesystem_error&) {
        throw std::runtime_error(
            "native filesystem path cannot be represented as UTF-8");
    }
}

fs::path require_normalized_absolute_local_path_utf8(
    const std::string& value,
    const std::string& field_name)
{
    if (!valid_utf8(value)) {
        throw path_error(field_name, "must be valid UTF-8");
    }
    if (value.find('\0') != std::string::npos) {
        throw path_error(field_name, "contains an embedded NUL");
    }
    if (has_unc_or_device_prefix(value)) {
        throw path_error(field_name, "must not use a UNC or device namespace");
    }

    fs::path path;
    try {
        path = fs::u8path(value);
    } catch (const fs::filesystem_error&) {
        throw path_error(field_name, "cannot be converted from UTF-8");
    }
    if (!path.is_absolute()) {
        throw path_error(field_name, "must be an absolute local filesystem path");
    }

    const fs::path normalized = path.lexically_normal();
    const std::string normalized_utf8 = path_to_utf8(normalized);
    if (normalized_utf8 != value) {
        throw path_error(field_name, "must be lexically normalized");
    }

    return normalized;
}

} // namespace usk::base
