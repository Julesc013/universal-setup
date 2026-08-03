// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_UTF8_PATH_H
#define USK_UTF8_PATH_H

#include <filesystem>
#include <string>

namespace usk::base {

bool valid_utf8(const std::string& value) noexcept;

std::string path_to_utf8(const std::filesystem::path& path);

std::filesystem::path require_normalized_absolute_local_path_utf8(
    const std::string& value,
    const std::string& field_name);

} // namespace usk::base

#endif
