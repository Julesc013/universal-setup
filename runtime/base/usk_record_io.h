// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_RECORD_IO_H
#define USK_RECORD_IO_H

#include <cstddef>
#include <filesystem>
#include <string>

namespace usk::record_io {

bool valid_identifier(const std::string& value);
void require_safe_directory(const std::filesystem::path& path);
void create_directory_exclusive(const std::filesystem::path& parent, const std::string& name);
void write_new_durable_text(const std::filesystem::path& path, const std::string& content);
std::string read_stable_text(const std::filesystem::path& path, std::size_t max_bytes);
void rename_no_replace(const std::filesystem::path& source, const std::filesystem::path& target);

} // namespace usk::record_io

#endif
