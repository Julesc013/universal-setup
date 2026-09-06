// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_UTF8_PATH_H
#define USK_UTF8_PATH_H

#include <filesystem>
#include <string>
#include <stdexcept>

namespace usk::base {

class NativePathLimitExceeded final : public std::runtime_error {
public:
    explicit NativePathLimitExceeded(const std::string& message) : std::runtime_error(message) {}
};

enum class NativePathKind { file, directory };

// Pure admission only: this grants no filesystem or object-ownership authority.
// Windows uses conservative ordinary-path limits independent of host opt-in.
void require_native_path_capacity(
    const std::filesystem::path& path,
    NativePathKind kind,
    const std::string& purpose);

bool valid_utf8(const std::string& value) noexcept;

std::string path_to_utf8(const std::filesystem::path& path);

std::filesystem::path require_normalized_absolute_local_path_utf8(
    const std::string& value,
    const std::string& field_name);

} // namespace usk::base

#endif
