// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PACKAGE_VERIFY_H
#define USK_PACKAGE_VERIFY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char* usk_package_verify_command_json(
    const char* request_json,
    size_t request_size,
    int audit_mode,
    int* out_command_status
);

void usk_package_verify_command_free(char* value);

#ifdef __cplusplus
}

#include <filesystem>
#include <string>

namespace usk::verify {
std::string sha256_hex_file(const std::filesystem::path& path);
}
#endif

#endif
