// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_MAINTENANCE_CONTEXT_INTERNAL_H
#define USK_MAINTENANCE_CONTEXT_INTERNAL_H

#include <filesystem>
#include <stdexcept>
#include <system_error>

namespace usk::lifecycle::detail {

// Consume a no-follow observation only. A positive directory result still
// requires native identity observation, including rejection of reparse objects.
// Neither result grants mutation or pathname cleanup authority.
inline bool maintenance_directory_present(
    const std::filesystem::file_status& status, const std::error_code& error)
{
    if (status.type() == std::filesystem::file_type::not_found &&
        (!error || error == std::errc::no_such_file_or_directory)) {
        return false;
    }
    if (error || status.type() != std::filesystem::file_type::directory) {
        throw std::runtime_error("maintenance installed root has an unsafe or indeterminate type");
    }
    return true;
}

} // namespace usk::lifecycle::detail

#endif
