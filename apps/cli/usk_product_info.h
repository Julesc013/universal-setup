// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PRODUCT_INFO_H
#define USK_PRODUCT_INFO_H

#include <filesystem>
#include <string>
#include <vector>

namespace usk::command {

// Reopen the compiled sidecar and stream its complete stored ZIP payload.
// This is read-only product inspection, not plan or install authority.
std::string inspect_product_info(const std::filesystem::path& bundle_path);

// Verify the complete packaged byte closure, then resolve a component graph.
// This returns a read-only selection, not a machine plan or install authority.
std::string inspect_product_selection(const std::filesystem::path& bundle_path,
    const std::vector<std::string>& requested);

} // namespace usk::command

#endif
