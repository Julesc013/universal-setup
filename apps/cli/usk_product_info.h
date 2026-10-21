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

// Verify the same complete packaged closure, then compose the existing public
// read-only install request. Options are an app-private, closed JSON document.
std::string compose_product_install_plan(const std::filesystem::path& bundle_path,
    const std::string& options_json);

} // namespace usk::command

#endif
