// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PRODUCT_INSTALL_H
#define USK_PRODUCT_INSTALL_H

#include "usk_one_shot.h"
#include <filesystem>
#include <string>

namespace usk::command {

// A review is bounded by the existing response ceiling, including its request.
// It is untrusted user data, never a publisher admission or authority grant.
OneShotResult plan_product_install(const std::filesystem::path& bundle,
    const std::string& options, const OneShotContextConfig& context);
OneShotResult apply_product_install(const std::filesystem::path& bundle,
    const std::string& review, const std::string& confirmation,
    const OneShotContextConfig& context, const CandidateTransport& transport);

} // namespace usk::command
#endif
