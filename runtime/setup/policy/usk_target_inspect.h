// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_TARGET_INSPECT_H
#define USK_TARGET_INSPECT_H

#include "usk_target_policy.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace usk::policy {

struct TargetInspectionRequest {
    TargetClass target_class = TargetClass::foreign_owned;
    std::filesystem::path target_root;
    std::filesystem::path authorized_acceptance_root;
    std::filesystem::path source_archive;
    std::uint64_t required_bytes = 0;
    std::vector<std::string> persistent_effects;
};

struct InspectedTarget {
    TargetEvidence evidence;
    TargetPolicyDecision decision;
};

TargetEvidence inspect_live_target(const TargetInspectionRequest& request);

InspectedTarget inspect_and_evaluate_live_target(
    Activation activation,
    const TargetInspectionRequest& request);

} // namespace usk::policy

#endif
