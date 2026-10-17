// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_MAINTENANCE_INSPECTION_INTERNAL_H
#define USK_MAINTENANCE_INSPECTION_INTERNAL_H

#include "usk_json.h"
#include <string>

namespace usk::lifecycle::detail {

// Plain internal read-only results shared across transaction/lifecycle layers.
// They carry no native owner, scope, custody or mutation authority.
struct MaintenanceEffectReconciliation {
    std::string state = "indeterminate";
    std::string pending_kind;
    std::string source_digest;
    std::string history_digest;
    std::string result_digest;
};

struct MaintenanceContinuationInspection {
    std::string transaction_snapshot_sha256;
    std::string history_digest;
    std::string next_kind;
    json::Value next_details;
    bool pending = false;
    bool effects_complete = false;
    bool sealed = false;
};

} // namespace usk::lifecycle::detail
#endif
