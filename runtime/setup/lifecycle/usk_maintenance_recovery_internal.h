// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_MAINTENANCE_RECOVERY_INTERNAL_H
#define USK_MAINTENANCE_RECOVERY_INTERNAL_H

#include "usk_transaction_session.h"
#include <string>

namespace usk::lifecycle::detail {

struct MaintenanceEffectReconciliation {
    std::string state = "indeterminate";
    std::string pending_kind;
    std::string source_digest;
    std::string history_digest;
    std::string result_digest;
};

// Read-only comparison with the original immutable context and actual retained
// objects. compatible_before_effect / compatible_after_effect describe current
// postconditions; neither proves which actor performed an effect or authorizes
// replay, deletion, transfer of ownership or a completion record.
MaintenanceEffectReconciliation reconcile_maintenance_effect(
    const transaction::TransactionSpec& spec);

} // namespace usk::lifecycle::detail
#endif
