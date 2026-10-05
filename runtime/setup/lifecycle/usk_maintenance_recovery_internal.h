// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_MAINTENANCE_RECOVERY_INTERNAL_H
#define USK_MAINTENANCE_RECOVERY_INTERNAL_H

#include "usk_transaction_session.h"
#include "usk_maintenance_effect_journal.h"
#include "usk_state_repository.h"
#include "usk_audit_repository.h"
#include <functional>
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

// Internal operation-local backend, supplied by the owner of the native
// operation. require_authority must retain and revalidate the original intent,
// current installed revision, generation/worker fence, record parents and all
// affected objects. apply_effect must use those held objects. These callbacks
// are not a public authorization interface; the executor has no path fallback.
struct MaintenanceRecoveryOperations {
    std::function<void(const transaction::TransactionSpec&,
        const transaction::RecoveryInspection&,
        const transaction::MaintenanceEffectInspection&)> require_authority;
    // Returns applied, or retained only for an unchanged bound directory.
    std::function<std::string(const transaction::TransactionSpec&,
        const transaction::MaintenanceEffectInspection&)> apply_effect;
};

// Resolves exactly one pending intent, never the entire transaction. Pins the
// inspected transaction and history before/after effects and record writes.
// An uncertain backend effect leaves the intent unresolved; it is not retried.
MaintenanceEffectReconciliation recover_pending_maintenance_effect(
    const transaction::TransactionSpec& spec,
    const std::string& expected_transaction_snapshot_sha256,
    const std::string& expected_history_digest,
    const MaintenanceRecoveryOperations& operations,
    transaction::FaultInjector injector = {});

// Read-only reconstruction of bounded metadata postimages against the original
// immutable snapshot. They confer no write, native-object or revision authority.
state::OwnershipManifest maintenance_ownership_postimage(
    const transaction::TransactionSpec& spec,
    const transaction::MaintenanceEffectInspection& history);
state::InstalledState maintenance_installed_postimage(
    const transaction::TransactionSpec& spec,
    const transaction::MaintenanceEffectInspection& history);
audit::AuditInput maintenance_audit_postimage(
    const transaction::TransactionSpec& spec,
    const transaction::MaintenanceEffectInspection& history);

} // namespace usk::lifecycle::detail
#endif
