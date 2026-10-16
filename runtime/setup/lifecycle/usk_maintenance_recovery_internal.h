// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_MAINTENANCE_RECOVERY_INTERNAL_H
#define USK_MAINTENANCE_RECOVERY_INTERNAL_H

#include "usk_transaction_session.h"
#include "usk_maintenance_inspection_internal.h"
#include "usk_maintenance_effect_journal.h"
#include "usk_state_repository.h"
#include "usk_audit_repository.h"
#include <functional>
#include <string>

namespace usk::lifecycle::detail {

// Read-only comparison with the original immutable context and actual retained
// objects. compatible_before_effect / compatible_after_effect describe current
// postconditions; neither proves which actor performed an effect or authorizes
// replay, deletion, transfer of ownership or a completion record.
MaintenanceEffectReconciliation reconcile_maintenance_effect(
    const transaction::TransactionSpec& spec);

// Bounded create-only original plan and owned-object observations, joined to
// the actual transaction/context and original immutable installed revision.
// Source readers and payload bytes are never stored here. This read-only
// record confers no native custody, replay or current-revision authority.
json::Value read_maintenance_reviewed_plan(const transaction::TransactionSpec& spec);

// Selects the next original reviewed effect from the exact completed prefix,
// original owned observations and creation-handle stream identities. Missing
// sources, skipped effects and conflicting observations refuse. Read-only;
// the native operation owner must independently retain mutation authority.
MaintenanceContinuationInspection inspect_maintenance_continuation(
    const transaction::TransactionSpec& spec);

// Completed sealed history only. Validates the entire original ordered effect
// prefix and immutable ownership/installed/audit postimages without reading
// current payload paths. The result proves no current health or native actor,
// lease membership or mutation authority; the native reader supplies those
// separate protected-record observations before reporting an old completion.
MaintenanceContinuationInspection inspect_completed_maintenance_history(
    const transaction::TransactionSpec& spec);

// Exact old pure bodies for the private native inspection adapter. They never
// dispatch another scope; their ordinary protected reads retain all fences.
MaintenanceContinuationInspection inspect_maintenance_continuation_unscoped(
    const transaction::TransactionSpec& spec);
MaintenanceEffectReconciliation reconcile_maintenance_effect_unscoped(
    const transaction::TransactionSpec& spec);

// Fixed initial snapshot validation only; this pure predicate grants no native
// scope, authority, completion or mutation permission.
void require_maintenance_pending_recovery_snapshot(
    const transaction::RecoveryInspection& transaction,
    const transaction::MaintenanceEffectInspection& history,
    const std::string& expected_transaction_snapshot_sha256,
    const std::string& expected_history_digest);

// Exact post-completion metadata predicate; no authority or effects.
void require_maintenance_completed_effect_prefix(
    const transaction::RecoveryInspection& expected_transaction,
    const transaction::MaintenanceEffectInspection& expected_history,
    const transaction::RecoveryInspection& current,
    const transaction::MaintenanceEffectInspection& completed);

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

#if defined(_WIN32)
// Fixed read-only pins for the original private native backend. Only its two
// concrete, unchanged callback targets and current weak engine binding can
// select this reader. Ordinary, replaced and wrapped callbacks return false
// and retain their original separate reads/calls. No callback runs in a recipe.
enum class NativeMaintenanceRecoveryPrefixPin { exact_snapshot, original_context };
bool require_current_native_maintenance_recovery_prefix(
    const transaction::TransactionSpec& spec,
    const transaction::RecoveryInspection& expected_transaction,
    const transaction::MaintenanceEffectInspection& expected_history,
    const MaintenanceRecoveryOperations& operations,
    NativeMaintenanceRecoveryPrefixPin pin);
// Fixed no-injector completion tail. The concrete owner finishes every pure
// read and its full fresh exit before the separately fenced journal write.
// Decline only before a native begin; begun failures cannot fall back.
bool complete_current_native_maintenance_recovery_effect(
    const transaction::TransactionSpec& spec,
    const transaction::RecoveryInspection& expected_transaction,
    const transaction::MaintenanceEffectInspection& expected_history,
    const MaintenanceRecoveryOperations& operations,
    const std::string& outcome, const std::string& result_digest);

// Two fixed adjacent pure lifecycle groups. Outputs remain metadata and appear
// only after the full original-record/global exit proof. No callback, effect,
// grant or journal transition enters either body. Both original targets and
// weak engine binding are required; a decline leaves every output unchanged.
bool reconcile_current_native_maintenance_recovery_prefix(
    const transaction::TransactionSpec& spec,
    const transaction::RecoveryInspection& expected_transaction,
    const transaction::MaintenanceEffectInspection& expected_history,
    const MaintenanceRecoveryOperations& operations,
    MaintenanceEffectReconciliation& output);
// Original-backend initial pair/predicates and first pin/reconciliation form
// one effect-free body. With injector absent, compatible-before preparation
// also includes the discarded postimage checks and following exact prefix pin.
// Finish the full original-record/global exit before publishing any output;
// the preparation flag replaces only those completed reads, never effect checks.
// A decline leaves all outputs, including the preparation flag, unchanged.
bool inspect_current_native_maintenance_pending_recovery(
    const transaction::TransactionSpec& spec,
    const std::string& expected_transaction_snapshot_sha256,
    const std::string& expected_history_digest,
    const MaintenanceRecoveryOperations& operations, bool prepare_before_effect,
    transaction::RecoveryInspection& output_transaction,
    transaction::MaintenanceEffectInspection& output_history,
    MaintenanceEffectReconciliation& output_reconciliation, bool& output_pre_effect_prepared);
bool inspect_current_native_maintenance_recovery_step(
    const transaction::TransactionSpec& spec,
    const transaction::RecoveryInspection& expected_transaction,
    const transaction::MaintenanceEffectInspection& expected_history,
    const MaintenanceRecoveryOperations& operations,
    MaintenanceContinuationInspection& output_selection,
    transaction::RecoveryInspection& output_transaction,
    transaction::MaintenanceEffectInspection& output_history);
// Fixed recovery-only readers. Exact original backend targets select them;
// no supplied callback/effect enters either scope. Validation grants nothing.
bool validate_current_native_maintenance_recovery_postimage(
    const transaction::TransactionSpec& spec,
    const transaction::MaintenanceEffectInspection& history,
    const MaintenanceRecoveryOperations& operations);
bool validate_current_native_maintenance_appended_intent(
    const transaction::TransactionSpec& spec, const std::string& source_digest,
    const MaintenanceContinuationInspection& selected,
    const transaction::MaintenanceEffectInspection& previous_history,
    const MaintenanceRecoveryOperations& operations);
// Fixed adjacent reads AFTER the journal write has returned. The full fresh
// original-record/global exit precedes all outputs. No supplied callback,
// journal transition, grant or effect enters either composition. Declines
// preserve all outputs; callers retain the ordinary separate path.
bool validate_current_native_maintenance_appended_intent_with_owner(
    const transaction::TransactionSpec& spec,
    const transaction::RecoveryInspection& expected_transaction,
    const transaction::MaintenanceEffectInspection& expected_history,
    const std::string& source_digest, const MaintenanceContinuationInspection& selected,
    const transaction::MaintenanceEffectInspection& previous_history,
    const MaintenanceRecoveryOperations& operations);
bool reconcile_current_native_maintenance_completed_effect(
    const transaction::TransactionSpec& spec,
    const transaction::RecoveryInspection& expected_transaction,
    const transaction::MaintenanceEffectInspection& expected_history,
    const MaintenanceRecoveryOperations& operations, MaintenanceEffectReconciliation& output);
#endif

// Resolves exactly one pending intent, never the entire transaction. Pins the
// inspected transaction and history before/after effects and record writes.
// An uncertain backend effect leaves the intent unresolved; it is not retried.
MaintenanceEffectReconciliation recover_pending_maintenance_effect(
    const transaction::TransactionSpec& spec,
    const std::string& expected_transaction_snapshot_sha256,
    const std::string& expected_history_digest,
    const MaintenanceRecoveryOperations& operations,
    transaction::FaultInjector injector = {});

// Continues the complete original committed maintenance operation without
// source readers or replanning. The same operation-owned backend is required
// throughout every effect, metadata write, seal and transaction transition.
// Precommit transactions retain their separate refusal and missing staged
// bytes are never invented. Success requires the sealed complete prefix.
transaction::RecoveryInspection recover_maintenance_transaction(
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
