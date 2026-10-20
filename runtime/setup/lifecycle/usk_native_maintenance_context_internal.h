// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_NATIVE_MAINTENANCE_CONTEXT_INTERNAL_H
#define USK_NATIVE_MAINTENANCE_CONTEXT_INTERNAL_H
#if defined(_WIN32)
#include "usk_protected_install_publisher_internal.h"
#include "usk_publisher_installation_lease.h"
#include "usk_publisher_metadata.h"
#include "usk_native_maintenance_transaction_internal.h"
#include "usk_record_io.h"
#include <memory>
namespace usk::transaction { class MaintenanceEffectJournal; }
namespace usk::lifecycle::detail {
struct MaintenanceRecoveryOperations;
struct MaintenanceContinuationInspection;
struct MaintenanceEffectReconciliation;
struct MaintenancePendingRecoveryReads;
enum class NativeMaintenanceRecoveryPrefixPin;
// Native staging custody for the private service engine. Construction is
// inaccessible to the public lifecycle, JSON and supplied callback backends.
// The caller retains original state/intent, admission, channel and lease for
// this entire lifetime. Existing paths are admitted independently; reopened
// objects are never labelled as this worker's native creations.
// The fresh private constructor publishes bounded create-only original custody
// before the first lifecycle journal. The engine must complete all request/
// capacity preflight and supply its effects-may-exist output. This owner marks
// that output before its first record effect, including constructor failure.
class NativeMaintenanceContext final {
public:
    ~NativeMaintenanceContext();
    NativeMaintenanceContext(const NativeMaintenanceContext&) = delete;
    NativeMaintenanceContext& operator=(const NativeMaintenanceContext&) = delete;
private:
    friend bool require_current_native_maintenance_recovery_prefix(
        const usk::transaction::TransactionSpec&,
        const usk::transaction::RecoveryInspection&,
        const usk::transaction::MaintenanceEffectInspection&,
        const MaintenanceRecoveryOperations&, NativeMaintenanceRecoveryPrefixPin);
    friend bool complete_current_native_maintenance_recovery_effect(
        const usk::transaction::TransactionSpec&,
        const usk::transaction::RecoveryInspection&,
        const usk::transaction::MaintenanceEffectInspection&,
        const MaintenanceRecoveryOperations&, const std::string&, const std::string&);
    friend bool reconcile_and_complete_current_native_maintenance_recovery_effect(
        const usk::transaction::TransactionSpec&,
        const usk::transaction::RecoveryInspection&,
        const usk::transaction::MaintenanceEffectInspection&,
        const MaintenanceRecoveryOperations&, const std::string&,
        MaintenanceEffectReconciliation&);
    friend bool reconcile_current_native_maintenance_recovery_prefix(
        const usk::transaction::TransactionSpec&,
        const usk::transaction::RecoveryInspection&,
        const usk::transaction::MaintenanceEffectInspection&,
        const MaintenanceRecoveryOperations&, MaintenanceEffectReconciliation&);
    friend bool inspect_current_native_maintenance_pending_recovery(
        const usk::transaction::TransactionSpec&, const std::string&, const std::string&,
        const MaintenanceRecoveryOperations&, bool,
        usk::transaction::RecoveryInspection&, usk::transaction::MaintenanceEffectInspection&,
        MaintenanceEffectReconciliation&, bool&);
    friend bool inspect_current_native_maintenance_recovery_step(
        const usk::transaction::TransactionSpec&,
        const usk::transaction::RecoveryInspection&,
        const usk::transaction::MaintenanceEffectInspection&,
        const MaintenanceRecoveryOperations&, MaintenanceContinuationInspection&,
        usk::transaction::RecoveryInspection&, usk::transaction::MaintenanceEffectInspection&,
        bool, std::unique_ptr<usk::transaction::MaintenanceEffectJournal>&,
        std::unique_ptr<MaintenancePendingRecoveryReads>&);
    friend bool apply_current_native_maintenance_recovery_cleanup(
        const usk::transaction::TransactionSpec&,
        const usk::transaction::MaintenanceEffectInspection&,
        const MaintenanceRecoveryOperations&, std::string&);
    friend bool validate_current_native_maintenance_recovery_postimage(
        const usk::transaction::TransactionSpec&,
        const usk::transaction::MaintenanceEffectInspection&,
        const MaintenanceRecoveryOperations&);
    friend bool validate_current_native_maintenance_appended_intent(
        const usk::transaction::TransactionSpec&, const std::string&,
        const MaintenanceContinuationInspection&,
        const usk::transaction::MaintenanceEffectInspection&,
        const MaintenanceRecoveryOperations&);
    friend bool validate_current_native_maintenance_appended_intent_with_owner(
        const usk::transaction::TransactionSpec&,
        const usk::transaction::RecoveryInspection&,
        const usk::transaction::MaintenanceEffectInspection&,
        const std::string&, const MaintenanceContinuationInspection&,
        const usk::transaction::MaintenanceEffectInspection&,
        const MaintenanceRecoveryOperations&);
    friend bool reconcile_current_native_maintenance_completed_effect(
        const usk::transaction::TransactionSpec&,
        const usk::transaction::RecoveryInspection&,
        const usk::transaction::MaintenanceEffectInspection&,
        const MaintenanceRecoveryOperations&, MaintenanceEffectReconciliation&);
    friend std::string usk::platform::windows::execute_candidate_restricted_publisher(
        const usk::platform::windows::CandidatePublisherConfiguration&, bool&);
    NativeMaintenanceContext(HANDLE volume, const std::wstring& volume_root,
        const std::wstring& service_name,
        const usk::platform::windows::PublisherInstallOperationGuard& guard,
        const usk::platform::windows::PublisherMaintenanceStateSnapshot& original_state,
        const usk::platform::windows::PublisherInstallOperationContext& original_context,
        const usk::platform::windows::PublisherInstallationLease& lease,
        const usk::platform::windows::RegisteredPublisherAdmission& admission,
        const usk::platform::windows::PublisherRequestChannel& channel,
        const usk::transaction::TransactionSpec& spec, HANDLE cancel_event,
        bool& effects_may_exist);
    // Fresh child operation only: borrow the already active original concrete
    // owner, including its existing pinned security lifetime. It supplies no
    // SCM admission/channel handle and cannot select another original request.
    NativeMaintenanceContext(HANDLE volume, const std::wstring& volume_root,
        const std::wstring& service_name,
        const usk::platform::windows::PublisherInstallOperationGuard& guard,
        const usk::platform::windows::PublisherMaintenanceStateSnapshot& original_state,
        const usk::platform::windows::PublisherInstallOperationContext& original_context,
        const usk::platform::windows::PublisherInstallationLease& lease,
        usk::platform::windows::PublisherEffectExecutionOwner& original_child,
        const usk::transaction::TransactionSpec& spec, HANDLE cancel_event,
        bool& effects_may_exist);
    enum class RecoveryAdmission { ended_original_holder };
    NativeMaintenanceContext(HANDLE volume, const std::wstring& volume_root,
        const std::wstring& service_name,
        const usk::platform::windows::PublisherInstallOperationGuard& guard,
        const usk::platform::windows::PublisherMaintenanceStateSnapshot& original_state,
        const usk::platform::windows::PublisherInstallOperationContext& original_context,
        const usk::platform::windows::PublisherInstallationLease& lease,
        usk::platform::windows::PublisherEffectExecutionOwner& original_child,
        const usk::transaction::TransactionSpec& spec, HANDLE cancel_event,
        bool& effects_may_exist, RecoveryAdmission);
    NativeMaintenanceContext(HANDLE volume, const std::wstring& volume_root,
        const std::wstring& service_name,
        const usk::platform::windows::PublisherInstallOperationGuard& guard,
        const usk::platform::windows::PublisherMaintenanceStateSnapshot& original_state,
        const usk::platform::windows::PublisherInstallOperationContext& original_context,
        const usk::platform::windows::PublisherInstallationLease& lease,
        const usk::platform::windows::RegisteredPublisherAdmission& admission,
        const usk::platform::windows::PublisherRequestChannel& channel,
        const usk::transaction::TransactionSpec& spec, HANDLE cancel_event,
        bool& effects_may_exist, RecoveryAdmission);
    // Engine-only existing-operation observation. It acquires read/list
    // handles, no lease, metadata session or effect fence. All old holders
    // must be ended, committed membership unchanged and pending lease names
    // empty. Unsupported/ambiguous states refuse rather than become grants.
    enum class InspectionAdmission { ended_original_holder };
    NativeMaintenanceContext(HANDLE volume, const std::wstring& volume_root,
        const std::wstring& service_name,
        const usk::platform::windows::PublisherInstallOperationGuard& guard,
        const usk::platform::windows::PublisherMaintenanceStateSnapshot& original_state,
        const usk::platform::windows::PublisherInstallOperationContext& original_context,
        usk::platform::windows::PublisherEffectExecutionOwner& original_child,
        const usk::transaction::TransactionSpec& spec, HANDLE cancel_event,
        std::uint64_t deadline_tick, InspectionAdmission);
    // Owned observations after explicit successful finalization; no callbacks,
    // handles or effect authority escape. A failure remains sticky.
    usk::json::Value inspect_recovery() const;
    void bind_owner_backend();
    void bind_reader_backend();
    // Only the engine can obtain this live-owner adapter. It retains no owner
    // lifetime; copied callbacks refuse before dereference after scope exit.
    MaintenanceRecoveryOperations recovery_operations() const;
    class RecordByteRead;
    struct Impl;
    static Impl* original_recovery_reader(const MaintenanceRecoveryOperations&);
    std::unique_ptr<Impl> impl_;
    std::unique_ptr<usk::platform::windows::ScopedPublisherEffectFence> fence_;
    std::unique_ptr<usk::record_io::ScopedNativeRecordReadOperations> record_read_scope_;
    // Destroy the borrowed callback scope before its owning operations/handles.
    std::unique_ptr<usk::transaction::detail::ScopedNativeMaintenanceTransaction> scope_;
};

}
#endif
#endif
