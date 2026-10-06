// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_NATIVE_MAINTENANCE_CONTEXT_INTERNAL_H
#define USK_NATIVE_MAINTENANCE_CONTEXT_INTERNAL_H
#if defined(_WIN32)
#include "usk_protected_install_publisher_internal.h"
#include "usk_publisher_installation_lease.h"
#include "usk_publisher_metadata.h"
#include "usk_native_maintenance_transaction_internal.h"
#include <memory>
namespace usk::lifecycle::detail {
struct MaintenanceRecoveryOperations;
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
    enum class RecoveryAdmission { ended_original_holder };
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
    void bind_owner_backend();
    // Only the engine can obtain this live-owner adapter. It retains no owner
    // lifetime; copied callbacks refuse before dereference after scope exit.
    MaintenanceRecoveryOperations recovery_operations() const;
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::unique_ptr<usk::platform::windows::ScopedPublisherEffectFence> fence_;
    // Destroy the borrowed callback scope before its owning operations/handles.
    std::unique_ptr<usk::transaction::detail::ScopedNativeMaintenanceTransaction> scope_;
};
}
#endif
#endif
