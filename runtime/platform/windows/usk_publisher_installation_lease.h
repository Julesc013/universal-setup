// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_INSTALLATION_LEASE_H
#define USK_PUBLISHER_INSTALLATION_LEASE_H
#if defined(_WIN32)
#include "usk_install_lease.h"
#include "usk_publisher_volume_operation_guard.h"
#include <functional>
#include <memory>
namespace usk::platform::windows {
class PublisherInstallationLease;

usk::json::Value observe_publisher_lease_holder();
// Read-only native facts, without a protection/ownership verdict.
usk::json::Value observe_publisher_lease_root_identity(HANDLE root);
std::string observe_publisher_install_state_revision(HANDLE state_root,
    const std::string& install_id, const std::string& service_sid);
usk::transaction::InstallLeasePreviousHolder observe_publisher_previous_lease_holder(
    const usk::json::Value& holder);

// Immutable original operation intent, protected on the admitted volume before
// setup bootstrap or active ownership. Construction is read-only; prepare is
// called only after ordinary reviewed-plan revalidation. No public JSON grants
// this native context or permits changing an existing operation.
class PublisherInstallOperationContext final {
public:
    PublisherInstallOperationContext(HANDLE volume, const std::wstring& volume_root,
        const std::wstring& service_name, const PublisherInstallOperationGuard& guard,
        const std::string& install_id, const std::string& operation_id);
    ~PublisherInstallOperationContext();
    PublisherInstallOperationContext(const PublisherInstallOperationContext&) = delete;
    PublisherInstallOperationContext& operator=(const PublisherInstallOperationContext&) = delete;
    bool exists() const;
    void prepare(const usk::json::Value& reviewed_snapshot, const std::string& initial_state_revision);
    void bind_state_roots(HANDLE setup_root, HANDLE state_root);
    std::string lease_binding_sha256() const;
    const usk::json::Value& record() const;
    void require_fence() const;
    // Read-only inspection of this operation's reserved, pre-candidate
    // bootstrap. Only an exact original sourceful apply may preserve it.
    bool bootstrap_resume_required() const;
    // Requires the live native lease, never a supplied ownership document.
    // Persists absence per attempt and any exact preservation intent before
    // a no-replace move. Incomplete anchors remain protected and retained.
    void prepare_publication(const PublisherInstallationLease& lease);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Internal restricted-service backend. The caller retains the actual native
// state root and volume/install guards for this entire lifetime. Initialization
// of an empty protected repository is a separate bootstrap effect. Ownership
// is persisted and read back before the caller installs its effect fence.
// The append-only journal has finite budgets and refuses exhaustion; no
// timestamp, PID alone, caller assertion or timeout permits live takeover.
class PublisherInstallationLease final {
public:
    PublisherInstallationLease(HANDLE state_root, const std::wstring& volume_root,
        const std::wstring& service_name, const PublisherInstallOperationGuard& guard,
        const usk::transaction::InstallLeaseRequest& request,
        const std::function<std::string()>& observe_state_revision);
    ~PublisherInstallationLease();
    PublisherInstallationLease(const PublisherInstallationLease&) = delete;
    PublisherInstallationLease& operator=(const PublisherInstallationLease&) = delete;
    void require_start() const;
    void require_fence() const;
    void finish(bool handoff);
    const usk::json::Value& ownership() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace usk::platform::windows
#endif
#endif
