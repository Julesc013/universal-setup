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
struct PublisherTreeObservation;
enum class PublisherOperationKind { install_local, repair, move, uninstall };

// Read-only original maintenance preimage under the actual installation guard.
// Keeps the protected setup/state parents and exact original installed and
// ownership records alive. No constructor writes, bootstraps or grants effects.
// The owning native engine keeps this alive throughout the operation.
class PublisherMaintenanceStateSnapshot final {
public:
    PublisherMaintenanceStateSnapshot(HANDLE volume, const std::wstring& volume_root,
        const std::wstring& setup_component, const std::wstring& service_name,
        const PublisherInstallOperationGuard& guard, const std::string& install_id);
    ~PublisherMaintenanceStateSnapshot();
    PublisherMaintenanceStateSnapshot(const PublisherMaintenanceStateSnapshot&) = delete;
    PublisherMaintenanceStateSnapshot& operator=(const PublisherMaintenanceStateSnapshot&) = delete;
    HANDLE setup_root() const;
    HANDLE state_root() const;
    const std::string& initial_state_revision() const;
    const usk::json::Value& installed_state() const;
    const usk::json::Value& ownership_manifest() const;
    void require_custody() const;
    // Fresh apply only: the complete actual installed record set must still
    // equal its original guarded revision before the first intent write.
    void require_initial_revision() const;
    usk::json::Value reviewed_snapshot(PublisherOperationKind kind,
        const std::string& operation_id, const usk::json::Value& reviewed_plan,
        const usk::json::Value& apply_request) const;
private:
    friend class PublisherInstallOperationContext;
    PublisherMaintenanceStateSnapshot(HANDLE volume, const std::wstring& volume_root,
        const std::wstring& service_name, const PublisherInstallOperationGuard& guard,
        const usk::json::Value& original_snapshot);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Closed data binding only, with no native ownership/lease verdict. Recovery
// separately proves the retained original records, completed prefix and the
// allowed current revision. This cannot activate a maintenance backend.
void require_publisher_maintenance_snapshot_binding(const usk::json::Value& snapshot,
    PublisherOperationKind kind, const std::string& install_id,
    const std::string& operation_id, const std::string& initial_state_revision);

// Derive one create-only record-set postimage from a complete original v2
// snapshot and a separately validated installed document. Data association
// only: the native owner must prove the exact original pending effect, bytes,
// actual publication and allowed current revision. No observed set is adopted.
usk::json::Value derive_publisher_maintenance_postimage_bindings(
    const usk::json::Value& original_snapshot, const usk::json::Value& installed_postimage);

// Internal data-shape check using the native tree observer's slash paths.
// Security, held handles, exact original bytes and ownership remain separate
// mandatory native checks; passing this helper grants no publication effects.
void require_publisher_bootstrap_prefix_shape(const PublisherTreeObservation& tree);

usk::json::Value observe_publisher_lease_holder();
// Read-only native facts, without a protection/ownership verdict.
usk::json::Value observe_publisher_lease_root_identity(HANDLE root);
std::string observe_publisher_install_state_revision(HANDLE state_root,
    const std::string& install_id, const std::string& service_sid);
// Exact sorted native record set behind the revision. The operation retains
// this original set to derive only its reviewed installed postimage revision.
usk::json::Value observe_publisher_install_state_bindings(HANDLE state_root,
    const std::string& install_id, const std::string& service_sid);
// Read-only fresh-install preflight under the actual installation guard. An
// absent setup root represents empty state; existing state/installed roots
// must be complete and safe. The caller separately validates the full setup
// ownership marker and layout read-only before preparing durable intent.
// This creates no context, layout or ownership record and grants no effects.
// Returns whether the actual setup root was present.
bool require_publisher_initial_install_state_revision(HANDLE volume,
    const std::wstring& volume_root, const std::wstring& setup_component,
    const PublisherInstallOperationGuard& guard, const std::string& install_id,
    const std::string& service_sid);
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
    PublisherInstallOperationContext(HANDLE volume, const std::wstring& volume_root,
        const std::wstring& service_name, const PublisherInstallOperationGuard& guard,
        const std::string& install_id, const std::string& operation_id,
        PublisherOperationKind kind);
    ~PublisherInstallOperationContext();
    PublisherInstallOperationContext(const PublisherInstallOperationContext&) = delete;
    PublisherInstallOperationContext& operator=(const PublisherInstallOperationContext&) = delete;
    bool exists() const;
    void prepare(const usk::json::Value& reviewed_snapshot, const std::string& initial_state_revision);
    // V1 install preparation keeps its original empty-revision semantics.
    // Maintenance builds V2 intent from the held native preimage and exact
    // reviewed plan/request; it repeats the guarded revision before any write.
    void prepare_maintenance(const PublisherMaintenanceStateSnapshot& state,
        const usk::json::Value& reviewed_plan, const usk::json::Value& apply_request);
    // Read-only recovery of the exact protected original records, even when
    // a bound postimage is now the newest installed record. No new plan or
    // current-revision grant is inferred from successfully restoring custody.
    std::unique_ptr<PublisherMaintenanceStateSnapshot> restore_maintenance_state() const;
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
    // Read-only native recovery proof: the supplied original active record
    // must be an exact member of this held protected journal, followed only
    // by this same unfinished operation. Every earlier holder must actually
    // have ended (PID plus birth identity); the current lease is a newer
    // recovery generation. This proves no payload/metadata postcondition.
    void require_recovery_lineage(const usk::json::Value& original_ownership) const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace usk::platform::windows
#endif
#endif
