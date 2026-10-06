// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PROTECTED_INSTALL_PUBLISHER_INTERNAL_H
#define USK_PROTECTED_INSTALL_PUBLISHER_INTERNAL_H
#if defined(_WIN32)
#include "usk_protected_publisher_finalization_internal.h"
#include "usk_json.h"
#include <exception>
#include <functional>
#include <optional>
namespace usk::transaction { struct TransactionSpec; }
namespace usk::platform::windows {
class PublisherRequestChannel;
class RegisteredPublisherAdmission;
// Private candidate host configuration. This is not a public SDK capability.
// Live SCM/token and held-volume observations precede any execution. The lab
// hook provisions its independently admitted disposable boundary only; apply
// never replaces a volume ACL. General production qualification stays absent.
struct CandidatePublisherConfiguration {
    std::wstring service_name, receipt_path, volume_root;
    bool prepublish_gate=false, poststage_gate=false, postrename_gate=false,
        postjournal_gate=false, recover_prepared=false, recover_snapshot_only=false,
        recover_reviewed=false,
        recover_sealed_journal=false, recover_visible_bound=false,
        selected_archive_mode=false, verify_installed=false;
    std::wstring selected_archive_path, reviewed_plan_envelope_path;
    std::string selected_archive_sha256, reviewed_plan_envelope_sha256;
    // Authenticated transport bytes, compared to the independently reviewed
    // request and durable snapshot before any publication/recovery effect.
    std::optional<std::string> submitted_apply_request;
    // Minimal authenticated recovery request. The protected snapshot supplies
    // the original plan, source and consumer policy; this carries no new plan.
    std::optional<std::string> submitted_recovery_request;
    // Distinct read-only request; it cannot act as an install apply grant.
    std::optional<std::string> submitted_verify_request;
    // Opt-in account from the authenticated request channel, durably bound in
    // snapshot v4 before effects. Empty preserves the v2/v3 private profile.
    std::string consumer_read_sid;
    bool interrupt_consumer_grant = false;
    HANDLE stop_event=nullptr;
    // Borrowed private channel; the host owns it across execution and reply.
    // Its authenticated identification token never enters configuration JSON.
    const PublisherRequestChannel* authenticated_request=nullptr;
    const RegisteredPublisherAdmission* registered_admission=nullptr;
    std::function<void(HANDLE,const std::string&)> prepare_disposable_boundary;
};
class StaleReviewedInstallRequest final : public std::runtime_error {
public:
    StaleReviewedInstallRequest() : std::runtime_error(
        "reviewed install reentry differs from durable plan and source") {}
    explicit StaleReviewedInstallRequest(const std::string& reason) : std::runtime_error(reason) {}
};
// Constructed only when the engine's read-only native revision preflight
// raises the actual typed mismatch before apply entry. Later mismatches keep
// the ordinary lease error and its conservative effects/recovery status.
class StaleReviewedMaintenanceRequest final : public std::runtime_error {
public:
    explicit StaleReviewedMaintenanceRequest(const std::string& reason) : std::runtime_error(reason) {}
};
class InstallStateRevisionChangedBeforeEffects final : public std::runtime_error {
public:
    InstallStateRevisionChangedBeforeEffects() : std::runtime_error(
        "installed state changed before effects") {}
};
std::string execute_candidate_restricted_publisher(
    const CandidatePublisherConfiguration&, bool& effects_may_exist);
void require_candidate_publisher_execution_records(
    const usk::json::Value& prepared, const usk::json::Value& visible,
    const std::wstring& service_name, const std::string& service_sid);
// Read-only proof from the actual original protected completion records and
// immutable completed public metadata. Available only inside the registered
// engine; it observes no current payload and grants no mutation capability.
usk::json::Value observe_candidate_original_consumer_install(HANDLE volume,
    const std::wstring& volume_root, const std::wstring& service_name);
}
namespace usk::lifecycle {
class ProtectedApplyEffectsRetained final : public std::runtime_error {
public:
    explicit ProtectedApplyEffectsRetained(const std::string& reason) :
        std::runtime_error("protected apply may retain material; recovery required: " + reason) {}
};
void require_candidate_snapshot_apply_binding(const usk::json::Value& snapshot);
// Only the active private engine can retain a real exception across its C-ABI
// call. A public preflight stale-plan error is retained separately, before that
// engine has entered apply; neither function interprets response JSON.
void retain_candidate_publisher_operation_failure(std::exception_ptr failure);
void retain_candidate_publisher_preflight_stale_plan(std::exception_ptr failure);
// Read-only original policy context from the live engine's held native record.
// It is absent outside that engine, and a different plan request is refused.
std::optional<usk::json::Value> candidate_publisher_plan_replay(const usk::json::Value& plan_request);
// Read-only source preflight for a protected original bootstrap intent. Uses
// the public archive grammar/budgets and exact actual identity/file closure;
// it grants no target mutation or reviewed-plan acceptance.
void require_candidate_bootstrap_source(const usk::json::Value& snapshot);
// No exposed constructor, setter, callback or JSON activation can create the
// operation-scoped context. Only the concrete live service engine creates it.
std::optional<InstallResult> apply_in_candidate_publisher_context(
    const InstallPlan&, const std::string& transaction_id, const std::string& applied_at);
// Called after the ordinary typed maintenance plan has passed its complete
// preflight, immediately before the first journal. Only the concrete active
// engine can install the private continuation; public JSON cannot create it.
void prepare_in_candidate_maintenance_context(const usk::transaction::TransactionSpec&,
    const usk::state::InstalledState&, const usk::json::Value& reviewed_plan);
}
#endif
#endif
