// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PROTECTED_INSTALL_PUBLISHER_INTERNAL_H
#define USK_PROTECTED_INSTALL_PUBLISHER_INTERNAL_H
#if defined(_WIN32)
#include "usk_protected_publisher_finalization_internal.h"
#include "usk_json.h"
#include <functional>
#include <optional>
namespace usk::platform::windows {
// Private candidate host configuration. This is not a public SDK capability.
// Live SCM/token and held-volume observations precede any execution. The lab
// hook provisions its independently admitted disposable boundary only; apply
// never replaces a volume ACL. General production qualification stays absent.
struct CandidatePublisherConfiguration {
    std::wstring service_name, receipt_path, volume_root;
    bool prepublish_gate=false, poststage_gate=false, postrename_gate=false,
        postjournal_gate=false, recover_prepared=false, recover_snapshot_only=false,
        recover_sealed_journal=false, recover_visible_bound=false,
        selected_archive_mode=false;
    std::wstring selected_archive_path, reviewed_plan_envelope_path;
    std::string selected_archive_sha256, reviewed_plan_envelope_sha256;
    HANDLE stop_event=nullptr;
    std::function<void(HANDLE,const std::string&)> prepare_disposable_boundary;
};
class StaleReviewedInstallRequest final : public std::runtime_error {
public:
    StaleReviewedInstallRequest() : std::runtime_error(
        "reviewed install reentry differs from durable plan and source") {}
};
std::string execute_candidate_restricted_publisher(
    const CandidatePublisherConfiguration&, bool& effects_may_exist);
}
namespace usk::lifecycle {
class ProtectedApplyEffectsRetained final : public std::runtime_error {
public:
    explicit ProtectedApplyEffectsRetained(const std::string& reason) :
        std::runtime_error("protected apply may retain material; recovery required: " + reason) {}
};
void require_candidate_snapshot_apply_binding(const usk::json::Value& snapshot);
// No exposed constructor, setter, callback or JSON activation can create the
// operation-scoped context. Only the concrete live service engine creates it.
std::optional<InstallResult> apply_in_candidate_publisher_context(
    const InstallPlan&, const std::string& transaction_id, const std::string& applied_at);
}
#endif
#endif
