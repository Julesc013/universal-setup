// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_INSTALL_RESTART_H
#define USK_INSTALL_RESTART_H

#include "usk_lifecycle.h"
#include "usk_transaction_session.h"
#include "usk_json.h"
#include <stdexcept>

namespace usk::lifecycle {
struct InstallRestartRequest {
    std::string transaction_id;
    std::string journal_snapshot_sha256;
    std::string audit_chain_digest;
};
class RestartEffectsRetained final : public std::runtime_error {
public:
    explicit RestartEffectsRetained(const std::string& detail) : std::runtime_error(detail) {}
};
struct InstallReplayContext {
    transaction::TransactionSpec prior_spec;
    std::string source_digest;
    std::string audit_chain_id;
    std::string genesis;
};
std::string install_stream_source_context(const InstallPlan& plan);
std::string install_stream_source_digest(const InstallPlan& plan);
json::Value install_context_root_identities(const LifecycleRoots& roots, const std::filesystem::path& target_root);
json::Value read_install_stream_context(const transaction::RecoveryInspection& inspection,
    const LifecycleRoots& roots, const std::filesystem::path& target_root);
std::string install_stream_entry_digest(const std::string& source_digest, const PayloadFile& file);
std::string install_audit_chain_id(const std::string& install_id,
    const std::string& transaction_id, bool replay);
InstallReplayContext inspect_install_replay(const InstallPlan& plan,
    const InstallRestartRequest& request, const std::string& new_transaction_id);
void create_install_replay_audit(const InstallPlan& plan, const InstallReplayContext& context,
    const std::string& transaction_id, const std::string& applied_at,
    const LifecycleFaultInjector& fault_injector);
InstallResult restart_install(const InstallPlan& plan, const std::string& reviewed_plan_digest,
    const std::string& transaction_id, const std::string& applied_at,
    const InstallRestartRequest& restart, LifecycleFaultInjector fault_injector = {},
    LifecycleCancellation cancellation = {});
} // namespace usk::lifecycle
#endif
