// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_install_restart.h"
#include "usk_audit_repository.h"
#include "usk_json.h"
#include "usk_record_io.h"
#include <algorithm>
#include <set>

using usk::json::Value;
namespace usk::lifecycle {
namespace {
bool digest(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
Value validate_genesis(const audit::AuditEvent& event, const InstallPlan& plan,
    const std::string& transaction_id, const transaction::RecoveryInspection& inspection) {
    const Value value = json::parse(event.message);
    const std::set<std::string> keys{"schema", "prior_audit_chain_id", "prior_audit_chain_digest",
        "prior_transaction_id", "prior_journal_snapshot_sha256", "plan_id", "plan_digest",
        "source_digest", "transaction_id"};
    std::set<std::string> actual;
    for (const auto& member : value.as_object()) actual.insert(member.first);
    if (actual != keys || json::canonical(value) != event.message ||
        value.at("schema").as_string() != "usk.install_replay_genesis.v1" ||
        value.at("transaction_id").as_string() != transaction_id ||
        value.at("prior_transaction_id").as_string() != inspection.restart_origin_transaction_id ||
        value.at("prior_journal_snapshot_sha256").as_string() != inspection.restart_origin_snapshot_sha256 ||
        value.at("plan_id").as_string() != plan.plan_id ||
        value.at("plan_digest").as_string() != plan.plan_digest ||
        value.at("source_digest").as_string() != inspection.stream_source_digest ||
        !record_io::valid_identifier(value.at("prior_audit_chain_id").as_string()) ||
        !digest(value.at("prior_audit_chain_digest").as_string()) ||
        event.operation != "recovery" || event.subject_type != "journal" ||
        event.subject_id != inspection.restart_origin_transaction_id ||
        event.details_digest != json::sha256_canonical(value)) {
        throw std::runtime_error("prior replay audit genesis does not bind its original journal and source context");
    }
    return value;
}
void validate_replay_lineage(const InstallPlan& plan, transaction::TransactionSpec spec,
    transaction::RecoveryInspection inspection, std::string expected_audit_head) {
    std::set<std::string> visited;
    for (std::size_t depth = 0; depth < 64u; ++depth) {
        if (!visited.insert(spec.transaction_id).second || inspection.commit_started) {
            throw std::runtime_error("install replay refuses a cycle or uncertain ancestor commit");
        }
        (void)read_install_stream_context(inspection, plan.roots, plan.target_root);
        const auto chain_id = install_audit_chain_id(plan.install_id, spec.transaction_id,
            !inspection.restart_origin_transaction_id.empty());
        const auto chain = audit::AuditRepository(plan.roots.audit_root).read_and_validate_chain_bounded(chain_id, 1u);
        if (chain.size() != 1u || chain.front().event_digest != expected_audit_head) {
            throw std::runtime_error("install replay ancestor audit snapshot changed");
        }
        const auto& event = chain.front();
        if (event.transaction_id != spec.transaction_id || event.plan_id != plan.plan_id ||
            event.phase != "validated" || event.status != "pass") {
            throw std::runtime_error("install replay audit transaction or plan context is incompatible");
        }
        if (inspection.restart_origin_transaction_id.empty()) {
            if (event.operation != "install_local" || event.subject_type != "plan" ||
                event.subject_id != plan.plan_id || event.details_digest != plan.plan_digest) {
                throw std::runtime_error("install replay audit does not bind the reviewed original plan");
            }
            return;
        }
        const auto genesis = validate_genesis(event, plan, spec.transaction_id, inspection);
        const auto expected_snapshot = inspection.restart_origin_snapshot_sha256;
        spec.transaction_id = inspection.restart_origin_transaction_id;
        inspection = transaction::TransactionSession::inspect_recovery(spec);
        if (inspection.snapshot_sha256 != expected_snapshot ||
            inspection.stream_source_digest != install_stream_source_digest(plan) ||
            genesis.at("prior_audit_chain_id").as_string() != install_audit_chain_id(plan.install_id,
                spec.transaction_id, !inspection.restart_origin_transaction_id.empty())) {
            throw std::runtime_error("install replay ancestor journal or audit identity changed");
        }
        expected_audit_head = genesis.at("prior_audit_chain_digest").as_string();
    }
    throw std::runtime_error("install replay exceeds its 64-journal lineage bound");
}
} // namespace
json::Value install_context_root_identities(const LifecycleRoots& roots, const std::filesystem::path& target_root) {
    return Value(Value::Object{
        {"setup_root", Value(transaction::observe_directory_identity(roots.state_root.parent_path()))},
        {"state_root", Value(transaction::observe_directory_identity(roots.state_root))},
        {"journal_root", Value(transaction::observe_directory_identity(roots.state_root / "transactions"))},
        {"audit_root", Value(transaction::observe_directory_identity(roots.audit_root))},
        {"staging_parent", Value(transaction::observe_directory_identity(roots.staging_parent))},
        {"target_parent", Value(transaction::observe_directory_identity(target_root.parent_path()))}});
}
json::Value read_install_stream_context(const transaction::RecoveryInspection& inspection,
    const LifecycleRoots& roots, const std::filesystem::path& target_root) {
    if (inspection.stream_source_context.empty()) throw std::runtime_error("original install source context is unavailable");
    const auto context = json::parse(inspection.stream_source_context);
    const std::set<std::string> expected{"schema", "archive_sha256", "archive_identity_digest", "entry_set_digest",
        "plan_digest", "policy_digest", "policy_context", "root_identities"};
    std::set<std::string> actual;
    for (const auto& member : context.as_object()) actual.insert(member.first);
    if (actual != expected || context.at("schema").as_string() != "usk.install_stream_source.v1" ||
        json::canonical(context) != inspection.stream_source_context ||
        json::sha256_canonical(context) != inspection.stream_source_digest ||
        json::canonical(context.at("root_identities")) != json::canonical(install_context_root_identities(roots, target_root))) {
        throw std::runtime_error("original install context or observed native root identities changed");
    }
    for (const auto* key : {"archive_sha256", "archive_identity_digest", "entry_set_digest", "plan_digest", "policy_digest"}) {
        if (!digest(context.at(key).as_string())) throw std::runtime_error("original install source context digest is invalid");
    }
    (void)context.at("policy_context").as_string();
    return context;
}
std::string install_stream_source_context(const InstallPlan& plan) {
    if (plan.recipe.source_identity_digest.empty() && plan.recipe.entry_set_digest.empty()) return {};
    if (!digest(plan.recipe.source_identity_digest) || !digest(plan.recipe.entry_set_digest) ||
        !plan.validate_source || std::any_of(plan.files.begin(), plan.files.end(),
            [](const PayloadFile& file) { return !file.reader; })) {
        throw std::runtime_error("install stream source binding is incomplete");
    }
    return json::canonical(Value(Value::Object{
        {"archive_sha256", Value(plan.recipe.source_archive_digest)},
        {"archive_identity_digest", Value(plan.recipe.source_identity_digest)},
        {"entry_set_digest", Value(plan.recipe.entry_set_digest)},
        {"plan_digest", Value(plan.plan_digest)}, {"policy_digest", Value(plan.recipe.policy_digest)},
        {"policy_context", Value(plan.recipe.restart_policy_context)},
        {"root_identities", install_context_root_identities(plan.roots, plan.target_root)},
        {"schema", Value("usk.install_stream_source.v1")}}));
}
std::string install_stream_source_digest(const InstallPlan& plan) {
    const auto context = install_stream_source_context(plan);
    return context.empty() ? std::string{} : json::sha256_canonical(json::parse(context));
}
std::string install_stream_entry_digest(const std::string& source_digest, const PayloadFile& file) {
    if (source_digest.empty()) return {};
    return json::sha256_canonical(Value(Value::Object{
        {"source_digest", Value(source_digest)}, {"relative_path", Value(file.relative_path)},
        {"sha256", Value(file.sha256)}, {"size_bytes", Value(file.size_bytes)}}));
}
std::string install_audit_chain_id(const std::string& install_id,
    const std::string& transaction_id, bool replay) {
    if (!replay) return "audit." + install_id;
    return "replay." + json::sha256_canonical(Value(Value::Object{
        {"install_id", Value(install_id)}, {"transaction_id", Value(transaction_id)}}));
}
InstallReplayContext inspect_install_replay(const InstallPlan& plan,
    const InstallRestartRequest& request, const std::string& new_transaction_id) {
    if (!record_io::valid_identifier(request.transaction_id) ||
        !record_io::valid_identifier(new_transaction_id) || request.transaction_id == new_transaction_id ||
        !digest(request.journal_snapshot_sha256) || !digest(request.audit_chain_digest)) {
        throw std::runtime_error("install replay identity is invalid");
    }
    InstallReplayContext context;
    context.prior_spec = {request.transaction_id, plan.plan_id, plan.plan_digest, "install_local",
        plan.roots.staging_parent, plan.target_root, plan.roots.state_root, plan.roots.audit_root};
    context.source_digest = install_stream_source_digest(plan);
    if (context.source_digest.empty()) throw std::runtime_error("install replay requires an exact archive source binding");
    const auto prior = transaction::TransactionSession::inspect_recovery(context.prior_spec);
    if (prior.snapshot_sha256 != request.journal_snapshot_sha256 ||
        prior.stream_source_digest != context.source_digest) {
        throw std::runtime_error("install replay prior snapshot or stream source changed");
    }
    validate_replay_lineage(plan, context.prior_spec, prior, request.audit_chain_digest);
    const auto old_chain_id = install_audit_chain_id(plan.install_id, request.transaction_id,
        !prior.restart_origin_transaction_id.empty());
    context.audit_chain_id = install_audit_chain_id(plan.install_id, new_transaction_id, true);
    audit::require_chain_path_capacity(plan.roots.audit_root, context.audit_chain_id);
    context.genesis = json::canonical(Value(Value::Object{
        {"schema", Value("usk.install_replay_genesis.v1")},
        {"prior_audit_chain_id", Value(old_chain_id)},
        {"prior_audit_chain_digest", Value(request.audit_chain_digest)},
        {"prior_transaction_id", Value(request.transaction_id)},
        {"prior_journal_snapshot_sha256", Value(request.journal_snapshot_sha256)},
        {"plan_id", Value(plan.plan_id)}, {"plan_digest", Value(plan.plan_digest)},
        {"source_digest", Value(context.source_digest)}, {"transaction_id", Value(new_transaction_id)}}));
    plan.validate_source();
    return context;
}
void create_install_replay_audit(const InstallPlan& plan, const InstallReplayContext& context,
    const std::string& transaction_id, const std::string& applied_at,
    const LifecycleFaultInjector& fault_injector) {
    audit::AuditRepository repository(plan.roots.audit_root);
    repository.initialize_chain(context.audit_chain_id);
    if (fault_injector) fault_injector("install_local", "after_replay_audit_directory_create");
    repository.append(context.audit_chain_id, audit::AuditInput{
        applied_at, "recovery", "validated", "pass", "journal", context.prior_spec.transaction_id,
        json::sha256_canonical(json::parse(context.genesis)), transaction_id, plan.plan_id, context.genesis});
}
} // namespace usk::lifecycle
