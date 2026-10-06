// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_native_maintenance_transaction_internal.h"
#if defined(_WIN32)
#include "usk_json.h"
#include <algorithm>
#include <map>
#include <stdexcept>
#include <exception>
namespace usk::transaction::detail {
namespace {
thread_local const NativeMaintenanceTransactionOperations* active_operations = nullptr;
thread_local std::weak_ptr<const void> active_binding;
}
void require_native_maintenance_origin_binding(bool native_origin,
    const std::weak_ptr<const void>& original, const std::weak_ptr<const void>& current) {
    if (!native_origin) {
        if (!current.expired()) throw std::runtime_error("ordinary transaction cannot adopt a native maintenance owner");
        return;
    }
    if (original.expired() || current.expired() || original.owner_before(current) || current.owner_before(original))
        throw std::runtime_error("native maintenance transaction lost its original owner; no generic fallback");
}
ScopedNativeMaintenanceTransaction::ScopedNativeMaintenanceTransaction(
    const NativeMaintenanceTransactionOperations& operations) : operations_(operations) {
    if (active_operations || !operations.require_authority || !operations.persist_journal || !operations.create_staging_root ||
        !operations.ensure_stream_parent || !operations.open_stream || !operations.require_stream ||
        !operations.finish_stream || !operations.observe_commit_closure || !operations.observe_file ||
        !operations.commit || !operations.apply_effect || !operations.confirm_effect_completion)
        throw std::runtime_error("native maintenance transaction owner is absent, incomplete or nested");
    // A distinct control block identifies this lifetime even if an operations
    // object or native owner address is later reused. Sessions retain weak
    // identity only, and cannot prolong or resurrect an ended engine scope.
    identity_ = std::make_shared<const unsigned char>(static_cast<unsigned char>(0));
    active_binding = identity_;
    active_operations = &operations_;
}
ScopedNativeMaintenanceTransaction::~ScopedNativeMaintenanceTransaction() {
    if (active_operations != &operations_) std::terminate();
    active_operations = nullptr;
    active_binding.reset();
}
const NativeMaintenanceTransactionOperations* ScopedNativeMaintenanceTransaction::current() { return active_operations; }
std::weak_ptr<const void> ScopedNativeMaintenanceTransaction::current_binding() { return active_binding; }
std::optional<NativeMaintenanceFileObservation> observe_current_native_maintenance_file(
    const std::filesystem::path& path) {
    if (!active_operations) return std::nullopt;
    if (active_binding.expired() || !active_operations->observe_file)
        throw std::runtime_error("native maintenance file observer lost its original owner; no pathname fallback");
    return active_operations->observe_file(path);
}
void require_native_maintenance_journal_binding(const TransactionSpec& spec,
    const std::filesystem::path& path, const std::string& content,
    const std::string& predecessor_sha256, bool first) {
    namespace fs = std::filesystem;
    const auto normalized = [](const fs::path& p) { return fs::absolute(p).lexically_normal(); };
    if (normalized(path) != normalized(spec.state_root / "transactions" / (spec.transaction_id + ".journal.json")) ||
        content.empty() || content.size() > 4u * 1024u * 1024u ||
        first != predecessor_sha256.empty() || (!first &&
            (predecessor_sha256.size() != 64 || !std::all_of(predecessor_sha256.begin(), predecessor_sha256.end(),
                [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }))))
        throw std::runtime_error("native maintenance journal path, predecessor or byte bound differs");
    const auto value = usk::json::parse(content, {4u * 1024u * 1024u, 64u, 2u * 1024u * 1024u, 1024u * 1024u});
    if (value.at("schema").as_string() != "usk.transaction_journal.v1" ||
        value.at("transaction_id").as_string() != spec.transaction_id ||
        value.at("plan_id").as_string() != spec.plan_id || value.at("plan_digest").as_string() != spec.plan_digest ||
        value.at("operation").as_string() != spec.operation ||
        (spec.operation != "repair" && spec.operation != "move" && spec.operation != "uninstall"))
        throw std::runtime_error("native maintenance journal belongs to another original operation");
    std::map<std::string, fs::path> roots;
    for (const auto& row : value.at("roots").as_array())
        if (!roots.emplace(row.at("role").as_string(), normalized(fs::u8path(row.at("root").as_string()))).second)
            throw std::runtime_error("native maintenance journal repeats a root");
    const std::map<std::string, fs::path> expected{
        {"target", normalized(spec.target_root)}, {"staging", normalized(spec.staging_parent / (".usk-stage-" + spec.transaction_id))},
        {"setup_state", normalized(spec.state_root)}, {"audit", normalized(spec.audit_root)}};
    if (roots != expected) throw std::runtime_error("native maintenance journal roots differ from its original owner");
    const auto& transitions = value.at("transitions").as_array();
    if (transitions.empty() || transitions.size() > 100000 ||
        value.at("current_state").as_string() != transitions.back().at("to").as_string() ||
        (first && (transitions.size() != 1 || transitions[0].at("sequence").as_unsigned() != 0 ||
            transitions[0].at("to").as_string() != "created" ||
            transitions[0].at("from").type() != usk::json::Value::Type::null_value)))
        throw std::runtime_error("native maintenance journal transition binding differs");
}
}
#endif
