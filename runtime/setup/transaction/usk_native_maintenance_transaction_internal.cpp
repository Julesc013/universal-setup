// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_native_maintenance_transaction_internal.h"
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "usk_maintenance_effect_journal.h"
#include "usk_maintenance_inspection_internal.h"
#include "usk_json.h"
#include "usk_sha256.h"
#include <algorithm>
#include <map>
#include <stdexcept>
#include <exception>
#include <sstream>
#include <utility>
namespace usk::transaction::detail {
namespace {
thread_local const NativeMaintenanceTransactionOperations* active_operations = nullptr;
thread_local std::weak_ptr<const void> active_binding;
}
NativeMaintenanceTransactionOperations native_maintenance_inspection_operations(
    const NativeMaintenanceTransactionOperations& readers) {
    if (!readers.observe_file || !readers.file_pair_queries_available || !readers.observe_file_pair ||
        !readers.inspect_prefix || !readers.inspect_effect_history ||
        !readers.inspect_continuation || !readers.reconcile_effect)
        throw std::runtime_error("native maintenance inspection reader is incomplete");
    NativeMaintenanceTransactionOperations result;
    result.observe_file = readers.observe_file;
    result.file_pair_queries_available = readers.file_pair_queries_available;
    result.observe_file_pair = readers.observe_file_pair;
    result.inspect_prefix = readers.inspect_prefix;
    result.inspect_effect_history = readers.inspect_effect_history;
    result.inspect_continuation = readers.inspect_continuation;
    result.reconcile_effect = readers.reconcile_effect;
    const auto denied = [](const auto&...) {
        throw std::runtime_error("native maintenance inspection cannot authorize or perform effects");
    };
    result.require_authority = denied;
    result.persist_journal = denied;
    result.create_staging_root = denied;
    result.ensure_stream_parent = denied;
    result.open_stream = [](const auto&...) -> std::intptr_t {
        throw std::runtime_error("native maintenance inspection cannot open a writer");
    };
    result.require_stream = denied;
    result.finish_stream = denied;
    result.observe_commit_closure = [](const auto&...) -> CommitClosureObservation {
        throw std::runtime_error("native maintenance inspection cannot create a commit closure");
    };
    result.resume_effect_history = [](const auto&...) -> MaintenanceEffectInspection {
        throw std::runtime_error("native maintenance inspection cannot resume an effect journal");
    };
    result.commit = denied;
    result.apply_effect = [](const auto&...) -> NativeMaintenanceTransactionOperations::EffectResult {
        throw std::runtime_error("native maintenance inspection cannot apply an effect");
    };
    result.confirm_effect_completion = denied;
    return result;
}
void require_native_maintenance_inspection_lifetime(std::uint32_t process, std::uint32_t thread,
    std::intptr_t cancellation_observer, std::uint64_t deadline_tick, bool& failed) {
    const auto cancellation = reinterpret_cast<HANDLE>(cancellation_observer);
    if (failed || GetCurrentProcessId() != process || GetCurrentThreadId() != thread ||
        GetTickCount64() >= deadline_tick || !cancellation || cancellation == INVALID_HANDLE_VALUE ||
        WaitForSingleObject(cancellation, 0) != WAIT_TIMEOUT) {
        failed = true;
        throw std::runtime_error("native maintenance inspection is expired, cancelled or owned elsewhere");
    }
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
        !operations.file_pair_queries_available || !operations.observe_file_pair ||
        !operations.inspect_prefix || !operations.inspect_effect_history || !operations.resume_effect_history ||
        !operations.inspect_continuation || !operations.reconcile_effect ||
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
bool native_maintenance_file_pair_queries_available() {
    if (!active_operations) return false;
    const auto* operations = active_operations;
    const auto binding = active_binding;
    require_native_maintenance_origin_binding(true, binding, active_binding);
    if (!operations->file_pair_queries_available || !operations->observe_file_pair)
        throw std::runtime_error("native maintenance file pair availability lost its original owner");
    const bool available = operations->file_pair_queries_available();
    require_native_maintenance_origin_binding(true, binding, active_binding);
    if (active_operations != operations)
        throw std::runtime_error("native maintenance file pair availability changed its original owner");
    return available;
}
std::optional<std::array<NativeMaintenanceFileObservation, 2>> observe_current_native_maintenance_file_pair(
    const std::array<std::filesystem::path, 2>& paths) {
    if (!active_operations) return std::nullopt;
    const auto* operations = active_operations;
    const auto binding = active_binding;
    require_native_maintenance_origin_binding(true, binding, active_binding);
    if (!operations->observe_file_pair)
        throw std::runtime_error("native maintenance file pair lost its original observer");
    auto result = operations->observe_file_pair(paths);
    require_native_maintenance_origin_binding(true, binding, active_binding);
    if (active_operations != operations)
        throw std::runtime_error("native maintenance file pair changed its original observer");
    return result;
}
bool inspect_current_native_maintenance_prefix(const TransactionSpec& spec,
    RecoveryInspection& output_transaction, MaintenanceEffectInspection& output_history) {
    if (!active_operations) return false;
    const auto* operations = active_operations;
    const auto original = active_binding;
    require_native_maintenance_origin_binding(true, original, active_binding);
    if (!operations->inspect_prefix)
        throw std::runtime_error("native maintenance prefix lost its original reader; no fallback");
    RecoveryInspection transaction;
    MaintenanceEffectInspection history;
    operations->inspect_prefix(spec, transaction, history);
    require_native_maintenance_origin_binding(true, original, active_binding);
    if (active_operations != operations)
        throw std::runtime_error("native maintenance prefix changed its original operations");
    output_transaction = std::move(transaction);
    output_history = std::move(history);
    return true;
}
bool inspect_current_native_maintenance_continuation(const TransactionSpec& spec,
    lifecycle::detail::MaintenanceContinuationInspection& output) {
    if (!active_operations) return false;
    const auto* operations = active_operations;
    const auto original = active_binding;
    require_native_maintenance_origin_binding(true, original, active_binding);
    if (!operations->inspect_continuation)
        throw std::runtime_error("native maintenance continuation lost its original reader; no fallback");
    lifecycle::detail::MaintenanceContinuationInspection result;
    operations->inspect_continuation(spec, result);
    require_native_maintenance_origin_binding(true, original, active_binding);
    if (active_operations != operations)
        throw std::runtime_error("native maintenance continuation changed its original operations");
    output = std::move(result);
    return true;
}
bool reconcile_current_native_maintenance_effect(const TransactionSpec& spec,
    lifecycle::detail::MaintenanceEffectReconciliation& output) {
    if (!active_operations) return false;
    const auto* operations = active_operations;
    const auto original = active_binding;
    require_native_maintenance_origin_binding(true, original, active_binding);
    if (!operations->reconcile_effect)
        throw std::runtime_error("native maintenance reconciliation lost its original reader; no fallback");
    lifecycle::detail::MaintenanceEffectReconciliation result;
    operations->reconcile_effect(spec, result);
    require_native_maintenance_origin_binding(true, original, active_binding);
    if (active_operations != operations)
        throw std::runtime_error("native maintenance reconciliation changed its original operations");
    output = std::move(result);
    return true;
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
        value.at("current_state").as_string() != transitions.back().at("to").as_string())
        throw std::runtime_error("native maintenance journal transition binding differs");
    if (!first) return;
    if (transitions.size() == 1) {
        if (transitions[0].at("sequence").as_unsigned() != 0 ||
            transitions[0].at("to").as_string() != "created" ||
            transitions[0].at("from").type() != usk::json::Value::Type::null_value)
            throw std::runtime_error("native maintenance first journal is not created");
        return;
    }
    // The only cumulative first snapshot is the complete pre-staging intent.
    // Never admit an arbitrary later journal as a new no-replace publication.
    const auto& metadata = value.at("recovery_metadata");
    const auto stream = read_stream_journal(value, [](const fs::path&) { return false; });
    if (transitions.size() != 4 || metadata.at("staging_identity").type() != usk::json::Value::Type::null_value ||
        !metadata.at("staged_files").as_array().empty() ||
        metadata.at("commit_cleanup_policy").as_string() != "retain_only" ||
        !stream.present || stream.source_digest.empty() || stream.source_context.empty() ||
        !stream.entries.empty() || !stream.publication_root_identity.empty())
        throw std::runtime_error("native maintenance first journal is not pre-staging intent");
    const char* phases[]{"created", "validated", "planned", "staging"};
    std::ostringstream chain;
    for (std::size_t i = 0; i < 4; ++i) {
        const auto& transition = transitions[i];
        const std::string from = i == 0 ? std::string{} : phases[i - 1];
        if (transition.at("sequence").as_unsigned() != i ||
            (i == 0 ? transition.at("from").type() != usk::json::Value::Type::null_value :
                transition.at("from").as_string() != from) ||
            transition.at("to").as_string() != phases[i] ||
            transition.at("transition_id").as_string() != spec.transaction_id + "." + std::to_string(i) ||
            !transition.at("durable_before_external_visibility").as_boolean() ||
            transition.at("recorded_at").as_string().empty())
            throw std::runtime_error("native maintenance initial intent chain differs");
        chain << i << '\0' << from << '\0' << phases[i] << '\0'
            << transition.at("recorded_at").as_string() << '\n';
    }
    const auto bytes = chain.str();
    usk::base::Sha256 digest;
    digest.update(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    if (value.at("journal_digest").as_string() != digest.finish() ||
        value.at("updated_at").as_string() != transitions.back().at("recorded_at").as_string())
        throw std::runtime_error("native maintenance initial intent digest differs");
}
}
#endif
