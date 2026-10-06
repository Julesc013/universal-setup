// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_maintenance_effect_journal.h"
#include "usk_native_maintenance_transaction_internal.h"
#include "usk_record_io.h"
#include "usk_utf8_path.h"

#include <algorithm>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;
namespace {
using usk::json::Value;
constexpr std::uint64_t maximum_records = 200002u;
constexpr std::uint64_t maximum_journal_bytes = 64u * 1024u * 1024u;
constexpr std::size_t maximum_record_bytes = 32768u;

bool digest(const std::string& value)
{
    return value.size() == 64u && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

bool native_identity(const std::string& value)
{
    return value.size() == 33u && value[16] == ':' &&
        std::count(value.begin(), value.end(), ':') == 1 &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return c == ':' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
}

void exact_keys(const Value& value, const std::set<std::string>& expected)
{
    std::set<std::string> actual;
    for (const auto& item : value.as_object()) actual.insert(item.first);
    if (actual != expected) throw std::runtime_error("maintenance journal fields are invalid");
}

std::string normalized(const fs::path& path)
{
    return fs::absolute(path).lexically_normal().generic_u8string();
}

void relative_path(const std::string& text, bool allow_root = false)
{
    if (allow_root && text.empty()) return;
    const fs::path path = fs::u8path(text);
    if (text.empty() || text.size() > 4096u || path.is_absolute() || path.has_root_path() ||
        path.generic_u8string() != text ||
        std::any_of(text.begin(), text.end(), [](unsigned char c) {
            return c < 0x20u || c == 0x7fu || c == ':' || c == '\\';
        })) throw std::runtime_error("maintenance effect path is invalid");
    for (const auto& component : path) {
        if (component.empty() || component == "." || component == "..")
            throw std::runtime_error("maintenance effect path is not relative and normalized");
    }
}

void root_observation(const Value& root, const fs::path& expected)
{
    exact_keys(root, {"root", "native_identity"});
    if (root.at("root").as_string() != normalized(expected) ||
        !native_identity(root.at("native_identity").as_string()))
        throw std::runtime_error("maintenance context root observation is invalid");
}

void validate_context(const usk::transaction::TransactionSpec& spec, const std::string& text)
{
    if (text.empty() || text.size() > 16384u)
        throw std::runtime_error("maintenance context exceeds its bound");
    const Value value = usk::json::parse(text, {16384u, 8u, 128u, 16384u});
    std::set<std::string> keys{"schema", "operation", "install_id", "transaction_id", "plan_id",
        "plan_digest", "policy_digest", "applied_at", "original_installed_transaction_id",
        "original_installed_state_digest", "ownership_manifest_ref", "ownership_manifest_digest",
        "original_source_archive_digest", "installed_root", "operation_target_root",
        "operation_target_parent", "staging_parent", "state_root", "audit_root"};
    if (value.contains("reviewed_plan_ref") || value.contains("reviewed_plan_sha256")) {
        keys.insert("reviewed_plan_ref");
        keys.insert("reviewed_plan_sha256");
        exact_keys(value, keys);
        if (value.at("reviewed_plan_ref").as_string() != spec.transaction_id + ".maintenance-plan.json" ||
            !digest(value.at("reviewed_plan_sha256").as_string()))
            throw std::runtime_error("maintenance reviewed-plan binding is invalid");
    } else {
        exact_keys(value, keys);
    }
    if (usk::json::canonical(value) != text ||
        value.at("schema").as_string() != "usk.maintenance_source_context.v1" ||
        (spec.operation != "repair" && spec.operation != "move" && spec.operation != "uninstall") ||
        value.at("operation").as_string() != spec.operation ||
        value.at("transaction_id").as_string() != spec.transaction_id ||
        value.at("plan_id").as_string() != spec.plan_id ||
        value.at("plan_digest").as_string() != spec.plan_digest ||
        !usk::record_io::valid_identifier(spec.transaction_id) ||
        !usk::record_io::valid_identifier(spec.plan_id) || !digest(spec.plan_digest) ||
        !usk::record_io::valid_identifier(value.at("install_id").as_string()) ||
        !usk::record_io::valid_identifier(value.at("original_installed_transaction_id").as_string()) ||
        value.at("original_installed_transaction_id").as_string() == spec.transaction_id ||
        value.at("applied_at").as_string().empty() || value.at("applied_at").as_string().size() > 64u)
        throw std::runtime_error("maintenance context does not bind the transaction");
    for (const char* key : {"policy_digest", "original_installed_state_digest",
            "ownership_manifest_digest", "original_source_archive_digest"}) {
        if (!digest(value.at(key).as_string()))
            throw std::runtime_error("maintenance context digest is invalid");
    }
    relative_path(value.at("ownership_manifest_ref").as_string());
    const auto& installed = value.at("installed_root");
    exact_keys(installed, {"root", "native_identity", "parent"});
    const fs::path installed_root = fs::u8path(installed.at("root").as_string());
    if (!installed_root.is_absolute() || normalized(installed_root) != installed.at("root").as_string() ||
        (installed.at("native_identity").type() != Value::Type::null_value &&
         !native_identity(installed.at("native_identity").as_string())))
        throw std::runtime_error("maintenance installed-root observation is invalid");
    root_observation(installed.at("parent"), installed_root.parent_path());
    if (value.at("operation_target_root").as_string() != normalized(spec.target_root))
        throw std::runtime_error("maintenance operation target changed");
    root_observation(value.at("operation_target_parent"), fs::absolute(spec.target_root).parent_path());
    root_observation(value.at("staging_parent"), spec.staging_parent);
    root_observation(value.at("state_root"), spec.state_root);
    root_observation(value.at("audit_root"), spec.audit_root);
}

void validate_effect(const std::string& operation, const std::string& kind, const Value& details)
{
    if (usk::json::canonical(details).size() > 8192u)
        throw std::runtime_error("maintenance effect exceeds its bound");
    if (kind == "backup_file" || kind == "replace_file" || kind == "remove_file") {
        std::set<std::string> keys{"relative_path", "native_identity", "sha256", "size_bytes"};
        if (kind == "remove_file") keys.insert("root_role");
        exact_keys(details, keys);
        relative_path(details.at("relative_path").as_string());
        if (!native_identity(details.at("native_identity").as_string()) ||
            !digest(details.at("sha256").as_string()) ||
            details.at("size_bytes").as_unsigned() > (1ull << 32))
            throw std::runtime_error("maintenance file observation is invalid");
        if (kind != "remove_file" && operation != "repair")
            throw std::runtime_error("maintenance file exchange belongs to repair");
        if (kind == "remove_file") {
            const auto& role = details.at("root_role").as_string();
            if ((role != "installed" && role != "operation_target") || operation == "move" ||
                (operation == "repair" && role != "operation_target"))
                throw std::runtime_error("maintenance removal root role is invalid");
        }
    } else if (kind == "remove_directory") {
        exact_keys(details, {"root_role", "relative_path", "native_identity"});
        relative_path(details.at("relative_path").as_string(), true);
        const auto& role = details.at("root_role").as_string();
        if (!native_identity(details.at("native_identity").as_string()) || operation == "move" ||
            (role != "installed" && role != "operation_target") ||
            (operation == "repair" && role != "operation_target"))
            throw std::runtime_error("maintenance directory observation is invalid");
    } else if (kind == "publish_target") {
        exact_keys(details, {"native_identity"});
        if (!native_identity(details.at("native_identity").as_string()))
            throw std::runtime_error("maintenance publication observation is invalid");
    } else if (kind == "write_ownership") {
        exact_keys(details, {"manifest_id", "prior_manifest_digest"});
        if (operation == "uninstall" ||
            !usk::record_io::valid_identifier(details.at("manifest_id").as_string()) ||
            !digest(details.at("prior_manifest_digest").as_string()))
            throw std::runtime_error("maintenance ownership binding is invalid");
    } else if (kind == "write_installed") {
        std::set<std::string> keys{"install_id", "state_digest"};
        if (details.as_object().count("state_revision")) keys.insert("state_revision");
        exact_keys(details, keys);
        if (!usk::record_io::valid_identifier(details.at("install_id").as_string()) ||
            !digest(details.at("state_digest").as_string()))
            throw std::runtime_error("maintenance installed-state binding is invalid");
        if (keys.count("state_revision")) {
            const auto& revision = details.at("state_revision");
            exact_keys(revision, {"target_root", "ownership_manifest_ref", "ownership_manifest_digest",
                "transaction_id", "created_at", "lifecycle_status", "last_verification"});
            for (const char* key : {"target_root", "ownership_manifest_ref", "transaction_id",
                    "created_at", "lifecycle_status"}) (void)revision.at(key).as_string();
            if (!digest(revision.at("ownership_manifest_digest").as_string()))
                throw std::runtime_error("maintenance installed-state ownership digest is invalid");
            const auto& verification = revision.at("last_verification");
            exact_keys(verification, {"report_id", "report_digest", "status", "verified_at"});
            for (const char* key : {"report_id", "status", "verified_at"}) (void)verification.at(key).as_string();
            if (!digest(verification.at("report_digest").as_string()))
                throw std::runtime_error("maintenance installed-state verification digest is invalid");
        }
    } else if (kind == "append_audit") {
        std::set<std::string> keys{"chain_id", "input_digest"};
        if (details.as_object().count("input")) keys.insert("input");
        exact_keys(details, keys);
        if (!usk::record_io::valid_identifier(details.at("chain_id").as_string()) ||
            !digest(details.at("input_digest").as_string()))
            throw std::runtime_error("maintenance audit binding is invalid");
        if (keys.count("input")) {
            const auto& input = details.at("input");
            exact_keys(input, {"created_at", "operation", "phase", "status", "subject_type",
                "subject_id", "details_digest", "transaction_id", "plan_id", "message"});
            for (const auto& member : input.as_object()) (void)member.second.as_string();
            if (usk::json::sha256_canonical(input) != details.at("input_digest").as_string())
                throw std::runtime_error("maintenance audit postimage digest differs");
        }
    } else {
        throw std::runtime_error("maintenance effect kind is unknown");
    }
}

void validate_completion(const std::string& kind, const std::string& outcome,
    const std::string& result_digest)
{
    const bool metadata = kind == "write_ownership" || kind == "write_installed" || kind == "append_audit";
    if ((outcome != "applied" && (outcome != "retained" || kind != "remove_directory")) ||
        (metadata ? !digest(result_digest) : !result_digest.empty()))
        throw std::runtime_error("maintenance completion is invalid");
}

std::string filename(std::uint64_t sequence)
{
    std::ostringstream out;
    out << std::setw(20) << std::setfill('0') << sequence << ".json";
    return out.str();
}

Value read_record(const fs::path& path, std::uint64_t& bytes)
{
    const std::string text = usk::record_io::read_stable_text(path, maximum_record_bytes);
    if (bytes > maximum_journal_bytes - text.size())
        throw std::runtime_error("maintenance journal exceeds its byte bound");
    bytes += text.size();
    const Value value = usk::json::parse(text, {maximum_record_bytes, 12u, 256u, 16384u});
    exact_keys(value, {"schema", "sequence", "transaction_id", "source_digest", "phase",
        "details", "previous_digest", "digest"});
    auto body = value;
    const auto hash = body.at("digest").as_string();
    body.as_object().erase("digest");
    if (usk::json::canonical(value) + "\n" != text || !digest(hash) ||
        usk::json::sha256_canonical(body) != hash ||
        value.at("schema").as_string() != "usk.maintenance_effect_record.v1")
        throw std::runtime_error("maintenance journal record is invalid");
    return value;
}
} // namespace

namespace usk::transaction {
MaintenanceEffectJournal::MaintenanceEffectJournal(TransactionSpec spec,
    const std::string& source_context, FaultInjector injector)
    : spec_(std::move(spec)), injector_(std::move(injector))
{
    bind_original_owner();
    validate_context(spec_, source_context);
    source_digest_ = json::sha256_canonical(json::parse(source_context));
    directory_ = fs::absolute(spec_.state_root).lexically_normal() / "transactions" /
        (spec_.transaction_id + ".maintenance");
    base::require_native_path_capacity(directory_ / filename(maximum_records - 1u),
        base::NativePathKind::file, "maintenance effect journal");
    record_io::require_safe_directory(directory_.parent_path());
    record_io::create_directory_exclusive(directory_.parent_path(), directory_.filename().string());
    directory_identity_ = observe_directory_identity(directory_);
    persist("context", Value(Value::Object{{"source_context", Value(source_context)},
        {"directory_identity", Value(directory_identity_)}}));
}

void MaintenanceEffectJournal::bind_original_owner()
{
#if defined(_WIN32)
    native_origin_ = detail::ScopedNativeMaintenanceTransaction::current() != nullptr;
    if (native_origin_) native_origin_binding_ = detail::ScopedNativeMaintenanceTransaction::current_binding();
#endif
    require_effect_authority();
}

void MaintenanceEffectJournal::require_effect_authority() const
{
#if defined(_WIN32)
    detail::require_native_maintenance_origin_binding(native_origin_, native_origin_binding_,
        detail::ScopedNativeMaintenanceTransaction::current_binding());
    const auto* native = detail::ScopedNativeMaintenanceTransaction::current();
    if (native_origin_) {
        if (!native) throw std::runtime_error("native maintenance effect journal lost its original owner");
        native->require_authority(spec_);
    } else if (native) throw std::runtime_error("ordinary effect journal cannot adopt native maintenance custody");
#endif
}

void MaintenanceEffectJournal::persist(const std::string& phase, const Value& details)
{
    if (failed_ || sealed_ || sequence_ >= maximum_records)
        throw std::runtime_error("maintenance journal cannot accept another record");
    try {
        require_effect_authority();
        if (injector_) injector_(phase, "before_record");
        require_effect_authority();
        if (observe_directory_identity(directory_) != directory_identity_)
            throw std::runtime_error("maintenance journal directory changed");
        if (sequence_ != 0u) {
            std::uint64_t ignored_bytes = 0;
            const auto prior = read_record(directory_ / filename(sequence_ - 1u), ignored_bytes);
            if (prior.at("digest").as_string() != last_digest_)
                throw std::runtime_error("maintenance journal predecessor changed");
        }
        Value value(Value::Object{{"schema", Value("usk.maintenance_effect_record.v1")},
            {"sequence", Value(sequence_)}, {"transaction_id", Value(spec_.transaction_id)},
            {"source_digest", Value(source_digest_)}, {"phase", Value(phase)}, {"details", details},
            {"previous_digest", last_digest_.empty() ? Value{} : Value(last_digest_)}});
        const std::string hash = json::sha256_canonical(value);
        value.as_object().emplace("digest", Value(hash));
        const std::string text = json::canonical(value) + "\n";
        if (text.size() > maximum_record_bytes || bytes_ > maximum_journal_bytes - text.size())
            throw std::runtime_error("maintenance journal exceeds its bound");
        record_io::write_new_durable_text(directory_ / filename(sequence_), text);
        if (observe_directory_identity(directory_) != directory_identity_)
            throw std::runtime_error("maintenance journal directory changed after persistence");
        last_digest_ = hash;
        bytes_ += text.size();
        ++sequence_;
        if (injector_) injector_(phase, "after_record");
        require_effect_authority();
    } catch (...) {
        // A failed write/callback may have left a durable record. Reopening
        // through inspection is required; this object cannot retry over it.
        failed_ = true;
        throw;
    }
}

void MaintenanceEffectJournal::begin_effect(const std::string& kind, const Value& details)
{
    if (!pending_kind_.empty()) throw std::logic_error("maintenance effect is still unresolved");
    validate_effect(spec_.operation, kind, details);
    pending_sequence_ = sequence_;
    persist("intent", Value(Value::Object{{"kind", Value(kind)}, {"effect", details}}));
    pending_kind_ = kind;
    payload_attempted_ = false;
    payload_outcome_.clear();
}

std::optional<std::string> MaintenanceEffectJournal::apply_payload_effect()
{
    require_effect_authority();
    if (failed_ || sealed_ || pending_kind_.empty() || payload_attempted_)
        throw std::runtime_error("maintenance payload intent is absent, failed or already attempted");
    if (pending_kind_ != "backup_file" && pending_kind_ != "replace_file" &&
        pending_kind_ != "remove_file" && pending_kind_ != "remove_directory")
        throw std::runtime_error("maintenance payload dispatch received a non-payload intent");
#if defined(_WIN32)
    if (native_origin_) {
        const auto history = inspect(spec_, source_digest_, true);
        if (history.journal_digest != last_digest_ || history.next_sequence != sequence_ ||
            history.pending_sequence != pending_sequence_ || history.pending_kind != pending_kind_)
            throw std::runtime_error("maintenance payload dispatch lost its exact original intent");
        const auto* native = detail::ScopedNativeMaintenanceTransaction::current();
        payload_attempted_ = true;
        try {
            payload_outcome_ = native->apply_payload(spec_, history);
            require_effect_authority();
            validate_completion(pending_kind_, payload_outcome_, {});
            return payload_outcome_;
        } catch (...) { failed_ = true; throw; }
    }
#endif
    return std::nullopt;
}

void MaintenanceEffectJournal::complete_effect(const std::string& outcome, const std::string& result_digest)
{
    if (pending_kind_.empty()) throw std::logic_error("maintenance completion has no intent");
#if defined(_WIN32)
    if (native_origin_ && (pending_kind_ == "backup_file" || pending_kind_ == "replace_file" ||
        pending_kind_ == "remove_file" || pending_kind_ == "remove_directory")) {
        require_effect_authority();
        if (!resumed_ && (!payload_attempted_ || payload_outcome_.empty() || outcome != payload_outcome_))
            throw std::runtime_error("native maintenance payload completion lacks its actual owner outcome");
        const auto history = inspect(spec_, source_digest_, true);
        if (history.journal_digest != last_digest_ || history.next_sequence != sequence_ ||
            history.pending_sequence != pending_sequence_ || history.pending_kind != pending_kind_)
            throw std::runtime_error("native maintenance completion lost its original pending intent");
        detail::ScopedNativeMaintenanceTransaction::current()->confirm_payload_completion(spec_, history, outcome);
        require_effect_authority();
    }
#endif
    validate_completion(pending_kind_, outcome, result_digest);
    persist("complete", Value(Value::Object{{"intent_sequence", Value(pending_sequence_)},
        {"kind", Value(pending_kind_)}, {"outcome", Value(outcome)},
        {"result_digest", result_digest.empty() ? Value{} : Value(result_digest)}}));
    pending_kind_.clear();
}

void MaintenanceEffectJournal::seal()
{
    if (!pending_kind_.empty()) throw std::logic_error("maintenance journal has an unresolved intent");
    persist("sealed", Value{});
    sealed_ = true;
}

MaintenanceEffectInspection MaintenanceEffectJournal::inspect(const TransactionSpec& spec,
    const std::string& expected_source_digest, bool retain_completed)
{
    if (!record_io::valid_identifier(spec.transaction_id) || !digest(expected_source_digest))
        throw std::runtime_error("maintenance inspection identity is invalid");
    const fs::path directory = fs::absolute(spec.state_root).lexically_normal() / "transactions" /
        (spec.transaction_id + ".maintenance");
    const std::string directory_identity = observe_directory_identity(directory);
    std::vector<fs::path> records;
    for (const auto& entry : fs::directory_iterator(directory)) {
        if (records.size() >= maximum_records || !entry.is_regular_file() || entry.is_symlink())
            throw std::runtime_error("maintenance journal directory is not exact");
        records.push_back(entry.path());
    }
    if (records.empty()) throw std::runtime_error("maintenance journal has no original context");
    std::sort(records.begin(), records.end());
    MaintenanceEffectInspection result;
    std::uint64_t bytes = 0;
    std::uint64_t pending_sequence = 0;
    for (std::size_t index = 0; index < records.size(); ++index) {
        const auto value = read_record(records[index], bytes);
        if (records[index].filename().string() != filename(index) ||
            value.at("sequence").as_unsigned() != index ||
            value.at("transaction_id").as_string() != spec.transaction_id ||
            value.at("source_digest").as_string() != expected_source_digest || result.sealed ||
            (index == 0u ? value.at("previous_digest").type() != Value::Type::null_value :
             value.at("previous_digest").as_string() != result.journal_digest))
            throw std::runtime_error("maintenance journal chain or binding is invalid");
        const auto& phase = value.at("phase").as_string();
        const auto& details = value.at("details");
        if (index == 0u) {
            if (phase != "context") throw std::runtime_error("maintenance journal lacks original context");
            exact_keys(details, {"source_context", "directory_identity"});
            if (details.at("directory_identity").as_string() != directory_identity)
                throw std::runtime_error("maintenance journal directory identity changed");
            result.source_context = details.at("source_context").as_string();
            validate_context(spec, result.source_context);
            result.source_digest = json::sha256_canonical(json::parse(result.source_context));
            if (result.source_digest != expected_source_digest)
                throw std::runtime_error("maintenance original context digest changed");
        } else if (phase == "intent") {
            exact_keys(details, {"kind", "effect"});
            if (!result.pending_kind.empty()) throw std::runtime_error("maintenance intents overlap");
            result.pending_kind = details.at("kind").as_string();
            result.pending_details = details.at("effect");
            validate_effect(spec.operation, result.pending_kind, result.pending_details);
            pending_sequence = index;
        } else if (phase == "complete") {
            exact_keys(details, {"intent_sequence", "kind", "outcome", "result_digest"});
            if (result.pending_kind.empty() || details.at("kind").as_string() != result.pending_kind ||
                details.at("intent_sequence").as_unsigned() != pending_sequence)
                throw std::runtime_error("maintenance completion does not bind an intent");
            const std::string hash = details.at("result_digest").type() == Value::Type::null_value ?
                std::string{} : details.at("result_digest").as_string();
            validate_completion(result.pending_kind, details.at("outcome").as_string(), hash);
            if (retain_completed) result.completed.push_back({pending_sequence, result.pending_kind,
                result.pending_details, details.at("outcome").as_string(), hash});
            result.pending_kind.clear();
            result.pending_details = Value{};
            ++result.completed_effects;
        } else if (phase == "sealed") {
            if (!result.pending_kind.empty() || details.type() != Value::Type::null_value)
                throw std::runtime_error("maintenance journal sealed with an unresolved effect");
            result.sealed = true;
        } else {
            throw std::runtime_error("maintenance journal phase is invalid");
        }
        result.journal_digest = value.at("digest").as_string();
    }
    if (observe_directory_identity(directory) != directory_identity)
        throw std::runtime_error("maintenance journal directory changed during inspection");
    result.next_sequence = records.size();
    result.pending_sequence = pending_sequence;
    result.serialized_bytes = bytes;
    result.directory_identity = directory_identity;
    return result;
}

MaintenanceEffectJournal::MaintenanceEffectJournal(TransactionSpec spec,
    MaintenanceEffectInspection inspected, FaultInjector injector)
    : spec_(std::move(spec)), injector_(std::move(injector)),
      directory_(fs::absolute(spec_.state_root).lexically_normal() / "transactions" /
          (spec_.transaction_id + ".maintenance")), directory_identity_(std::move(inspected.directory_identity)),
      source_digest_(std::move(inspected.source_digest)), last_digest_(std::move(inspected.journal_digest)),
      pending_kind_(std::move(inspected.pending_kind)), pending_sequence_(inspected.pending_sequence),
      sequence_(inspected.next_sequence), bytes_(inspected.serialized_bytes)
{
#if defined(_WIN32)
    resumed_ = true;
#endif
    bind_original_owner();
}

std::unique_ptr<MaintenanceEffectJournal> MaintenanceEffectJournal::resume(const TransactionSpec& spec,
    const std::string& expected_source_digest, const std::string& expected_history_digest, FaultInjector injector)
{
    auto inspected = inspect(spec, expected_source_digest);
    if (!digest(expected_history_digest) || inspected.journal_digest != expected_history_digest || inspected.sealed)
        throw std::runtime_error("maintenance continuation snapshot changed or is sealed");
    return std::unique_ptr<MaintenanceEffectJournal>(new MaintenanceEffectJournal(
        spec, std::move(inspected), std::move(injector)));
}
} // namespace usk::transaction
