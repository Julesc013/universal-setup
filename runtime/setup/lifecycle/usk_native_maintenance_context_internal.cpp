// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_native_maintenance_context_internal.h"
#if defined(_WIN32)
#include "usk_publisher_anchor_create.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_consumer_access.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_execution_observation.h"
#include "usk_publisher_effect_execution_internal.h"
#include "usk_publisher_handle_observation.h"
#include "usk_publisher_metadata.h"
#include "usk_publisher_maintenance_mutation.h"
#include "usk_publisher_process_boundary.h"
#include "usk_publisher_registration.h"
#include "usk_publisher_request_channel.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_tree_observation.h"
#include "usk_publisher_worker_security.h"
#include "usk_record_io.h"
#include "usk_utf8_path.h"
#include "usk_sha256.h"
#include "usk_maintenance_recovery_internal.h"
#include <algorithm>
#include <array>
#include <iomanip>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace usk::lifecycle::detail {
namespace fs = std::filesystem;
using usk::json::Value;
using namespace usk::platform::windows;
namespace {
bool equal(const Value& a, const Value& b) { return json::equal_values(a, b); }
void members(const Value& value, const std::set<std::string>& expected) {
    if (value.as_object().size() != expected.size())
        throw std::runtime_error("native maintenance custody fields differ");
    for (const auto& item : value.as_object()) if (!expected.count(item.first))
        throw std::runtime_error("native maintenance custody field is unknown");
}
bool digest(const std::string& value) {
    return value.size() == 64u && std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}
std::string raw_digest(const std::string& text) {
    base::Sha256 hash;
    hash.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
    return hash.finish();
}
std::string sequence_name(std::uint64_t sequence) {
    std::ostringstream name;
    name << std::setw(20) << std::setfill('0') << sequence << ".json";
    return name.str();
}
json::ParseLimits custody_parse_limits(std::size_t maximum) {
    json::ParseLimits limits;
    limits.max_bytes = maximum;
    limits.max_values = maximum > 4u * 1024u * 1024u ? 2000000u : 100000u;
    return limits;
}
void require_custody_value_budget(const Value& value, std::size_t maximum) {
    const auto limits = custody_parse_limits(maximum);
    std::size_t count = 0;
    const auto visit = [&](const auto& self, const Value& current, std::size_t depth) -> void {
        if (++count > limits.max_values || depth > limits.max_depth ||
            (current.type() == Value::Type::string && current.as_string().size() > limits.max_string_bytes))
            throw std::runtime_error("native maintenance custody exceeds its closed-reader value budget");
        if (current.type() == Value::Type::array) for (const auto& child : current.as_array()) self(self, child, depth + 1u);
        if (current.type() == Value::Type::object) for (const auto& child : current.as_object()) {
            if (child.first.size() > limits.max_string_bytes)
                throw std::runtime_error("native maintenance custody key exceeds its closed-reader string budget");
            self(self, child.second, depth + 1u);
        }
    };
    visit(visit, value, 0u);
}
bool same(const PublisherHandleObservation& a, const PublisherHandleObservation& b) {
    return equal(publisher_handle_observation_json(a), publisher_handle_observation_json(b));
}
Value consumer_grant_postimage(Value before, const std::string& consumer_sid) {
    auto& aces = before.as_object().at("dacl_aces").as_array();
    if (aces.size() != 2u) throw std::runtime_error("native maintenance read grant lacks its private preimage");
    require_publisher_consumer_sid(consumer_sid);
    aces.emplace_back(Value::Object{{"type", Value(static_cast<std::uint64_t>(ACCESS_ALLOWED_ACE_TYPE))},
        {"flags", Value(std::uint64_t{0})},
        {"access_mask", Value(static_cast<std::uint64_t>(publisher_consumer_read_access_mask()))},
        {"sid", Value(consumer_sid)}});
    return before;
}
class Held final {
public:
    Held() = default;
    ~Held() { if (!close_attempted && value != INVALID_HANDLE_VALUE && value) CloseHandle(value); }
    Held(const Held&) = delete;
    Held& operator=(const Held&) = delete;
    HANDLE value = INVALID_HANDLE_VALUE;
    void close_observer_once() {
        if (close_attempted || value == INVALID_HANDLE_VALUE || !value)
            throw std::runtime_error("native maintenance observer is unavailable for release");
        close_attempted = true;
        if (!CloseHandle(value))
            throw std::runtime_error("native maintenance observer close was not confirmed; retained recovery required");
        value = INVALID_HANDLE_VALUE;
    }
    void adopt_after_confirmed_close(Held& replacement) {
        if (!close_attempted || value != INVALID_HANDLE_VALUE || replacement.close_attempted ||
            replacement.value == INVALID_HANDLE_VALUE || !replacement.value)
            throw std::runtime_error("native maintenance observer transfer lacks a confirmed release");
        value = replacement.value;
        replacement.value = INVALID_HANDLE_VALUE;
        close_attempted = false;
    }
private:
    // A failed observer close is quarantined through worker disposal. Its
    // numeric value is never used again and the destructor never retries it.
    bool close_attempted = false;
};
std::optional<PublisherDirectoryEntry> child_with_names(HANDLE parent, const std::wstring& name,
    const PublisherMaintenanceNames* maintenance_names) {
    std::optional<PublisherDirectoryEntry> result;
    for (const auto& entry : observe_publisher_directory_entries(parent, 64u * 1024u * 1024u, maintenance_names)) {
        if (CompareStringOrdinal(entry.name.c_str(), -1, name.c_str(), -1, TRUE) != CSTR_EQUAL) continue;
        if (entry.name != name || result) throw std::runtime_error("native maintenance child name is ambiguous");
        result = entry;
    }
    return result;
}
std::string journal_identity(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info)) throw std::runtime_error("native maintenance journal identity unavailable");
    std::ostringstream text;
    text << std::hex << std::setfill('0') << std::setw(16) << info.dwVolumeSerialNumber << ':' <<
        std::setw(16) << ((static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow);
    return text.str();
}
}
struct NativeMaintenanceContext::Impl {
    struct Entry {
        Held handle;
        Entry* parent = nullptr;
        std::wstring name;
        PublisherHandleObservation facts{};
        bool directory = true, created = false, restored_creation = false, complete = false;
        // Creation provenance belongs to the object. This flag distinguishes
        // a subsequently reopened observer from its original creation handle.
        bool reopened_observer = false;
        std::uint64_t size = 0;
        std::string sha256, stream_identity;
    };
    HANDLE volume;
    const std::wstring volume_root, service_name;
    const PublisherInstallOperationGuard& guard;
    const PublisherMaintenanceStateSnapshot& original_state;
    const PublisherInstallOperationContext& original_context;
    const PublisherInstallationLease& lease;
    const RegisteredPublisherAdmission* const admission;
    const PublisherRequestChannel* const channel;
    PublisherEffectExecutionOwner* const original_child;
    const transaction::TransactionSpec spec;
    HANDLE cancel_event;
    PublisherServiceObservation service;
    PublisherWorkerTokenContext worker_context{};
    Value worker, process_boundary, registration, selection, client, original_broker;
    std::unique_ptr<PublisherWorkerSecurityContinuity> worker_continuity;
    Value original_consumer_completion;
    std::string original_consumer_sid;
    std::vector<std::wstring> consumer_payload_roots;
    PublisherHandleObservation volume_facts;
    PublisherVolumeObservation volume_observation;
    std::vector<unsigned char> descriptor;
    std::map<fs::path, std::unique_ptr<Entry>> directories;
    std::unique_ptr<PublisherMaintenanceNames> maintenance_names;
    std::map<fs::path, std::unique_ptr<Entry>> files;
    std::map<fs::path, std::unique_ptr<Entry>> original_files;
    // Read-only repair verification custody never enters the mutation maps.
    std::map<fs::path, std::unique_ptr<Entry>> verification_files;
    std::map<fs::path, Entry*> original_directories;
    std::set<fs::path> absent_original_files, absent_original_directories;
    fs::path original_admission_path;
    std::string original_admission_text, original_admission_sha256;
    fs::path native_custody_directory, native_snapshot_directory;
    std::uint64_t native_custody_sequence = 0;
    std::size_t native_custody_bytes = 0;
    std::string native_custody_digest;
    bool custody_failed = false;
    bool restored_owner = false;
    Value original_lease_ownership;
    std::string admitted_lease_revision;
    Entry* installed_root = nullptr;
    Entry* removed_original_root_parent = nullptr;
    std::wstring removed_original_root_name;
    std::string original_root_identity;
    bool payload_failed = false;
    std::set<std::string> attempted_payload_histories;
    struct ConfirmedPayload {
        std::string transaction_sha256, outcome = "applied", result_digest;
        std::shared_ptr<const std::string> transaction_text;
        bool confirmed = false;
    };
    std::map<std::string, std::shared_ptr<const std::string>> transaction_snapshots;
    std::size_t transaction_snapshot_bytes = 0;
    std::map<std::string, std::unique_ptr<ConfirmedPayload>> payload_outcomes;
    std::string active_payload_transaction, active_payload_history;
    Entry* staging_parent = nullptr;
    Entry* target_parent = nullptr;
    Entry* staging = nullptr;
    bool publication_attempted = false, publication_confirmed = false;
    std::shared_ptr<const std::string> publication_transaction_text;
    std::string publication_transaction_sha256, original_source_context;
    fs::path installed_record_path, prepared_record_path;
    Entry* installed_parent = nullptr;
    std::unique_ptr<Entry> installed_postimage_file;
    PublisherHandleObservation installed_record_facts;
    Value installed_postimage_bindings;
    std::string installed_record_text, installed_record_sha256, prepared_transaction_sha256, prepared_history_sha256;
    bool installed_prepared = false, installed_issue_active = false, installed_confirmed = false, installed_uncertain = false;
    transaction::detail::NativeMaintenanceTransactionOperations operations;
    std::function<void()> effect_fence;
    record_io::NativeRecordReadOperations record_reads;
    std::unique_ptr<PublisherMetadataSession> metadata;
    // These are protected-record observers. Neither their reopened handles
    // nor a parsed creator document is labelled as this worker's creation.
    std::vector<std::unique_ptr<Entry>> restoration_record_observers;
    struct RestorationCustody {
        Value original, created, publication;
        std::vector<Value> records;
        std::map<std::string, std::shared_ptr<const std::string>> snapshots;
        std::map<std::uint64_t, Value> intents;
        std::string original_text, created_text, last_digest;
        std::size_t record_bytes = 0, snapshot_bytes = 0;
    };

    std::optional<PublisherDirectoryEntry> child(HANDLE parent, const std::wstring& name) const {
        return child_with_names(parent, name, maintenance_names.get());
    }

    std::string read_restoration_record(const fs::path& path, std::size_t maximum) {
        original_context.require_fence(); original_state.require_custody(); lease.require_fence();
        auto& parent = open_directory(path.parent_path());
        const auto listed = child(parent.handle.value, path.filename().wstring());
        if (!listed || (listed->attributes & FILE_ATTRIBUTE_DIRECTORY))
            throw std::runtime_error("native maintenance original protected record is absent");
        auto entry = std::make_unique<Entry>();
        entry->parent = &parent; entry->name = path.filename().wstring(); entry->directory = false;
        entry->handle.value = open_publisher_listed_child(parent.handle.value, *listed);
        entry->facts = facts(entry->handle.value, false);
        FILE_STANDARD_INFO size{}; LARGE_INTEGER zero{};
        if (!GetFileInformationByHandleEx(entry->handle.value, FileStandardInfo, &size, sizeof(size)) ||
            size.DeletePending || size.Directory || size.EndOfFile.QuadPart <= 0 ||
            static_cast<std::uint64_t>(size.EndOfFile.QuadPart) > maximum ||
            !SetFilePointerEx(entry->handle.value, zero, nullptr, FILE_BEGIN))
            throw std::runtime_error("native maintenance original protected record exceeds its bound");
        std::string text(static_cast<std::size_t>(size.EndOfFile.QuadPart), '\0'); DWORD read = 0;
        if (!ReadFile(entry->handle.value, text.data(), static_cast<DWORD>(text.size()), &read, nullptr) ||
            read != text.size()) throw std::runtime_error("native maintenance original protected record read failed");
        entry->size = text.size(); entry->sha256 = raw_digest(text);
        require_bytes(*entry);
        restoration_record_observers.push_back(std::move(entry));
        original_context.require_fence(); original_state.require_custody(); lease.require_fence();
        return text;
    }
    static Value closed_record(const std::string& text, const std::set<std::string>& fields,
        std::size_t maximum = 1024u * 1024u) {
        auto value = json::parse(text, custody_parse_limits(maximum)); members(value, fields);
        if (json::canonical(value) + "\n" != text)
            throw std::runtime_error("native maintenance original protected record is not canonical");
        return value;
    }
    RestorationCustody read_restoration_custody() {
        RestorationCustody saved;
        const auto& snapshot = original_context.record().at("reviewed_snapshot");
        const auto transactions = spec.state_root / "transactions";
        saved.original_text = read_restoration_record(transactions /
            (spec.transaction_id + ".native-maintenance-original.json"), 16u * 1024u * 1024u);
        const auto original_schema = json::parse(saved.original_text, custody_parse_limits(16u * 1024u * 1024u)).at("schema").as_string();
        const bool child_original = original_schema == "usk.publisher.maintenance_original_custody.v3" ||
            original_schema == "usk.publisher.maintenance_original_custody.v4";
        std::set<std::string> original_fields{"schema", "transaction_id", "operation", "plan_digest",
            "original_context_sha256", "original_lease_ownership", "worker_security", "process_boundary",
            "registration_sha256", "authenticated_client", "original_consumer_completion", "installed_root", "installed_root_journal_identity", "original_objects"};
        if (child_original) original_fields.insert("broker_readback");
        saved.original = closed_record(saved.original_text, original_fields, 16u * 1024u * 1024u);
        const auto& original = saved.original;
        if ((!child_original && original.at("schema").as_string() != "usk.publisher.maintenance_original_custody.v2") ||
            original.at("transaction_id").as_string() != spec.transaction_id ||
            original.at("operation").as_string() != spec.operation || original.at("plan_digest").as_string() != spec.plan_digest ||
            original.at("original_context_sha256").as_string() != original_context.lease_binding_sha256() ||
            original.at("authenticated_client").at("user_sid").as_string() != client.at("user_sid").as_string() ||
            !digest(original.at("registration_sha256").as_string()) ||
            !equal(original.at("original_consumer_completion"), original_consumer_completion))
            throw std::runtime_error("native maintenance original custody differs from its protected intent/caller");
        if (child_original) require_publisher_effect_maintenance_original_record(original,
            snapshot.at("apply_request"), service_name);
        const auto& old_lease = original.at("original_lease_ownership");
        // The actual journal, actual current native generation and an ended
        // PID+birth holder are proved before consuming any creator/outcome.
        lease.require_recovery_lineage(old_lease);
        if (old_lease.at("expected_state_revision").as_string() != snapshot.at("initial_state_revision").as_string() ||
            original.at("worker_security").at("process_id").as_unsigned() != old_lease.at("holder").at("process_id").as_unsigned() ||
            original.at("process_boundary").at("process_id").as_unsigned() != old_lease.at("holder").at("process_id").as_unsigned())
            throw std::runtime_error("native maintenance original creator differs from its actual lease holder");
        const auto original_sha = raw_digest(saved.original_text), old_lease_sha = json::sha256_canonical(old_lease);
        saved.created_text = read_restoration_record(transactions /
            (spec.transaction_id + ".native-maintenance-created.json"), 16u * 1024u * 1024u);
        saved.created = closed_record(saved.created_text, {"schema", "transaction_id", "plan_digest", "original_context_sha256",
            "original_admission_sha256", "lease_ownership_sha256", "transaction_snapshot_sha256", "source_context",
            "worker_security", "process_boundary", "registration_sha256", "authenticated_client", "root", "root_parent",
            "target_parent", "root_native_identity", "created_objects"}, 16u * 1024u * 1024u);
        if (saved.created.at("schema").as_string() != "usk.publisher.maintenance_created_closure.v2" ||
            saved.created.at("transaction_id").as_string() != spec.transaction_id ||
            saved.created.at("plan_digest").as_string() != spec.plan_digest ||
            saved.created.at("original_context_sha256").as_string() != original_context.lease_binding_sha256() ||
            saved.created.at("original_admission_sha256").as_string() != original_sha ||
            saved.created.at("lease_ownership_sha256").as_string() != old_lease_sha)
            throw std::runtime_error("native maintenance created closure lost its actual original admission");
        for (const auto* name : {"worker_security", "process_boundary", "registration_sha256", "authenticated_client"})
            if (!equal(saved.created.at(name), original.at(name)))
                throw std::runtime_error("native maintenance created closure changed its original provenance");
        const auto current = transaction::TransactionSession::inspect_recovery(spec);
        const auto history = transaction::MaintenanceEffectJournal::inspect(spec, current.stream_source_digest, true);
        if (current.stream_source_context != saved.created.at("source_context").as_string() ||
            history.source_context != current.stream_source_context ||
            !equal(read_maintenance_reviewed_plan(spec).at("reviewed_plan"), snapshot.at("reviewed_plan")))
            throw std::runtime_error("native maintenance restoration changed its original transaction/plan");
        const auto snapshot_path = transactions / (spec.transaction_id + ".native-maintenance-snapshots");
        auto& snapshots = open_directory(snapshot_path);
        const auto snapshot_entries = observe_publisher_directory_entries(snapshots.handle.value);
        if (snapshot_entries.size() > 100000u) throw std::runtime_error("native maintenance snapshot count exceeds its bound");
        for (const auto& entry : snapshot_entries) {
            const auto name = fs::path(entry.name).u8string();
            if (name.size() != 69u || name.substr(64) != ".json" || !digest(name.substr(0, 64)))
                throw std::runtime_error("native maintenance retained snapshot name differs");
            auto text = read_restoration_record(snapshot_path / entry.name, 4u * 1024u * 1024u);
            if (text.size() > 16u * 1024u * 1024u - saved.snapshot_bytes || raw_digest(text) != name.substr(0, 64))
                throw std::runtime_error("native maintenance retained snapshot bytes exceed or differ from their bound");
            saved.snapshot_bytes += text.size();
            transaction::TransactionSession::require_recovery_transition_extension(spec, text, name.substr(0, 64), current.snapshot_sha256);
            if (!saved.snapshots.emplace(name.substr(0, 64), std::make_shared<const std::string>(std::move(text))).second)
                throw std::runtime_error("native maintenance retained snapshot repeats");
        }
        const auto publication_snapshot = saved.created.at("transaction_snapshot_sha256").as_string();
        if (!saved.snapshots.count(publication_snapshot))
            throw std::runtime_error("native maintenance original publication snapshot is absent");
        const auto custody_path = transactions / (spec.transaction_id + ".native-maintenance-custody");
        auto& custody = open_directory(custody_path);
        const auto entries = observe_publisher_directory_entries(custody.handle.value);
        if (entries.empty() || entries.size() > 200000u)
            throw std::runtime_error("native maintenance custody count exceeds its bound");
        std::map<std::wstring, PublisherDirectoryEntry> ordered;
        for (const auto& entry : entries) if (!ordered.emplace(entry.name, entry).second)
            throw std::runtime_error("native maintenance custody name repeats");
        std::set<std::uint64_t> confirmed_sequences;
        std::set<std::string> checked_writers;
        std::map<std::uint64_t, const transaction::CompletedMaintenanceEffect*> completed_by_sequence;
        for (const auto& completed : history.completed) completed_by_sequence.emplace(completed.intent_sequence, &completed);
        std::map<std::uint64_t, Value> intents;
        for (const auto& item : ordered) {
            const auto sequence = static_cast<std::uint64_t>(saved.records.size());
            if (item.first != fs::u8path(sequence_name(sequence)).wstring())
                throw std::runtime_error("native maintenance custody prefix has a gap or unknown name");
            const auto text = read_restoration_record(custody_path / item.first, 1024u * 1024u);
            if (text.size() > 256u * 1024u * 1024u - saved.record_bytes)
                throw std::runtime_error("native maintenance custody bytes exceed their bound");
            auto record = closed_record(text, {"schema", "transaction_id", "plan_digest", "original_context_sha256",
                "original_admission_sha256", "original_lease_ownership_sha256", "writer_lease_ownership", "sequence", "kind", "previous_record_sha256",
                "transaction_snapshot_sha256", "pending_history_sha256", "pending_intent_sequence", "details"});
            if (record.at("schema").as_string() != "usk.publisher.maintenance_native_custody.v2" ||
                record.at("transaction_id").as_string() != spec.transaction_id || record.at("plan_digest").as_string() != spec.plan_digest ||
                record.at("original_context_sha256").as_string() != original_context.lease_binding_sha256() ||
                record.at("original_admission_sha256").as_string() != original_sha ||
                record.at("original_lease_ownership_sha256").as_string() != old_lease_sha ||
                record.at("sequence").as_unsigned() != sequence ||
                !equal(record.at("previous_record_sha256"), saved.last_digest.empty() ? Value{} : Value(saved.last_digest)) ||
                !saved.snapshots.count(record.at("transaction_snapshot_sha256").as_string()))
                throw std::runtime_error("native maintenance custody record changed its original prefix/binding");
            if (checked_writers.insert(json::sha256_canonical(record.at("writer_lease_ownership"))).second)
                lease.require_recovery_lineage(record.at("writer_lease_ownership"));
            const auto& kind = record.at("kind").as_string(); const auto& details = record.at("details");
            if (kind == "confirmed_publication") {
                members(details, {"created_closure_sha256", "root", "parent", "publication_transaction_snapshot_sha256"});
                if (sequence != 0u || details.at("created_closure_sha256").as_string() != raw_digest(saved.created_text) ||
                    details.at("publication_transaction_snapshot_sha256").as_string() != publication_snapshot ||
                    record.at("transaction_snapshot_sha256").as_string() != publication_snapshot ||
                    record.at("pending_history_sha256").type() != Value::Type::null_value ||
                    record.at("pending_intent_sequence").type() != Value::Type::null_value ||
                    !equal(details.at("parent"), saved.created.at("target_parent")))
                    throw std::runtime_error("native maintenance publication lacks its original confirmed receipt");
                saved.publication = details;
            } else {
                if (saved.publication.type() != Value::Type::object || !digest(record.at("pending_history_sha256").as_string()))
                    throw std::runtime_error("native maintenance effect custody precedes its confirmed publication");
                const auto intent_sequence = record.at("pending_intent_sequence").as_unsigned();
                auto found_intent = intents.find(intent_sequence);
                if (found_intent == intents.end()) {
                    const auto intent_text = read_restoration_record(transactions / (spec.transaction_id + ".maintenance") /
                        sequence_name(intent_sequence), 32768u);
                    auto intent = json::parse(intent_text);
                    if (intent.at("phase").as_string() != "intent" || intent.at("sequence").as_unsigned() != intent_sequence ||
                        intent.at("transaction_id").as_string() != spec.transaction_id ||
                        intent.at("source_digest").as_string() != history.source_digest)
                        throw std::runtime_error("native maintenance custody intent differs from its original history");
                    found_intent = intents.emplace(intent_sequence, std::move(intent)).first;
                }
                const auto& intent = found_intent->second;
                if (intent.at("digest").as_string() != record.at("pending_history_sha256").as_string())
                    throw std::runtime_error("native maintenance custody changed its original intent digest");
                const auto completed = completed_by_sequence.find(intent_sequence);
                if (completed != completed_by_sequence.end()) {
                    if (completed->second->kind != intent.at("details").at("kind").as_string() ||
                        !equal(completed->second->details, intent.at("details").at("effect")))
                        throw std::runtime_error("native maintenance custody intent differs from its completed prefix");
                } else if (history.pending_sequence != intent_sequence ||
                    history.pending_kind != intent.at("details").at("kind").as_string() ||
                    !equal(history.pending_details, intent.at("details").at("effect")) ||
                    history.journal_digest != record.at("pending_history_sha256").as_string())
                    throw std::runtime_error("native maintenance custody intent is outside its exact original prefix");
                if (kind == "confirmed_effect") {
                    members(details, {"intent_sequence", "effect_kind", "effect_details", "outcome", "result_digest",
                        "effect_transaction_snapshot_sha256"});
                    if (details.at("intent_sequence").as_unsigned() != intent_sequence ||
                        intent.at("details").at("kind").as_string() != details.at("effect_kind").as_string() ||
                        !equal(intent.at("details").at("effect"), details.at("effect_details")) ||
                        details.at("effect_transaction_snapshot_sha256").as_string() != record.at("transaction_snapshot_sha256").as_string() ||
                        !confirmed_sequences.insert(intent_sequence).second)
                        throw std::runtime_error("native maintenance confirmed outcome lost its actual original intent");
                    auto result = details.at("result_digest").type() == Value::Type::null_value ?
                        std::string{} : details.at("result_digest").as_string();
                    if (completed != completed_by_sequence.end() &&
                        (completed->second->outcome != details.at("outcome").as_string() || completed->second->result_digest != result))
                        throw std::runtime_error("native maintenance confirmed outcome is outside the exact original completed prefix");
                    if (details.at("outcome").as_string() != "applied" &&
                        !(details.at("outcome").as_string() == "retained" && details.at("effect_kind").as_string() == "remove_directory"))
                        throw std::runtime_error("native maintenance confirmed outcome is unsupported");
                } else if (kind == "later_created_directory") {
                    members(details, {"relative_path", "object", "parent", "native_identity"});
                    const auto relative = owned_relative(details.at("relative_path").as_string());
                    if (*relative.begin() != fs::path("backup") || intent.at("details").at("kind").as_string() != "backup_file")
                        throw std::runtime_error("native maintenance later creation is outside its original backup role");
                } else if (kind == "created_owned_parent") {
                    members(details, {"relative_path", "object", "parent", "native_identity"});
                    const auto relative = owned_relative(details.at("relative_path").as_string());
                    const auto file = owned_relative(intent.at("details").at("effect").at("relative_path").as_string());
                    const auto below = file.lexically_relative(relative);
                    const auto& ownership = snapshot.at("ownership_manifest").at("directories").as_array();
                    if (spec.operation != "repair" || intent.at("details").at("kind").as_string() != "replace_file" ||
                        below.empty() || below == fs::path(".") || *below.begin() == fs::path("..") ||
                        std::none_of(ownership.begin(), ownership.end(), [&](const auto& owned) {
                            return owned_relative(owned.at("relative_path").as_string()) == relative;
                        })) throw std::runtime_error("native repair parent is outside its original owned replacement path");
                } else if (kind == "consumer_read_grant") {
                    members(details, {"root_role", "relative_path", "before", "after", "parent", "native_identity", "consumer_sid"});
                    const auto role = details.at("root_role").as_string();
                    const auto text = details.at("relative_path").as_string();
                    const auto relative = text.empty() ? fs::path{} : owned_relative(text);
                    const auto effect = intent.at("details").at("kind").as_string();
                    if (original_consumer_sid.empty() || details.at("consumer_sid").as_string() != original_consumer_sid ||
                        !equal(details.at("after"), consumer_grant_postimage(details.at("before"), original_consumer_sid)) ||
                        !((spec.operation == "move" && role == "operation_target" && effect == "publish_target") ||
                          (spec.operation == "repair" && role == "installed" && effect == "replace_file" && !relative.empty())))
                        throw std::runtime_error("native maintenance read grant differs from its original consumer/intent");
                    if (spec.operation == "repair") {
                        const auto file = owned_relative(intent.at("details").at("effect").at("relative_path").as_string());
                        const auto below = file.lexically_relative(relative);
                        if (below.empty() || *below.begin() == fs::path(".."))
                            throw std::runtime_error("native repair read grant is outside its original replacement path");
                    }
                } else if (kind == "created_metadata") {
                    members(details, {"setup_relative_path", "object", "parent", "size_bytes", "sha256"});
                    (void)owned_relative(details.at("setup_relative_path").as_string());
                    if (!digest(details.at("sha256").as_string()) || details.at("size_bytes").as_unsigned() > 4u * 1024u * 1024u)
                        throw std::runtime_error("native maintenance metadata creation exceeds its original bound");
                    const auto& effect_kind = intent.at("details").at("kind").as_string();
                    if (effect_kind != "write_ownership" && effect_kind != "write_installed" && effect_kind != "append_audit")
                        throw std::runtime_error("native maintenance metadata creation has a non-metadata intent");
                } else throw std::runtime_error("native maintenance custody kind is unsupported");
            }
            saved.record_bytes += text.size(); saved.last_digest = raw_digest(text); saved.records.push_back(std::move(record));
        }
        // Record custody and lineage remain read-only. The separate owner
        // restore must still prove payload/parent/metadata native postimages.
        for (const auto& completed : history.completed)
            if (completed.kind != "publish_target" && !confirmed_sequences.count(completed.intent_sequence))
                throw std::runtime_error("native maintenance completed prefix lacks its original confirmed custody");
        saved.intents = std::move(intents);
        for (const auto& observer : restoration_record_observers) require_bytes(*observer);
        lease.require_recovery_lineage(old_lease);
        return saved;
    }
    struct RestoredObject {
        Value object, parent;
        fs::path path;
        bool directory = false, removed = false;
        std::uint64_t size = 0;
        std::string sha256, native_identity;
    };
    static Value renamed_facts(Value object, const Value& parent, const fs::path& component) {
        object.as_object().at("native_name") = Value(parent.at("native_name").as_string() + "\\" + component.u8string());
        return object;
    }
    static Value published_facts(Value object, const Value& from, const Value& to) {
        const auto old_root = from.at("native_name").as_string(), next_root = to.at("native_name").as_string();
        auto name = object.at("native_name").as_string();
        if (name != old_root && name.rfind(old_root + "\\", 0) != 0)
            throw std::runtime_error("native maintenance creation escaped its original root");
        name.replace(0, old_root.size(), next_root);
        object.as_object().at("native_name") = Value(std::move(name));
        return object;
    }
    void restore_custody(RestorationCustody saved) {
        const auto& snapshot = original_context.record().at("reviewed_snapshot");
        const auto installed_path = normalized(fs::u8path(snapshot.at("installed_state").at("target_root").as_string()));
        original_lease_ownership = saved.original.at("original_lease_ownership");
        const auto& created_root = saved.created.at("root");
        const auto published_root = renamed_facts(created_root, saved.created.at("target_parent"), spec.target_root.filename());
        if (!equal(published_root, saved.publication.at("root")) ||
            !equal(publisher_handle_observation_json(staging_parent->facts), saved.created.at("root_parent")) ||
            !equal(publisher_handle_observation_json(target_parent->facts), saved.created.at("target_parent")))
            throw std::runtime_error("native maintenance publication changed its original native namespace postimage");
        std::map<fs::path, RestoredObject> original_files_after, original_directories_after, created_files_after, created_directories_after;
        std::map<fs::path, RestoredObject> verification_files_after;
        const auto verification_manifest = repair_verification_manifest();
        std::set<fs::path> repaired_parent_creations;
        for (const auto& item : saved.original.at("original_objects").as_array()) {
            const bool directory = item.at("type").as_string() == "directory";
            if (!directory && item.at("type").as_string() != "file")
                throw std::runtime_error("native maintenance original object type differs");
            members(item, directory ? std::set<std::string>{"relative_path", "type", "present", "object", "parent", "native_identity"} :
                std::set<std::string>{"relative_path", "type", "present", "object", "parent", "native_identity", "size_bytes", "sha256"});
            const auto text = item.at("relative_path").as_string();
            const auto relative = text.empty() && directory ? fs::path{} : owned_relative(text);
            const auto verification = directory ? verification_manifest.end() : verification_manifest.find(relative);
            if (verification != verification_manifest.end() && (!item.at("present").as_boolean() ||
                item.at("size_bytes").as_unsigned() != verification->second->at("size_bytes").as_unsigned() ||
                item.at("sha256").as_string() != verification->second->at("sha256").as_string()))
                throw std::runtime_error("native repair verification custody differs from its original owned bytes");
            if (!item.at("present").as_boolean()) {
                if (item.at("object").type() != Value::Type::null_value || item.at("parent").type() != Value::Type::null_value ||
                    item.at("native_identity").type() != Value::Type::null_value)
                    throw std::runtime_error("native maintenance absent original acquired object facts");
                (directory ? absent_original_directories : absent_original_files).insert(relative); continue;
            }
            RestoredObject object{item.at("object"), item.at("parent"), relative.empty() ? installed_path : installed_path / relative, directory};
            object.native_identity = item.at("native_identity").as_string();
            if (!directory) { object.size = item.at("size_bytes").as_unsigned(); object.sha256 = item.at("sha256").as_string(); }
            auto& objects = directory ? original_directories_after :
                (verification != verification_manifest.end() ? verification_files_after : original_files_after);
            if (!objects.emplace(relative, std::move(object)).second)
                throw std::runtime_error("native maintenance original object repeats");
        }
        if (verification_files_after.size() != verification_manifest.size() ||
            original_files_after.size() + verification_files_after.size() > 100000u || original_directories_after.size() > 100001u ||
            !original_directories_after.count(fs::path{}) ||
            !equal(original_directories_after.at(fs::path{}).object, saved.original.at("installed_root")))
            throw std::runtime_error("native maintenance original installed root is absent");
        created_directories_after.emplace(fs::path{}, RestoredObject{published_root, saved.created.at("target_parent"), spec.target_root, true});
        created_directories_after.at(fs::path{}).native_identity = saved.created.at("root_native_identity").as_string();
        for (const auto& item : saved.created.at("created_objects").as_array()) {
            members(item, {"relative_path", "object", "native_identity", "size_bytes", "sha256"});
            const auto relative = owned_relative(item.at("relative_path").as_string());
            const bool directory = (item.at("object").at("attributes").as_unsigned() & FILE_ATTRIBUTE_DIRECTORY) != 0;
            RestoredObject object{published_facts(item.at("object"), created_root, published_root), Value{}, spec.target_root / relative, directory};
            object.native_identity = item.at("native_identity").as_string();
            if (!directory) { object.size = item.at("size_bytes").as_unsigned(); object.sha256 = item.at("sha256").as_string(); }
            if (!(directory ? created_directories_after : created_files_after).emplace(relative, std::move(object)).second)
                throw std::runtime_error("native maintenance original creation repeats");
        }
        const auto assign_created_parent = [&](const fs::path& relative, RestoredObject& object) {
            const auto parent = created_directories_after.find(relative.parent_path());
            if (parent == created_directories_after.end())
                throw std::runtime_error("native maintenance original creation lacks its parent custody");
            object.parent = parent->second.object;
            if (!equal(object.object, renamed_facts(object.object, object.parent, relative.filename())))
                throw std::runtime_error("native maintenance original creation has a contradictory native path");
        };
        for (auto& item : created_directories_after) if (!item.first.empty()) assign_created_parent(item.first, item.second);
        for (auto& item : created_files_after) assign_created_parent(item.first, item.second);
        std::map<std::uint64_t, const Value*> metadata_creations;
        for (const auto& record : saved.records) {
            const auto& kind = record.at("kind").as_string(); const auto& details = record.at("details");
            if (kind == "later_created_directory") {
                const auto relative = owned_relative(details.at("relative_path").as_string());
                const auto parent = created_directories_after.find(relative.parent_path());
                if (parent == created_directories_after.end() || parent->second.removed ||
                    !equal(parent->second.object, details.at("parent")) ||
                    !equal(details.at("object"), renamed_facts(details.at("object"), details.at("parent"), relative.filename())) ||
                    !created_directories_after.emplace(relative, RestoredObject{details.at("object"), details.at("parent"), spec.target_root / relative, true}).second)
                    throw std::runtime_error("native maintenance later directory changed its original creator/parent");
                created_directories_after.at(relative).native_identity = details.at("native_identity").as_string();
            } else if (kind == "created_owned_parent") {
                const auto relative = owned_relative(details.at("relative_path").as_string());
                const auto parent = original_directories_after.find(relative.parent_path());
                if (!absent_original_directories.count(relative) || parent == original_directories_after.end() ||
                    parent->second.removed || !equal(parent->second.object, details.at("parent")) ||
                    !equal(details.at("object"), renamed_facts(details.at("object"), details.at("parent"), relative.filename())) ||
                    !original_directories_after.emplace(relative, RestoredObject{details.at("object"), details.at("parent"), installed_path / relative, true}).second)
                    throw std::runtime_error("native repair parent changed its original absence/creator lineage");
                original_directories_after.at(relative).native_identity = details.at("native_identity").as_string();
                repaired_parent_creations.insert(relative);
            } else if (kind == "consumer_read_grant") {
                const auto role = details.at("root_role").as_string();
                const auto text = details.at("relative_path").as_string();
                const auto relative = text.empty() ? fs::path{} : owned_relative(text);
                const bool directory = (details.at("before").at("attributes").as_unsigned() & FILE_ATTRIBUTE_DIRECTORY) != 0;
                RestoredObject* object = nullptr;
                if (role == "operation_target") {
                    auto& objects = directory ? created_directories_after : created_files_after;
                    const auto found = objects.find(relative);
                    if (found != objects.end() && found->second.path == spec.target_root / relative) object = &found->second;
                } else if (role == "installed" && directory && repaired_parent_creations.count(relative)) {
                    object = &original_directories_after.at(relative);
                } else if (role == "installed" && !directory) {
                    const auto found = created_files_after.find(fs::path("payload") / relative);
                    if (found != created_files_after.end() && found->second.path == installed_path / relative) object = &found->second;
                }
                if (!object || object->removed || object->directory != directory ||
                    !equal(object->object, details.at("before")) || !equal(object->parent, details.at("parent")) ||
                    object->native_identity != details.at("native_identity").as_string())
                    throw std::runtime_error("native maintenance read grant lacks its exact surviving creator postimage");
                const auto before = object->object;
                object->object = details.at("after");
                if (directory) {
                    const auto update = [&](auto& objects) { for (auto& item : objects)
                        if (item.second.path.parent_path() == object->path && equal(item.second.parent, before))
                            item.second.parent = object->object;
                    };
                    update(created_directories_after); update(created_files_after);
                    update(original_directories_after); update(original_files_after); update(verification_files_after);
                }
            } else if (kind == "created_metadata") {
                if (!metadata_creations.emplace(record.at("pending_intent_sequence").as_unsigned(), &details).second)
                    throw std::runtime_error("native maintenance intent has repeated metadata creations");
            } else if (kind == "confirmed_effect") {
                const auto& effect = details.at("effect_kind").as_string(); const auto& data = details.at("effect_details");
                const auto relative = data.contains("relative_path") && !data.at("relative_path").as_string().empty() ?
                    owned_relative(data.at("relative_path").as_string()) : fs::path{};
                if (effect == "backup_file") {
                    auto& object = original_files_after.at(relative);
                    if (object.native_identity != data.at("native_identity").as_string() || object.size != data.at("size_bytes").as_unsigned() ||
                        object.sha256 != data.at("sha256").as_string())
                        throw std::runtime_error("native maintenance backup intent changed its original object/bytes");
                    const auto backup = fs::path("backup") / relative;
                    const auto& parent = created_directories_after.at(backup.parent_path());
                    if (object.removed || parent.removed) throw std::runtime_error("native maintenance backup lost original custody");
                    object.object = renamed_facts(object.object, parent.object, backup.filename());
                    object.parent = parent.object; object.path = spec.target_root / backup;
                } else if (effect == "replace_file") {
                    auto& object = created_files_after.at(fs::path("payload") / relative);
                    if (object.native_identity != data.at("native_identity").as_string() || object.size != data.at("size_bytes").as_unsigned() ||
                        object.sha256 != data.at("sha256").as_string())
                        throw std::runtime_error("native maintenance replacement intent changed its original creation/bytes");
                    const auto& parent = original_directories_after.at(relative.parent_path());
                    if (object.removed || parent.removed) throw std::runtime_error("native maintenance replacement lost original custody");
                    object.object = renamed_facts(object.object, parent.object, relative.filename());
                    object.parent = parent.object; object.path = installed_path / relative;
                } else if (effect == "remove_file" || effect == "remove_directory") {
                    const bool directory = effect == "remove_directory";
                    const auto role = data.at("root_role").as_string();
                    RestoredObject* object = nullptr;
                    if (role == "installed") object = &(directory ? original_directories_after : original_files_after).at(relative);
                    else if (role == "operation_target" && directory) object = &created_directories_after.at(relative);
                    else if (role == "operation_target" && spec.operation == "repair" && !relative.empty() && *relative.begin() == fs::path("backup"))
                        object = &original_files_after.at(relative.lexically_relative("backup"));
                    else if (role == "operation_target" && spec.operation == "uninstall" && relative == fs::path("operation.marker"))
                        object = &created_files_after.at(relative);
                    if (!object || object->removed || object->directory != directory)
                        throw std::runtime_error("native maintenance removal lost its exact original object");
                    if (object->native_identity != data.at("native_identity").as_string() || (!directory &&
                        (object->size != data.at("size_bytes").as_unsigned() || object->sha256 != data.at("sha256").as_string())))
                        throw std::runtime_error("native maintenance removal intent changed its original object/bytes");
                    object->removed = details.at("outcome").as_string() == "applied";
                }
            }
        }
        const auto require_absent = [&](const RestoredObject& object) {
            // Descendants of a confirmed removed parent are checked at that
            // nearest surviving parent's native child; never reopen through
            // an absent directory and adopt a same-path substitute.
            for (const auto& item : created_directories_after) if (item.second.removed &&
                object.path != item.second.path && object.path.lexically_relative(item.second.path).generic_u8string().rfind("..", 0) != 0)
                return;
            for (const auto& item : original_directories_after) if (item.second.removed &&
                object.path != item.second.path && object.path.lexically_relative(item.second.path).generic_u8string().rfind("..", 0) != 0)
                return;
            auto& parent = open_directory(object.path.parent_path());
            if (!equal(publisher_handle_observation_json(parent.facts), object.parent) || child(parent.handle.value, object.path.filename().wstring()))
                throw std::runtime_error("native maintenance confirmed removal no longer has its original absence");
        };
        const auto restore_directory = [&](const RestoredObject& object, const fs::path& key, bool creation) -> Entry* {
            if (object.removed) { require_absent(object); return nullptr; }
            auto& observed = open_directory(object.path);
            if (!equal(publisher_handle_observation_json(observed.facts), object.object) ||
                !equal(publisher_handle_observation_json(observed.parent ? observed.parent->facts : volume_facts), object.parent) ||
                (!object.native_identity.empty() && journal_identity(observed.handle.value) != object.native_identity))
                throw std::runtime_error("native maintenance restored directory differs from its original postimage");
            observed.restored_creation = creation;
            if (creation) {
                const auto actual_key = relative_volume_path(object.path);
                if (actual_key != key) {
                    auto node = directories.extract(actual_key); node.key() = key;
                    if (!directories.insert(std::move(node)).inserted)
                        throw std::runtime_error("native maintenance restored directory key conflicts");
                }
            }
            return &observed;
        };
        for (const auto& item : original_directories_after) {
            auto* entry = restore_directory(item.second, relative_volume_path(item.second.path), repaired_parent_creations.count(item.first) != 0u);
            if (entry) original_directories.emplace(item.first, entry);
        }
        original_root_identity = saved.original.at("installed_root_journal_identity").as_string();
        const auto& original_root = original_directories_after.at(fs::path{});
        if (original_root.removed) {
            if (spec.operation != "uninstall" || original_root.native_identity != original_root_identity)
                throw std::runtime_error("native maintenance original root removal differs from its saved custody");
            removed_original_root_parent = &open_directory(installed_path.parent_path());
            removed_original_root_name = installed_path.filename().wstring();
            if (!equal(publisher_handle_observation_json(removed_original_root_parent->facts), original_root.parent) ||
                child(removed_original_root_parent->handle.value, removed_original_root_name))
                throw std::runtime_error("native maintenance original root removal lost its held-parent absence");
        } else {
            installed_root = original_directories.at(fs::path{});
            if (journal_identity(installed_root->handle.value) != original_root_identity)
                throw std::runtime_error("native maintenance original installed root identity changed");
        }
        const auto staging_key = relative_volume_path(spec.staging_parent / (".usk-stage-" + spec.transaction_id));
        // Keep native-path keys while opening descendants. Re-key all creator
        // entries only after every parent has been independently opened.
        std::vector<std::pair<fs::path, fs::path>> created_keys;
        for (const auto& item : created_directories_after) {
            auto* entry = restore_directory(item.second, relative_volume_path(item.second.path), true);
            if (entry) {
                created_keys.emplace_back(relative_volume_path(item.second.path), item.first.empty() ? staging_key : staging_key / item.first);
                if (item.first.empty()) staging = entry;
            }
        }
        const auto restore_file = [&](const RestoredObject& object, bool creation, bool read_only = false) -> std::unique_ptr<Entry> {
            if (object.removed) { require_absent(object); return {}; }
            auto& parent = open_directory(object.path.parent_path());
            if (!equal(publisher_handle_observation_json(parent.facts), object.parent))
                throw std::runtime_error("native maintenance restored file changed its original parent");
            const auto listed = child(parent.handle.value, object.path.filename().wstring());
            if (!listed || (listed->attributes & FILE_ATTRIBUTE_DIRECTORY))
                throw std::runtime_error("native maintenance original surviving file is absent");
            auto entry = std::make_unique<Entry>();
            entry->directory = false; entry->parent = &parent; entry->name = object.path.filename().wstring();
            entry->handle.value = read_only ? open_publisher_listed_child(parent.handle.value, *listed) :
                open_publisher_listed_maintenance_file(parent.handle.value, *listed);
            entry->facts = facts(entry->handle.value, false); entry->size = object.size; entry->sha256 = object.sha256;
            entry->stream_identity = journal_identity(entry->handle.value);
            if (!equal(publisher_handle_observation_json(entry->facts), object.object) ||
                (!object.native_identity.empty() && entry->stream_identity != object.native_identity))
                throw std::runtime_error("native maintenance restored file differs from its original native postimage");
            require_bytes(*entry); entry->restored_creation = creation; entry->complete = true;
            return entry;
        };
        for (const auto& item : original_files_after) {
            auto entry = restore_file(item.second, false); if (entry) original_files.emplace(item.first, std::move(entry));
        }
        for (const auto& item : created_files_after) {
            auto entry = restore_file(item.second, true); if (entry) files.emplace(item.first, std::move(entry));
        }
        for (const auto& item : verification_files_after) {
            auto entry = restore_file(item.second, false, true);
            if (!entry || !verification_files.emplace(item.first, std::move(entry)).second)
                throw std::runtime_error("native repair verification custody is absent or repeated");
        }
        const auto require_original_absence = [&](const fs::path& relative, bool directory) {
            auto missing = relative;
            auto parent = original_directories_after.find(missing.parent_path());
            while (parent == original_directories_after.end() && !missing.parent_path().empty()) {
                missing = missing.parent_path();
                if (!absent_original_directories.count(missing))
                    throw std::runtime_error("native maintenance original absence crossed an unowned ancestor");
                parent = original_directories_after.find(missing.parent_path());
            }
            if (parent == original_directories_after.end())
                throw std::runtime_error("native maintenance original absence lacks retained parent custody");
            RestoredObject absent{Value{}, parent->second.object, installed_path / missing, missing != relative || directory};
            require_absent(absent);
        };
        for (const auto& relative : absent_original_files) {
            const auto replacement = created_files_after.find(fs::path("payload") / relative);
            if (replacement == created_files_after.end() || replacement->second.removed ||
                normalized(replacement->second.path) != normalized(installed_path / relative))
                require_original_absence(relative, false);
        }
        for (const auto& relative : absent_original_directories)
            if (!repaired_parent_creations.count(relative)) require_original_absence(relative, true);
        for (const auto& record : saved.records) if (record.at("kind").as_string() == "confirmed_effect") {
            const auto& data = record.at("details"); const auto sequence = data.at("intent_sequence").as_unsigned();
            const auto& effect = data.at("effect_kind").as_string();
            if (effect == "write_ownership" || effect == "write_installed" || effect == "append_audit") {
                const auto found = metadata_creations.find(sequence);
                if (found == metadata_creations.end()) throw std::runtime_error("native maintenance metadata outcome lacks its actual creator receipt");
                const auto& creation = *found->second; const auto& details = data.at("effect_details");
                const auto path = normalized(spec.state_root.parent_path() / owned_relative(creation.at("setup_relative_path").as_string()));
                const auto text = read_restoration_record(path, 4u * 1024u * 1024u);
                const auto& observed = *restoration_record_observers.back();
                if (observed.size != creation.at("size_bytes").as_unsigned() || observed.sha256 != creation.at("sha256").as_string() ||
                    !equal(publisher_handle_observation_json(observed.facts), creation.at("object")) ||
                    !equal(publisher_handle_observation_json(observed.parent->facts), creation.at("parent")))
                    throw std::runtime_error("native maintenance metadata postimage differs from its actual creator");
                const auto document = json::parse(text);
                if (effect == "write_installed") {
                    auto expected = snapshot.at("installed_state");
                    for (const auto* field : {"target_root", "ownership_manifest_ref", "ownership_manifest_digest", "transaction_id",
                            "created_at", "lifecycle_status", "last_verification"})
                        expected.as_object().at(field) = details.at("state_revision").at(field);
                    if (path != installed_record_path || !equal(expected, document) || json::canonical(document) + "\n" != text || installed_confirmed)
                        throw std::runtime_error("native maintenance installed postimage changed its original reviewed intent");
                    installed_postimage_bindings = derive_publisher_maintenance_postimage_bindings(snapshot, document);
                    installed_record_text = text; installed_record_sha256 = observed.sha256; installed_record_facts = observed.facts;
                    installed_parent = observed.parent;
                    RestoredObject restored{creation.at("object"), creation.at("parent"), path, false, false, observed.size, observed.sha256};
                    installed_postimage_file = restore_file(restored, true);
                    installed_prepared = true; installed_confirmed = true;
                } else if (effect == "write_ownership") {
                    if (path != normalized(spec.state_root / "ownership" / (details.at("manifest_id").as_string() + ".json")) ||
                        document.at("manifest_digest").as_string() != data.at("result_digest").as_string())
                        throw std::runtime_error("native maintenance ownership postimage changed its original intent");
                } else {
                    std::ostringstream name; name << std::setw(20) << std::setfill('0') << document.at("sequence").as_unsigned() << ".event.json";
                    if (path != normalized(spec.audit_root / "chains" / details.at("chain_id").as_string() / name.str()) ||
                        document.at("transaction_id").as_string() != spec.transaction_id ||
                        document.at("event_digest").as_string() != data.at("result_digest").as_string())
                        throw std::runtime_error("native maintenance audit postimage changed its original intent");
                }
            }
            auto outcome = std::make_unique<ConfirmedPayload>();
            outcome->transaction_sha256 = data.at("effect_transaction_snapshot_sha256").as_string();
            outcome->transaction_text = saved.snapshots.at(outcome->transaction_sha256);
            outcome->outcome = data.at("outcome").as_string();
            outcome->result_digest = data.at("result_digest").type() == Value::Type::null_value ? std::string{} : data.at("result_digest").as_string();
            outcome->confirmed = true;
            payload_outcomes.emplace(record.at("pending_history_sha256").as_string(), std::move(outcome));
            attempted_payload_histories.insert(record.at("pending_history_sha256").as_string());
        }
        for (const auto& item : created_keys) if (item.first != item.second) {
            auto node = directories.extract(item.first); node.key() = item.second;
            if (!directories.insert(std::move(node)).inserted)
                throw std::runtime_error("native maintenance restored creation key conflicts");
        }
        const auto selected = inspect_maintenance_continuation(spec);
        const auto current = transaction::TransactionSession::inspect_recovery(spec);
        if (selected.transaction_snapshot_sha256 != current.snapshot_sha256)
            throw std::runtime_error("native maintenance original complete prefix changed during restoration");
        original_admission_text = std::move(saved.original_text); original_admission_sha256 = raw_digest(original_admission_text);
        original_admission_path = spec.state_root / "transactions" / (spec.transaction_id + ".native-maintenance-original.json");
        native_custody_directory = spec.state_root / "transactions" / (spec.transaction_id + ".native-maintenance-custody");
        native_snapshot_directory = spec.state_root / "transactions" / (spec.transaction_id + ".native-maintenance-snapshots");
        native_custody_sequence = saved.records.size(); native_custody_bytes = saved.record_bytes; native_custody_digest = std::move(saved.last_digest);
        transaction_snapshot_bytes = saved.snapshot_bytes; transaction_snapshots = std::move(saved.snapshots);
        publication_transaction_sha256 = saved.created.at("transaction_snapshot_sha256").as_string();
        publication_transaction_text = transaction_snapshots.at(publication_transaction_sha256);
        original_source_context = saved.created.at("source_context").as_string();
        publication_attempted = true; publication_confirmed = true;
        admitted_lease_revision = installed_confirmed ? json::sha256_canonical(installed_postimage_bindings) : snapshot.at("initial_state_revision").as_string();
        lease.require_recovery_lineage(original_lease_ownership);
    }

    Impl(HANDLE boundary, const std::wstring& root, const std::wstring& service_label,
        const PublisherInstallOperationGuard& installation_guard,
        const PublisherMaintenanceStateSnapshot& state,
        const PublisherInstallOperationContext& context, const PublisherInstallationLease& active_lease,
        const RegisteredPublisherAdmission* registered, const PublisherRequestChannel* authenticated,
        PublisherEffectExecutionOwner* child_owner,
        const transaction::TransactionSpec& transaction_spec, HANDLE cancel, bool restore = false)
        : volume(boundary), volume_root(root), service_name(service_label), guard(installation_guard),
          original_state(state), original_context(context), lease(active_lease), admission(registered),
          channel(authenticated), original_child(child_owner), spec(transaction_spec), cancel_event(cancel) {
        if (original_child ? (admission || channel) : (!admission || !channel))
            throw std::runtime_error("native maintenance requires one concrete original execution owner");
        restored_owner = restore;
        const auto& snapshot = original_context.record().at("reviewed_snapshot");
        if (snapshot.at("schema").as_string() != "usk.publisher.maintenance_reviewed_snapshot.v2" ||
            !equal(selected_native_envelope().at("apply_request"), snapshot.at("apply_request")))
            throw std::runtime_error("native maintenance lacks its exact original reviewed request");
        const auto& plan = snapshot.at("reviewed_plan");
        if (spec.operation != snapshot.at("operation").as_string() ||
            spec.transaction_id != snapshot.at("operation_id").as_string() ||
            spec.plan_id != plan.at("plan_id").as_string() || spec.plan_digest != json::sha256_canonical(plan) ||
            normalized(spec.state_root) != normalized(fs::u8path(plan.at("state_root").as_string())) ||
            normalized(spec.audit_root) != normalized(fs::u8path(plan.at("audit_root").as_string())) ||
            normalized(spec.staging_parent) != normalized(fs::u8path(plan.at("staging_parent").as_string())) ||
            spec.required_commit_authority != transaction::CommitAuthorityRequirement::legacy_observed)
            throw std::runtime_error("native maintenance transaction differs from the original reviewed plan");
        const auto installed_root = normalized(fs::u8path(snapshot.at("installed_state").at("target_root").as_string()));
        const fs::path expected_target = spec.operation == "move" ? fs::u8path(plan.at("new_root").as_string()) :
            installed_root.parent_path() / ((spec.operation == "repair" ? ".usk-repair-" : ".usk-uninstall-") + spec.transaction_id);
        if ((spec.operation != "repair" && spec.operation != "move" && spec.operation != "uninstall") ||
            normalized(spec.target_root) != normalized(expected_target) ||
            normalized(spec.state_root.parent_path()).filename().u8string() != snapshot.at("setup_component").as_string())
            throw std::runtime_error("native maintenance operation target differs from its original action");
        if (restore) original_state.require_custody();
        else original_state.require_initial_revision();
        original_context.require_fence();
        lease.require_start();
        if (!equal(original_state.installed_state(), snapshot.at("installed_state")) ||
            !equal(original_state.ownership_manifest(), snapshot.at("ownership_manifest")) ||
            original_state.initial_state_revision() != snapshot.at("initial_state_revision").as_string() ||
            !equal(observe_publisher_lease_root_identity(volume), snapshot.at("volume_root_identity")) ||
            !equal(observe_publisher_lease_root_identity(original_state.setup_root()), snapshot.at("setup_root_identity")) ||
            !equal(observe_publisher_lease_root_identity(original_state.state_root()), snapshot.at("state_root_identity")))
            throw std::runtime_error("native maintenance borrowed state differs from its original native intent");
        const auto native_owner = original_child ? original_child->observe_current() :
            observe_current_publisher_native_execution_owner(service_name);
        service = native_owner.service;
        worker_context = native_owner.worker;
        if (service.service_name != service_name)
            throw std::runtime_error("native maintenance original service name changed");
        volume_facts = observe_publisher_directory_handle(volume);
        require_publisher_object_security_shape(volume_facts, service.service_sid);
        volume_observation = observe_local_ntfs_volume_handle(volume);
        registration = registered_native_evidence();
        selection = selected_native_observation();
        const auto& target = registration.at("target_identity").at("volume_identity");
        if (registration.at("service_name").as_string() != fs::path(service_name).u8string() ||
            registration.at("service_sid").as_string() != service.service_sid ||
            registration.at("process_id").as_unsigned() != service.process_id ||
            target.at("volume_root").as_string() != fs::path(volume_root).u8string() ||
            target.at("root_file_id").as_string() != volume_facts.file_id ||
            target.at("volume_serial").as_string() != std::to_string(volume_observation.file_id_volume_serial))
            throw std::runtime_error("native maintenance registration differs from its held volume/service");
        client = authenticated_native_access(volume).at("client");
        if (client.at("user_sid").as_string() != registration.at("configured_caller_sid").as_string())
            throw std::runtime_error("native maintenance authenticated caller differs from registration");
        if (original_child) {
            // Reuse the owner's original pinned native lifetime. Never settle
            // or construct a second baseline after intent/lease effects.
            original_broker = original_child->service_admission();
            const auto security = original_child->security().observe_current();
            process_boundary = security.at("process_boundary");
            worker = security.at("worker_security");
            if (!equal(lease.ownership().at("holder"), observe_publisher_lease_holder()))
                throw std::runtime_error("native maintenance lease does not belong to its actual child");
        } else {
            process_boundary = observe_current_publisher_process_boundary();
            worker = observe_settled_publisher_worker_security(service, cancel_event);
            worker_continuity = std::make_unique<PublisherWorkerSecurityContinuity>(worker);
        }
        require_publisher_process_boundary(process_boundary, worker_context.process_id,
            worker_context.service_sid, worker_context.token.process_groups);
        require_publisher_worker_security(worker, worker_context);
        descriptor = make_publisher_directory_security_descriptor(std::wstring(service.service_sid.begin(), service.service_sid.end()));
        // These are already admitted canonical protected parents. Bind only
        // this original operation's generated staging and repair/uninstall
        // roots to their actual native identities before observing those names.
        staging_parent = &open_directory(spec.staging_parent);
        target_parent = &open_directory(spec.target_root.parent_path());
        maintenance_names.reset(new PublisherMaintenanceNames(staging_parent->handle.value,
            target_parent->handle.value, spec.transaction_id, spec.operation));
        // Actual protected completion and immutable original public records
        // are proved before recognizing any payload read ACE. The private
        // engine and this owner supply the live native guard/lease; returned
        // JSON alone cannot construct this owner or authorize an effect.
        original_consumer_completion = observe_candidate_original_consumer_install(volume, volume_root, service_name,
            *maintenance_names);
        if (original_consumer_completion.at("install_id").as_string() != snapshot.at("install_id").as_string() ||
            normalized(fs::u8path(original_consumer_completion.at("setup_root").as_string())) != normalized(spec.state_root.parent_path()))
            throw std::runtime_error("native maintenance original consumer completion belongs to another install");
        original_consumer_sid = original_consumer_completion.at("consumer_read_sid").as_string();
        for (const auto& path : {installed_root, normalized(spec.target_root)}) {
            auto native = volume_facts.native_name;
            if (native.empty()) throw std::runtime_error("native maintenance volume name is absent");
            for (const auto& part : relative_volume_path(path)) {
                if (native.back() != L'\\') native += L'\\';
                native += part.wstring();
            }
            consumer_payload_roots.push_back(std::move(native));
        }
        retain_original_consumer_records();
        const auto setup_component = fs::u8path(snapshot.at("setup_component").as_string());
        if (relative_volume_path(spec.state_root) != setup_component / "state" ||
            relative_volume_path(spec.audit_root) != setup_component / "audit" ||
            (spec.operation != "move" && relative_volume_path(spec.staging_parent) != setup_component / "staging"))
            throw std::runtime_error("native maintenance metadata paths do not name the original held setup roots");
        installed_record_path = normalized(spec.state_root / "installed" /
            (snapshot.at("install_id").as_string() + "." + spec.transaction_id + ".json"));
        if (restore) restore_custody(read_restoration_custody());
        else { original_lease_ownership = lease.ownership(); admitted_lease_revision = snapshot.at("initial_state_revision").as_string(); }
        require_authority(spec);
        effect_fence = [this] { require_authority(spec); };
        operations.require_authority = [this](const auto& s) { require_authority(s); };
        operations.create_staging_root = [this](const auto& s, const auto& p) { create_staging(s, p); };
        operations.ensure_stream_parent = [this](const auto& s, const auto& p) { ensure_parent(s, p); };
        operations.open_stream = [this](const auto& s, const auto& p, auto size, const auto& sha) { return open_stream(s, p, size, sha); };
        operations.require_stream = [this](const auto& s, auto h) { require_stream(s, h); };
        operations.finish_stream = [this](const auto& s, auto h, const auto& id, auto size, const auto& sha) { finish_stream(s, h, id, size, sha); };
        operations.observe_commit_closure = [this](const auto& s, const auto& p, const auto& files) {
            return observe_created_closure(s, p, files);
        };
        operations.observe_file = [this](const auto& p) { return observe_owned_file(p); };
        operations.commit = [this](const auto& s, const auto& p, const auto& id, const auto& closure) { commit(s, p, id, closure); };
        operations.apply_effect = [this](const auto& s, const auto& history) { return apply_effect(s, history); };
        operations.confirm_effect_completion = [this](const auto& s, const auto& history,
            const auto& outcome, const auto& result_digest) {
            confirm_effect_completion(s, history, outcome, result_digest);
        };
        if (!restore) admit_original_payload();
        require_authority(spec);
        if (!restore) prepare_original_admission();
    }
    static fs::path normalized(const fs::path& path) { return fs::absolute(path).lexically_normal(); }
    static fs::path owned_relative(const std::string& value) {
        const auto relative = fs::u8path(value);
        if (value.empty() || value.size() > 4096u || relative.has_root_path())
            throw std::runtime_error("native maintenance owned path is not a bounded relative path");
        for (const auto& component : relative)
            if (!is_publisher_canonical_component(component.wstring()))
                throw std::runtime_error("native maintenance owned path contains an unsafe component");
        return relative;
    }
    fs::path relative_volume_path(const fs::path& path) const {
        const auto absolute = normalized(path);
        const auto drive = absolute.root_name().wstring() + L"\\";
        wchar_t mapped[128]{};
        if (drive.size() != 3 || drive[1] != L':' ||
            !GetVolumeNameForVolumeMountPointW(drive.c_str(), mapped, static_cast<DWORD>(std::size(mapped))) ||
            CompareStringOrdinal(mapped, -1, volume_root.c_str(), -1, TRUE) != CSTR_EQUAL)
            throw std::runtime_error("native maintenance public path lost its admitted volume mapping");
        auto native = volume_facts.native_name;
        for (const auto& component : absolute.relative_path()) {
            if (!native.empty() && native.back() != L'\\') native += L'\\';
            native += component.wstring();
            if (!is_publisher_canonical_component(component.wstring()) &&
                (!maintenance_names || !maintenance_names->allows_native_path(native)))
                throw std::runtime_error("native maintenance path has an unsafe component");
        }
        return absolute.relative_path();
    }
    Value registered_native_evidence() const {
        return original_child ? original_child->service_admission().at("registered_admission") : admission->evidence();
    }
    Value selected_native_envelope() const {
        if (original_child) {
            const auto selected = child_native_selection();
            if (!selected.at("present").as_boolean())
                throw std::runtime_error("native maintenance original child reviewed selection is absent");
            return selected.at("envelope");
        }
        if (!admission->has_selected_reviewed_operation())
            throw std::runtime_error("native maintenance original SCM reviewed selection is absent");
        return admission->selected_reviewed_envelope();
    }
    Value selected_native_observation() const {
        if (original_child) {
            const auto selected = child_native_selection();
            if (!selected.at("present").as_boolean())
                throw std::runtime_error("native maintenance original child reviewed selection is absent");
            return selected.at("observation");
        }
        return admission->selected_reviewed_operation_observation();
    }
    Value child_native_selection() const {
        if (!restored_owner) return original_child->selected_reviewed_operation();
        const auto selected = original_child->selected_original_maintenance_recovery();
        if (!selected.at("present").as_boolean())
            throw std::runtime_error("native maintenance original recovery enrollment is absent");
        // Every selected-operation fence independently compares the broker's
        // original proof with this child's actual guarded handles and bytes.
        original_context.require_original_recovery_intent_observation(selected.at("intent"));
        return selected;
    }
    Value authenticated_native_access(HANDLE handle) const {
        return original_child ? original_child->authenticated_object_access(handle) :
            channel->observe_authenticated_object_access(handle);
    }
    void require_client_read_only(HANDLE handle, const PublisherHandleObservation& facts) const {
        auto access = authenticated_native_access(handle);
        if (!equal(access.at("client"), client) || !equal(access.at("native_object"), publisher_handle_observation_json(facts)))
            throw std::runtime_error("native maintenance authenticated object binding changed");
        access.as_object().erase("client"); access.as_object().erase("native_object");
        access.as_object().emplace("client_sha256", Value(json::sha256_canonical(client)));
        access.as_object().emplace("native_object_sha256", Value(json::sha256_canonical(publisher_handle_observation_json(facts))));
        require_publisher_authenticated_object_access(access, client, publisher_handle_observation_json(facts));
        constexpr DWORD mutation = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD |
            FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER;
        for (const auto& [name, check] : access.at("checks").as_object())
            if (name == "maximum_allowed" ? (check.at("granted").as_unsigned() & mutation) != 0 :
                check.at("allowed").as_boolean() || check.at("granted").as_unsigned() != 0)
                throw std::runtime_error("native maintenance caller retains object mutation rights");
    }
    PublisherHandleObservation facts(HANDLE handle, bool directory) const {
        const auto observed = directory ? observe_publisher_directory_handle(handle) : observe_publisher_file_handle(handle);
        if (observed.dacl_aces.size() == 3u) {
            const bool payload = std::any_of(consumer_payload_roots.begin(), consumer_payload_roots.end(), [&](const auto& root) {
                return observed.native_name == root || (observed.native_name.size() > root.size() &&
                    observed.native_name.compare(0, root.size(), root) == 0 && observed.native_name[root.size()] == L'\\');
            });
            if (original_consumer_sid.empty() || !payload)
                throw std::runtime_error("native maintenance consumer ACE is outside its original approved payload");
            (void)publisher_consumer_read_object_projection(observed, service.service_sid, original_consumer_sid, true);
        } else require_publisher_object_security_shape(observed, service.service_sid);
        require_publisher_stream_shape(handle);
        observe_publisher_noninheritable_handle_flags(handle);
        if (observe_local_ntfs_volume_handle(handle).file_id_volume_serial != volume_observation.file_id_volume_serial)
            throw std::runtime_error("native maintenance object changed volume");
        require_client_read_only(handle, observed);
        return observed;
    }
    void require_entry(const Entry& entry) const {
        if (!same(facts(entry.handle.value, entry.directory), entry.facts))
            throw std::runtime_error("native maintenance retained object changed");
        const HANDLE parent = entry.parent ? entry.parent->handle.value : volume;
        if (entry.parent) require_entry(*entry.parent);
        const auto listed = child(parent, entry.name);
        if (!listed) throw std::runtime_error("native maintenance retained child is absent");
        Held independent;
        independent.value = open_publisher_listed_child(parent, *listed, false, false, false,
            false, false, maintenance_names.get());
        if (!same(facts(independent.value, entry.directory), entry.facts))
            throw std::runtime_error("native maintenance retained parent link changed");
    }
    Entry& open_directory(const fs::path& path) {
        fs::path key;
        Entry* parent = nullptr;
        for (const auto& part : relative_volume_path(path)) {
            key /= part;
            auto found = directories.find(key);
            if (found != directories.end()) { parent = found->second.get(); require_entry(*parent); continue; }
            auto entry = std::make_unique<Entry>();
            entry->parent = parent; entry->name = part.wstring();
            // Allocate the owner and map node before opening a native handle.
            auto inserted = directories.emplace(key, std::move(entry));
            auto& held = *inserted.first->second;
            const HANDLE parent_handle = parent ? parent->handle.value : volume;
            const auto listed = child(parent_handle, held.name);
            if (!listed || !(listed->attributes & FILE_ATTRIBUTE_DIRECTORY))
                throw std::runtime_error("native maintenance required protected directory is absent");
            held.handle.value = open_publisher_listed_child(parent_handle, *listed, true, false, true,
                false, false, maintenance_names.get());
            held.facts = facts(held.handle.value, true);
            require_entry(held); parent = &held;
        }
        if (!parent) throw std::runtime_error("native maintenance refuses using the volume as an operation parent");
        return *parent;
    }
    void require_authority(const transaction::TransactionSpec& supplied) const {
        if (supplied.transaction_id != spec.transaction_id || supplied.plan_id != spec.plan_id || supplied.plan_digest != spec.plan_digest ||
            supplied.operation != spec.operation || normalized(supplied.staging_parent) != normalized(spec.staging_parent) ||
            normalized(supplied.target_root) != normalized(spec.target_root) || normalized(supplied.state_root) != normalized(spec.state_root) ||
            normalized(supplied.audit_root) != normalized(spec.audit_root) || supplied.required_commit_authority != spec.required_commit_authority)
            throw std::runtime_error("native maintenance callback received a different transaction");
        if (GetCurrentProcessId() != worker_context.process_id || (cancel_event && WaitForSingleObject(cancel_event, 0) != WAIT_TIMEOUT))
            throw std::runtime_error("native maintenance worker stopped or changed");
        guard.require_owned(volume_root, original_context.record().at("install_id").as_string());
        original_context.require_fence(); original_state.require_custody(); lease.require_fence();
        const auto& ownership = lease.ownership();
        const auto& snapshot = original_context.record().at("reviewed_snapshot");
        transaction::require_install_lease_record(ownership);
        if (ownership.at("install_id").as_string() != snapshot.at("install_id").as_string() ||
            ownership.at("operation").as_string() != spec.operation ||
            ownership.at("operation_id").as_string() != spec.transaction_id ||
            ownership.at("operation_context_sha256").as_string() != original_context.lease_binding_sha256() ||
            ownership.at("expected_state_revision").as_string() != admitted_lease_revision ||
            !equal(ownership.at("state_root_identity"), snapshot.at("state_root_identity")))
            throw transaction::InstallLeaseStale();
        if (restored_owner) lease.require_recovery_lineage(original_lease_ownership);
        for (const auto& observer : restoration_record_observers) require_bytes(*observer);
        if (removed_original_root_parent) {
            require_entry(*removed_original_root_parent);
            if (child(removed_original_root_parent->handle.value, removed_original_root_name))
                throw std::runtime_error("native maintenance removed original root was replaced");
        }
        if (!same(observe_publisher_directory_handle(volume), volume_facts) ||
            !equal(registered_native_evidence(), registration) || !equal(selected_native_observation(), selection))
            throw std::runtime_error("native maintenance held registration or boundary changed");
        // This is bounded failure context from the already existing owner;
        // none of these values admits a thread or authorizes another effect.
        const auto failure_context = json::canonical(Value(Value::Object{
            {"schema", Value("usk.native_maintenance_security_failure_context.v1")},
            {"checkpoint", Value("require_authority")},
            {"operation", Value(spec.operation)}, {"transaction_id", Value(spec.transaction_id)},
            {"restored_owner", Value(restored_owner)},
            {"next_native_custody_sequence", Value(native_custody_sequence)},
            {"active_payload_transaction_sha256", Value(active_payload_transaction)},
            {"active_payload_history_sha256", Value(active_payload_history)},
            {"installed_prepared", Value(installed_prepared)},
            {"installed_issue_active", Value(installed_issue_active)},
            {"installed_confirmed", Value(installed_confirmed)}}));
        Value current_worker, current_process;
        if (original_child) {
            const auto current_broker = original_child->service_admission();
            if (!equal(publisher_effect_broker_immutable_record(current_broker),
                publisher_effect_broker_immutable_record(original_broker)))
                throw std::runtime_error("native maintenance original child broker changed");
            const auto security = original_child->security().observe_current(failure_context);
            current_worker = security.at("worker_security");
            current_process = security.at("process_boundary");
        } else {
            current_worker = worker_continuity->observe_current(failure_context);
            current_process = observe_current_publisher_process_boundary();
        }
        require_publisher_worker_security(current_worker, worker_context);
        require_publisher_process_boundary(current_process, worker_context.process_id,
            worker_context.service_sid, worker_context.token.process_groups);
        if (!equal(current_process, process_boundary))
            throw std::runtime_error("native maintenance frozen process boundary changed");
        if (installed_uncertain || payload_failed || custody_failed)
            throw std::runtime_error("native maintenance effect is uncertain; no further effects");
        if (!active_payload_history.empty()) {
            const auto current = transaction::TransactionSession::inspect_recovery(spec);
            const auto history = transaction::MaintenanceEffectJournal::inspect(spec, current.stream_source_digest);
            if (current.snapshot_sha256 != active_payload_transaction || history.journal_digest != active_payload_history)
                throw std::runtime_error("native maintenance original payload intent changed at its effect fence");
        }
        const auto current_bindings = observe_publisher_install_state_bindings(original_state.state_root(),
            original_context.record().at("install_id").as_string(), service.service_sid);
        const bool original_revision = equal(current_bindings, snapshot.at("installed_record_bindings"));
        const bool postimage_revision = installed_prepared && equal(current_bindings, installed_postimage_bindings);
        if (installed_confirmed ? !postimage_revision :
            (installed_issue_active ? (!original_revision && !postimage_revision) : !original_revision))
            throw transaction::InstallStateRevisionStale();
        require_installed_custody();
        (void)relative_volume_path(spec.state_root); (void)relative_volume_path(spec.target_root);
        require_client_read_only(volume, volume_facts);
        if (staging_parent) require_entry(*staging_parent);
        if (target_parent) require_entry(*target_parent);
    }
    void require_installed_custody() const {
        if (!installed_postimage_file || installed_postimage_file->handle.value == INVALID_HANDLE_VALUE) return;
        const auto observed = facts(installed_postimage_file->handle.value, false);
        const bool pending = same(observed, installed_postimage_file->facts);
        const bool published = same(observed, installed_record_facts);
        if (installed_confirmed ? !published : (installed_issue_active ? (!pending && !published) : !pending))
            throw std::runtime_error("native maintenance installed creation custody changed");
        if (installed_parent) require_entry(*installed_parent);
    }
    void require_installed_bytes() const {
        require_installed_custody();
        const HANDLE file = installed_postimage_file->handle.value;
        FILE_STANDARD_INFO size{}; FILE_BASIC_INFO first{}, last{};
        LARGE_INTEGER zero{};
        if (!GetFileInformationByHandleEx(file, FileStandardInfo, &size, sizeof(size)) ||
            size.EndOfFile.QuadPart < 0 || static_cast<std::uint64_t>(size.EndOfFile.QuadPart) != installed_record_text.size() ||
            !GetFileInformationByHandleEx(file, FileBasicInfo, &first, sizeof(first)) ||
            !SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
            throw std::runtime_error("native maintenance installed bytes are unavailable");
        base::Sha256 hash;
        std::array<unsigned char, 64u * 1024u> bytes{};
        std::size_t remaining = installed_record_text.size();
        while (remaining) {
            const DWORD wanted = static_cast<DWORD>(std::min(remaining, bytes.size()));
            DWORD count = 0;
            if (!ReadFile(file, bytes.data(), wanted, &count, nullptr) || count != wanted)
                throw std::runtime_error("native maintenance installed bytes changed");
            hash.update(bytes.data(), count); remaining -= count;
        }
        if (hash.finish() != installed_record_sha256 ||
            !GetFileInformationByHandleEx(file, FileBasicInfo, &last, sizeof(last)) ||
            first.LastWriteTime.QuadPart != last.LastWriteTime.QuadPart || first.ChangeTime.QuadPart != last.ChangeTime.QuadPart)
            throw std::runtime_error("native maintenance installed byte postimage changed");
        require_installed_custody();
    }
    std::optional<std::string> read_owned_record(const fs::path& path, std::size_t maximum) const {
        // Only this operation's exact published installed postimage is served.
        // Other records keep their ordinary no-mutation-sharing reader. Never
        // reopen this creator with weaker sharing or release its custody.
        if (normalized(path) != installed_record_path) return std::nullopt;
        require_authority(spec);
        if (!installed_confirmed || !installed_postimage_file || !installed_postimage_file->complete ||
            installed_record_text.size() > maximum)
            throw std::runtime_error("native maintenance record read lacks a confirmed bounded installed postimage");
        require_installed_bytes();
        const HANDLE file = installed_postimage_file->handle.value;
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
            throw std::runtime_error("native maintenance installed record position unavailable");
        std::string text(installed_record_text.size(), '\0');
        std::size_t offset = 0;
        while (offset != text.size()) {
            const auto wanted = static_cast<DWORD>(std::min<std::size_t>(64u * 1024u, text.size() - offset));
            DWORD count = 0;
            if (!ReadFile(file, text.data() + offset, wanted, &count, nullptr) || count != wanted)
                throw std::runtime_error("native maintenance installed record read changed");
            offset += count;
        }
        if (text != installed_record_text)
            throw std::runtime_error("native maintenance installed record differs from its original confirmed bytes");
        require_installed_bytes(); require_authority(spec);
        return text;
    }
    void metadata_prepare(const fs::path& path, const std::string& text) {
        require_authority(spec);
        if (normalized(path).parent_path() != installed_record_path.parent_path()) return;
        if (normalized(path) != installed_record_path || installed_prepared || !publication_confirmed)
            throw std::runtime_error("native maintenance refuses an unrelated or repeated installed publication");
        const auto tx = transaction::TransactionSession::inspect_recovery(spec);
        const auto history = transaction::MaintenanceEffectJournal::inspect(spec, tx.stream_source_digest, true);
        const auto& snapshot = original_context.record().at("reviewed_snapshot");
        const auto source = json::parse(history.source_context);
        const auto artifact = read_maintenance_reviewed_plan(spec);
        const auto next = inspect_maintenance_continuation(spec);
        if (tx.stream_source_context != history.source_context || history.pending_kind != "write_installed" ||
            !next.pending || next.next_kind != "write_installed" || next.history_digest != history.journal_digest ||
            !equal(artifact.at("reviewed_plan"), snapshot.at("reviewed_plan")) ||
            source.at("install_id").as_string() != snapshot.at("install_id").as_string() ||
            source.at("original_installed_transaction_id").as_string() != snapshot.at("installed_state").at("transaction_id").as_string() ||
            source.at("original_installed_state_digest").as_string() != snapshot.at("reviewed_plan").at("installed_state_digest").as_string() ||
            source.at("ownership_manifest_digest").as_string() != snapshot.at("ownership_manifest").at("manifest_digest").as_string() ||
            source.at("applied_at").as_string() != snapshot.at("apply_request").at("applied_at").as_string())
            throw std::runtime_error("native maintenance installed publication lost its original pending effect");
        const auto expected = maintenance_installed_postimage(spec, history);
        if (state::serialize_installed_state(expected) != text)
            throw std::runtime_error("native maintenance installed bytes differ from the original reviewed postimage");
        auto bindings = derive_publisher_maintenance_postimage_bindings(snapshot, json::parse(text));
        auto owner = std::make_unique<Entry>(); // Allocate custody before the writer's native create.
        owner->directory = false; owner->created = true;
        installed_parent = &open_directory(installed_record_path.parent_path());
        prepared_record_path = path;
        installed_record_text = text;
        base::Sha256 hash; hash.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
        installed_record_sha256 = hash.finish();
        prepared_transaction_sha256 = tx.snapshot_sha256; prepared_history_sha256 = history.journal_digest;
        installed_postimage_bindings = std::move(bindings);
        installed_postimage_file = std::move(owner);
        installed_prepared = true;
        require_authority(spec);
    }
    bool metadata_created(const fs::path& path, const std::string& text, HANDLE file) {
        require_authority(spec);
        if (normalized(path).parent_path() != installed_record_path.parent_path()) return false;
        if (!installed_prepared || path != prepared_record_path || text != installed_record_text ||
            installed_postimage_file->handle.value != INVALID_HANDLE_VALUE)
            throw std::runtime_error("native maintenance installed creation differs from its prepared effect");
        auto observed = facts(file, false);
        installed_record_facts = observed;
        installed_record_facts.native_name = installed_parent->facts.native_name + L"\\" + installed_record_path.filename().wstring();
        installed_postimage_file->facts = std::move(observed);
        // Transfer only at the last nonthrowing step. The writer immediately
        // releases its local owner and then borrows this exact created handle.
        installed_postimage_file->handle.value = file;
        return true;
    }
    void metadata_before_issue(const fs::path& path, const std::string& text) {
        require_authority(spec);
        if (normalized(path).parent_path() != installed_record_path.parent_path()) return;
        if (path != prepared_record_path || text != installed_record_text || installed_issue_active || installed_confirmed)
            throw std::runtime_error("native maintenance installed publication cannot be retried");
        const auto tx = transaction::TransactionSession::inspect_recovery(spec);
        const auto history = transaction::MaintenanceEffectJournal::inspect(spec, tx.stream_source_digest);
        if (tx.snapshot_sha256 != prepared_transaction_sha256 || history.journal_digest != prepared_history_sha256 ||
            history.pending_kind != "write_installed")
            throw std::runtime_error("native maintenance original pending installed effect changed before publication");
        require_installed_bytes();
        require_authority(spec);
        installed_issue_active = true; // Last step before the writer's actual native call.
    }
    void metadata_confirm(const fs::path& path, const std::string& text, HANDLE file) {
        require_authority(spec);
        if (normalized(path).parent_path() != installed_record_path.parent_path()) {
            if (active_payload_history.empty()) return;
            const auto tx = transaction::TransactionSession::inspect_recovery(spec);
            const auto history = transaction::MaintenanceEffectJournal::inspect(spec, tx.stream_source_digest);
            const auto& details = history.pending_details;
            bool selected = false;
            if (history.pending_kind == "write_ownership") selected = normalized(path) ==
                normalized(spec.state_root / "ownership" / (details.at("manifest_id").as_string() + ".json"));
            else if (history.pending_kind == "append_audit" &&
                normalized(path).parent_path() == normalized(spec.audit_root / "chains" /
                    details.at("chain_id").as_string())) {
                const auto document = json::parse(text);
                std::ostringstream name;
                name << std::setw(20) << std::setfill('0') << document.at("sequence").as_unsigned() << ".event.json";
                if (path.filename().u8string() != name.str() ||
                    document.at("audit_chain_id").as_string() != details.at("chain_id").as_string() ||
                    document.at("transaction_id").as_string() != spec.transaction_id)
                    throw std::runtime_error("native maintenance audit creation differs from its actual selected append");
                selected = true;
            }
            if (selected) {
                (void)require_pending(history.pending_kind);
                persist_metadata_creation(path, text, file);
            }
            return;
        }
        if (!installed_issue_active || installed_confirmed || path != prepared_record_path || text != installed_record_text ||
            file != installed_postimage_file->handle.value ||
            !same(observe_publisher_file_handle(file), installed_record_facts))
            throw std::runtime_error("native maintenance installed publication is unconfirmed");
        require_installed_bytes();
        const auto listed = child(installed_parent->handle.value, installed_record_path.filename().wstring());
        if (!listed) throw std::runtime_error("native maintenance published installed child is absent");
        Held linked;
        linked.value = open_publisher_listed_child(installed_parent->handle.value, *listed);
        if (!same(facts(linked.value, false), installed_record_facts) ||
            !equal(observe_publisher_install_state_bindings(original_state.state_root(),
                original_context.record().at("install_id").as_string(), service.service_sid), installed_postimage_bindings))
            throw std::runtime_error("native maintenance installed revision lacks its exact native postimage");
        installed_confirmed = true; installed_issue_active = false; installed_postimage_file->complete = true;
        require_authority(spec);
        persist_metadata_creation(path, text, file);
    }
    void persist_metadata_creation(const fs::path& path, const std::string& text, HANDLE file) {
        // This callback receives the protected writer's actual new handle
        // after confirmed no-replace publication and before writer disposal.
        // Reopened child handles below are observers, never labelled creations.
        const auto object = facts(file, false);
        auto& parent = open_directory(path.parent_path());
        const auto listed = child(parent.handle.value, path.filename().wstring());
        if (!listed) throw std::runtime_error("native maintenance metadata creation lost its parent link");
        Held linked;
        linked.value = open_publisher_listed_child(parent.handle.value, *listed);
        if (!same(facts(linked.value, false), object))
            throw std::runtime_error("native maintenance metadata creation differs from its published child");
        FILE_STANDARD_INFO size{}; FILE_BASIC_INFO first{}, last{}; LARGE_INTEGER zero{};
        if (!GetFileInformationByHandleEx(file, FileStandardInfo, &size, sizeof(size)) ||
            size.DeletePending || size.Directory || size.EndOfFile.QuadPart < 0 ||
            static_cast<std::uint64_t>(size.EndOfFile.QuadPart) != text.size() ||
            !GetFileInformationByHandleEx(file, FileBasicInfo, &first, sizeof(first)) ||
            !SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
            throw std::runtime_error("native maintenance metadata creation bytes are unavailable");
        base::Sha256 actual, expected;
        expected.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
        const auto expected_sha256 = expected.finish();
        std::array<unsigned char, 64u * 1024u> bytes{}; std::size_t remaining = text.size();
        while (remaining) {
            const auto wanted = static_cast<DWORD>(std::min(remaining, bytes.size())); DWORD count = 0;
            if (!ReadFile(file, bytes.data(), wanted, &count, nullptr) || count != wanted)
                throw std::runtime_error("native maintenance metadata creation read changed");
            actual.update(bytes.data(), count); remaining -= count;
        }
        if (actual.finish() != expected_sha256 ||
            !GetFileInformationByHandleEx(file, FileBasicInfo, &last, sizeof(last)) ||
            first.LastWriteTime.QuadPart != last.LastWriteTime.QuadPart ||
            first.ChangeTime.QuadPart != last.ChangeTime.QuadPart || !same(facts(file, false), object))
            throw std::runtime_error("native maintenance metadata creation postimage changed");
        require_entry(parent); require_authority(spec);
        persist_native_custody("created_metadata", Value(Value::Object{
            {"setup_relative_path", Value(normalized(path).lexically_relative(normalized(spec.state_root.parent_path())).generic_u8string())},
            {"object", publisher_handle_observation_json(object)}, {"parent", publisher_handle_observation_json(parent.facts)},
            {"size_bytes", Value(static_cast<std::uint64_t>(text.size()))}, {"sha256", Value(expected_sha256)}}));
        require_entry(parent); require_authority(spec);
    }
    void metadata_failed(const fs::path& path) noexcept {
        if (installed_prepared && path == prepared_record_path && installed_issue_active) {
            installed_uncertain = true; installed_issue_active = false;
        }
    }
    fs::path staging_relative(const fs::path& path) const {
        const auto root = normalized(spec.staging_parent / (".usk-stage-" + spec.transaction_id));
        const auto relative = normalized(path).lexically_relative(root);
        if (relative.empty()) throw std::runtime_error("native maintenance stream escaped staging");
        if (relative != fs::path(".")) for (const auto& component : relative)
            if (!is_publisher_canonical_component(component.wstring())) throw std::runtime_error("native maintenance stream component refused");
        return relative;
    }
    void use_directory_parent_observer(Entry& entry) {
        if (!entry.directory || !entry.parent || (!entry.created && !entry.restored_creation))
            throw std::runtime_error("native maintenance parent observer lacks original directory custody");
        try {
            require_authority(spec); require_entry(entry);
            const auto listed = child(entry.parent->handle.value, entry.name);
            if (!listed) throw std::runtime_error("native maintenance directory observer child is absent");
            Held replacement;
            replacement.value = open_publisher_listed_child(entry.parent->handle.value, *listed,
                true, false, true, false, false, maintenance_names.get());
            const auto access = observe_publisher_handle_granted_access(replacement.value);
            if (!same(facts(replacement.value, true), entry.facts) ||
                (access & DELETE) || (access & (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY)) !=
                    (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY))
                throw std::runtime_error("native maintenance directory parent observer changed identity/access");
            // Open before closing: the exact root/object remains held across
            // this transition, while its later destination role has no DELETE.
            require_entry(entry); require_authority(spec);
            entry.handle.close_observer_once();
            entry.handle.adopt_after_confirmed_close(replacement);
            entry.reopened_observer = true;
            require_entry(entry); require_authority(spec);
        } catch (...) { custody_failed = true; throw; }
    }
    void reopen_created_descendant(Entry& entry, const std::string& native_identity) {
        if (!entry.created || !entry.parent || entry.handle.value != INVALID_HANDLE_VALUE)
            throw std::runtime_error("native maintenance descendant observer lacks its released creator");
        require_entry(*entry.parent); require_authority(spec);
        const auto listed = child(entry.parent->handle.value, entry.name);
        if (!listed) throw std::runtime_error("native maintenance original created descendant is absent");
        Held replacement;
        replacement.value = entry.directory ? open_publisher_listed_child(entry.parent->handle.value, *listed,
            true, false, true, false, false, maintenance_names.get()) :
            open_publisher_listed_maintenance_file(entry.parent->handle.value, *listed);
        if (!same(facts(replacement.value, entry.directory), entry.facts) ||
            journal_identity(replacement.value) != native_identity ||
            (entry.directory && (observe_publisher_handle_granted_access(replacement.value) & DELETE)))
            throw std::runtime_error("native maintenance descendant observer changed original identity/facts");
        entry.handle.adopt_after_confirmed_close(replacement);
        entry.reopened_observer = true;
        if (entry.directory) require_entry(entry); else require_bytes(entry);
        require_authority(spec);
    }
    Entry& create_directory(Entry& parent, const fs::path& relative, const std::wstring& name) {
        require_entry(parent);
        const auto key = relative_volume_path(spec.staging_parent / (".usk-stage-" + spec.transaction_id)) / relative;
        if (directories.count(key) || child(parent.handle.value, name)) throw std::runtime_error("native maintenance create-only directory exists");
        auto entry = std::make_unique<Entry>(); entry->parent = &parent; entry->name = name; entry->created = true;
        auto inserted = directories.emplace(key.lexically_normal(), std::move(entry));
        auto& held = *inserted.first->second;
        held.handle.value = create_staged_directory_relative_with_descriptor(parent.handle.value, name, descriptor,
            maintenance_names.get());
        held.facts = facts(held.handle.value, true); require_entry(held);
        if (publication_confirmed) {
            try {
                persist_native_custody("later_created_directory", Value(Value::Object{
                    {"relative_path", Value(relative.generic_u8string())},
                    {"object", publisher_handle_observation_json(held.facts)},
                    {"parent", publisher_handle_observation_json(parent.facts)},
                    {"native_identity", Value(journal_identity(held.handle.value))}}));
            } catch (...) { custody_failed = true; throw; }
            use_directory_parent_observer(held);
        }
        return held;
    }
    void create_staging(const transaction::TransactionSpec& s, const fs::path& path) {
        require_authority(s);
        if (staging || publication_attempted || staging_relative(path) != fs::path("."))
            throw std::runtime_error("native maintenance staging creation is not the original root");
        staging = &create_directory(*staging_parent, {}, path.filename().wstring());
        require_authority(s);
    }
    void ensure_parent(const transaction::TransactionSpec& s, const fs::path& path) {
        require_authority(s);
        if (!staging || publication_attempted) throw std::runtime_error("native maintenance staging parent unavailable");
        Entry* parent = staging;
        fs::path relative;
        for (const auto& part : staging_relative(path)) {
            if (part == fs::path(".")) continue;
            relative /= part;
            const auto key = (relative_volume_path(spec.staging_parent / (".usk-stage-" + spec.transaction_id)) / relative).lexically_normal();
            const auto found = directories.find(key);
            parent = found == directories.end() ? &create_directory(*parent, relative, part.wstring()) : found->second.get();
            require_entry(*parent);
        }
        require_authority(s);
    }
    std::intptr_t open_stream(const transaction::TransactionSpec& s, const fs::path& path, std::uint64_t size, const std::string& sha) {
        require_authority(s);
        const auto relative = staging_relative(path);
        if (!staging || publication_attempted || relative == fs::path(".") || files.count(relative) ||
            files.size() >= 100000u || sha.size() != 64 || sha.find_first_not_of("0123456789abcdef") != std::string::npos)
            throw std::runtime_error("native maintenance stream is not a new staged file");
        const auto parent_key = (relative_volume_path(spec.staging_parent / (".usk-stage-" + spec.transaction_id)) / relative.parent_path()).lexically_normal();
        const auto found = directories.find(parent_key);
        if (found == directories.end()) throw std::runtime_error("native maintenance stream parent lacks creation custody");
        auto entry = std::make_unique<Entry>();
        entry->parent = found->second.get(); entry->name = path.filename().wstring(); entry->directory = false;
        entry->created = true; entry->size = size; entry->sha256 = sha;
        auto inserted = files.emplace(relative, std::move(entry)); auto& held = *inserted.first->second;
        require_entry(*held.parent);
        held.handle.value = create_file_relative_with_descriptor(held.parent->handle.value, held.name, descriptor);
        held.facts = facts(held.handle.value, false);
        held.stream_identity = transaction::stream_output_identity(reinterpret_cast<std::intptr_t>(held.handle.value));
        require_entry(held); require_authority(s);
        return reinterpret_cast<std::intptr_t>(held.handle.value);
    }
    Entry& stream(std::intptr_t handle) const {
        for (const auto& item : files) if (reinterpret_cast<std::intptr_t>(item.second->handle.value) == handle) return *item.second;
        throw std::runtime_error("native maintenance stream handle is outside engine custody");
    }
    void require_stream(const transaction::TransactionSpec& s, std::intptr_t handle) const {
        require_authority(s); const auto& entry = stream(handle);
        if (publication_attempted || !entry.created || entry.directory || entry.reopened_observer)
            throw std::runtime_error("native maintenance stream is unavailable for staging");
        require_entry(entry);
        if (transaction::stream_output_identity(handle) != entry.stream_identity)
            throw std::runtime_error("native maintenance stream creation identity changed");
    }
    void require_bytes(const Entry& entry) const {
        require_entry(entry);
        FILE_STANDARD_INFO before{}, after{}; FILE_BASIC_INFO first{}, last{};
        LARGE_INTEGER zero{};
        if (!GetFileInformationByHandleEx(entry.handle.value, FileStandardInfo, &before, sizeof(before)) ||
            !GetFileInformationByHandleEx(entry.handle.value, FileBasicInfo, &first, sizeof(first)) || before.DeletePending ||
            before.Directory || before.EndOfFile.QuadPart < 0 || static_cast<std::uint64_t>(before.EndOfFile.QuadPart) != entry.size ||
            !SetFilePointerEx(entry.handle.value, zero, nullptr, FILE_BEGIN)) throw std::runtime_error("native maintenance held stream size/position changed");
        base::Sha256 hash; std::array<unsigned char, 64u * 1024u> buffer{}; std::uint64_t consumed = 0;
        while (consumed < entry.size) {
            const auto requested = static_cast<DWORD>(std::min<std::uint64_t>(buffer.size(), entry.size - consumed)); DWORD read = 0;
            if (!ReadFile(entry.handle.value, buffer.data(), requested, &read, nullptr) || !read || read > requested)
                throw std::runtime_error("native maintenance held stream read unavailable");
            hash.update(buffer.data(), read); consumed += read;
        }
        if (hash.finish() != entry.sha256 || !GetFileInformationByHandleEx(entry.handle.value, FileStandardInfo, &after, sizeof(after)) ||
            !GetFileInformationByHandleEx(entry.handle.value, FileBasicInfo, &last, sizeof(last)) || after.DeletePending ||
            after.EndOfFile.QuadPart != before.EndOfFile.QuadPart || last.LastWriteTime.QuadPart != first.LastWriteTime.QuadPart ||
            last.ChangeTime.QuadPart != first.ChangeTime.QuadPart) throw std::runtime_error("native maintenance held stream bytes changed");
        require_entry(entry);
    }
    void finish_stream(const transaction::TransactionSpec& s, std::intptr_t handle, const std::string& id, std::uint64_t size, const std::string& sha) {
        require_stream(s, handle); auto& entry = stream(handle);
        if (entry.complete || id != entry.stream_identity || size != entry.size || sha != entry.sha256)
            throw std::runtime_error("native maintenance stream completion differs from its reviewed creation");
        require_bytes(entry);
        // NTFS may reserve more clusters while this original writer is open
        // and release them on its last close. Finalize that owned allocation
        // before sealing, so the exact stream facts survive publication's
        // required descendant release. Never relax the phase comparison.
        FILE_ALLOCATION_INFO allocation{};
        allocation.AllocationSize.QuadPart = static_cast<LONGLONG>(entry.size);
        if (!SetFileInformationByHandle(entry.handle.value, FileAllocationInfo, &allocation, sizeof(allocation)) ||
            !FlushFileBuffers(entry.handle.value))
            throw std::runtime_error("native maintenance stream allocation/flush was not confirmed");
        require_bytes(entry); entry.complete = true; require_authority(s);
    }
    std::map<fs::path, const Value*> repair_verification_manifest() const {
        std::map<fs::path, const Value*> result;
        if (spec.operation != "repair") return result;
        const auto& snapshot = original_context.record().at("reviewed_snapshot");
        const auto& owned = snapshot.at("ownership_manifest").at("files").as_array();
        const auto& replacements = snapshot.at("reviewed_plan").at("replacement_files").as_array();
        if (owned.size() > 100000u || replacements.size() > 100000u)
            throw std::runtime_error("native repair verification closure exceeds its finite bound");
        for (const auto& file : owned)
            if (!result.emplace(owned_relative(file.at("relative_path").as_string()), &file).second)
                throw std::runtime_error("native repair owned verification path repeated");
        for (const auto& file : replacements)
            if (result.erase(owned_relative(file.at("relative_path").as_string())) != 1u)
                throw std::runtime_error("native repair replacement is outside its exact owned closure");
        return result;
    }
    void admit_original_file_bytes(Entry& held, std::uint64_t& logical_bytes) {
        FILE_STANDARD_INFO standard{};
        if (!GetFileInformationByHandleEx(held.handle.value, FileStandardInfo, &standard, sizeof(standard)) ||
            standard.DeletePending || standard.Directory || standard.EndOfFile.QuadPart < 0 ||
            static_cast<std::uint64_t>(standard.EndOfFile.QuadPart) > (1ull << 32) ||
            static_cast<std::uint64_t>(standard.EndOfFile.QuadPart) > (1ull << 34) - logical_bytes)
            throw std::runtime_error("native maintenance original owned bytes exceed observation bounds");
        held.size = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart); logical_bytes += held.size;
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(held.handle.value, zero, nullptr, FILE_BEGIN))
            throw std::runtime_error("native maintenance original file position unavailable");
        base::Sha256 hash; std::array<unsigned char, 64u * 1024u> bytes{}; std::uint64_t consumed = 0;
        while (consumed < held.size) {
            DWORD count = 0;
            const DWORD wanted = static_cast<DWORD>(std::min<std::uint64_t>(bytes.size(), held.size - consumed));
            if (!ReadFile(held.handle.value, bytes.data(), wanted, &count, nullptr) || count != wanted)
                throw std::runtime_error("native maintenance original owned file read changed");
            hash.update(bytes.data(), count); consumed += count;
        }
        held.sha256 = hash.finish(); held.stream_identity = journal_identity(held.handle.value);
        require_bytes(held);
    }
    void admit_original_payload() {
        const auto& snapshot = original_context.record().at("reviewed_snapshot");
        const auto root = fs::u8path(snapshot.at("installed_state").at("target_root").as_string());
        installed_root = &open_directory(root);
        original_root_identity = journal_identity(installed_root->handle.value);
        original_directories.emplace(fs::path{}, installed_root);
        if (spec.operation == "move") return; // Original root retained; staging owns the new closure.
        const auto& ownership = snapshot.at("ownership_manifest");
        const auto& planned_files = spec.operation == "repair" ?
            snapshot.at("reviewed_plan").at("replacement_files") : ownership.at("files");
        if (planned_files.as_array().size() > 100000u || ownership.at("directories").as_array().size() > 100000u)
            throw std::runtime_error("native maintenance original custody exceeds its finite closure bound");
        std::set<fs::path> owned_directories;
        for (const auto& value : ownership.at("directories").as_array())
            if (!owned_directories.insert(owned_relative(value.at("relative_path").as_string())).second)
                throw std::runtime_error("native maintenance original owned directory repeated");
        // Parents sort before their descendants. Absence is observed through
        // the nearest retained original parent; it never grants adoption.
        for (const auto& relative : owned_directories) {
            const auto parent = original_directories.find(relative.parent_path());
            if (parent == original_directories.end()) {
                if (!absent_original_directories.count(relative.parent_path()))
                    throw std::runtime_error("native maintenance original directory lacks an owned ancestor");
                absent_original_directories.insert(relative); continue;
            }
            require_entry(*parent->second);
            const auto listed = child(parent->second->handle.value, relative.filename().wstring());
            if (!listed) { absent_original_directories.insert(relative); continue; }
            if (!(listed->attributes & FILE_ATTRIBUTE_DIRECTORY))
                throw std::runtime_error("native maintenance original owned directory changed type");
            original_directories.emplace(relative, &open_directory(root / relative));
        }
        std::uint64_t logical_bytes = 0;
        for (const auto& file : planned_files.as_array()) {
            const auto relative = owned_relative(file.at("relative_path").as_string());
            const auto original_parent = original_directories.find(relative.parent_path());
            if (original_parent == original_directories.end()) {
                if (!absent_original_directories.count(relative.parent_path()))
                    throw std::runtime_error("native maintenance original file lacks an owned ancestor");
                absent_original_files.insert(relative); continue;
            }
            auto& parent = *original_parent->second;
            const auto listed = child(parent.handle.value, relative.filename().wstring());
            if (!listed) { absent_original_files.insert(relative); continue; }
            if (listed->attributes & FILE_ATTRIBUTE_DIRECTORY)
                throw std::runtime_error("native maintenance original owned file changed type");
            auto entry = std::make_unique<Entry>();
            entry->parent = &parent; entry->name = relative.filename().wstring(); entry->directory = false;
            auto inserted = original_files.emplace(relative, std::move(entry));
            if (!inserted.second) throw std::runtime_error("native maintenance original owned file repeated");
            auto& held = *inserted.first->second;
            held.handle.value = open_publisher_listed_maintenance_file(parent.handle.value, *listed);
            held.facts = facts(held.handle.value, false);
            admit_original_file_bytes(held, logical_bytes);
        }
        for (const auto& item : repair_verification_manifest()) {
            const auto& relative = item.first;
            const auto original_parent = original_directories.find(relative.parent_path());
            if (original_parent == original_directories.end())
                throw std::runtime_error("native repair healthy file lacks its retained original parent");
            auto& parent = *original_parent->second;
            require_entry(parent);
            const auto listed = child(parent.handle.value, relative.filename().wstring());
            if (!listed || (listed->attributes & FILE_ATTRIBUTE_DIRECTORY))
                throw std::runtime_error("native repair healthy owned file is absent or changed type");
            auto entry = std::make_unique<Entry>();
            entry->parent = &parent; entry->name = relative.filename().wstring(); entry->directory = false;
            auto inserted = verification_files.emplace(relative, std::move(entry));
            if (!inserted.second) throw std::runtime_error("native repair healthy owned file repeated");
            auto& held = *inserted.first->second;
            held.handle.value = open_publisher_listed_child(parent.handle.value, *listed);
            held.facts = facts(held.handle.value, false);
            admit_original_file_bytes(held, logical_bytes);
            if (held.size != item.second->at("size_bytes").as_unsigned() ||
                held.sha256 != item.second->at("sha256").as_string())
                throw std::runtime_error("native repair healthy owned bytes differ from the original manifest");
        }
    }
    void retain_original_consumer_records() {
        const auto publication = spec.target_root.root_path() / "publication";
        for (const auto& record : std::vector<std::pair<fs::path, std::string>>{
            {publication / "journal" / "lab-prepared-evidence.json", "prepared_record_sha256"},
            {publication / "journal" / "lab-reviewed-plan.json", "reviewed_snapshot_sha256"},
            {publication / "journal" / "lab-visible-evidence.json", "visible_record_sha256"},
            {publication / "state" / "lab-installed-state.json", "completion_record_sha256"}}) {
            const auto text = read_restoration_record(record.first, 4u * 1024u * 1024u);
            if (raw_digest(text) != original_consumer_completion.at(record.second).as_string())
                throw std::runtime_error("native maintenance protected original consumer record changed");
        }
    }
    void prepare_original_admission() {
        require_authority(spec);
        constexpr std::size_t maximum = 16u * 1024u * 1024u;
        original_admission_path = spec.state_root / "transactions" /
            (spec.transaction_id + ".native-maintenance-original.json");
        base::require_native_path_capacity(original_admission_path, base::NativePathKind::file,
            "native maintenance original custody");
        Value document(Value::Object{{"schema", Value(original_child ?
                "usk.publisher.maintenance_original_custody.v4" : "usk.publisher.maintenance_original_custody.v2")},
            {"transaction_id", Value(spec.transaction_id)}, {"operation", Value(spec.operation)},
            {"plan_digest", Value(spec.plan_digest)},
            {"original_context_sha256", Value(original_context.lease_binding_sha256())},
            {"original_lease_ownership", lease.ownership()}, {"worker_security", worker},
            {"process_boundary", process_boundary}, {"registration_sha256", Value(json::sha256_canonical(registration))},
            {"authenticated_client", client}, {"original_consumer_completion", original_consumer_completion},
            {"installed_root", publisher_handle_observation_json(installed_root->facts)},
            {"installed_root_journal_identity", Value(original_root_identity)}});
        if (original_child) document.as_object().emplace("broker_readback", original_broker);
        std::size_t charged = json::canonical(document).size() + 128u;
        Value::Array objects;
        const auto append = [&](Value object) {
            const auto bytes = json::canonical(object).size() + 1u;
            if (charged > maximum || bytes > maximum - charged)
                throw std::runtime_error("native maintenance original custody exceeds its durable bound");
            charged += bytes; objects.push_back(std::move(object));
        };
        const auto append_files = [&](const auto& entries) {
            for (const auto& item : entries) {
                const auto& file = *item.second; require_bytes(file);
                append(Value(Value::Object{{"relative_path", Value(item.first.generic_u8string())},
                    {"type", Value("file")}, {"present", Value(true)},
                    {"object", publisher_handle_observation_json(file.facts)},
                    {"parent", publisher_handle_observation_json(file.parent->facts)},
                    {"native_identity", Value(file.stream_identity)},
                    {"size_bytes", Value(file.size)}, {"sha256", Value(file.sha256)}}));
            }
        };
        append_files(original_files); append_files(verification_files);
        for (const auto& relative : absent_original_files)
            append(Value(Value::Object{{"relative_path", Value(relative.generic_u8string())},
                {"type", Value("file")}, {"present", Value(false)}, {"object", Value{}},
                {"parent", Value{}}, {"native_identity", Value{}}, {"size_bytes", Value{}}, {"sha256", Value{}}}));
        for (const auto& item : original_directories) {
            const auto& directory = *item.second; require_entry(directory);
            append(Value(Value::Object{{"relative_path", Value(item.first.generic_u8string())},
                {"type", Value("directory")}, {"present", Value(true)},
                {"object", publisher_handle_observation_json(directory.facts)},
                {"parent", publisher_handle_observation_json(directory.parent ? directory.parent->facts : volume_facts)},
                {"native_identity", Value(journal_identity(directory.handle.value))}}));
        }
        for (const auto& relative : absent_original_directories)
            append(Value(Value::Object{{"relative_path", Value(relative.generic_u8string())},
                {"type", Value("directory")}, {"present", Value(false)}, {"object", Value{}},
                {"parent", Value{}}, {"native_identity", Value{}}}));
        document.as_object().emplace("original_objects", Value(std::move(objects)));
        if (original_child) require_publisher_effect_maintenance_original_record(document,
            original_context.record().at("reviewed_snapshot").at("apply_request"), service_name);
        require_custody_value_budget(document, maximum);
        original_admission_text = json::canonical(document) + "\n";
        if (original_admission_text.size() > maximum)
            throw std::runtime_error("native maintenance original custody exceeds its durable bound");
        base::Sha256 hash;
        hash.update(reinterpret_cast<const unsigned char*>(original_admission_text.data()), original_admission_text.size());
        original_admission_sha256 = hash.finish();
        native_custody_directory = spec.state_root / "transactions" / (spec.transaction_id + ".native-maintenance-custody");
        native_snapshot_directory = spec.state_root / "transactions" / (spec.transaction_id + ".native-maintenance-snapshots");
        base::require_native_path_capacity(native_custody_directory / "00000000000000000000.json",
            base::NativePathKind::file, "native maintenance later custody");
        base::require_native_path_capacity(native_snapshot_directory / (std::string(64, '0') + ".json"),
            base::NativePathKind::file, "native maintenance retained snapshot");
        require_authority(spec);
    }
    void persist_original_admission() {
        require_authority(spec);
        // The private constructor is now effectful: original context, approved
        // request and result capacity must be established by the engine before
        // entry. The caller's effects output is marked before this create-only
        // record, which precedes the first
        // lifecycle journal and is never treated as a recovered creator grant.
        record_io::write_new_durable_text(original_admission_path, original_admission_text);
        if (record_io::read_stable_text(original_admission_path, 16u * 1024u * 1024u) != original_admission_text)
            throw std::runtime_error("native maintenance original custody readback differs");
        record_io::create_directory_exclusive(native_custody_directory.parent_path(), native_custody_directory.filename().u8string());
        record_io::create_directory_exclusive(native_snapshot_directory.parent_path(), native_snapshot_directory.filename().u8string());
        require_authority(spec);
    }
    void persist_native_custody(const std::string& kind, Value details) {
        require_authority(spec);
        const auto tx = transaction::TransactionSession::inspect_recovery(spec);
        Value pending_sequence;
        if (!active_payload_history.empty()) {
            const auto history = transaction::MaintenanceEffectJournal::inspect(spec, tx.stream_source_digest);
            if (history.journal_digest != active_payload_history || history.pending_kind.empty())
                throw std::runtime_error("native maintenance custody lost its exact active intent");
            pending_sequence = Value(history.pending_sequence);
        }
        Value record(Value::Object{{"schema", Value("usk.publisher.maintenance_native_custody.v2")},
            {"transaction_id", Value(spec.transaction_id)}, {"plan_digest", Value(spec.plan_digest)},
            {"original_context_sha256", Value(original_context.lease_binding_sha256())},
            {"original_admission_sha256", Value(original_admission_sha256)},
            {"original_lease_ownership_sha256", Value(json::sha256_canonical(original_lease_ownership))},
            {"writer_lease_ownership", lease.ownership()},
            {"sequence", Value(native_custody_sequence)}, {"kind", Value(kind)},
            {"previous_record_sha256", native_custody_digest.empty() ? Value{} : Value(native_custody_digest)},
            {"transaction_snapshot_sha256", Value(tx.snapshot_sha256)},
            {"pending_history_sha256", active_payload_history.empty() ? Value{} : Value(active_payload_history)},
            {"pending_intent_sequence", std::move(pending_sequence)},
            {"details", std::move(details)}});
        require_custody_value_budget(record, 1024u * 1024u);
        const auto text = json::canonical(record) + "\n";
        constexpr std::size_t maximum_record = 1024u * 1024u;
        constexpr std::size_t maximum_total = 256u * 1024u * 1024u;
        if (native_custody_sequence >= 200000u || text.size() > maximum_record ||
            native_custody_bytes > maximum_total || text.size() > maximum_total - native_custody_bytes)
            throw std::runtime_error("native maintenance later custody exceeds its finite bounds");
        std::ostringstream name;
        name << std::setw(20) << std::setfill('0') << native_custody_sequence << ".json";
        const auto path = native_custody_directory / name.str();
        base::Sha256 hash;
        hash.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
        auto next_digest = hash.finish(); // Allocate before the record effect.
        record_io::write_new_durable_text(path, text);
        if (record_io::read_stable_text(path, maximum_record) != text)
            throw std::runtime_error("native maintenance later custody readback differs");
        require_authority(spec);
        native_custody_digest.swap(next_digest);
        native_custody_bytes += text.size(); ++native_custody_sequence;
    }
    transaction::MaintenanceEffectInspection require_pending(const std::string& kind) const {
        require_authority(spec);
        const auto tx = transaction::TransactionSession::inspect_recovery(spec);
        const auto history = transaction::MaintenanceEffectJournal::inspect(spec, tx.stream_source_digest, true);
        const auto artifact = read_maintenance_reviewed_plan(spec);
        const auto next = inspect_maintenance_continuation(spec);
        const auto source = json::parse(history.source_context);
        const auto& snapshot = original_context.record().at("reviewed_snapshot");
        if (history.pending_kind != kind || !next.pending || next.next_kind != kind ||
            next.history_digest != history.journal_digest || !equal(next.next_details, history.pending_details) ||
            tx.stream_source_context != history.source_context ||
            !equal(artifact.at("reviewed_plan"), snapshot.at("reviewed_plan")) ||
            source.at("install_id").as_string() != snapshot.at("install_id").as_string() ||
            source.at("original_installed_transaction_id").as_string() != snapshot.at("installed_state").at("transaction_id").as_string() ||
            source.at("applied_at").as_string() != snapshot.at("apply_request").at("applied_at").as_string() ||
            normalized(fs::u8path(source.at("installed_root").at("root").as_string())) !=
                normalized(fs::u8path(snapshot.at("installed_state").at("target_root").as_string())) ||
            source.at("installed_root").at("native_identity").as_string() != original_root_identity)
            throw std::runtime_error("native maintenance payload lost its original reviewed next intent");
        require_authority(spec);
        return history;
    }
    Entry& target_directory(const fs::path& relative, bool create_backup = false) {
        if (!staging || !publication_confirmed) throw std::runtime_error("native maintenance published creation is unavailable");
        Entry* parent = staging; fs::path partial;
        for (const auto& component : relative) {
            if (!is_publisher_canonical_component(component.wstring()))
                throw std::runtime_error("native maintenance target directory is not canonical");
            partial /= component;
            const auto key = (relative_volume_path(spec.staging_parent / (".usk-stage-" + spec.transaction_id)) / partial).lexically_normal();
            const auto found = directories.find(key);
            if (found == directories.end()) {
                if (!create_backup || *partial.begin() != fs::path("backup"))
                    throw std::runtime_error("native maintenance target directory lacks original creation custody");
                parent = &create_directory(*parent, partial, component.wstring());
            } else parent = found->second.get();
            if (!parent->created && !parent->restored_creation)
                throw std::runtime_error("native maintenance target directory lacks proved creation custody");
            require_entry(*parent);
        }
        require_entry(*parent); return *parent;
    }
    Entry& repair_parent(const fs::path& relative_file) {
        const auto intent = require_pending("replace_file");
        if (spec.operation != "repair" || owned_relative(intent.pending_details.at("relative_path").as_string()) != relative_file || !installed_root)
            throw std::runtime_error("native repair parent lacks its exact original replacement intent");
        Entry* parent = installed_root; fs::path relative;
        for (const auto& component : relative_file.parent_path()) {
            relative /= component;
            const auto existing = original_directories.find(relative);
            if (existing != original_directories.end()) { parent = existing->second; require_entry(*parent); continue; }
            if (!absent_original_directories.count(relative))
                throw std::runtime_error("native repair parent was not originally absent and owned");
            require_entry(*parent);
            if (child(parent->handle.value, component.wstring()))
                throw std::runtime_error("native repair absent parent was replaced");
            const auto key = relative_volume_path(fs::u8path(original_state.installed_state().at("target_root").as_string()) / relative);
            auto entry = std::make_unique<Entry>(); entry->parent = parent; entry->name = component.wstring(); entry->created = true;
            const auto inserted = directories.emplace(key, std::move(entry));
            if (!inserted.second) throw std::runtime_error("native repair parent creation conflicts with retained custody");
            auto& held = *inserted.first->second;
            (void)require_pending("replace_file");
            held.handle.value = create_staged_directory_relative_with_descriptor(parent->handle.value, held.name, descriptor);
            held.facts = facts(held.handle.value, true); require_entry(held);
            persist_native_custody("created_owned_parent", Value(Value::Object{
                {"relative_path", Value(relative.generic_u8string())}, {"object", publisher_handle_observation_json(held.facts)},
                {"parent", publisher_handle_observation_json(parent->facts)},
                {"native_identity", Value(journal_identity(held.handle.value))}}));
            if (!original_directories.emplace(relative, &held).second)
                throw std::runtime_error("native repair parent creator was repeated");
            use_directory_parent_observer(held);
            parent = &held;
        }
        require_entry(*parent); (void)require_pending("replace_file"); return *parent;
    }
    static void require_file_details(const Entry& entry, const Value& details) {
        if (entry.stream_identity != details.at("native_identity").as_string() ||
            entry.size != details.at("size_bytes").as_unsigned() || entry.sha256 != details.at("sha256").as_string())
            throw std::runtime_error("native maintenance file differs from its original pending intent");
    }
    void rename_file(Entry& file, Entry& destination, const std::wstring& component) {
        require_bytes(file); require_entry(destination);
        auto postimage = file.facts;
        postimage.native_name = destination.facts.native_name + L"\\" + component;
        auto next_component = component;
        (void)rename_publisher_bound_file_no_replace(file.handle.value, file.parent->handle.value, file.name,
            destination.handle.value, component, file.facts, file.parent->facts, destination.facts, file.size, file.sha256);
        file.parent = &destination; file.name.swap(next_component); file.facts = std::move(postimage);
        require_bytes(file);
    }
    std::string remove_entry(Entry& entry, const Value& details) {
        require_entry(entry);
        if (!entry.parent) throw std::runtime_error("native maintenance removal cannot use the volume as an operation parent");
        if (entry.directory) {
            if (journal_identity(entry.handle.value) != details.at("native_identity").as_string())
                throw std::runtime_error("native maintenance directory lost its original identity");
            // Keep the observer when a bound directory is nonempty. The native
            // primitive independently returns retained without an issued call.
            if (!observe_publisher_directory_entries(entry.handle.value).empty()) {
                const auto result = remove_publisher_bound_empty_directory(entry.parent->handle.value, entry.name,
                    entry.facts, entry.parent->facts, maintenance_names.get());
                if (result.native_call_attempted || result.absence_confirmed)
                    throw std::runtime_error("native maintenance nonempty directory unexpectedly changed");
                return "retained";
            }
        } else { require_file_details(entry, details); require_bytes(entry); }
        const auto expected = entry.facts;
        auto& parent = *entry.parent; require_entry(parent);
        // The primitive owns its affected mark/close handle. Release this
        // owner's redundant observer first, retaining full original facts,
        // creation provenance and independently held parent/generation custody.
        entry.handle.close_observer_once();
        const auto result = entry.directory ? remove_publisher_bound_empty_directory(parent.handle.value, entry.name, expected, parent.facts,
            maintenance_names.get()) :
            remove_publisher_bound_file(parent.handle.value, entry.name, expected, parent.facts, entry.size, entry.sha256);
        if (!result.native_call_attempted || !result.absence_confirmed)
            throw std::runtime_error("native maintenance removal was not confirmed; retained recovery required");
        return "applied";
    }
    std::shared_ptr<const std::string> retained_transaction_text(const std::string& expected_sha256) {
        const auto found = transaction_snapshots.find(expected_sha256);
        if (found != transaction_snapshots.end()) {
            if (transaction::TransactionSession::inspect_recovery(spec).snapshot_sha256 != expected_sha256)
                throw std::runtime_error("native maintenance retained transaction snapshot changed");
            return found->second;
        }
        const auto text = record_io::read_stable_text(spec.state_root / "transactions" /
            (spec.transaction_id + ".journal.json"), 4u * 1024u * 1024u);
        base::Sha256 hash; hash.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
        if (hash.finish() != expected_sha256 ||
            transaction::TransactionSession::inspect_recovery(spec).snapshot_sha256 != expected_sha256)
            throw std::runtime_error("native maintenance original transaction bytes changed");
        constexpr std::size_t maximum = 16u * 1024u * 1024u;
        if (transaction_snapshot_bytes > maximum || text.size() > maximum - transaction_snapshot_bytes)
            throw std::runtime_error("native maintenance retained transaction snapshots exceed their bound");
        auto retained = std::make_shared<const std::string>(text);
        const auto path = native_snapshot_directory / (expected_sha256 + ".json");
        try {
            record_io::write_new_durable_text(path, text);
            if (record_io::read_stable_text(path, 4u * 1024u * 1024u) != text)
                throw std::runtime_error("native maintenance retained transaction readback differs");
            require_authority(spec);
        } catch (...) { custody_failed = true; throw; }
        transaction_snapshots.emplace(expected_sha256, retained);
        transaction_snapshot_bytes += text.size();
        return retained;
    }
    void grant_created_payload(Entry& entry, const std::string& role, const fs::path& relative) {
        if ((!entry.created && !entry.restored_creation) || !entry.parent || original_consumer_sid.empty())
            throw std::runtime_error("native maintenance read grant lacks original approved creator custody");
        require_entry(entry);
        if (!entry.directory) require_bytes(entry);
        if (entry.facts.dacl_aces.size() == 3u) {
            (void)publisher_consumer_read_object_projection(entry.facts, service.service_sid, original_consumer_sid, true);
            return; // Full facts already match the retained confirmed creator/grant receipt.
        }
        const auto before = entry.facts;
        try {
            require_authority(spec);
            const auto listed = child(entry.parent->handle.value, entry.name);
            if (!listed) throw std::runtime_error("native maintenance consumer-grant recipient is absent");
            Held acl;
            acl.value = open_publisher_listed_child(entry.parent->handle.value, *listed,
                false, false, false, true, false, maintenance_names.get());
            const auto access = observe_publisher_handle_granted_access(acl.value);
            if (!same(facts(acl.value, entry.directory), before) || !(access & WRITE_DAC) || (access & DELETE))
                throw std::runtime_error("native maintenance ACL observer changed recipient/access");
            require_entry(entry);
            if (!entry.directory) require_bytes(entry);
            entry.facts = grant_publisher_consumer_read_object(acl.value, entry.directory, before,
                service.service_sid, original_consumer_sid);
            require_entry(entry);
            if (!entry.directory) require_bytes(entry);
            acl.close_observer_once();
            require_authority(spec);
            persist_native_custody("consumer_read_grant", Value(Value::Object{
                {"root_role", Value(role)}, {"relative_path", Value(relative.generic_u8string())},
                {"before", publisher_handle_observation_json(before)}, {"after", publisher_handle_observation_json(entry.facts)},
                {"parent", publisher_handle_observation_json(entry.parent->facts)},
                {"native_identity", Value(journal_identity(entry.handle.value))}, {"consumer_sid", Value(original_consumer_sid)}}));
        } catch (...) { custody_failed = true; throw; }
    }
    void complete_consumer_access(const transaction::MaintenanceEffectInspection& history) {
        if (!((spec.operation == "repair" && history.pending_kind == "replace_file") ||
              (spec.operation == "move" && history.pending_kind == "publish_target"))) return;
        // A validated legacy completion has no reader policy to extend.
        // Namespace/creator confirmation remains mandatory in its caller.
        if (original_consumer_sid.empty()) return;
        (void)require_pending(history.pending_kind);
        const auto tx = transaction::TransactionSession::inspect_recovery(spec);
        try {
            // A resumed pending completion can have a newer transaction
            // snapshot than its old writer. Retain its actual bytes before
            // any grant; every effect fence pins this SHA and original intent.
            (void)retained_transaction_text(tx.snapshot_sha256);
            active_payload_transaction = tx.snapshot_sha256; active_payload_history = history.journal_digest;
            (void)require_pending(history.pending_kind);
            if (spec.operation == "repair") {
                const auto relative = owned_relative(history.pending_details.at("relative_path").as_string());
                auto& file = *files.at(fs::path("payload") / relative);
                const auto parent = original_directories.find(relative.parent_path());
                if (parent == original_directories.end() || file.parent != parent->second || file.name != relative.filename().wstring())
                    throw std::runtime_error("native repair read grant precedes its confirmed replacement");
                grant_created_payload(file, "installed", relative);
                // Deepest parents first. A parent update never invalidates a
                // previously retained child; every receipt preserves full facts.
                auto path = relative.parent_path();
                while (!path.empty()) {
                    auto* directory = original_directories.at(path);
                    if (directory->created || directory->restored_creation) grant_created_payload(*directory, "installed", path);
                    path = path.parent_path();
                }
            } else {
                if (!staging || staging->parent != target_parent || staging->name != spec.target_root.filename().wstring())
                    throw std::runtime_error("native move read grant precedes its confirmed publication");
                for (auto& item : files) grant_created_payload(*item.second, "operation_target", item.first);
                const auto key = relative_volume_path(spec.staging_parent / (".usk-stage-" + spec.transaction_id));
                for (auto item = directories.rbegin(); item != directories.rend(); ++item) {
                    auto& directory = *item->second;
                    if (!(directory.created || directory.restored_creation)) continue;
                    const auto relative = item->first.lexically_relative(key);
                    if (relative.empty() || *relative.begin() == fs::path(".."))
                        throw std::runtime_error("native move read grant escaped its original creation closure");
                    grant_created_payload(directory, "operation_target", relative == fs::path(".") ? fs::path{} : relative);
                }
            }
            (void)require_pending(history.pending_kind);
            active_payload_transaction.clear(); active_payload_history.clear();
        } catch (...) { payload_failed = true; throw; }
    }
    transaction::detail::NativeMaintenanceTransactionOperations::EffectResult apply_effect(const transaction::TransactionSpec& supplied,
        const transaction::MaintenanceEffectInspection& inspected) {
        require_authority(supplied);
        const auto history = require_pending(inspected.pending_kind);
        if (history.journal_digest != inspected.journal_digest || history.source_context != inspected.source_context ||
            history.pending_sequence != inspected.pending_sequence || !equal(history.pending_details, inspected.pending_details) ||
            !publication_confirmed || payload_outcomes.size() >= 100000u ||
            !attempted_payload_histories.insert(history.journal_digest).second)
            throw std::runtime_error("native maintenance payload lacks its single original publication/intent");
        try {
            const auto tx = transaction::TransactionSession::inspect_recovery(spec);
            const auto pinned = transaction::MaintenanceEffectJournal::inspect(spec, tx.stream_source_digest);
            if (pinned.journal_digest != history.journal_digest)
                throw std::runtime_error("native maintenance payload intent changed before native entry");
            auto confirmation = std::make_unique<ConfirmedPayload>();
            confirmation->transaction_sha256 = tx.snapshot_sha256;
            confirmation->transaction_text = retained_transaction_text(tx.snapshot_sha256);
            const auto inserted = payload_outcomes.emplace(history.journal_digest, std::move(confirmation));
            if (!inserted.second) throw std::runtime_error("native maintenance outcome already exists for this intent");
            active_payload_transaction = tx.snapshot_sha256;
            active_payload_history = history.journal_digest;
            require_authority(supplied);
            const auto& details = history.pending_details;
            const auto relative = details.contains("relative_path") ?
                fs::u8path(details.at("relative_path").as_string()) : fs::path{};
            std::string outcome = "applied", result_digest;
            if (history.pending_kind == "backup_file") {
                auto& file = *original_files.at(relative);
                require_file_details(file, details);
                const auto backup = fs::path("backup") / relative;
                auto& parent = target_directory(backup.parent_path(), true);
                // Directory creation precedes rename but leaves the durable
                // original backup intent unresolved on any failure.
                (void)require_pending(history.pending_kind);
                rename_file(file, parent, backup.filename().wstring());
            } else if (history.pending_kind == "replace_file") {
                auto& file = *files.at(fs::path("payload") / relative);
                if ((!file.created && !file.restored_creation) || !file.complete)
                    throw std::runtime_error("native repair replacement lacks completed creation custody");
                require_file_details(file, details);
                auto& parent = repair_parent(relative);
                rename_file(file, parent, relative.filename().wstring());
            } else if (history.pending_kind == "remove_file") {
                const auto role = details.at("root_role").as_string();
                Entry* file = nullptr;
                if (role == "installed") file = original_files.at(relative).get();
                else if (role == "operation_target" && spec.operation == "repair" && *relative.begin() == fs::path("backup")) {
                    auto original = relative.lexically_relative("backup"); file = original_files.at(original).get();
                    if (file->parent != &target_directory(relative.parent_path()) || file->name != relative.filename().wstring())
                        throw std::runtime_error("native maintenance backup cleanup lost its original rename postimage");
                } else if (role == "operation_target" && spec.operation == "uninstall" && relative == fs::path("operation.marker"))
                    file = files.at(relative).get();
                else throw std::runtime_error("native maintenance removal is outside its original role");
                outcome = remove_entry(*file, details);
            } else if (history.pending_kind == "remove_directory") {
                const auto role = details.at("root_role").as_string();
                Entry* directory = role == "installed" ? original_directories.at(relative) :
                    role == "operation_target" ? &target_directory(relative) : nullptr;
                if (!directory) throw std::runtime_error("native maintenance directory removal has an unrelated role");
                outcome = remove_entry(*directory, details);
                if (outcome == "retained" && role != "installed")
                    throw std::runtime_error("native maintenance created cleanup directory is not empty");
            } else if (history.pending_kind == "write_ownership") {
                auto postimage = maintenance_ownership_postimage(spec, history);
                result_digest = state::StateRepository(spec.state_root).write_ownership(std::move(postimage)).manifest_digest;
            } else if (history.pending_kind == "write_installed") {
                const auto postimage = maintenance_installed_postimage(spec, history);
                state::StateRepository(spec.state_root).write_installed(postimage);
                result_digest = details.at("state_digest").as_string();
            } else if (history.pending_kind == "append_audit") {
                const auto postimage = maintenance_audit_postimage(spec, history);
                result_digest = audit::AuditRepository(spec.audit_root).append(
                    details.at("chain_id").as_string(), postimage).event_digest;
            } else throw std::runtime_error("native maintenance owned effect kind is unsupported");
            require_authority(supplied);
            const auto after = transaction::MaintenanceEffectJournal::inspect(spec, history.source_digest);
            if (after.journal_digest != history.journal_digest)
                throw std::runtime_error("native maintenance intent changed during its effect");
            inserted.first->second->outcome = outcome;
            inserted.first->second->result_digest = result_digest;
            persist_native_custody("confirmed_effect", Value(Value::Object{
                {"intent_sequence", Value(history.pending_sequence)}, {"effect_kind", Value(history.pending_kind)},
                {"effect_details", history.pending_details}, {"outcome", Value(outcome)},
                {"result_digest", result_digest.empty() ? Value{} : Value(result_digest)},
                {"effect_transaction_snapshot_sha256", Value(tx.snapshot_sha256)}}));
            inserted.first->second->confirmed = true;
            complete_consumer_access(history);
            active_payload_transaction.clear(); active_payload_history.clear();
            return {outcome, result_digest};
        } catch (...) { payload_failed = true; throw; }
    }
    void confirm_effect_completion(const transaction::TransactionSpec& supplied,
        const transaction::MaintenanceEffectInspection& inspected, const std::string& outcome,
        const std::string& result_digest, bool complete_grants = true) {
        require_authority(supplied);
        const auto current = require_pending(inspected.pending_kind);
        const auto tx = transaction::TransactionSession::inspect_recovery(spec);
        if (current.pending_kind == "publish_target") {
            if (current.journal_digest != inspected.journal_digest || !equal(current.pending_details, inspected.pending_details) ||
                !publication_confirmed || !staging || outcome != "applied" || !result_digest.empty())
                throw std::runtime_error("native maintenance publication completion lacks its original confirmed custody");
            transaction::TransactionSession::require_recovery_transition_extension(spec,
                *publication_transaction_text, publication_transaction_sha256, tx.snapshot_sha256);
            require_entry(*staging);
            for (const auto& file : files) require_bytes(*file.second);
            if (complete_grants) complete_consumer_access(current);
            require_authority(supplied);
            return;
        }
        const auto found = payload_outcomes.find(current.journal_digest);
        if (current.journal_digest != inspected.journal_digest || !equal(current.pending_details, inspected.pending_details) ||
            found == payload_outcomes.end() || !found->second->confirmed || found->second->outcome != outcome ||
            (!found->second->result_digest.empty() && found->second->result_digest != result_digest))
            throw std::runtime_error("native maintenance completion has no actual owned confirmed outcome");
        transaction::TransactionSession::require_recovery_transition_extension(spec,
            *found->second->transaction_text, found->second->transaction_sha256, tx.snapshot_sha256);
        if (complete_grants) complete_consumer_access(current);
        // No observed-postcondition or newly resumed journal can fabricate an
        // outcome. Restored native creator/ended-holder proof remains absent
        // until the concrete source-free owner factory joins it separately.
        require_authority(supplied);
    }
    void require_recovery_authority(const transaction::TransactionSpec& supplied,
        const transaction::RecoveryInspection& inspected_transaction,
        const transaction::MaintenanceEffectInspection& inspected_history) {
        require_authority(supplied);
        if (!publication_confirmed || original_source_context.empty())
            throw std::runtime_error("native live maintenance recovery has no original confirmed publication");
        const auto current = transaction::TransactionSession::inspect_recovery(spec);
        const auto history = transaction::MaintenanceEffectJournal::inspect(spec, current.stream_source_digest);
        if (current.snapshot_sha256 != inspected_transaction.snapshot_sha256 ||
            history.journal_digest != inspected_history.journal_digest ||
            history.pending_sequence != inspected_history.pending_sequence ||
            history.pending_kind != inspected_history.pending_kind ||
            !equal(history.pending_details, inspected_history.pending_details) ||
            current.stream_source_context != original_source_context || history.source_context != original_source_context ||
            !equal(read_maintenance_reviewed_plan(spec).at("reviewed_plan"),
                original_context.record().at("reviewed_snapshot").at("reviewed_plan")))
            throw std::runtime_error("native maintenance recovery changed its original transaction or context");
        transaction::TransactionSession::require_recovery_transition_extension(spec,
            *publication_transaction_text, publication_transaction_sha256, current.snapshot_sha256);
        const auto selected = inspect_maintenance_continuation(spec);
        if (selected.transaction_snapshot_sha256 != current.snapshot_sha256 ||
            selected.history_digest != history.journal_digest)
            throw std::runtime_error("native maintenance recovery changed its original complete prefix");
        if (!history.pending_kind.empty()) {
            (void)require_pending(history.pending_kind);
            const auto observation = reconcile_maintenance_effect(spec);
            if (observation.state == "compatible_after_effect") {
                if (history.pending_kind == "publish_target") {
                    require_entry(*staging);
                    for (const auto& file : files) require_bytes(*file.second);
                } else {
                    const auto actual = payload_outcomes.find(history.journal_digest);
                    if (actual == payload_outcomes.end() || !actual->second->confirmed)
                        throw std::runtime_error("native maintenance postcondition lacks its actual confirmed outcome");
                    confirm_effect_completion(supplied, history, actual->second->outcome, observation.result_digest, false);
                }
            }
        }
        require_authority(supplied);
    }
    std::string apply_recovery_effect(const transaction::TransactionSpec& supplied,
        const transaction::MaintenanceEffectInspection& history) {
        const auto current = transaction::TransactionSession::inspect_recovery(spec);
        require_recovery_authority(supplied, current, history);
        const auto confirmed = payload_outcomes.find(history.journal_digest);
        if (confirmed != payload_outcomes.end() && confirmed->second->confirmed) {
            complete_consumer_access(history);
            const auto observation = reconcile_maintenance_effect(spec);
            confirm_effect_completion(supplied, history, confirmed->second->outcome, observation.result_digest);
            return confirmed->second->outcome; // Actual same-owner result; never another native call.
        }
        return apply_effect(supplied, history).outcome;
    }
    transaction::detail::NativeMaintenanceFileObservation observe_owned_file(const fs::path& path) const {
        require_authority(spec);
        auto wanted = volume_facts.native_name;
        if (!wanted.empty() && wanted.back() != L'\\') wanted += L'\\';
        wanted += relative_volume_path(path).native();
        const Entry* selected = nullptr;
        const auto select = [&](const auto& entries) {
            for (const auto& item : entries) {
                const auto& entry = *item.second;
                if (entry.handle.value == INVALID_HANDLE_VALUE || entry.facts.native_name != wanted) continue;
                if (selected) throw std::runtime_error("native maintenance file observation has ambiguous held custody");
                selected = &entry;
            }
        };
        select(files); select(original_files); select(verification_files);
        if (!selected || selected->directory || (selected->created && !selected->complete))
            throw std::runtime_error("native maintenance file observation is outside its retained completed files");
        require_bytes(*selected);
        transaction::detail::NativeMaintenanceFileObservation result{
            journal_identity(selected->handle.value), selected->sha256, selected->size};
        require_authority(spec);
        return result;
    }
    transaction::CommitClosureObservation observe_created_closure(const transaction::TransactionSpec& s,
        const fs::path& path, const std::vector<transaction::CommitClosureFile>& requested) const {
        require_authority(s);
        if (!staging || !staging->created || publication_attempted || staging_relative(path) != fs::path(".") ||
            requested.size() != files.size() || requested.size() > transaction::maximum_commit_closure_entries)
            throw std::runtime_error("native maintenance closure lacks its original unpublished creation set");
        std::set<std::string> expected_files, expected_directories;
        std::vector<PublisherExpectedFile> expected;
        for (const auto& file : requested) {
            const auto relative = owned_relative(file.relative_path.generic_u8string());
            if (!expected_files.insert(relative.generic_u8string()).second)
                throw std::runtime_error("native maintenance closure repeats a recorded file");
            std::size_t depth = 0;
            for (const auto& part : relative) {
                (void)part;
                if (++depth > transaction::maximum_commit_closure_depth)
                    throw std::runtime_error("native maintenance closure path depth exceeded");
            }
            for (auto parent = relative.parent_path(); !parent.empty(); parent = parent.parent_path())
                expected_directories.insert(parent.generic_u8string());
            if (expected_files.size() + expected_directories.size() > transaction::maximum_commit_closure_entries)
                throw std::runtime_error("native maintenance closure entry budget exceeded");
            const auto found = files.find(relative);
            if (found == files.end() || !found->second->created || !found->second->complete ||
                found->second->size != file.size_bytes || found->second->sha256 != file.sha256 ||
                found->second->stream_identity != file.stream_output_identity)
                throw std::runtime_error("native maintenance closure differs from its completed stream creators");
            require_bytes(*found->second);
            expected.push_back({relative.generic_wstring(), file.size_bytes, file.sha256});
        }
        require_entry(*staging);
        const auto tree = observe_publisher_tree(staging->handle.value);
        require_publisher_tree_security_shape(tree, service.service_sid);
        require_publisher_tree_exact_file_closure(tree, expected);
        if (tree.descendants.size() != expected_files.size() + expected_directories.size() ||
            !same(tree.root, staging->facts))
            throw std::runtime_error("native maintenance closure has an unrelated root or directory");
        transaction::CommitClosureObservation result{{"D:", journal_identity(staging->handle.value)}};
        for (const auto& object : tree.descendants) {
            const auto relative = fs::path(object.relative_path);
            const bool directory = (object.object.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const Entry* held = nullptr;
            if (directory) {
                if (!expected_directories.count(relative.generic_u8string()))
                    throw std::runtime_error("native maintenance closure has an unrecorded directory");
                const auto found = directories.find((relative_volume_path(path) / relative).lexically_normal());
                if (found == directories.end() || !found->second->created)
                    throw std::runtime_error("native maintenance closure directory lacks its original creator");
                held = found->second.get(); require_entry(*held);
            } else {
                held = files.at(relative).get(); require_bytes(*held);
                if (object.size != held->size || object.sha256 != held->sha256)
                    throw std::runtime_error("native maintenance closure bytes differ from its held stream");
            }
            if (!same(object.object, held->facts) ||
                !result.emplace((directory ? "D:" : "F:") + relative.generic_u8string(),
                    journal_identity(held->handle.value)).second)
                throw std::runtime_error("native maintenance closure lost its exact native creation identity");
        }
        require_publisher_tree_phase_match(tree, observe_publisher_tree(staging->handle.value));
        require_authority(s);
        return result;
    }
    void commit(const transaction::TransactionSpec& s, const fs::path& path, const std::string& id,
        const transaction::CommitClosureObservation& closure) {
        require_authority(s);
        (void)require_pending("publish_target");
        if (!staging || publication_attempted || staging_relative(path) != fs::path(".") ||
            journal_identity(staging->handle.value) != id || closure.empty())
            throw std::runtime_error("native maintenance commit lacks its original created root/closure");
        const auto transaction = transaction::TransactionSession::inspect_recovery(spec);
        publication_transaction_text = retained_transaction_text(transaction.snapshot_sha256);
        publication_transaction_sha256 = transaction.snapshot_sha256;
        original_source_context = transaction.stream_source_context;
        std::vector<PublisherExpectedFile> expected;
        std::vector<transaction::CommitClosureFile> journal_files;
        Value::Array created;
        for (const auto& item : files) {
            const auto& entry = *item.second;
            if (!entry.created || !entry.complete) throw std::runtime_error("native maintenance commit has an incomplete creation");
            require_bytes(entry); expected.push_back({item.first.generic_wstring(), entry.size, entry.sha256});
            journal_files.push_back({item.first, entry.sha256, entry.size, entry.stream_identity});
        }
        for (const auto& item : directories) if (item.second->created) require_entry(*item.second);
        const auto sealed = observe_publisher_tree(staging->handle.value);
        require_publisher_tree_security_shape(sealed, service.service_sid);
        require_publisher_tree_exact_file_closure(sealed, expected);
        if (observe_created_closure(s, path, journal_files) != closure)
            throw std::runtime_error("native maintenance generic closure differs from the held created tree");
        for (const auto& object : sealed.descendants) {
            const auto relative = fs::path(object.relative_path);
            const bool directory = (object.object.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const HANDLE created_handle = directory ? directories.at((relative_volume_path(path) / relative).lexically_normal())->handle.value :
                files.at(relative)->handle.value;
            created.push_back(Value(Value::Object{
            {"relative_path", Value(relative.generic_u8string())},
            {"object", publisher_handle_observation_json(object.object)},
            {"native_identity", Value(journal_identity(created_handle))},
            {"size_bytes", Value(object.size)}, {"sha256", Value(object.sha256)}}));
        }
        // This record describes this worker's held creations, not a recovered
        // handle or a callback assertion. It precedes the native publication.
        const Value custody(Value::Object{{"schema", Value("usk.publisher.maintenance_created_closure.v2")},
            {"transaction_id", Value(spec.transaction_id)}, {"plan_digest", Value(spec.plan_digest)},
            {"original_context_sha256", Value(original_context.lease_binding_sha256())},
            {"original_admission_sha256", Value(original_admission_sha256)},
            {"lease_ownership_sha256", Value(json::sha256_canonical(lease.ownership()))},
            {"transaction_snapshot_sha256", Value(publication_transaction_sha256)},
            {"source_context", Value(original_source_context)},
            {"worker_security", worker}, {"process_boundary", process_boundary},
            {"registration_sha256", Value(json::sha256_canonical(registration))},
            {"authenticated_client", client}, {"root", publisher_handle_observation_json(sealed.root)},
            {"root_parent", publisher_handle_observation_json(staging_parent->facts)},
            {"target_parent", publisher_handle_observation_json(target_parent->facts)},
            {"root_native_identity", Value(journal_identity(staging->handle.value))},
            {"created_objects", Value(std::move(created))}});
        require_custody_value_budget(custody, 16u * 1024u * 1024u);
        const auto text = json::canonical(custody) + "\n";
        if (text.size() > 16u * 1024u * 1024u) throw std::runtime_error("native maintenance created closure exceeds its durable bound");
        const auto custody_path = spec.state_root / "transactions" / (spec.transaction_id + ".native-maintenance-created.json");
        record_io::write_new_durable_text(custody_path, text);
        if (record_io::read_stable_text(custody_path, 16u * 1024u * 1024u) != text)
            throw std::runtime_error("native maintenance created closure readback differs");
        require_authority(s);
        require_publisher_tree_phase_match(sealed, observe_publisher_tree(staging->handle.value));
        // Prepare every retained object's known namespace postimage before
        // calling native rename. Allocation failure therefore precedes it.
        const auto new_name = target_parent->facts.native_name + L"\\" + spec.target_root.filename().wstring();
        std::vector<std::pair<Entry*, PublisherHandleObservation>> after;
        for (const auto& item : directories) if (item.second->created) {
            auto fact = item.second->facts; fact.native_name.replace(0, sealed.root.native_name.size(), new_name);
            after.emplace_back(item.second.get(), std::move(fact));
        }
        for (const auto& item : files) {
            auto fact = item.second->facts; fact.native_name.replace(0, sealed.root.native_name.size(), new_name);
            after.emplace_back(item.second.get(), std::move(fact));
        }
        std::vector<std::pair<Entry*, std::string>> descendants;
        for (const auto& item : directories) if (item.second->created && item.second.get() != staging)
            descendants.emplace_back(item.second.get(), journal_identity(item.second->handle.value));
        const auto depth = [](const Entry* entry) {
            std::size_t result = 0;
            for (; entry; entry = entry->parent) ++result;
            return result;
        };
        std::stable_sort(descendants.begin(), descendants.end(), [&](const auto& a, const auto& b) {
            return depth(a.first) < depth(b.first);
        });
        for (const auto& item : files)
            descendants.emplace_back(item.second.get(), journal_identity(item.second->handle.value));
        auto next_component = spec.target_root.filename().wstring();
        // Freeze all borrowed streams before releasing descendants. NTFS
        // directory rename requires them closed. The protected root and its
        // outside parents remain held, with the exact creator closure durable.
        // Any uncertain close/rename/postimage grants neither retry nor cleanup.
        publication_attempted = true;
        try {
            for (auto it = descendants.rbegin(); it != descendants.rend(); ++it)
                it->first->handle.close_observer_once();
            require_entry(*staging); require_authority(s);
            require_publisher_tree_phase_match(sealed, observe_publisher_tree(staging->handle.value));
            (void)probe_publisher_bound_rename_no_replace(staging->handle.value, target_parent->handle.value,
                next_component, sealed.root, target_parent->facts, [&] { require_authority(s); }, maintenance_names.get());
            staging->parent = target_parent; staging->name.swap(next_component);
            for (auto& item : after) item.first->facts = std::move(item.second);
            use_directory_parent_observer(*staging);
            for (const auto& item : descendants) reopen_created_descendant(*item.first, item.second);
            require_publisher_tree_phase_match(sealed, observe_publisher_tree(staging->handle.value), new_name);
            for (const auto& item : directories) if (item.second->created) require_entry(*item.second);
            for (const auto& item : files) require_bytes(*item.second);
            require_authority(s);
            publication_confirmed = true;
            base::Sha256 created_hash;
            created_hash.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
            persist_native_custody("confirmed_publication", Value(Value::Object{
                {"created_closure_sha256", Value(created_hash.finish())},
                {"root", publisher_handle_observation_json(staging->facts)},
                {"parent", publisher_handle_observation_json(target_parent->facts)},
                {"publication_transaction_snapshot_sha256", Value(publication_transaction_sha256)}}));
            complete_consumer_access(require_pending("publish_target"));
        } catch (...) { custody_failed = true; throw; }
    }
};
NativeMaintenanceContext::NativeMaintenanceContext(HANDLE volume, const std::wstring& root, const std::wstring& service,
    const PublisherInstallOperationGuard& guard, const PublisherMaintenanceStateSnapshot& state,
    const PublisherInstallOperationContext& context, const PublisherInstallationLease& lease,
    const RegisteredPublisherAdmission& admission, const PublisherRequestChannel& channel,
    const transaction::TransactionSpec& spec, HANDLE cancel, bool& effects_may_exist)
    : impl_(std::make_unique<Impl>(volume, root, service, guard, state, context, lease, &admission, &channel, nullptr, spec, cancel)) {
    bind_owner_backend();
    effects_may_exist = true;
    impl_->persist_original_admission();
    scope_.reset(new transaction::detail::ScopedNativeMaintenanceTransaction(impl_->operations));
}
NativeMaintenanceContext::NativeMaintenanceContext(HANDLE volume, const std::wstring& root, const std::wstring& service,
    const PublisherInstallOperationGuard& guard, const PublisherMaintenanceStateSnapshot& state,
    const PublisherInstallOperationContext& context, const PublisherInstallationLease& lease,
    PublisherEffectExecutionOwner& original_child, const transaction::TransactionSpec& spec, HANDLE cancel,
    bool& effects_may_exist)
    : impl_(std::make_unique<Impl>(volume, root, service, guard, state, context, lease, nullptr, nullptr,
        &original_child, spec, cancel)) {
    bind_owner_backend();
    effects_may_exist = true;
    impl_->persist_original_admission();
    scope_.reset(new transaction::detail::ScopedNativeMaintenanceTransaction(impl_->operations));
}
NativeMaintenanceContext::NativeMaintenanceContext(HANDLE volume, const std::wstring& root, const std::wstring& service,
    const PublisherInstallOperationGuard& guard, const PublisherMaintenanceStateSnapshot& state,
    const PublisherInstallOperationContext& context, const PublisherInstallationLease& lease,
    const RegisteredPublisherAdmission& admission, const PublisherRequestChannel& channel,
    const transaction::TransactionSpec& spec, HANDLE cancel, bool& effects_may_exist, RecoveryAdmission) {
    // This path resumes material from the original operation. Even a refused
    // restoration must preserve the caller's retained-material status.
    effects_may_exist = true;
    impl_ = std::make_unique<Impl>(volume, root, service, guard, state, context, lease, &admission, &channel, nullptr, spec, cancel, true);
    bind_owner_backend();
    scope_.reset(new transaction::detail::ScopedNativeMaintenanceTransaction(impl_->operations));
}
NativeMaintenanceContext::NativeMaintenanceContext(HANDLE volume, const std::wstring& root, const std::wstring& service,
    const PublisherInstallOperationGuard& guard, const PublisherMaintenanceStateSnapshot& state,
    const PublisherInstallOperationContext& context, const PublisherInstallationLease& lease,
    PublisherEffectExecutionOwner& original_child, const transaction::TransactionSpec& spec, HANDLE cancel,
    bool& effects_may_exist, RecoveryAdmission) {
    effects_may_exist = true;
    impl_ = std::make_unique<Impl>(volume, root, service, guard, state, context, lease, nullptr, nullptr,
        &original_child, spec, cancel, true);
    bind_owner_backend();
    scope_.reset(new transaction::detail::ScopedNativeMaintenanceTransaction(impl_->operations));
}
void NativeMaintenanceContext::bind_owner_backend() {
    fence_ = std::make_unique<ScopedPublisherEffectFence>(impl_->effect_fence);
    impl_->metadata = std::make_unique<PublisherMetadataSession>(impl_->volume, impl_->volume_root,
        fs::path(impl_->volume_root) / fs::u8path(impl_->original_context.record().at("reviewed_snapshot").at("setup_component").as_string()),
        impl_->service_name, true, Impl::normalized(impl_->spec.state_root.parent_path()));
    usk::platform::windows::detail::MetadataRecordPublicationHooks hooks;
    hooks.prepare = [this](const auto& p, const auto& text) { impl_->metadata_prepare(p, text); };
    hooks.created = [this](const auto& p, const auto& text, HANDLE file) { return impl_->metadata_created(p, text, file); };
    hooks.before_issue = [this](const auto& p, const auto& text) { impl_->metadata_before_issue(p, text); };
    hooks.confirm = [this](const auto& p, const auto& text, HANDLE file) { impl_->metadata_confirm(p, text, file); };
    hooks.failed = [this](const auto& p) { impl_->metadata_failed(p); };
    impl_->metadata->bind_native_maintenance_publication(std::move(hooks));
    impl_->operations.persist_journal = [this](const auto& spec, const auto& path, const auto& text,
        const auto& predecessor, bool first) {
        try {
            impl_->require_authority(spec);
            transaction::detail::require_native_maintenance_journal_binding(spec, path, text, predecessor, first);
            impl_->metadata->persist_maintenance_journal(path, text, predecessor, first);
            impl_->require_authority(spec);
        } catch (...) {
            // A failed journal may have advanced durable state. Stop all
            // effects through this original owner and preserve the first error.
            impl_->custody_failed = true;
            throw;
        }
    };
    impl_->record_reads.read_owned_text = [this](const auto& p, auto maximum) {
        return impl_->read_owned_record(p, maximum);
    };
    record_read_scope_.reset(new record_io::ScopedNativeRecordReadOperations(impl_->record_reads));
}
NativeMaintenanceContext::~NativeMaintenanceContext() {
    scope_.reset();
    record_read_scope_.reset();
    impl_->metadata.reset();
    fence_.reset();
}
MaintenanceRecoveryOperations NativeMaintenanceContext::recovery_operations() const {
    using Scope = transaction::detail::ScopedNativeMaintenanceTransaction;
    const auto original = Scope::current_binding();
    const auto* expected = &impl_->operations;
    const auto pin = [original, expected] {
        transaction::detail::require_native_maintenance_origin_binding(true, original, Scope::current_binding());
        if (Scope::current() != expected)
            throw std::runtime_error("native maintenance recovery lost its original engine scope");
    };
    pin();
    impl_->require_authority(impl_->spec);
    if (!impl_->publication_confirmed)
        throw std::runtime_error("native live maintenance recovery requires original confirmed publication");
    auto* owner = impl_.get();
    MaintenanceRecoveryOperations backend;
    backend.require_authority = [pin, owner](const auto& s, const auto& tx, const auto& history) {
        pin(); owner->require_recovery_authority(s, tx, history); pin();
    };
    backend.apply_effect = [pin, owner](const auto& s, const auto& history) {
        pin(); auto result = owner->apply_recovery_effect(s, history); pin(); return result;
    };
    return backend;
}
}
#endif
