// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_lifecycle.h"
#include "usk_maintenance_creator_records_internal.h"
#include "usk_completed_maintenance_records_internal.h"
#include "usk_owned_retirement_lease_history_internal.h"
#include "usk_install_lease.h"
#if defined(_WIN32)
#include "usk_owned_publisher_retirement_internal.h"
#include "usk_owned_retirement_object_history_internal.h"
#include "usk_sha256.h"
#endif
#include "usk_maintenance_recovery_internal.h"
#include <array>
#include "usk_audit_repository.h"
#include "usk_maintenance_effect_journal.h"
#include "usk_transaction_session.h"
#include "usk_json.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
namespace fs = std::filesystem;
namespace {
void require(bool ok) { if (!ok) throw std::runtime_error("retirement record reader control failed"); }
template<class Action> void refuses(Action action) {
    bool refused = false;
    try { action(); } catch (const std::exception&) { refused = true; }
    require(refused);
}
std::string read_text(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("owned record input unavailable");
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
struct Fixture {
    fs::path root = fs::temp_directory_path() /
        ("usk-retirement-records-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    usk::lifecycle::LifecycleRoots roots{root / "staging", root / "state", root / "audit"};
    Fixture() {
        fs::create_directories(roots.staging_parent);
        fs::create_directories(roots.state_root);
        fs::create_directories(roots.audit_root);
        usk::state::StateRepository::initialize_layout(roots.state_root);
        fs::create_directory(roots.state_root / "transactions");
        usk::audit::AuditRepository::initialize_layout(roots.audit_root);
    }
    ~Fixture() { std::error_code ignored; fs::remove_all(root, ignored); }
};
struct Record { std::string name, text; };

void retirement_lease_controls() {
    using usk::json::Value;
    using namespace usk::transaction;
    using usk::lifecycle::detail::decode_owned_retirement_lease_history;
    const Value root(Value::Object{{"file_id", Value(std::string(32, 'a'))}, {"volume_serial", Value("123")}});
    const Value holder(Value::Object{{"process_id", Value(std::uint64_t{101})},
        {"process_creation_time", Value("00000000000000aa")}});
    const std::string id = "install.lease-history", a(64, 'a'), b(64, 'b'), c(64, 'c');
    const auto active = [&](const std::optional<Value>& previous, const std::string& operation,
            const std::string& operation_id, const std::string& attempt, const std::string& revision,
            const std::string& binding = std::string(64, 'd')) {
        return derive_install_lease_ownership(previous,
            {id, operation, operation_id, attempt, revision, true, binding}, root, holder, revision,
            InstallLeasePreviousHolder::ended);
    };
    const auto complete = [&](const Value& value, const std::string& revision, bool handoff = false) {
        return finish_install_lease_ownership(value, root, holder, revision, handoff);
    };
    const auto first = active({}, "install_local", "op.install", "attempt.1", a);
    const auto installed = complete(first, b);
    const auto reentry = active(installed, "install_local", "op.install", "attempt.2", b);
    const auto rebound = complete(reentry, b);
    const auto repair = active(rebound, "repair", "op.repair", "attempt.3", b);
    const auto repaired = complete(repair, c);
    const std::vector<Value> history{first, installed, reentry, rebound, repair, repaired};
    const auto result = decode_owned_retirement_lease_history(history, id, root, c);
    require(result.size() == 3 && !result[0].repeated_completion && result[1].repeated_completion &&
        !result[2].repeated_completion && usk::json::equal_values(result[0].original_active, first) &&
        usk::json::equal_values(result[1].completed, rebound));
    // The existing immutable-operation selector intentionally still refuses
    // this reuse. This ledger reader is a separate metadata check, not replay.
    refuses([&] { (void)select_completed_install_lease_history(history, first); });
    const auto inspect = [&](const std::vector<Value>& values) {
        return decode_owned_retirement_lease_history(values, id, root,
            values.back().at("result_state_revision").type() == Value::Type::string ?
                values.back().at("result_state_revision").as_string() : c);
    };
    require(inspect({first, installed}).size() == 1);
    refuses([&] { (void)decode_owned_retirement_lease_history({}, id, root, c); });
    refuses([&] { (void)decode_owned_retirement_lease_history(history, "other.install", root, c); });
    auto wrong_root = root; wrong_root.as_object().at("file_id") = Value(std::string(32, 'b'));
    refuses([&] { (void)decode_owned_retirement_lease_history(history, id, wrong_root, c); });
    refuses([&] { (void)decode_owned_retirement_lease_history(history, id, root, b); });
    refuses([&] { (void)decode_owned_retirement_lease_history(history, id, root, "not-a-revision"); });
    refuses([&] { (void)inspect({first}); });
    refuses([&] { (void)inspect({first, complete(first, b, true)}); });
    refuses([&] { (void)inspect({installed}); });
    refuses([&] { (void)inspect({first, installed, reentry, complete(reentry, c)}); });
    const auto changed_context = active(installed, "install_local", "op.install", "attempt.changed", b, a);
    refuses([&] { (void)inspect({first, installed, changed_context, complete(changed_context, b)}); });
    const auto changed_role = active(installed, "repair", "op.install", "attempt.role", b);
    refuses([&] { (void)inspect({first, installed, changed_role, complete(changed_role, b)}); });
    const auto stale_reentry = active(installed, "install_local", "op.install", "attempt.stale", a);
    refuses([&] { (void)inspect({first, installed, stale_reentry, complete(stale_reentry, a)}); });
    const auto moved = active(installed, "move", "op.move", "attempt.move", b);
    refuses([&] { (void)inspect({first, installed, moved, complete(moved, c)}); });
    const auto unsupported = active(installed, "update", "op.update", "attempt.update", b);
    refuses([&] { (void)inspect({first, installed, unsupported, complete(unsupported, c)}); });
    auto drift = history; drift[3].as_object().at("holder") = Value(Value::Object{
        {"process_id", Value(std::uint64_t{102})}, {"process_creation_time", Value("00000000000000aa")}});
    drift[3].as_object().erase("ownership_sha256");
    drift[3].as_object().emplace("ownership_sha256", Value(usk::json::sha256_canonical(drift[3])));
    refuses([&] { (void)inspect(drift); });
    auto gap = history; gap.erase(gap.begin() + 2);
    refuses([&] { (void)inspect(gap); });
    // An ended original attempt can continue through a recorded handoff,
    // but its plain-data completion does not establish actual holder death.
    const auto pending = active(installed, "repair", "op.interrupted", "attempt.pending", b);
    const auto handed = complete(pending, b, true);
    const auto resumed = active(handed, "repair", "op.interrupted", "attempt.resumed", b);
    const auto recovered = inspect({first, installed, pending, handed, resumed, complete(resumed, c)});
    require(recovered.size() == 2 && !recovered[1].repeated_completion &&
        usk::json::equal_values(recovered[1].original_active, pending));
    const auto ended_resume = active(pending, "repair", "op.interrupted", "attempt.ended-resume", b);
    const auto ended_recovered = inspect({first, installed, pending, ended_resume, complete(ended_resume, c)});
    require(ended_recovered.size() == 2 &&
        usk::json::equal_values(ended_recovered[1].original_active, pending));
    const auto unfinished = active(rebound, "repair", "op.unfinished", "attempt.unfinished", b);
    refuses([&] { (void)inspect({first, installed, reentry, rebound, unfinished}); });
    refuses([&] { (void)decode_owned_retirement_lease_history(std::vector<Value>(4097, first), id, root, b); });
    std::vector<Value> full{first, installed};
    for (unsigned i = 1; i < 2048; ++i) {
        const auto next = active(full.back(), "install_local", "op.install", "capacity." + std::to_string(i), b);
        full.push_back(next); full.push_back(complete(next, b));
    }
    require(full.size() == 4096 && inspect(full).size() == 2048);
    full.push_back(active(full.back(), "repair", "op.over-capacity", "capacity.extra", b));
    refuses([&] { (void)decode_owned_retirement_lease_history(full, id, root, b); });
}

// Collect only the ordinary fixture's historical inputs. Production admission
// must instead bind every byte/name/directory through its actual native owner.
usk::lifecycle::detail::CompletedMaintenanceHistoryBytes completed_bytes(
    const usk::transaction::TransactionSpec& spec)
{
    usk::lifecycle::detail::CompletedMaintenanceHistoryBytes result;
    const auto history = usk::transaction::TransactionSession::inspect_completed_history(spec);
    const auto context = usk::json::parse(history.stream.source_context);
    const auto id = context.at("install_id").as_string();
    result.transaction = read_text(spec.state_root / "transactions" / (spec.transaction_id + ".journal.json"));
    const auto directory = spec.state_root / "transactions" / (spec.transaction_id + ".maintenance");
    result.effect_directory_identity = usk::transaction::observe_directory_identity(directory);
    const auto collect = [](const fs::path& root) {
        std::vector<std::pair<std::string, std::string>> result;
        for (const auto& entry : fs::directory_iterator(root))
            result.emplace_back(entry.path().filename().string(), read_text(entry.path()));
        std::sort(result.begin(), result.end());
        return result;
    };
    result.effects = collect(directory);
    result.reviewed_plan = read_text(spec.state_root / "transactions" / context.at("reviewed_plan_ref").as_string());
    result.original_installed = read_text(spec.state_root / "installed" /
        (id + "." + context.at("original_installed_transaction_id").as_string() + ".json"));
    result.resulting_installed = read_text(spec.state_root / "installed" / (id + "." + spec.transaction_id + ".json"));
    const auto original = usk::state::decode_installed_record(result.original_installed);
    const auto installed = usk::state::decode_installed_record(result.resulting_installed);
    result.original_ownership = read_text(spec.state_root / original.ownership_manifest_ref);
    result.resulting_ownership = read_text(spec.state_root / installed.ownership_manifest_ref);
    result.audit = collect(spec.audit_root / "chains" / original.audit_chain_id);
    return result;
}

void completed_history_controls(const usk::transaction::TransactionSpec& spec, const fs::path& fixture_root)
{
    using usk::lifecycle::detail::decode_completed_maintenance_history;
    const auto bytes = completed_bytes(spec);
    const auto live = usk::lifecycle::detail::inspect_completed_maintenance_history(spec);
    const auto decoded = decode_completed_maintenance_history(spec, bytes);
    require(decoded.effects_complete && decoded.sealed && !decoded.pending && decoded.next_kind.empty() &&
        decoded.transaction_snapshot_sha256 == live.transaction_snapshot_sha256 &&
        decoded.history_digest == live.history_digest);
    // Positively prove the new route does not reopen even a repository parent.
    // RAII restores this owned fixture on all failures, leaving no moved tree.
    struct Withheld {
        fs::path original, hidden;
        explicit Withheld(fs::path path) : original(std::move(path)), hidden(original.string() + ".withheld") {
            fs::rename(original, hidden);
        }
        ~Withheld() { std::error_code error; fs::rename(hidden, original, error); }
    };
    {
        Withheld withheld(fixture_root);
        require(decode_completed_maintenance_history(spec, bytes).effects_complete);
        refuses([&] { (void)usk::lifecycle::detail::inspect_completed_maintenance_history(spec); });
    }
    for (unsigned variant = 0; variant != 11; ++variant) {
        auto bad = bytes;
        if (variant == 0) bad.effects.pop_back(); // no final seal
        if (variant == 1) std::swap(bad.effects[0], bad.effects[1]);
        if (variant == 2) bad.effects.push_back(bad.effects.back());
        if (variant == 3) bad.effect_directory_identity = "unbound";
        if (variant == 4) bad.reviewed_plan += " ";
        if (variant == 5) bad.original_installed = bytes.resulting_installed;
        if (variant == 6) bad.resulting_installed = bytes.original_installed;
        if (variant == 7) bad.audit.pop_back(); // completion event missing
        if (variant == 8) std::swap(bad.audit[0], bad.audit[1]);
        if (variant == 9) bad.resulting_ownership += " ";
        if (variant == 10) bad.transaction = std::string(16u * 1024u * 1024u + 1u, ' ');
        refuses([&] { (void)decode_completed_maintenance_history(spec, bad); });
    }
    auto moved = spec; moved.operation = "move";
    refuses([&] { (void)decode_completed_maintenance_history(moved, bytes); });
    std::cout << spec.operation << " complete byte history entered without live paths; metadata only\n";
}
// Metadata shape/association controls only. The synthetic historical fields
// confer no native creator, token, holder, currentness or retirement verdict.
void creator_records() {
    using usk::json::Value;
    using usk::lifecycle::detail::decode_maintenance_original_custody_record;
    using usk::lifecycle::detail::decode_maintenance_created_closure_record;
    using usk::lifecycle::detail::require_maintenance_created_closure_binding;
    const std::array<std::string, 5> bindings{
        "tx.original", std::string(64, 'a'), std::string(64, 'b'),
        std::string(64, 'c'), std::string(64, 'd')};
    const auto text = [](const Value& value) { return usk::json::canonical(value) + "\n"; };
    Value original(Value::Object{});
    for (const auto* key : {"schema", "transaction_id", "operation", "plan_digest",
            "original_context_sha256", "original_lease_ownership", "worker_security", "process_boundary",
            "registration_sha256", "authenticated_client", "original_consumer_completion",
            "installed_root", "installed_root_journal_identity", "original_objects"})
        original.as_object().emplace(key, Value());
    original.as_object().at("schema") = Value("usk.publisher.maintenance_original_custody.v2");
    const auto decoded = decode_maintenance_original_custody_record(text(original));
    require(usk::json::equal_values(decoded, original));
    for (const char* schema : {"usk.publisher.maintenance_original_custody.v3",
            "usk.publisher.maintenance_original_custody.v4"}) {
        auto child = original;
        child.as_object().at("schema") = Value(schema);
        child.as_object().emplace("broker_readback", Value(Value::Object{}));
        require(usk::json::equal_values(decode_maintenance_original_custody_record(text(child)), child));
        child.as_object().erase("broker_readback");
        refuses([&] { (void)decode_maintenance_original_custody_record(text(child)); });
    }
    for (unsigned variant = 0; variant != 5; ++variant) {
        auto bad = original;
        if (variant == 0) bad.as_object().emplace("unknown", Value(true));
        if (variant == 1) bad.as_object().erase("installed_root");
        if (variant == 2) bad.as_object().at("schema") = Value("usk.publisher.maintenance_original_custody.v1");
        if (variant == 3) bad.as_object().at("schema") = Value("usk.publisher.maintenance_original_custody.v5");
        if (variant == 4) bad.as_object().emplace("broker_readback", Value(Value::Object{}));
        refuses([&] { (void)decode_maintenance_original_custody_record(text(bad)); });
    }
    refuses([&] { (void)decode_maintenance_original_custody_record(text(original) + " "); });
    refuses([&] { (void)decode_maintenance_original_custody_record(usk::json::canonical(original)); });
    refuses([&] { (void)decode_maintenance_original_custody_record(std::string(16u * 1024u * 1024u + 1u, ' ')); });
    Value created(Value::Object{});
    for (const auto* key : {"schema", "transaction_id", "plan_digest", "original_context_sha256",
            "original_admission_sha256", "lease_ownership_sha256", "transaction_snapshot_sha256",
            "source_context", "worker_security", "process_boundary", "registration_sha256",
            "authenticated_client", "root", "root_parent", "target_parent", "root_native_identity", "created_objects"})
        created.as_object().emplace(key, Value());
    created.as_object().at("schema") = Value("usk.publisher.maintenance_created_closure.v2");
    const std::array<const char*, 5> fields{"transaction_id", "plan_digest", "original_context_sha256",
        "original_admission_sha256", "lease_ownership_sha256"};
    for (std::size_t i = 0; i < bindings.size(); ++i) created.as_object().at(fields[i]) = Value(bindings[i]);
    const auto parse = [&](const std::string& bytes, const std::array<std::string, 5>& expected) {
        auto value = decode_maintenance_created_closure_record(bytes, expected[0], expected[1]);
        require_maintenance_created_closure_binding(value, decoded, expected[2], expected[3], expected[4]);
        return value;
    };
    require(usk::json::equal_values(parse(text(created), bindings), created));
    for (std::size_t i = 0; i < bindings.size(); ++i) {
        auto wrong = bindings; wrong[i] = "different";
        refuses([&] { (void)parse(text(created), wrong); });
    }
    for (const auto* key : {"worker_security", "process_boundary", "registration_sha256", "authenticated_client"}) {
        auto bad = created; bad.as_object().at(key) = Value("different");
        refuses([&] { (void)parse(text(bad), bindings); });
    }
    for (unsigned variant = 0; variant != 3; ++variant) {
        auto bad = created;
        if (variant == 0) bad.as_object().emplace("unknown", Value(true));
        if (variant == 1) bad.as_object().erase("root");
        if (variant == 2) bad.as_object().at("schema") = Value("usk.publisher.maintenance_created_closure.v1");
        refuses([&] { (void)parse(text(bad), bindings); });
    }
    refuses([&] { (void)parse(text(created) + " ", bindings); });
    refuses([&] { (void)parse(std::string(16u * 1024u * 1024u + 1u, ' '), bindings); });
}
}
#if defined(_WIN32)
usk::platform::windows::PublisherHandleObservation historical_object(const usk::json::Value& v) {
    using namespace usk::platform::windows;
    PublisherHandleObservation o{};
    o.file_id=v.at("file_id").as_string();o.native_name=fs::u8path(v.at("native_name").as_string()).wstring();
    o.attributes=static_cast<std::uint32_t>(v.at("attributes").as_unsigned());
    o.reparse_tag=static_cast<std::uint32_t>(v.at("reparse_tag").as_unsigned());
    o.link_count=static_cast<std::uint32_t>(v.at("link_count").as_unsigned());
    o.case_sensitive=v.at("case_sensitive").as_boolean();o.owner_sid=v.at("owner_sid").as_string();
    o.dacl_protected=v.at("dacl_protected").as_boolean();
    for(const auto& ace:v.at("dacl_aces").as_array())
        o.dacl_aces.push_back({static_cast<std::uint8_t>(ace.at("type").as_unsigned()),
            static_cast<std::uint8_t>(ace.at("flags").as_unsigned()),
            static_cast<std::uint32_t>(ace.at("access_mask").as_unsigned()),ace.at("sid").as_string()});
    return o;
}
std::string historical_raw_sha(const std::string& text) {
    usk::base::Sha256 hash;
    hash.update(reinterpret_cast<const unsigned char*>(text.data()),text.size());return hash.finish();
}
void historical_boundary_controls(const usk::lifecycle::detail::OwnedPublisherRetirementHistory& history,
    const std::wstring& service)
{
    using usk::json::Value;using namespace usk::lifecycle::detail;
    using usk::platform::windows::PublisherRetirementRecord;
    std::map<std::wstring,const PublisherRetirementRecord*> records;
    for(const auto& record:history.records) records.emplace(record.relative_path,&record);
    const auto& snapshot=*records.at(L"publication\\journal\\lab-reviewed-plan.json");
    const auto& prepared=*records.at(L"publication\\journal\\lab-prepared-evidence.json");
    const auto& visible=*records.at(L"publication\\journal\\lab-visible-evidence.json");
    const auto& completion=*records.at(L"publication\\state\\lab-installed-state.json");
    const auto consumer=usk::json::parse(snapshot.bytes).at("consumer_read_sid").as_string();
    const auto sid=history.registration.at("service_sid").as_string();
    const auto bad_initial=[&](Value wrong) {
        auto adjusted=usk::json::parse(completion.bytes);
        const auto changed=usk::json::canonical(wrong)+"\n";
        adjusted.as_object().at("visible_record_sha256")=Value(historical_raw_sha(changed));
        refuses([&]{(void)decode_owned_retirement_install_history(snapshot.bytes,prepared.bytes,changed,
            usk::json::canonical(adjusted)+"\n",service,sid,consumer);});
    };
    auto wrong=usk::json::parse(visible.bytes);
    wrong.as_object().at("prepared_record_sha256")=Value(std::string(64,'0'));bad_initial(wrong);
    wrong=usk::json::parse(visible.bytes);
    wrong.as_object().at("source_file_id")=usk::json::parse(prepared.bytes).at("destination_parent_file_id");bad_initial(wrong);
    // Retained original x64 calls must not acquire the current reader's ABI.
    // This default fixture's positive route runs under both x86 and x64 CTest.
    for(const auto header_bytes:{16u,20u,32u}) {
        wrong=usk::json::parse(visible.bytes);
        auto& call=wrong.as_object().at("rename_call");
        call.as_object().at("information_bytes")=Value(static_cast<std::uint64_t>(header_bytes)+
            call.at("file_name_bytes").as_unsigned());bad_initial(wrong);
    }
    wrong=usk::json::parse(visible.bytes);
    wrong.as_object().at("execution_phases").as_array()[0].as_object().at("execution")
        .as_object().at("platform").as_object().at("process_arch")=Value("x86");bad_initial(wrong);

    const auto original_entry=std::find_if(records.begin(),records.end(),[](const auto& entry) {
        return entry.first.find(L".native-maintenance-original.json")!=std::wstring::npos &&
            usk::json::parse(entry.second->bytes).at("operation").as_string()=="repair";
    });
    require(original_entry!=records.end());
    auto base=original_entry->first;
    base.resize(base.size()-std::wstring(L".native-maintenance-original.json").size());
    const auto& journal=*records.at(base+L".journal.json");
    const auto document=usk::json::parse(journal.bytes);
    usk::transaction::TransactionSpec spec;
    spec.transaction_id=document.at("transaction_id").as_string();spec.plan_id=document.at("plan_id").as_string();
    spec.plan_digest=document.at("plan_digest").as_string();spec.operation="repair";
    for(const auto& root:document.at("roots").as_array()) {
        const auto path=fs::u8path(root.at("root").as_string());const auto role=root.at("role").as_string();
        if(role=="target") spec.target_root=path;
        if(role=="staging") spec.staging_parent=path.parent_path();
        if(role=="setup_state") spec.state_root=path;
        if(role=="audit") spec.audit_root=path;
    }
    const auto completed=usk::transaction::TransactionSession::decode_completed_history(spec,journal.bytes);
    const auto effects_path=base+L".maintenance";
    usk::transaction::MaintenanceEffectRecordReader reader(spec,history.directories.at(effects_path).journal_identity,
        completed.stream.source_digest,
        static_cast<std::size_t>(std::count_if(records.begin(),records.end(),[&](const auto& item) {
            return fs::path(item.first).parent_path()==fs::path(effects_path);
        })),true);
    std::vector<Value> custody;
    const PublisherRetirementRecord* prefix=nullptr;
    for(const auto& entry:records) {
        const auto directory=fs::path(entry.first).parent_path();
        if(directory==fs::path(effects_path)) reader.consume(fs::path(entry.first).filename().u8string(),entry.second->bytes);
        if(directory==fs::path(base+L".native-maintenance-custody")) custody.push_back(usk::json::parse(entry.second->bytes));
        if(directory==fs::path(base+L".native-maintenance-snapshots")) prefix=entry.second;
    }
    require(prefix!=nullptr && !custody.empty());
    const auto effects=reader.finish();
    using usk::transaction::TransactionSession;
    TransactionSession::require_completed_transition_extension_bytes(spec,prefix->bytes,prefix->sha256,journal.bytes,journal.sha256);
    refuses([&]{TransactionSession::require_completed_transition_extension_bytes(spec,prefix->bytes+" ",prefix->sha256,journal.bytes,journal.sha256);});
    refuses([&]{TransactionSession::require_completed_transition_extension_bytes(spec,prefix->bytes,prefix->sha256,journal.bytes+" ",journal.sha256);});
    auto changed_prefix=usk::json::parse(prefix->bytes);
    changed_prefix.as_object().at("plan_id")=Value("plan.unrelated");
    const auto changed_text=usk::json::canonical(changed_prefix);
    refuses([&]{TransactionSession::require_completed_transition_extension_bytes(spec,changed_text,
        historical_raw_sha(changed_text),journal.bytes,journal.sha256);});
    const auto original=usk::json::parse(original_entry->second->bytes);
    const auto created=usk::json::parse(records.at(base+L".native-maintenance-created.json")->bytes);
    const auto artifact=usk::json::parse(records.at(base+L".maintenance-plan.json")->bytes);
    const auto root_id=usk::json::parse(completion.bytes).at("visible_root_file_id").as_string();
    const auto replay=[&](const Value& o,const Value& c,const std::vector<Value>& chain) {
        require_owned_retirement_object_history(spec,o,c,artifact,completed.stream,effects,chain,consumer,sid,root_id,"verified");
    };
    replay(original,created,custody);
    auto bad_original=original;
    auto file=std::find_if(bad_original.as_object().at("original_objects").as_array().begin(),
        bad_original.as_object().at("original_objects").as_array().end(),[](const Value& item){return item.at("type").as_string()=="file";});
    require(file!=bad_original.as_object().at("original_objects").as_array().end());
    file->as_object().at("object").as_object().at("native_name")=Value("\\publication\\destination\\another-root\\file");
    refuses([&]{replay(bad_original,created,custody);});
    bad_original=original;
    file=std::find_if(bad_original.as_object().at("original_objects").as_array().begin(),
        bad_original.as_object().at("original_objects").as_array().end(),[](const Value& item){return item.at("type").as_string()=="file";});
    file->as_object().at("parent")=created.at("target_parent");
    refuses([&]{replay(bad_original,created,custody);});
    auto bad_created=created;bad_created.as_object().at("created_objects").as_array().pop_back();
    refuses([&]{replay(original,bad_created,custody);});
    auto bad_custody=custody;
    auto grant=std::find_if(bad_custody.begin(),bad_custody.end(),[](const Value& v){return v.at("kind").as_string()=="consumer_read_grant";});
    require(grant!=bad_custody.end());
    grant->as_object().at("details").as_object().at("parent")=created.at("target_parent");
    refuses([&]{replay(original,created,bad_custody);});
    bad_custody=custody;
    grant=std::find_if(bad_custody.begin(),bad_custody.end(),[](const Value& v){return v.at("kind").as_string()=="consumer_read_grant";});
    auto& details=grant->as_object().at("details").as_object();
    details.at("before").as_object().at("file_id")=original.at("installed_root").at("file_id");
    details.at("after").as_object().at("file_id")=original.at("installed_root").at("file_id");
    details.at("native_identity")=original.at("installed_root_journal_identity");
    refuses([&]{replay(original,created,bad_custody);});
    // Reseal the complete custody chain so these discriminate the domain
    // binding, rather than failing only the outer raw-byte/hash-chain checks.
    for(unsigned variant=0;variant<2u;++variant) {
        auto bad=history;
        std::vector<usk::platform::windows::PublisherRetirementRecord*> chain;
        for(auto& record:bad.records)
            if(fs::path(record.relative_path).parent_path()==fs::path(base+L".native-maintenance-custody")) chain.push_back(&record);
        std::sort(chain.begin(),chain.end(),[](const auto* a,const auto* b){return a->relative_path<b->relative_path;});
        const auto unrelated=std::find_if(bad.records.begin(),bad.records.end(),[](const auto& record) {
            return record.relative_path.find(L"-active.json")!=std::wstring::npos &&
                usk::json::parse(record.bytes).at("operation").as_string()=="install_local";
        });
        require(unrelated!=bad.records.end());
        const auto prior=std::find_if(bad.records.begin(),bad.records.end(),[&](const auto& record) {
            return fs::path(record.relative_path).parent_path().filename()==fs::path("installed") &&
                usk::json::parse(record.bytes).at("transaction_id").as_string()==usk::json::parse(snapshot.bytes).at("transaction_id").as_string();
        });
        require(prior!=bad.records.end());
        bool changed=false;std::string previous;
        for(auto* record:chain) {
            auto value=usk::json::parse(record->bytes);
            value.as_object().at("previous_record_sha256")=previous.empty()?Value{}:Value(previous);
            if(variant==0u && !changed) {
                value.as_object().at("writer_lease_ownership")=usk::json::parse(unrelated->bytes);changed=true;
            } else if(variant==1u && value.at("kind").as_string()=="created_metadata" && !changed) {
                const auto intent=value.at("pending_intent_sequence").as_unsigned();
                const auto effect=std::find_if(effects.completed.begin(),effects.completed.end(),
                    [&](const auto& e){return e.intent_sequence==intent;});
                require(effect!=effects.completed.end());
                if(effect->kind=="write_installed") {
                    auto& data=value.as_object().at("details").as_object();
                    const auto setup=fs::u8path(usk::json::parse(snapshot.bytes).at("setup_root").as_string()).filename();
                    data.at("setup_relative_path")=Value(fs::path(prior->relative_path).lexically_relative(setup).generic_u8string());
                    data.at("object")=usk::platform::windows::publisher_handle_observation_json(prior->object);
                    data.at("parent")=usk::platform::windows::publisher_handle_observation_json(
                        history.directories.at(fs::path(prior->relative_path).parent_path().wstring()).object);
                    data.at("size_bytes")=Value(static_cast<std::uint64_t>(prior->bytes.size()));data.at("sha256")=Value(prior->sha256);
                    changed=true;
                }
            }
            record->bytes=usk::json::canonical(value)+"\n";record->sha256=historical_raw_sha(record->bytes);previous=record->sha256;
        }
        require(changed);
        refuses([&]{(void)validate_owned_publisher_retirement_history(bad,service);});
    }
}
void owned_retirement_history_controls(const fs::path& path) {

    using usk::json::Value;
    using namespace usk::lifecycle::detail;
    usk::json::ParseLimits limits;limits.max_bytes=16u*1024u*1024u;limits.max_values=2000000;
    const auto input=usk::json::parse(read_text(path),limits);
    OwnedPublisherRetirementHistory history;
    history.registration=input.at("registration");history.volume_root=fs::u8path(input.at("volume_root").as_string()).wstring();
    const auto service=fs::u8path(input.at("service_name").as_string()).wstring();
    for(const auto& value:input.at("records").as_array()) {
        usk::platform::windows::PublisherRetirementRecord record{};
        record.relative_path=fs::u8path(value.at("path").as_string()).wstring();record.object=historical_object(value.at("object"));
        record.bytes=value.at("text").as_string();record.sha256=value.at("sha256").as_string();
        history.records.push_back(std::move(record));
    }
    for(const auto& value:input.at("directories").as_array()) {
        usk::platform::windows::PublisherRetirementDirectoryMetadata directory{};
        directory.object=historical_object(value.at("object"));
        directory.lease_root_identity=value.at("lease_root_identity");directory.journal_identity=value.at("journal_identity").as_string();
        require(history.directories.emplace(fs::u8path(value.at("path").as_string()).wstring(),std::move(directory)).second);
    }
    const auto selected=validate_owned_publisher_retirement_history(history,service);
    historical_boundary_controls(history,service);
    require(selected.installation_ids.size()==1u && !selected.historical_holders.empty() &&
        !selected.reviewed_volume_paths.empty());
    // Exercise the actual native custody's generic relative-path projection.
    // Native observations/bytes are identical; only lookup separators differ.
    auto native=history;
    for(auto& record:native.records)
        std::replace(record.relative_path.begin(),record.relative_path.end(),L'\\',L'/');
    decltype(native.directories) native_directories;
    for(const auto& directory:native.directories) {
        auto name=directory.first;std::replace(name.begin(),name.end(),L'\\',L'/');
        require(native_directories.emplace(name,directory.second).second);
    }
    native.directories=std::move(native_directories);
    const auto native_selected=validate_owned_publisher_retirement_history(native,service);
    require(native_selected.installation_ids==selected.installation_ids &&
        native_selected.reviewed_volume_paths==selected.reviewed_volume_paths &&
        usk::json::equal_values(Value(Value::Array(native_selected.historical_holders)),
            Value(Value::Array(selected.historical_holders))));
    auto alias=native;alias.records.push_back(history.records.front());
    refuses([&]{(void)validate_owned_publisher_retirement_history(alias,service);});
    alias=native;
    const auto directory_alias=std::find_if(history.directories.begin(),history.directories.end(),
        [](const auto& entry){return entry.first.find(L'\\')!=std::wstring::npos;});
    require(directory_alias!=history.directories.end() && alias.directories.emplace(*directory_alias).second);
    refuses([&]{(void)validate_owned_publisher_retirement_history(alias,service);});
    auto bad=history;bad.volume_root=L"invalid";
    refuses([&]{(void)validate_owned_publisher_retirement_history(bad,service);});
    bad=history;bad.records.push_back(history.records.front());
    refuses([&]{(void)validate_owned_publisher_retirement_history(bad,service);});
    bad=history;bad.directories.emplace(L"unexplained-owned-root",history.directories.begin()->second);
    refuses([&]{(void)validate_owned_publisher_retirement_history(bad,service);});
    bad=history;bad.records.front().bytes+=" ";
    refuses([&]{(void)validate_owned_publisher_retirement_history(bad,service);});
    for(const auto* suffix:{L"lab-prepared-evidence.json",L"lab-visible-evidence.json",L"lab-installed-state.json",
            L".native-maintenance-original.json",L".native-maintenance-created.json",L"-roots.json",
            L"-active.json",L".event.json"}) {
        bad=history;
        const auto found=std::find_if(bad.records.begin(),bad.records.end(),[&](const auto& record){
            const std::wstring wanted(suffix);
            return record.relative_path.size()>=wanted.size() &&
                record.relative_path.compare(record.relative_path.size()-wanted.size(),wanted.size(),wanted)==0;});
        require(found!=bad.records.end());bad.records.erase(found);
        refuses([&]{(void)validate_owned_publisher_retirement_history(bad,service);});
    }
    std::cout<<"owned retirement metadata history: "<<selected.installation_ids.size()
        <<" installations, "<<selected.historical_holders.size()<<" historical holders; no native authority\n";
}
#endif
int main(int argc, char** argv) {
    try {
        creator_records();
        retirement_lease_controls();
#if defined(_WIN32)
        if(argc==1) owned_retirement_history_controls(fs::path(USK_SOURCE_DIR)/
            "tests/fixtures/setup/publisher-owned-uninstall-retirement-b6f4f28.v1.json");
        if(argc==3 && std::string(argv[1])=="--owned-retirement-history") {
            owned_retirement_history_controls(fs::u8path(argv[2]));return 0;
        }
#endif
        if (argc == 3 && std::string(argv[1]) == "--retirement-lease-history") {
            const auto input = usk::json::parse(read_text(argv[2]));
            require(input.as_object().size() == 4);
            const auto completions = usk::lifecycle::detail::decode_owned_retirement_lease_history(
                input.at("history").as_array(), input.at("install_id").as_string(),
                input.at("state_root_identity"), input.at("current_revision").as_string());
            std::size_t repeated = 0;
            for (const auto& completion : completions) if (completion.repeated_completion) ++repeated;
            std::cout << "retained lease metadata: " << completions.size() << " completions, " << repeated
                << " repeated; no native authority\n";
            return 0;
        }
        if (argc != 1) {
            // Optional replay of retained record bytes and separately supplied
            // bindings. This exercises metadata only; no native actor is made.
            require(argc == 5 && std::string(argv[1]) == "--creator-records");
            using usk::lifecycle::detail::decode_maintenance_original_custody_record;
            using usk::lifecycle::detail::decode_maintenance_created_closure_record;
            using usk::lifecycle::detail::require_maintenance_created_closure_binding;
            const auto original = decode_maintenance_original_custody_record(read_text(argv[2]));
            const auto bindings = usk::json::parse(read_text(argv[4]));
            const auto created = decode_maintenance_created_closure_record(read_text(argv[3]),
                bindings.at("transaction_id").as_string(), bindings.at("plan_digest").as_string());
            require_maintenance_created_closure_binding(created, original,
                bindings.at("original_context_sha256").as_string(),
                bindings.at("original_admission_sha256").as_string(),
                bindings.at("lease_ownership_sha256").as_string());
            std::cout << "retained creator metadata matches supplied bindings; no native authority\n";
            return 0;
        }
        using usk::transaction::TransactionSession;
        using usk::transaction::MaintenanceEffectJournal;
        using usk::transaction::MaintenanceEffectRecordReader;
        Fixture fixture;
        const auto target = fixture.root / "payload";
        usk::lifecycle::RecipeBinding recipe;
        recipe.product_id = "product.retirement";
        recipe.product_version = "1.0.0";
        recipe.recipe_digest = std::string(64, '1');
        recipe.source_archive_digest = std::string(64, '2');
        recipe.policy_digest = std::string(64, '3');
        recipe.provider_revision = "reader-fixture";
        recipe.components = {"core"};
        recipe.entrypoints = {{"application", "data.bin", "application"}};
        usk::lifecycle::PayloadFile payload;
        payload.relative_path = "data.bin";
        payload.bytes = {'d', 'a', 't', 'a'};
        const std::vector<usk::lifecycle::PayloadFile> files{payload};
        const auto install = usk::lifecycle::plan_install("plan.install", "install.readers",
            "2026-10-18T00:00:00Z", target, fixture.roots, recipe, files);
        (void)usk::lifecycle::apply_install(install, install.plan_digest,
            "tx.install", "2026-10-18T00:00:01Z");
        // An ordinary legacy ownership lookup may name the installation
        // rather than the manifest ID. Retain the canonical manifest too.
        auto legacy = usk::state::StateRepository(fixture.roots.state_root).read_installed("install.readers");
        const auto alias = fixture.roots.state_root / "ownership" / (legacy.install_id + ".json");
        fs::copy_file(fixture.roots.state_root / legacy.ownership_manifest_ref, alias);
        legacy.ownership_manifest_ref = "ownership/" + legacy.install_id + ".json";
        {
            std::ofstream record(fixture.roots.state_root / "installed" /
                (legacy.install_id + "." + legacy.transaction_id + ".json"), std::ios::binary | std::ios::trunc);
            record << usk::state::serialize_installed_state(legacy);
        }
        // Exercise the complete repair history too, including an actual
        // replacement and backup cleanup before uninstalling the same root.
        {
            std::ofstream damage(target / "data.bin", std::ios::binary | std::ios::trunc);
            damage << "damage";
        }
        const auto repair = usk::lifecycle::plan_repair(fixture.roots, "install.readers", "plan.repair",
            "2026-10-18T00:00:02Z", files);
        (void)usk::lifecycle::apply_repair(repair, repair.plan_digest, "tx.repair", "2026-10-18T00:00:03Z");
        const usk::transaction::TransactionSpec repair_spec{"tx.repair", repair.plan_id, repair.plan_digest, "repair",
            fixture.roots.staging_parent, target.parent_path() / ".usk-repair-tx.repair",
            fixture.roots.state_root, fixture.roots.audit_root};
        completed_history_controls(repair_spec, fixture.root);
        const auto plan = usk::lifecycle::plan_uninstall(fixture.roots, "install.readers",
            "plan.uninstall", "2026-10-18T00:00:04Z");
        const std::string tx = "tx.uninstall";
        const auto removed = usk::lifecycle::apply_uninstall(plan, plan.plan_digest,
            tx, "2026-10-18T00:00:05Z");
        require(removed.target_removed && !fs::exists(target));
        const usk::transaction::TransactionSpec spec{tx, plan.plan_id, plan.plan_digest, "uninstall",
            fixture.roots.staging_parent, target.parent_path() / (".usk-uninstall-" + tx),
            fixture.roots.state_root, fixture.roots.audit_root};
        completed_history_controls(spec, fixture.root);
        const auto journal = spec.state_root / "transactions" / (tx + ".journal.json");
        const auto text = read_text(journal);
        const auto baseline = TransactionSession::inspect_completed_history(spec);
        const auto decoded = TransactionSession::decode_completed_history(spec, text);
        require(decoded.journal_digest == baseline.journal_digest &&
            decoded.snapshot_sha256 == baseline.snapshot_sha256 &&
            decoded.recorded_at == baseline.recorded_at &&
            decoded.stream.source_digest == baseline.stream.source_digest);
        auto wrong = spec; wrong.transaction_id = "tx.other";
        refuses([&] { (void)TransactionSession::decode_completed_history(wrong, text); });
        auto altered = usk::json::parse(text);
        altered.as_object().at("current_state") = usk::json::Value("committing");
        refuses([&] { (void)TransactionSession::decode_completed_history(spec, usk::json::canonical(altered)); });
        altered = usk::json::parse(text);
        altered.as_object().at("journal_digest") = usk::json::Value(std::string(64, '0'));
        refuses([&] { (void)TransactionSession::decode_completed_history(spec, usk::json::canonical(altered)); });
        fs::rename(journal, journal.string() + ".withheld");
        require(TransactionSession::decode_completed_history(spec, text).snapshot_sha256 == baseline.snapshot_sha256);
        refuses([&] { (void)TransactionSession::inspect_completed_history(spec); });
        // The original native reader also needs to validate the first durable
        // source context before any effect record exists. This supplied-byte
        // check must remain independent of the original journal's pathname.
        require_maintenance_source_context(spec, baseline.stream.source_context);
        refuses([&] { require_maintenance_source_context(wrong, baseline.stream.source_context); });
        auto wrong_role = spec; wrong_role.operation = "repair";
        refuses([&] { require_maintenance_source_context(wrong_role, baseline.stream.source_context); });
        auto wrong_plan = spec; wrong_plan.plan_digest = std::string(64, '0');
        refuses([&] { require_maintenance_source_context(wrong_plan, baseline.stream.source_context); });
        auto wrong_root = spec; wrong_root.state_root /= "other";
        refuses([&] { require_maintenance_source_context(wrong_root, baseline.stream.source_context); });
        refuses([&] { require_maintenance_source_context(spec, baseline.stream.source_context + " "); });
        refuses([&] { require_maintenance_source_context(spec, std::string(16385u, ' ')); });
        auto invalid_context = usk::json::parse(baseline.stream.source_context);
        invalid_context.as_object().at("policy_digest") = usk::json::Value("invalid");
        refuses([&] { require_maintenance_source_context(spec, usk::json::canonical(invalid_context)); });
        // Data-shape validation cannot establish an original install binding.
        // The native owner must compare even a well-formed different ID.
        auto different_install = usk::json::parse(baseline.stream.source_context);
        different_install.as_object().at("install_id") = usk::json::Value("other.install");
        require_maintenance_source_context(spec, usk::json::canonical(different_install));

        fs::rename(journal.string() + ".withheld", journal);

        const auto directory = spec.state_root / "transactions" / (tx + ".maintenance");
        std::vector<fs::path> paths;
        for (const auto& entry : fs::directory_iterator(directory)) paths.push_back(entry.path());
        std::sort(paths.begin(), paths.end());
        std::vector<Record> records;
        for (const auto& path : paths) records.push_back({path.filename().string(), read_text(path)});
        require(records.size() > 3);
        const auto identity = usk::transaction::observe_directory_identity(directory);
        const auto source_digest = baseline.stream.source_digest;
        const auto expected = MaintenanceEffectJournal::inspect(spec, source_digest, true);
        MaintenanceEffectRecordReader reader(spec, identity, source_digest, records.size(), true);
        for (const auto& record : records) reader.consume(record.name, record.text);
        const auto observed = reader.finish();
        require(observed.sealed && observed.pending_kind.empty() &&
            observed.journal_digest == expected.journal_digest && observed.source_context == expected.source_context &&
            observed.next_sequence == expected.next_sequence && observed.serialized_bytes == expected.serialized_bytes &&
            observed.completed.size() == expected.completed.size() && observed.directory_identity == identity);
        for (std::size_t i = 0; i < observed.completed.size(); ++i) {
            const auto& a = observed.completed[i]; const auto& b = expected.completed[i];
            require(a.intent_sequence == b.intent_sequence && a.kind == b.kind && a.outcome == b.outcome &&
                a.result_digest == b.result_digest && usk::json::canonical(a.details) == usk::json::canonical(b.details));
        }
        refuses([&] { (void)reader.finish(); });
        refuses([&] { reader.consume(records[0].name, records[0].text); });
        MaintenanceEffectRecordReader incomplete(spec, identity, source_digest, records.size());
        incomplete.consume(records[0].name, records[0].text);
        refuses([&] { (void)incomplete.finish(); });
        refuses([&] { incomplete.consume(records[1].name, records[1].text); });
        for (unsigned variant = 0; variant != 4; ++variant) {
            MaintenanceEffectRecordReader failed(spec, identity, source_digest, records.size());
            failed.consume(records[0].name, records[0].text);
            const auto index = variant == 0 ? 2u : 1u;
            const auto name = variant == 1 ? records[0].name : records[index].name;
            const auto bytes = variant == 2 ? records[index].text + " " :
                variant == 3 ? std::string(32769u, ' ') : records[index].text;
            refuses([&] { failed.consume(name, bytes); });
            refuses([&] { (void)failed.finish(); });
        }
        refuses([&] { MaintenanceEffectRecordReader invalid(spec, identity, source_digest, 0); });
        refuses([&] { MaintenanceEffectRecordReader invalid(spec, identity, source_digest, 200003u); });
        MaintenanceEffectRecordReader wrong_directory(spec, "unbound", source_digest, records.size());
        refuses([&] { wrong_directory.consume(records[0].name, records[0].text); });
        refuses([&] { (void)wrong_directory.finish(); });
        // A valid context+intent prefix describes uncertainty, not completion.
        MaintenanceEffectRecordReader prefix(spec, identity, source_digest, 2);
        prefix.consume(records[0].name, records[0].text);
        prefix.consume(records[1].name, records[1].text);
        const auto pending = prefix.finish();
        require(!pending.sealed && !pending.pending_kind.empty());

        const auto& chain_id = removed.installed_state.audit_chain_id;
        const auto chain = usk::audit::AuditRepository(spec.audit_root).read_and_validate_chain(chain_id);
        require(!chain.empty());
        const auto audit_root = spec.audit_root / "chains" / chain_id;
        std::vector<fs::path> audit_paths;
        for (const auto& entry : fs::directory_iterator(audit_root)) audit_paths.push_back(entry.path());
        std::sort(audit_paths.begin(), audit_paths.end());
        require(audit_paths.size() == chain.size());
        std::string previous;
        for (std::size_t i = 0; i < audit_paths.size(); ++i) {
            const auto bytes = read_text(audit_paths[i]);
            const auto event = usk::audit::decode_audit_chain_record(bytes, chain_id,
                audit_paths[i].filename().string(), i, previous);
            require(event.event_digest == chain[i].event_digest);
            refuses([&] { (void)usk::audit::decode_audit_chain_record(bytes, "other.chain",
                audit_paths[i].filename().string(), i, previous); });
            refuses([&] { (void)usk::audit::decode_audit_chain_record(bytes, chain_id,
                "unbound.event.json", i, previous); });
            refuses([&] { (void)usk::audit::decode_audit_chain_record(bytes, chain_id,
                audit_paths[i].filename().string(), i, std::string(64, '0')); });
            previous = event.event_digest;
        }
        std::cout << "completed transaction, streaming effects and audit links retain metadata/context boundaries\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
