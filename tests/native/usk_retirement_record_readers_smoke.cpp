// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_lifecycle.h"
#include "usk_maintenance_creator_records_internal.h"
#include "usk_completed_maintenance_records_internal.h"
#include "usk_owned_retirement_lease_history_internal.h"
#include "usk_install_lease.h"
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
int main(int argc, char** argv) {
    try {
        creator_records();
        retirement_lease_controls();
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
