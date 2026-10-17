// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_lifecycle.h"
#include "usk_audit_repository.h"
#include "usk_maintenance_effect_journal.h"
#include "usk_transaction_session.h"
#include "usk_json.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
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
}
int main() {
    try {
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
        const auto plan = usk::lifecycle::plan_uninstall(fixture.roots, "install.readers",
            "plan.uninstall", "2026-10-18T00:00:02Z");
        const std::string tx = "tx.uninstall";
        const auto removed = usk::lifecycle::apply_uninstall(plan, plan.plan_digest,
            tx, "2026-10-18T00:00:03Z");
        require(removed.target_removed && !fs::exists(target));
        const usk::transaction::TransactionSpec spec{tx, plan.plan_id, plan.plan_digest, "uninstall",
            fixture.roots.staging_parent, target.parent_path() / (".usk-uninstall-" + tx),
            fixture.roots.state_root, fixture.roots.audit_root};
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
