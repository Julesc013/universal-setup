#include "usk_audit_repository.h"
#include "usk_lifecycle.h"
#include "usk_state_repository.h"
#include "usk_transaction_session.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

struct Fixture {
    fs::path root;
    usk::lifecycle::LifecycleRoots roots;

    Fixture()
    {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        root = fs::temp_directory_path() / ("usk-adversarial-" + std::to_string(nonce));
        roots = {root / "staging", root / "state", root / "audit"};
        fs::create_directories(roots.staging_parent);
        fs::create_directories(roots.state_root);
        fs::create_directories(roots.audit_root);
        usk::state::StateRepository::initialize_layout(roots.state_root);
        fs::create_directory(roots.state_root / "transactions");
        usk::audit::AuditRepository::initialize_layout(roots.audit_root);
        fs::create_directory(root / "targets");
    }

    ~Fixture()
    {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }
};

bool refuses(const std::function<void()>& operation)
{
    try {
        operation();
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

usk::lifecycle::RecipeBinding recipe(const std::string& product = "product.adversarial")
{
    return {product, "1.0.0",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "adversarial-provider-r1", {"core"},
        {{"application", "app/bin/program.exe", "application"}}};
}

std::vector<usk::lifecycle::PayloadFile> payload()
{
    return {{"app/bin/program.exe", {'p', 'r', 'o', 'g', 'r', 'a', 'm'}},
            {"app/data.txt", {'d', 'a', 't', 'a'}}};
}

void write_text(const fs::path& path, const std::string& value)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << value;
}

int plan_law(Fixture& fixture)
{
    auto expect_payload_refusal = [&](std::vector<usk::lifecycle::PayloadFile> files) {
        return refuses([&] {
            (void)usk::lifecycle::plan_install(
                "plan.refusal", "install.refusal", "2026-07-14T01:00:00Z",
                fixture.root / "targets/refusal", fixture.roots, recipe(), std::move(files));
        });
    };
    if (!expect_payload_refusal({{"NUL.txt", {'x'}}, {"app/bin/program.exe", {'x'}}}) ||
        !expect_payload_refusal({{"Case.txt", {'x'}}, {"case.TXT", {'y'}},
                                 {"app/bin/program.exe", {'x'}}}) ||
        !expect_payload_refusal({{std::string("unicode-") + "\xc3\xa9", {'x'}},
                                 {"app/bin/program.exe", {'x'}}}) ||
        !expect_payload_refusal({{std::string(4097, 'a'), {'x'}},
                                 {"app/bin/program.exe", {'x'}}}) ||
        !refuses([&] {
            (void)usk::lifecycle::plan_install(
                "plan.bad-time", "install.bad-time", "not-a-time",
                fixture.root / "targets/bad-time", fixture.roots, recipe(), payload());
        })) {
        return 1;
    }
    return 0;
}

bool establish_atomic_commit(Fixture& fixture)
{
    const auto plan = usk::lifecycle::plan_install(
        "plan.capability", "install.capability", "2026-07-14T01:00:01Z",
        fixture.root / "targets/capability", fixture.roots, recipe(), payload());
    try {
        (void)usk::lifecycle::apply_install(
            plan, plan.plan_digest, "tx.capability", "2026-07-14T01:00:02Z");
        return true;
    } catch (const usk::transaction::NoReplaceCommitUnavailable&) {
        return false;
    }
}

int target_and_source_drift(Fixture& fixture)
{
    const fs::path occupied = fixture.root / "targets/substituted";
    const auto occupied_plan = usk::lifecycle::plan_install(
        "plan.substitution", "install.substitution", "2026-07-14T01:01:00Z",
        occupied, fixture.roots, recipe(), payload());
    fs::create_directory(occupied);
    write_text(occupied / "sentinel", "retain");
    if (!refuses([&] {
            (void)usk::lifecycle::apply_install(
                occupied_plan, occupied_plan.plan_digest, "tx.substitution", "2026-07-14T01:01:01Z");
        }) || !fs::is_regular_file(occupied / "sentinel")) {
        return 10;
    }

    const fs::path source = fixture.root / "targets/source-drift";
    const auto install = usk::lifecycle::plan_install(
        "plan.source-drift.install", "install.source-drift", "2026-07-14T01:01:02Z",
        source, fixture.roots, recipe(), payload());
    (void)usk::lifecycle::apply_install(
        install, install.plan_digest, "tx.source-drift.install", "2026-07-14T01:01:03Z");
    const fs::path destination = fixture.root / "targets/source-drift-moved";
    const auto move = usk::lifecycle::plan_move(
        fixture.roots, "install.source-drift", "plan.source-drift.move",
        "2026-07-14T01:01:04Z", destination);
    write_text(source / "app/data.txt", "changed-after-plan");
    if (!refuses([&] {
            (void)usk::lifecycle::apply_move(
                move, move.plan_digest, "tx.source-drift.move", "2026-07-14T01:01:05Z");
        }) || fs::exists(destination)) {
        return 11;
    }
    return 0;
}

int foreign_content_races(Fixture& fixture)
{
    const fs::path target = fixture.root / "targets/foreign-race";
    const auto install = usk::lifecycle::plan_install(
        "plan.foreign.install", "install.foreign", "2026-07-14T01:02:00Z",
        target, fixture.roots, recipe(), payload());
    (void)usk::lifecycle::apply_install(
        install, install.plan_digest, "tx.foreign.install", "2026-07-14T01:02:01Z");
    write_text(target / "app/data.txt", "damaged");
    const auto repair = usk::lifecycle::plan_repair(
        fixture.roots, "install.foreign", "plan.foreign.repair",
        "2026-07-14T01:02:02Z", payload());
    write_text(target / "arrived-during-repair.txt", "retain");
    const auto repaired = usk::lifecycle::apply_repair(
        repair, repair.plan_digest, "tx.foreign.repair", "2026-07-14T01:02:03Z");
    if (repaired.after.status != "warn" ||
        !fs::is_regular_file(target / "arrived-during-repair.txt")) return 20;

    fs::remove(target / "arrived-during-repair.txt");
    const auto uninstall = usk::lifecycle::plan_uninstall(
        fixture.roots, "install.foreign", "plan.foreign.uninstall", "2026-07-14T01:02:04Z");
    write_text(target / "arrived-after-uninstall-plan.txt", "retain");
    if (!refuses([&] {
            (void)usk::lifecycle::apply_uninstall(
                uninstall, uninstall.plan_digest, "tx.foreign.uninstall", "2026-07-14T01:02:05Z");
        }) || !fs::is_regular_file(target / "app/bin/program.exe") ||
        !fs::is_regular_file(target / "arrived-after-uninstall-plan.txt")) {
        return 21;
    }
    auto older = usk::lifecycle::plan_uninstall(
        fixture.roots, "install.foreign", "plan.foreign.old-time", "2026-07-14T01:02:06Z");
    if (!refuses([&] {
            (void)usk::lifecycle::apply_uninstall(
                older, older.plan_digest, "tx.foreign.old-time", "2026-07-14T01:01:00Z");
        })) {
        return 22;
    }
    return 0;
}

int concurrent_writers(Fixture& fixture)
{
    const fs::path target = fixture.root / "targets/concurrent";
    const auto left = usk::lifecycle::plan_install(
        "plan.concurrent.left", "install.concurrent.left", "2026-07-14T01:03:00Z",
        target, fixture.roots, recipe("product.concurrent.left"), payload());
    const auto right = usk::lifecycle::plan_install(
        "plan.concurrent.right", "install.concurrent.right", "2026-07-14T01:03:00Z",
        target, fixture.roots, recipe("product.concurrent.right"), payload());
    std::atomic<int> succeeded{0};
    std::atomic<int> refused_count{0};
    auto apply = [&](const usk::lifecycle::InstallPlan& plan, const std::string& transaction) {
        try {
            (void)usk::lifecycle::apply_install(
                plan, plan.plan_digest, transaction, "2026-07-14T01:03:01Z");
            ++succeeded;
        } catch (const std::exception&) {
            ++refused_count;
        }
    };
    std::thread first(apply, std::cref(left), "tx.concurrent.left");
    std::thread second(apply, std::cref(right), "tx.concurrent.right");
    first.join();
    second.join();
    if (succeeded != 1 || refused_count != 1 || !fs::is_regular_file(target / "app/data.txt")) return 30;

    usk::audit::AuditRepository audit(fixture.roots.audit_root);
    audit.initialize_chain("audit.concurrent-append");
    std::atomic<int> audit_success{0};
    std::atomic<int> audit_refused{0};
    auto append = [&] {
        try {
            audit.append("audit.concurrent-append", usk::audit::AuditInput{
                "2026-07-14T01:03:02Z", "verify", "completed", "pass", "installation",
                "install.concurrent", std::string(64, '5'), {}, {}, "concurrent append"});
            ++audit_success;
        } catch (const std::exception&) {
            ++audit_refused;
        }
    };
    std::thread audit_left(append);
    std::thread audit_right(append);
    audit_left.join();
    audit_right.join();
    const auto events = audit.read_and_validate_chain("audit.concurrent-append");
    const int successes = audit_success.load();
    const int refusals = audit_refused.load();
    if (successes < 1 || successes > 2 || successes + refusals != 2 ||
        events.size() != static_cast<std::size_t>(successes)) {
        std::cerr << "audit concurrency result is not a complete valid chain: success="
                  << successes << " refused=" << refusals
                  << " events=" << events.size() << '\n';
        return 31;
    }
    return 0;
}

int bounded_scale(Fixture& fixture)
{
    auto files = payload();
    for (int index = 0; index < 256; ++index) {
        const std::string name = "bulk/group-" + std::to_string(index / 32) +
            "/file-" + std::to_string(index) + ".dat";
        files.push_back({name, std::vector<unsigned char>(128, static_cast<unsigned char>(index))});
    }
    const fs::path target = fixture.root / "targets/scale";
    const auto plan = usk::lifecycle::plan_install(
        "plan.scale", "install.scale", "2026-07-14T01:04:00Z",
        target, fixture.roots, recipe("product.scale"), std::move(files));
    const auto installed = usk::lifecycle::apply_install(
        plan, plan.plan_digest, "tx.scale", "2026-07-14T01:04:01Z");
    if (installed.ownership.files.size() != 258 || installed.verification.status != "pass") return 40;
    return 0;
}

int journal_root_tamper(Fixture& fixture)
{
    const fs::path target = fixture.root / "targets/journal-tamper";
    const auto plan = usk::lifecycle::plan_install(
        "plan.journal-tamper", "install.journal-tamper", "2026-07-14T01:05:00Z",
        target, fixture.roots, recipe(), payload());
    usk::transaction::TransactionSpec spec{
        "tx.journal-tamper", plan.plan_id, plan.plan_digest, "install_local",
        fixture.roots.staging_parent, target, fixture.roots.state_root, fixture.roots.audit_root};
    usk::transaction::TransactionSession transaction(spec);
    for (const auto& file : plan.files) transaction.stage_file(file.relative_path, file.bytes);
    transaction.mark_staged();
    transaction.mark_verified();
    transaction.commit_effect();
    transaction.mark_recovery_required();
    std::ifstream input(transaction.journal_path(), std::ios::binary);
    std::string text{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    input.close();
    const std::string marker = "\"role\":\"target\"";
    const std::size_t found = text.find(marker);
    if (found == std::string::npos) return 50;
    text.replace(found, marker.size(), "\"role\":\"source\"");
    write_text(transaction.journal_path(), text);
    if (!refuses([&] { (void)usk::transaction::TransactionSession::resume_finalization(spec); })) return 51;
    return 0;
}

int run()
{
    Fixture fixture;
    if (int result = plan_law(fixture)) return result;
    if (!establish_atomic_commit(fixture)) return 0;
    if (int result = target_and_source_drift(fixture)) return result;
    if (int result = foreign_content_races(fixture)) return result;
    if (int result = concurrent_writers(fixture)) return result;
    if (int result = bounded_scale(fixture)) return result;
    if (int result = journal_root_tamper(fixture)) return result;
    return 0;
}

} // namespace

int main()
{
    try {
        return run();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 250;
    }
}
