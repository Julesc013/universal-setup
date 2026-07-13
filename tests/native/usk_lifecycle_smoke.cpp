#include "usk_audit_repository.h"
#include "usk_lifecycle.h"
#include "usk_state_repository.h"
#include "usk_transaction_session.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;

namespace {

struct Fixture {
    fs::path root;
    usk::lifecycle::LifecycleRoots roots;

    Fixture()
    {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        root = fs::temp_directory_path() / ("usk-lifecycle-" + std::to_string(nonce));
        roots.staging_parent = root / "staging";
        roots.state_root = root / "state";
        roots.audit_root = root / "audit";
        fs::create_directories(roots.staging_parent);
        fs::create_directories(roots.state_root);
        fs::create_directories(roots.audit_root);
        usk::state::StateRepository::initialize_layout(roots.state_root);
        fs::create_directory(roots.state_root / "transactions");
        usk::audit::AuditRepository::initialize_layout(roots.audit_root);
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

usk::lifecycle::RecipeBinding recipe()
{
    return usk::lifecycle::RecipeBinding{
        "product.synthetic",
        "1.0.0",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "synthetic-provider-r1",
        {"core"},
        {{"application", "app/bin/program.exe", "application"}}};
}

std::vector<usk::lifecycle::PayloadFile> payload()
{
    return {
        {"app/bin/program.exe", {'p', 'r', 'o', 'g', 'r', 'a', 'm'}},
        {"app/readme.txt", {'r', 'e', 'a', 'd', 'm', 'e'}}};
}

void write_text(const fs::path& path, const std::string& text)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << text;
}

int run()
{
    Fixture fixture;
    const fs::path target = fixture.root / "targets/portable";
    fs::create_directories(target.parent_path());
    const auto plan = usk::lifecycle::plan_install(
        "plan.synthetic.install", "install.synthetic", "2026-07-14T00:10:00Z",
        target, fixture.roots, recipe(), payload());
    if (plan.plan_digest.size() != 64 || fs::exists(target)) return 1;

    auto drifted = plan;
    drifted.files.front().bytes.push_back('!');
    if (!refuses([&] {
            (void)usk::lifecycle::apply_install(
                drifted, plan.plan_digest, "tx.synthetic.drift", "2026-07-14T00:10:01Z");
        }) || fs::exists(target)) {
        return 2;
    }

    usk::lifecycle::InstallResult result;
    try {
        result = usk::lifecycle::apply_install(
            plan, plan.plan_digest, "tx.synthetic.install", "2026-07-14T00:10:02Z");
    } catch (const usk::transaction::NoReplaceCommitUnavailable&) {
        const auto recovery = usk::transaction::TransactionSession::inspect_recovery(
            usk::transaction::TransactionSpec{
                "tx.synthetic.install", plan.plan_id, plan.plan_digest, "install_local",
                fixture.roots.staging_parent, target, fixture.roots.state_root, fixture.roots.audit_root});
        return recovery.current_state == "recovery_required" && recovery.staging_exists &&
            !recovery.target_exists ? 0 : 9;
    }
    if (result.verification.status != "pass" || result.installed_state.lifecycle_status != "installed" ||
        !fs::is_regular_file(target / "app/bin/program.exe") ||
        usk::transaction::TransactionSession::inspect_recovery(usk::transaction::TransactionSpec{
            "tx.synthetic.install", plan.plan_id, plan.plan_digest, "install_local",
            fixture.roots.staging_parent, target, fixture.roots.state_root, fixture.roots.audit_root}).current_state !=
            "completed") {
        return 3;
    }

    const auto verified = usk::lifecycle::verify_installed(
        fixture.roots, "install.synthetic", "verify.synthetic.1", "2026-07-14T00:10:03Z");
    if (verified.status != "pass" || verified.files.size() != 2 || !verified.unknown_paths.empty()) return 4;

    write_text(target / "app/readme.txt", "changed");
    const auto modified = usk::lifecycle::verify_installed(
        fixture.roots, "install.synthetic", "verify.synthetic.2", "2026-07-14T00:10:04Z");
    if (modified.status != "fail" || modified.modified_files != 1) return 5;

    write_text(target / "app/readme.txt", "readme");
    write_text(target / "user-created.txt", "retain");
    const auto foreign = usk::lifecycle::verify_installed(
        fixture.roots, "install.synthetic", "verify.synthetic.3", "2026-07-14T00:10:05Z");
    if (foreign.status != "warn" || foreign.unknown_paths != std::vector<std::string>{"user-created.txt"}) return 6;

    write_text(target / "app/readme.txt", "damaged-again");
    const auto repair_plan = usk::lifecycle::plan_repair(
        fixture.roots, "install.synthetic", "plan.synthetic.repair", "2026-07-14T00:10:06Z", payload());
    const auto repair_result = usk::lifecycle::apply_repair(
        repair_plan, repair_plan.plan_digest, "tx.synthetic.repair", "2026-07-14T00:10:07Z");
    if (repair_result.after.status != "warn" ||
        repair_result.repaired_files != std::vector<std::string>{"app/readme.txt"} ||
        repair_result.retained_unknown_paths != std::vector<std::string>{"user-created.txt"}) {
        return 7;
    }

    const fs::path moved_target = fixture.root / "targets/moved-portable";
    const auto move_plan = usk::lifecycle::plan_move(
        fixture.roots, "install.synthetic", "plan.synthetic.move", "2026-07-14T00:10:08Z", moved_target);
    const auto move_result = usk::lifecycle::apply_move(
        move_plan, move_plan.plan_digest, "tx.synthetic.move", "2026-07-14T00:10:09Z");
    if (move_result.verification.status != "warn" || !fs::is_directory(target) ||
        !fs::is_regular_file(moved_target / "app/bin/program.exe") ||
        !fs::is_regular_file(moved_target / "user-created.txt") ||
        move_result.installed_state.lifecycle_status != "move_pending_acceptance") {
        return 8;
    }

    const auto blocked_plan = usk::lifecycle::plan_uninstall(
        fixture.roots, "install.synthetic", "plan.synthetic.uninstall.blocked", "2026-07-14T00:10:10Z");
    const auto blocked = usk::lifecycle::apply_uninstall(
        blocked_plan, blocked_plan.plan_digest, "tx.synthetic.uninstall.blocked", "2026-07-14T00:10:11Z");
    if (blocked.target_removed || blocked.deleted_owned_files.size() != 2 ||
        blocked.retained_unknown_paths != std::vector<std::string>{"user-created.txt"} ||
        blocked.installed_state.lifecycle_status != "uninstall_blocked" ||
        !fs::is_regular_file(moved_target / "user-created.txt")) {
        return 9;
    }

    fs::remove(moved_target / "user-created.txt");
    const auto clean_plan = usk::lifecycle::plan_uninstall(
        fixture.roots, "install.synthetic", "plan.synthetic.uninstall.clean", "2026-07-14T00:10:12Z");
    const auto clean = usk::lifecycle::apply_uninstall(
        clean_plan, clean_plan.plan_digest, "tx.synthetic.uninstall.clean", "2026-07-14T00:10:13Z");
    if (!clean.target_removed || fs::exists(moved_target) ||
        clean.installed_state.lifecycle_status != "retired") {
        return 10;
    }

    const auto chain = usk::audit::AuditRepository(fixture.roots.audit_root)
        .read_and_validate_chain("audit.install.synthetic");
    if (chain.size() != 6 || chain.front().phase != "validated" || chain.back().operation != "uninstall") return 11;

    const fs::path recovery_target = fixture.root / "targets/recovered-portable";
    const auto recovery_plan = usk::lifecycle::plan_install(
        "plan.synthetic.recovery", "install.recovered", "2026-07-14T00:10:14Z",
        recovery_target, fixture.roots, recipe(), payload());
    usk::audit::AuditRepository recovery_audit(fixture.roots.audit_root);
    recovery_audit.initialize_chain("audit.install.recovered");
    recovery_audit.append("audit.install.recovered", usk::audit::AuditInput{
        "2026-07-14T00:10:15Z", "install_local", "validated", "pass", "plan",
        recovery_plan.plan_id, recovery_plan.plan_digest, "tx.synthetic.recovery",
        recovery_plan.plan_id, "reviewed plan revalidated"});
    usk::transaction::TransactionSession interrupted(usk::transaction::TransactionSpec{
        "tx.synthetic.recovery", recovery_plan.plan_id, recovery_plan.plan_digest, "install_local",
        fixture.roots.staging_parent, recovery_target, fixture.roots.state_root, fixture.roots.audit_root});
    for (const auto& file : recovery_plan.files) interrupted.stage_file(file.relative_path, file.bytes);
    interrupted.mark_staged();
    interrupted.mark_verified();
    interrupted.commit_effect();
    interrupted.mark_recovery_required();
    const auto recovered = usk::lifecycle::recover_install_finalization(
        recovery_plan, "tx.synthetic.recovery", "2026-07-14T00:10:16Z");
    if (recovered.verification.status != "pass" ||
        usk::transaction::TransactionSession::inspect_recovery(usk::transaction::TransactionSpec{
            "tx.synthetic.recovery", recovery_plan.plan_id, recovery_plan.plan_digest, "install_local",
            fixture.roots.staging_parent, recovery_target, fixture.roots.state_root,
            fixture.roots.audit_root}).current_state != "completed") {
        return 12;
    }

    const fs::path occupied = fixture.root / "targets/occupied";
    fs::create_directory(occupied);
    const auto occupied_plan = usk::lifecycle::plan_install(
        "plan.synthetic.occupied", "install.occupied", "2026-07-14T00:10:17Z",
        occupied, fixture.roots, recipe(), payload());
    if (!refuses([&] {
            (void)usk::lifecycle::apply_install(
                occupied_plan, occupied_plan.plan_digest, "tx.synthetic.occupied", "2026-07-14T00:10:18Z");
        })) {
        return 13;
    }
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
