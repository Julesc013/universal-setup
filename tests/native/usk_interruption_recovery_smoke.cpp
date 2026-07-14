// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_audit_repository.h"
#include "usk_lifecycle.h"
#include "usk_state_repository.h"
#include "usk_transaction_session.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

struct Fixture {
    fs::path root;
    usk::lifecycle::LifecycleRoots roots;

    explicit Fixture(const std::string& name)
    {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        root = fs::temp_directory_path() /
            ("usk-interruption-" + name + "-" + std::to_string(nonce));
        roots = {root / "staging", root / "state", root / "audit"};
        fs::create_directories(roots.staging_parent);
        fs::create_directories(roots.state_root);
        fs::create_directories(roots.audit_root);
        usk::state::StateRepository::initialize_layout(roots.state_root);
        fs::create_directory(roots.state_root / "transactions");
        usk::audit::AuditRepository::initialize_layout(roots.audit_root);
        fs::create_directories(root / "targets");
    }

    ~Fixture()
    {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }
};

usk::lifecycle::RecipeBinding recipe()
{
    return {"product.synthetic.interruption", "1.0.0", std::string(64, '1'),
        std::string(64, '2'), std::string(64, '3'), "synthetic-provider-wu5", {"core"},
        {{"probe", "bin/probe.txt", "application"}}};
}

std::vector<usk::lifecycle::PayloadFile> payload()
{
    return {{"bin/probe.txt", {'s', 'y', 'n', 't', 'h', 'e', 't', 'i', 'c'}},
            {"data/config.txt", {'c', 'o', 'n', 'f', 'i', 'g'}}};
}

usk::lifecycle::InstallPlan install_plan(
    Fixture& fixture,
    const std::string& suffix,
    const std::string& created_at = "2026-07-14T02:00:00Z")
{
    return usk::lifecycle::plan_install("plan." + suffix, "install." + suffix, created_at,
        fixture.root / "targets" / suffix, fixture.roots, recipe(), payload());
}

bool inject_once_at(const std::string& expected, bool& injected,
    const std::string&, const std::string& point)
{
    if (!injected && point == expected) {
        injected = true;
        throw std::runtime_error("simulated interruption at " + expected);
    }
    return false;
}

int precommit_matrix()
{
    struct Case { const char* name; const char* point; bool staging_expected; };
    const std::vector<Case> cases = {
        {"after-journal", "transaction.created.after_journal", false},
        {"during-staging-create", "transaction.staging.after_staging_create", true},
        {"during-staged-write", "transaction.staging.after_stage_file", true},
        {"after-staged-verification", "transaction.verified.after_journal", true},
        {"before-commit", "transaction.committing.after_journal", true}};
    for (std::size_t index = 0; index < cases.size(); ++index) {
        Fixture fixture(cases[index].name);
        const auto plan = install_plan(fixture, cases[index].name);
        const std::string transaction_id = "tx." + std::string(cases[index].name);
        bool injected = false;
        try {
            (void)usk::lifecycle::apply_install(plan, plan.plan_digest, transaction_id,
                "2026-07-14T02:00:01Z", [&](const std::string& operation, const std::string& point) {
                    (void)inject_once_at(cases[index].point, injected, operation, point);
                });
        } catch (const std::runtime_error&) {
        }
        const usk::transaction::TransactionSpec spec{transaction_id, plan.plan_id, plan.plan_digest,
            "install_local", fixture.roots.staging_parent, plan.target_root,
            fixture.roots.state_root, fixture.roots.audit_root};
        const auto recovery = usk::transaction::TransactionSession::inspect_recovery(spec);
        if (!injected || fs::exists(plan.target_root) ||
            recovery.staging_exists != cases[index].staging_expected) return 10 + static_cast<int>(index);
        if (cases[index].staging_expected) {
            if (recovery.available_actions != std::vector<std::string>{"rollback"}) {
                return 20 + static_cast<int>(index);
            }
            auto rollback = usk::transaction::TransactionSession::resume_rollback(spec);
            rollback->rollback();
            if (usk::transaction::TransactionSession::inspect_recovery(spec).current_state != "rolled_back") {
                return 30 + static_cast<int>(index);
            }
        } else if (recovery.available_actions != std::vector<std::string>{"abandon"}) {
            return 40 + static_cast<int>(index);
        }
    }
    return 0;
}

int install_finalization_matrix()
{
    const std::vector<std::string> points = {
        "after_target_commit", "before_installed_state_commit", "before_audit_completion"};
    for (std::size_t index = 0; index < points.size(); ++index) {
        Fixture fixture("install-finalize-" + std::to_string(index));
        const auto plan = install_plan(fixture, "finalize-" + std::to_string(index));
        const std::string transaction_id = "tx.finalize." + std::to_string(index);
        bool injected = false;
        try {
            (void)usk::lifecycle::apply_install(plan, plan.plan_digest, transaction_id,
                "2026-07-14T02:01:00Z", [&](const std::string& operation, const std::string& point) {
                    (void)inject_once_at(points[index], injected, operation, point);
                });
        } catch (const std::runtime_error&) {
        }
        const usk::transaction::TransactionSpec spec{transaction_id, plan.plan_id, plan.plan_digest,
            "install_local", fixture.roots.staging_parent, plan.target_root,
            fixture.roots.state_root, fixture.roots.audit_root};
        const auto interrupted = usk::transaction::TransactionSession::inspect_recovery(spec);
        if (!injected || !interrupted.target_exists || interrupted.staging_exists ||
            interrupted.current_state != "recovery_required" ||
            interrupted.available_actions != std::vector<std::string>{"resume"}) return 50 + static_cast<int>(index);
        const auto recovered = usk::lifecycle::recover_install_finalization(
            plan, transaction_id, "2026-07-14T02:01:01Z");
        if (recovered.verification.status != "pass" ||
            usk::transaction::TransactionSession::inspect_recovery(spec).current_state != "completed") {
            return 60 + static_cast<int>(index);
        }
    }
    return 0;
}

void overwrite(const fs::path& path, const std::string& value)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << value;
}

int operation_recovery_required()
{
    {
        Fixture fixture("repair");
        const auto plan = install_plan(fixture, "repair", "2026-07-14T02:02:00Z");
        (void)usk::lifecycle::apply_install(
            plan, plan.plan_digest, "tx.repair.install", "2026-07-14T02:02:01Z");
        overwrite(plan.target_root / "data/config.txt", "damaged");
        const auto repair = usk::lifecycle::plan_repair(fixture.roots, plan.install_id,
            "plan.repair.interrupted", "2026-07-14T02:02:02Z", payload());
        bool injected = false;
        try {
            (void)usk::lifecycle::apply_repair(repair, repair.plan_digest, "tx.repair.interrupted",
                "2026-07-14T02:02:03Z", [&](const std::string& operation, const std::string& point) {
                    (void)inject_once_at("during_owned_replacement", injected, operation, point);
                });
        } catch (const std::runtime_error&) {
        }
        const fs::path bundle = plan.target_root.parent_path() / ".usk-repair-tx.repair.interrupted";
        const auto recovery = usk::transaction::TransactionSession::inspect_recovery({
            "tx.repair.interrupted", repair.plan_id, repair.plan_digest, "repair",
            fixture.roots.staging_parent, bundle, fixture.roots.state_root, fixture.roots.audit_root});
        if (!injected || recovery.current_state != "recovery_required" || !recovery.target_exists ||
            usk::state::StateRepository(fixture.roots.state_root).read_installed(plan.install_id).transaction_id !=
                "tx.repair.install") return 70;
    }
    {
        Fixture fixture("move");
        const auto plan = install_plan(fixture, "move", "2026-07-14T02:03:00Z");
        (void)usk::lifecycle::apply_install(
            plan, plan.plan_digest, "tx.move.install", "2026-07-14T02:03:01Z");
        const fs::path destination = fixture.root / "targets/move-destination";
        const auto move = usk::lifecycle::plan_move(fixture.roots, plan.install_id,
            "plan.move.interrupted", "2026-07-14T02:03:02Z", destination);
        bool injected = false;
        try {
            (void)usk::lifecycle::apply_move(move, move.plan_digest, "tx.move.interrupted",
                "2026-07-14T02:03:03Z", [&](const std::string& operation, const std::string& point) {
                    (void)inject_once_at("after_destination_commit", injected, operation, point);
                });
        } catch (const std::runtime_error&) {
        }
        const auto recovery = usk::transaction::TransactionSession::inspect_recovery({
            "tx.move.interrupted", move.plan_id, move.plan_digest, "move", move.staging_parent,
            destination, fixture.roots.state_root, fixture.roots.audit_root});
        if (!injected || recovery.current_state != "recovery_required" || !fs::is_directory(destination) ||
            !fs::is_directory(plan.target_root)) return 71;
    }
    {
        Fixture fixture("uninstall");
        const auto plan = install_plan(fixture, "uninstall", "2026-07-14T02:04:00Z");
        (void)usk::lifecycle::apply_install(
            plan, plan.plan_digest, "tx.uninstall.install", "2026-07-14T02:04:01Z");
        const auto uninstall = usk::lifecycle::plan_uninstall(fixture.roots, plan.install_id,
            "plan.uninstall.interrupted", "2026-07-14T02:04:02Z");
        bool injected = false;
        try {
            (void)usk::lifecycle::apply_uninstall(uninstall, uninstall.plan_digest,
                "tx.uninstall.interrupted", "2026-07-14T02:04:03Z",
                [&](const std::string& operation, const std::string& point) {
                    (void)inject_once_at("after_marker_commit", injected, operation, point);
                });
        } catch (const std::runtime_error&) {
        }
        const fs::path marker = plan.target_root.parent_path() / ".usk-uninstall-tx.uninstall.interrupted";
        const auto recovery = usk::transaction::TransactionSession::inspect_recovery({
            "tx.uninstall.interrupted", uninstall.plan_id, uninstall.plan_digest, "uninstall",
            fixture.roots.staging_parent, marker, fixture.roots.state_root, fixture.roots.audit_root});
        if (!injected || recovery.current_state != "recovery_required" ||
            !fs::is_regular_file(plan.target_root / "bin/probe.txt") || !recovery.target_exists) return 72;
    }
    return 0;
}

} // namespace

int main()
{
    if (const int result = precommit_matrix()) return result;
    if (const int result = install_finalization_matrix()) return result;
    return operation_recovery_required();
}
