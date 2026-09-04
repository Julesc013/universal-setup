// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_audit_repository.h"
#include "usk_lifecycle.h"
#include "usk_sha256.h"
#include "usk_stable_file.h"
#include "usk_state_repository.h"
#include "usk_transaction_session.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

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

std::vector<usk::lifecycle::PayloadFile> streaming_payload(
    bool corrupt_first_byte = false,
    bool fail_after_first_buffer = false)
{
    auto bytes = std::make_shared<std::vector<unsigned char>>(
        3u * 64u * 1024u + 17u);
    for (std::size_t index = 0; index < bytes->size(); ++index) {
        (*bytes)[index] = static_cast<unsigned char>(index % 251u);
    }
    usk::base::Sha256 digest;
    digest.update(bytes->data(), bytes->size());
    const std::string sha256 = digest.finish();
    return {{
        "app/bin/program.exe",
        {},
        sha256,
        static_cast<std::uint64_t>(bytes->size()),
        [bytes, corrupt_first_byte, fail_after_first_buffer](
            std::uint64_t offset,
            unsigned char* output,
            std::size_t capacity) -> std::size_t {
            if (fail_after_first_buffer && offset >= 64u * 1024u) {
                throw std::runtime_error("injected streaming source read failure");
            }
            if (offset >= bytes->size()) return 0;
            const std::size_t count = static_cast<std::size_t>(
                std::min<std::uint64_t>(capacity, bytes->size() - offset));
            std::memcpy(output, bytes->data() + offset, count);
            if (corrupt_first_byte && offset == 0u && count != 0u) output[0] ^= 0xffu;
            return count;
        },
        64u * 1024u}};
}

int streaming_install_and_fault_proof()
{
    {
        Fixture fixture;
        const fs::path target = fixture.root / "targets/streamed";
        fs::create_directories(target.parent_path());
        const auto plan = usk::lifecycle::plan_install(
            "plan.streaming.success", "install.streaming.success",
            "2026-08-27T00:00:00Z", target, fixture.roots, recipe(),
            streaming_payload());
        if (!plan.files.front().bytes.empty() || !plan.files.front().reader ||
            plan.files.front().size_bytes <= plan.files.front().stream_buffer_bytes) {
            return 20;
        }
        const auto result = usk::lifecycle::apply_install(
            plan, plan.plan_digest, "tx.streaming.success",
            "2026-08-27T00:00:01Z");
        if (result.verification.status != "pass" ||
            usk::base::sha256_hex_file(target / "app/bin/program.exe") !=
                plan.files.front().sha256) {
            return 21;
        }
    }
    {
        Fixture fixture;
        const fs::path target = fixture.root / "targets/write-fault";
        fs::create_directories(target.parent_path());
        const auto plan = usk::lifecycle::plan_install(
            "plan.streaming.write-fault", "install.streaming.write-fault",
            "2026-08-27T00:01:00Z", target, fixture.roots, recipe(),
            streaming_payload());
        const bool rejected = refuses([&] {
            (void)usk::lifecycle::apply_install(
                plan, plan.plan_digest, "tx.streaming.write-fault",
                "2026-08-27T00:01:01Z",
                [](const std::string&, const std::string& point) {
                    if (point == "transaction.staging.before_stream_write") {
                        throw std::runtime_error("injected streaming write failure");
                    }
                });
        });
        const auto recovery = usk::transaction::TransactionSession::inspect_recovery(
            usk::transaction::TransactionSpec{
                "tx.streaming.write-fault", plan.plan_id, plan.plan_digest,
                "install_local", fixture.roots.staging_parent, target,
                fixture.roots.state_root, fixture.roots.audit_root});
        if (!rejected || fs::exists(target) || recovery.current_state != "rolled_back" ||
            recovery.staging_exists || recovery.target_exists) {
            return 22;
        }
    }
    {
        Fixture fixture;
        const fs::path target = fixture.root / "targets/read-fault";
        fs::create_directories(target.parent_path());
        const auto plan = usk::lifecycle::plan_install(
            "plan.streaming.read-fault", "install.streaming.read-fault",
            "2026-08-27T00:02:00Z", target, fixture.roots, recipe(),
            streaming_payload(false, true));
        if (!refuses([&] {
                (void)usk::lifecycle::apply_install(
                    plan, plan.plan_digest, "tx.streaming.read-fault",
                    "2026-08-27T00:02:01Z");
            }) || fs::exists(target)) {
            return 23;
        }
    }
    {
        Fixture fixture;
        const fs::path target = fixture.root / "targets/cancelled";
        fs::create_directories(target.parent_path());
        const auto plan = usk::lifecycle::plan_install(
            "plan.streaming.cancelled", "install.streaming.cancelled",
            "2026-08-27T00:02:10Z", target, fixture.roots, recipe(),
            streaming_payload());
        std::size_t cancellation_checks = 0;
        if (!refuses([&] {
                (void)usk::lifecycle::apply_install(
                    plan, plan.plan_digest, "tx.streaming.cancelled",
                    "2026-08-27T00:02:11Z", {},
                    [&]() { return ++cancellation_checks >= 3u; });
            })) {
            return 25;
        }
        const auto recovery = usk::transaction::TransactionSession::inspect_recovery(
            usk::transaction::TransactionSpec{
                "tx.streaming.cancelled", plan.plan_id, plan.plan_digest,
                "install_local", fixture.roots.staging_parent, target,
                fixture.roots.state_root, fixture.roots.audit_root});
        if (fs::exists(target) || recovery.current_state != "rolled_back" ||
            recovery.staging_exists || recovery.target_exists) {
            return 26;
        }
    }
    {
        Fixture fixture;
        const fs::path target = fixture.root / "targets/nonexact-buffer";
        fs::create_directories(target.parent_path());
        auto files = streaming_payload();
        files.front().stream_buffer_bytes = 4u * 1024u * 1024u;
        if (!refuses([&] {
                (void)usk::lifecycle::plan_install(
                    "plan.streaming.nonexact", "install.streaming.nonexact",
                    "2026-08-27T00:02:20Z", target, fixture.roots, recipe(),
                    files);
            }) || fs::exists(target)) {
            return 27;
        }
    }
    {
        Fixture fixture;
        const fs::path target = fixture.root / "targets/integrity-fault";
        fs::create_directories(target.parent_path());
        const auto plan = usk::lifecycle::plan_install(
            "plan.streaming.integrity-fault", "install.streaming.integrity-fault",
            "2026-08-27T00:03:00Z", target, fixture.roots, recipe(),
            streaming_payload(true));
        if (!refuses([&] {
                (void)usk::lifecycle::apply_install(
                    plan, plan.plan_digest, "tx.streaming.integrity-fault",
                    "2026-08-27T00:03:01Z");
            }) || fs::exists(target)) {
            return 24;
        }
    }
    return 0;
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
        if (const int streaming = streaming_install_and_fault_proof()) {
            return streaming;
        }
        return run();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 250;
    }
}
