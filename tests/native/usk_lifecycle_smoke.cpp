// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_audit_repository.h"
#include "usk_install_restart.h"
#include "usk_lifecycle.h"
#include "usk_json.h"
#include "usk_sha256.h"
#include "usk_stable_file.h"
#include "usk_state_repository.h"
#include "usk_replacement_session.h"
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
    bool cleanup = true;

    explicit Fixture(const fs::path& selected_root = {}, bool remove_on_exit = true)
    {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        root = selected_root.empty() ?
            fs::temp_directory_path() / ("usk-lifecycle-" + std::to_string(nonce)) : selected_root;
        cleanup = remove_on_exit;
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
        if (!cleanup) return;
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

bool requires_retained_stream_recovery(
    const usk::lifecycle::InstallPlan& plan, const std::string& transaction_id)
{
    const usk::transaction::TransactionSpec spec{
        transaction_id, plan.plan_id, plan.plan_digest, "install_local",
        plan.roots.staging_parent, plan.target_root, plan.roots.state_root, plan.roots.audit_root};
    const auto recovery = usk::transaction::TransactionSession::inspect_recovery(spec);
    return recovery.current_state == "recovery_required" && recovery.staging_exists &&
        !recovery.target_exists &&
        recovery.available_actions == std::vector<std::string>{"retain_for_operator"} &&
        refuses([&] { (void)usk::transaction::TransactionSession::resume_rollback(spec); });
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
        if (!rejected || fs::exists(target) || recovery.current_state != "recovery_required" ||
            !recovery.staging_exists || recovery.target_exists ||
            recovery.available_actions != std::vector<std::string>{"retain_for_operator"}) {
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
            }) || fs::exists(target) ||
            !requires_retained_stream_recovery(plan, "tx.streaming.read-fault")) {
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
        if (fs::exists(target) || recovery.current_state != "recovery_required" ||
            !recovery.staging_exists || recovery.target_exists ||
            recovery.available_actions != std::vector<std::string>{"retain_for_operator"}) {
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
            }) || fs::exists(target) ||
            !requires_retained_stream_recovery(plan, "tx.streaming.integrity-fault")) {
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

void prepare_legacy_ownership_fixture(const fs::path& root,
    const usk::lifecycle::LifecycleRoots& roots, std::size_t file_count)
{
    const fs::path target = root / "targets/legacy";
    fs::create_directories(target);
    const unsigned char byte = 'x';
    usk::base::Sha256 hash;
    hash.update(&byte, 1);
    const std::string file_digest = hash.finish();

    usk::state::OwnershipManifest ownership;
    ownership.manifest_id = "ownership.legacy";
    ownership.install_id = "install.legacy";
    ownership.target_root = target.string();
    ownership.created_by_transaction_id = "tx.legacy.install";
    for (std::size_t index = 0; index < file_count; ++index) {
        const std::string relative = "entry-" + std::to_string(index) + ".bin";
        write_text(target / relative, "x");
        ownership.files.push_back({relative, file_digest, 1});
    }
    usk::state::StateRepository repository(roots.state_root);
    ownership = repository.write_ownership(std::move(ownership));

    usk::state::InstalledState installed;
    installed.install_id = ownership.install_id;
    installed.product_id = "product.legacy";
    installed.product_version = "1.0.0";
    installed.recipe_digest = std::string(64, '1');
    installed.source_archive_digest = std::string(64, '2');
    installed.target_root = target.string();
    installed.component_selection = {"core"};
    installed.ownership_manifest_ref = "ownership/" + ownership.manifest_id + ".json";
    installed.ownership_manifest_digest = ownership.manifest_digest;
    installed.entrypoints = {{"application", "entry-0.bin", "application"}};
    installed.provider_revision = "synthetic-provider-r1";
    installed.transaction_id = "tx.legacy.install";
    installed.created_at = "2026-07-14T00:00:00Z";
    installed.last_verification = {"verify.legacy.old", std::string(64, '0'),
        "pass", "2026-07-14T00:00:00Z"};
    installed.audit_chain_id = "audit.legacy";
    installed.lifecycle_status = "installed";
    repository.write_installed(installed);
}

int observe_legacy_ownership_fixture(const usk::lifecycle::LifecycleRoots& roots,
    std::size_t file_count, const std::string& operation)
{
    if (operation == "legacy_ownership_load") {
        const usk::state::StateRepository repository(roots.state_root);
        const auto ownership = repository.read_ownership("ownership.legacy");
        if (ownership.files.size() != file_count) return 62;
    }
    if (operation == "legacy_verify" || operation == "legacy_report") {
        const auto verified = usk::lifecycle::verify_installed(roots, "install.legacy",
            "verify.legacy.current", "2026-07-14T00:00:01Z");
        if (verified.status != "pass" || verified.files.size() != file_count) return 60;
        if (operation == "legacy_report") {
            using usk::json::Value;
            Value::Array files;
            for (const auto& file : verified.files) {
                Value::Object item{{"expected_sha256", Value(file.expected_sha256)},
                    {"relative_path", Value(file.relative_path)}, {"status", Value(file.status)}};
                if (!file.actual_sha256.empty()) item.emplace("actual_sha256", Value(file.actual_sha256));
                files.emplace_back(std::move(item));
            }
            Value::Array directories;
            for (const auto& directory : verified.directories) {
                directories.emplace_back(Value::Object{{"relative_path", Value(directory.relative_path)},
                    {"status", Value(directory.status)}});
            }
            Value::Array unknown;
            for (const auto& path : verified.unknown_paths) unknown.emplace_back(path);
            const Value legacy_payload(Value::Object{
                {"directories", Value(std::move(directories))}, {"files", Value(std::move(files))},
                {"install_id", Value(verified.install_id)},
                {"installed_state_digest", Value(verified.installed_state_digest)},
                {"ownership_manifest_digest", Value(verified.ownership_manifest_digest)},
                {"report_id", Value(verified.report_id)}, {"status", Value(verified.status)},
                {"summary", Value(Value::Object{{"missing_files", Value(verified.missing_files)},
                    {"modified_files", Value(verified.modified_files)},
                    {"unknown_paths", Value(static_cast<std::uint64_t>(verified.unknown_paths.size()))},
                    {"owned_files", Value(static_cast<std::uint64_t>(verified.files.size()))}})},
                {"unknown_paths", Value(std::move(unknown))}, {"verified_at", Value(verified.verified_at)}});
            if (verified.report_digest != usk::json::sha256_canonical(legacy_payload)) return 63;
        }
    }
    if (operation == "legacy_uninstall_plan" || operation == "legacy_report") {
        const auto uninstall = usk::lifecycle::plan_uninstall(roots, "install.legacy",
            "plan.legacy.uninstall", "2026-07-14T00:00:02Z");
        if (uninstall.verification.status != "pass" ||
            uninstall.verification.files.size() != file_count || uninstall.plan_digest.size() != 64) return 61;
        if (operation == "legacy_report") {
            using usk::json::Value;
            Value::Array files;
            for (const auto& file : uninstall.verification.files) {
                files.emplace_back(Value::Object{{"actual_sha256", Value(file.actual_sha256)},
                    {"expected_sha256", Value(file.expected_sha256)},
                    {"relative_path", Value(file.relative_path)}, {"status", Value(file.status)}});
            }
            Value::Array unknown;
            for (const auto& path : uninstall.verification.unknown_paths) unknown.emplace_back(path);
            const Value legacy_plan(Value::Object{
                {"audit_root", Value(fs::absolute(roots.audit_root).lexically_normal().generic_string())},
                {"created_at", Value(uninstall.created_at)},
                {"install_id", Value(uninstall.install_id)},
                {"installed_state_digest", Value(uninstall.installed_state_digest)},
                {"operation", Value("uninstall")},
                {"ownership_manifest_digest", Value(uninstall.ownership_manifest_digest)},
                {"plan_id", Value(uninstall.plan_id)}, {"policy_digest", Value(uninstall.policy_digest)},
                {"staging_parent", Value(fs::absolute(roots.staging_parent).lexically_normal().generic_string())},
                {"state_root", Value(fs::absolute(roots.state_root).lexically_normal().generic_string())},
                {"verification", Value(Value::Object{{"files", Value(std::move(files))},
                    {"status", Value(uninstall.verification.status)},
                    {"unknown_paths", Value(std::move(unknown))}})}});
            if (uninstall.plan_digest != usk::json::sha256_canonical(legacy_plan)) return 64;
        }
    }
    return 0;
}

int legacy_ownership_compatibility_proof()
{
    Fixture fixture;
    prepare_legacy_ownership_fixture(fixture.root, fixture.roots, 4097);
    return observe_legacy_ownership_fixture(fixture.roots, 4097, "legacy_report");
}

std::size_t legacy_probe_entries(const std::string& value)
{
    const auto parsed = std::stoull(value);
    if (parsed != 128 && parsed != 4097 && parsed != 8192) {
        throw std::runtime_error("legacy probe entry count is invalid");
    }
    return static_cast<std::size_t>(parsed);
}

fs::path legacy_probe_root(const std::string& value, bool require_empty)
{
    const fs::path root = fs::absolute(fs::path(value)).lexically_normal();
    if (root.filename().string().rfind("usk-legacy-probe-", 0) != 0 ||
        !fs::equivalent(root.parent_path(), fs::temp_directory_path()) ||
        !fs::is_directory(root) || fs::is_symlink(fs::symlink_status(root)) ||
        (require_empty && !fs::is_empty(root))) {
        throw std::runtime_error("legacy probe root must be a disposable empty temporary directory");
    }
    return root;
}

int run()
{
    Fixture fixture;
    const fs::path target = fixture.root / "targets/portable";
    fs::create_directories(target.parent_path());
    std::vector<usk::lifecycle::PayloadFile> too_many_files;
    too_many_files.reserve(4097);
    for (std::size_t index = 0; index < 4097; ++index) {
        too_many_files.push_back({"app/data/entry-" + std::to_string(index) + ".bin", {'x'}});
    }
    if (!refuses([&] {
            (void)usk::lifecycle::plan_install(
                "plan.synthetic.too-many", "install.synthetic.too-many", "2026-07-14T00:09:59Z",
                target, fixture.roots, recipe(), std::move(too_many_files));
        }) || fs::exists(target)) return 59;
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

    auto next_recipe = recipe();
    next_recipe.product_version = "2.0.0";
    const auto update_plan = usk::lifecycle::plan_update(
        fixture.roots, "install.synthetic", "plan.synthetic.update", "2026-07-14T00:10:07Z",
        "upgrade", target, next_recipe, payload());
    if (update_plan.old_snapshot_digest != usk::transaction::replacement_snapshot_digest(target) ||
        update_plan.old_complete_files.empty() ||
        update_plan.old_complete_files.front().sha256.empty() ||
        update_plan.old_complete_files.front().resource.file_id.empty()) {
        return 17;
    }

    const fs::path moved_target = fixture.root / "targets/moved-portable";
    auto move_plan = usk::lifecycle::plan_move(
        fixture.roots, "install.synthetic", "plan.synthetic.move", "2026-07-14T00:10:08Z", moved_target);
    if (move_plan.resource_observation.peak_payload_buffer != 64u * 1024u ||
        move_plan.resource_observation.peak_open_source_files != 1u ||
        move_plan.resource_observation.retained_payload != 0u ||
        move_plan.resource_observation.complete_payload_retained) {
        return 18;
    }
    const fs::path displaced_source = fixture.root / "targets/displaced-source";
    bool same_resource_observed = true;
    bool source_substitution_refused = refuses([&] {
        (void)usk::lifecycle::apply_move(move_plan, move_plan.plan_digest,
            "tx.synthetic.move.source-swap", "2026-07-14T00:10:09Z",
            [&](const std::string&, const std::string& point) {
                if (point != "transaction.staging.after_staging_create") return;
                fs::rename(target, displaced_source);
                fs::create_directory(target);
                for (const auto& file : move_plan.complete_files) {
                    const fs::path replacement = target / file.relative_path;
                    fs::create_directories(replacement.parent_path());
                    fs::rename(displaced_source / file.relative_path, replacement);
                    const usk::base::StableFile moved(replacement);
                    same_resource_observed = same_resource_observed &&
                        moved.identity().volume_id == file.resource.volume_id &&
                        moved.identity().file_id == file.resource.file_id &&
                        moved.identity().link_count == file.resource.link_count;
                }
            });
    });
    if (!source_substitution_refused || !same_resource_observed || fs::exists(moved_target)) return 58;
    for (const auto& file : move_plan.complete_files) {
        fs::rename(target / file.relative_path, displaced_source / file.relative_path);
    }
    fs::remove_all(target);
    fs::rename(displaced_source, target);

    bool stream_fault_refused = false;
    try {
        (void)usk::lifecycle::apply_move(move_plan, move_plan.plan_digest,
            "tx.synthetic.move.stream-fault", "2026-07-14T00:10:09Z",
            [](const std::string&, const std::string& point) {
                if (point == "transaction.staging.after_stream_intent") {
                    throw std::runtime_error("injected move stream intent failure");
                }
            });
    } catch (const std::exception& error) {
        stream_fault_refused = true;
        (void)error;
    }
    if (!stream_fault_refused || !fs::is_directory(target) || fs::exists(moved_target) ||
        !fs::exists(moved_target.parent_path() / ".usk-stage-tx.synthetic.move.stream-fault")) {
        return 19;
    }
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

    const auto initial_chain_id = usk::lifecycle::install_audit_chain_id(
        "install.synthetic", "tx.synthetic.install", false);
    const auto chain = usk::audit::AuditRepository(fixture.roots.audit_root)
        .read_and_validate_chain(initial_chain_id);
    if (chain.size() != 6 || chain.front().phase != "validated" || chain.back().operation != "uninstall") return 11;
    const auto initial_chain_head = chain.back().event_digest;

    const auto stale_reinstall_plan = usk::lifecycle::plan_install(
        "plan.synthetic.reinstall.stale", "install.synthetic", "2026-07-14T00:10:12Z",
        moved_target, fixture.roots, recipe(), payload());
    if (!refuses([&] {
            (void)usk::lifecycle::apply_install(stale_reinstall_plan, stale_reinstall_plan.plan_digest,
                "tx.synthetic.reinstall.stale", "2026-07-14T00:10:13Z");
        }) || fs::exists(moved_target) ||
        usk::audit::AuditRepository(fixture.roots.audit_root)
            .read_and_validate_chain(initial_chain_id).back().event_digest != initial_chain_head) {
        return 14;
    }

    const auto reinstall_plan = usk::lifecycle::plan_install(
        "plan.synthetic.reinstall", "install.synthetic", "2026-07-14T00:10:14Z",
        moved_target, fixture.roots, recipe(), payload());
    const auto reinstalled = usk::lifecycle::apply_install(
        reinstall_plan, reinstall_plan.plan_digest, "tx.synthetic.reinstall", "2026-07-14T00:10:15Z");
    const auto reinstall_chain_id = usk::lifecycle::next_install_audit_chain_id(
        "install.synthetic", "tx.synthetic.uninstall.clean");
    const auto reinstall_chain = usk::audit::AuditRepository(fixture.roots.audit_root)
        .read_and_validate_chain(reinstall_chain_id);
    const auto selected_reinstall = usk::state::StateRepository(fixture.roots.state_root)
        .read_installed("install.synthetic");
    const auto retained_initial_chain = usk::audit::AuditRepository(fixture.roots.audit_root)
        .read_and_validate_chain(initial_chain_id);
    if (reinstalled.verification.status != "pass" || initial_chain_id == reinstall_chain_id ||
        retained_initial_chain.size() != 6 || retained_initial_chain.back().event_digest != initial_chain_head ||
        reinstall_chain.size() != 2 || reinstall_chain.front().phase != "validated" ||
        reinstall_chain.back().phase != "completed" ||
        selected_reinstall.transaction_id != "tx.synthetic.reinstall" ||
        selected_reinstall.audit_chain_id != reinstall_chain_id ||
        !fs::equivalent(fs::path(selected_reinstall.target_root), moved_target)) {
        std::cerr << "reinstall state mismatch: chain=" << reinstall_chain.size()
                  << " selected=" << selected_reinstall.transaction_id
                  << " target=" << selected_reinstall.target_root
                  << " verification=" << reinstalled.verification.status
                  << " separate-chain=" << (initial_chain_id != reinstall_chain_id)
                  << " retained-head=" << (retained_initial_chain.back().event_digest == initial_chain_head)
                  << " validated=" << reinstall_chain.front().phase
                  << " completed=" << reinstall_chain.back().phase
                  << " target-match=" << fs::equivalent(fs::path(selected_reinstall.target_root), moved_target) << '\n';
        return 15;
    }

    const fs::path duplicate_target = fixture.root / "targets/duplicate-active";
    const auto duplicate_plan = usk::lifecycle::plan_install(
        "plan.synthetic.duplicate", "install.synthetic", "2026-07-14T00:10:16Z",
        duplicate_target, fixture.roots, recipe(), payload());
    const auto reinstall_chain_head = reinstall_chain.back().event_digest;
    if (!refuses([&] {
            (void)usk::lifecycle::apply_install(duplicate_plan, duplicate_plan.plan_digest,
                "tx.synthetic.duplicate", "2026-07-14T00:10:17Z");
        }) || fs::exists(duplicate_target) ||
        fs::exists(fixture.roots.state_root / "transactions/tx.synthetic.duplicate.journal.json") ||
        usk::audit::AuditRepository(fixture.roots.audit_root)
            .read_and_validate_chain(reinstall_chain_id).back().event_digest != reinstall_chain_head ||
        usk::state::StateRepository(fixture.roots.state_root)
            .read_installed("install.synthetic").transaction_id != "tx.synthetic.reinstall") {
        return 16;
    }

    const fs::path recovery_target = fixture.root / "targets/recovered-portable";
    const auto recovery_plan = usk::lifecycle::plan_install(
        "plan.synthetic.recovery", "install.recovered", "2026-07-14T00:10:18Z",
        recovery_target, fixture.roots, recipe(), payload());
    usk::audit::AuditRepository recovery_audit(fixture.roots.audit_root);
    const auto recovery_chain_id = usk::lifecycle::install_audit_chain_id(
        "install.recovered", "tx.synthetic.recovery", false);
    recovery_audit.initialize_chain(recovery_chain_id);
    recovery_audit.append(recovery_chain_id, usk::audit::AuditInput{
        "2026-07-14T00:10:19Z", "install_local", "validated", "pass", "plan",
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
        recovery_plan, "tx.synthetic.recovery", "2026-07-14T00:10:20Z");
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
        "plan.synthetic.occupied", "install.occupied", "2026-07-14T00:10:21Z",
        occupied, fixture.roots, recipe(), payload());
    if (!refuses([&] {
            (void)usk::lifecycle::apply_install(
                occupied_plan, occupied_plan.plan_digest, "tx.synthetic.occupied", "2026-07-14T00:10:22Z");
        })) {
        return 13;
    }
    return 0;
}

int memory_scenario(const std::string& operation, std::uint64_t payload_bytes,
    std::size_t entries, bool materialized)
{
    const auto maximum_payload = materialized ?
        128ull * 1024ull * 1024ull : 2ull * 1024ull * 1024ull * 1024ull;
    if (payload_bytes == 0 || payload_bytes > maximum_payload ||
        entries == 0 || entries > 4096) {
        throw std::runtime_error("memory scenario dimensions are invalid");
    }
    Fixture fixture;
    const std::uint64_t bytes_per_entry = (payload_bytes + entries - 1u) / entries;
    const fs::path source_path = fixture.root / "source.bin";
    {
        std::ofstream output(source_path, std::ios::binary);
        if (!output) throw std::runtime_error("memory scenario source create failed");
        const std::vector<char> chunk(64u * 1024u, 'x');
        for (std::uint64_t offset = 0; offset < bytes_per_entry;) {
            const auto count = static_cast<std::streamsize>(
                std::min<std::uint64_t>(chunk.size(), bytes_per_entry - offset));
            output.write(chunk.data(), count);
            if (!output) throw std::runtime_error("memory scenario source write failed");
            offset += static_cast<std::uint64_t>(count);
        }
    }
    auto source = std::make_shared<usk::base::StableFile>(source_path);
    const std::string source_digest = source->sha256_hex();
    const auto make_files = [&](bool use_materialized) {
        std::vector<usk::lifecycle::PayloadFile> files;
        files.reserve(entries);
        for (std::size_t index = 0; index < entries; ++index) {
            const std::string relative = index == 0 ? "app/bin/program.exe" :
                "app/data/entry-" + std::to_string(index) + ".bin";
            if (use_materialized) {
                files.push_back({relative, std::vector<unsigned char>(
                    static_cast<std::size_t>(bytes_per_entry), 'x')});
                continue;
            }
            files.push_back({relative, {}, source_digest, bytes_per_entry,
                [source](std::uint64_t offset, unsigned char* output, std::size_t capacity) {
                    const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(
                        capacity, source->identity().size_bytes - offset));
                    if (count != 0) source->read_into(offset, output, count);
                    return count;
                }, 64u * 1024u});
        }
        return files;
    };
    const fs::path target = fixture.root / "targets/portable";
    fs::create_directories(target.parent_path());
    const auto plan = usk::lifecycle::plan_install(
        "plan.memory.install", "install.memory", "2026-07-14T01:00:00Z",
        target, fixture.roots, recipe(),
        make_files(materialized && (operation == "install" || operation == "recovery")));
    if (operation == "plan_install") {
        if (plan.files.size() != entries) return 58;
        std::cout << "memory-scenario-pass plan_install streaming " <<
            (bytes_per_entry * entries) << ' ' << entries << '\n';
        return 0;
    }
    if (operation == "recovery") {
        if (!refuses([&] {
                (void)usk::lifecycle::apply_install(plan, plan.plan_digest,
                    "tx.memory.install", "2026-07-14T01:00:01Z",
                    [](const std::string&, const std::string& point) {
                        if (point == "after_target_commit")
                            throw std::runtime_error("injected recovery boundary");
                    });
            })) return 51;
        const auto result = usk::lifecycle::recover_install_finalization(
            plan, "tx.memory.install", "2026-07-14T01:00:02Z");
        if (result.verification.status != "pass") return 52;
    } else {
        const auto installed = usk::lifecycle::apply_install(
            plan, plan.plan_digest, "tx.memory.install", "2026-07-14T01:00:01Z");
        if (installed.verification.status != "pass") return 53;
        if (operation == "verify") {
            if (usk::lifecycle::verify_installed(fixture.roots, "install.memory",
                    "verify.memory", "2026-07-14T01:00:02Z").status != "pass") return 54;
        } else if (operation == "repair") {
            {
                std::ofstream damaged(target / "app/bin/program.exe", std::ios::binary | std::ios::trunc);
                damaged.put('!');
            }
            const auto repair = usk::lifecycle::plan_repair(fixture.roots, "install.memory",
                "plan.memory.repair", "2026-07-14T01:00:02Z", make_files(materialized));
            const auto result = usk::lifecycle::apply_repair(repair, repair.plan_digest,
                "tx.memory.repair", "2026-07-14T01:00:03Z");
            if (result.after.status != "pass") return 55;
        } else if (operation == "move") {
            const fs::path destination = fixture.root / "targets/moved";
            const auto move = usk::lifecycle::plan_move(fixture.roots, "install.memory",
                "plan.memory.move", "2026-07-14T01:00:02Z", destination);
            const auto result = usk::lifecycle::apply_move(move, move.plan_digest,
                "tx.memory.move", "2026-07-14T01:00:03Z");
            if (result.verification.status != "pass" || !fs::is_directory(destination)) return 56;
        } else if (operation == "update") {
            auto new_recipe = recipe();
            new_recipe.product_version = "2.0.0";
            const auto update = usk::lifecycle::plan_update(fixture.roots, "install.memory",
                "plan.memory.update", "2026-07-14T01:00:02Z", "upgrade", target,
                new_recipe, make_files(materialized));
            if (!refuses([&] { (void)usk::lifecycle::apply_update(update, update.plan_digest,
                    "tx.memory.update", "2026-07-14T01:00:03Z"); }) ||
                !fs::is_directory(target)) return 57;
        } else if (operation != "install") {
            throw std::runtime_error("unknown memory scenario operation");
        }
    }
    std::cout << "memory-scenario-pass " << operation << (materialized ? " materialized " : " streaming ") <<
        (bytes_per_entry * entries) << ' ' << entries << '\n';
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    try {
        if (argc == 4 && std::string(argv[1]) == "--prepare-legacy-memory") {
            const auto root = legacy_probe_root(argv[2], true);
            const auto entries = legacy_probe_entries(argv[3]);
            Fixture fixture(root, false);
            prepare_legacy_ownership_fixture(fixture.root, fixture.roots, entries);
            std::cout << "legacy-fixture-prepared " << entries << '\n';
            return 0;
        }
        if (argc == 5 && std::string(argv[1]) == "--observe-legacy-memory") {
            const std::string operation = argv[2];
            if (operation != "legacy_ownership_load" && operation != "legacy_verify" &&
                operation != "legacy_uninstall_plan" &&
                operation != "legacy_report") {
                throw std::runtime_error("unknown legacy observation operation");
            }
            const auto root = legacy_probe_root(argv[3], false);
            const auto entries = legacy_probe_entries(argv[4]);
            const usk::lifecycle::LifecycleRoots roots{
                root / "staging", root / "state", root / "audit"};
            if (const int result = observe_legacy_ownership_fixture(roots, entries, operation)) return result;
            std::cout << "memory-scenario-pass " << operation << " legacy_record " <<
                entries << ' ' << entries << '\n';
            return 0;
        }
        if ((argc == 5 || argc == 6) && std::string(argv[1]) == "--memory-scenario") {
            const bool materialized = argc == 6 && std::string(argv[5]) == "materialized";
            if (argc == 6 && !materialized)
                throw std::runtime_error("unknown memory scenario source kind");
            return memory_scenario(argv[2], std::stoull(argv[3]),
                static_cast<std::size_t>(std::stoull(argv[4])), materialized);
        }
        if (argc != 1) throw std::runtime_error("unknown lifecycle smoke arguments");
        if (const int streaming = streaming_install_and_fault_proof()) {
            return streaming;
        }
        if (const int legacy = legacy_ownership_compatibility_proof()) {
            return legacy;
        }
        return run();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 250;
    }
}
