// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_LIFECYCLE_H
#define USK_LIFECYCLE_H

#include "usk_state_repository.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace usk::lifecycle {

using LifecycleFaultInjector = std::function<void(
    const std::string& operation,
    const std::string& point)>;

struct PayloadFile {
    std::string relative_path;
    std::vector<unsigned char> bytes;
};

struct RecipeBinding {
    std::string product_id;
    std::string product_version;
    std::string recipe_digest;
    std::string source_archive_digest;
    std::string policy_digest;
    std::string provider_revision;
    std::vector<std::string> components;
    std::vector<usk::state::Entrypoint> entrypoints;
};

struct LifecycleRoots {
    std::filesystem::path staging_parent;
    std::filesystem::path state_root;
    std::filesystem::path audit_root;
};

struct InstallPlan {
    std::string plan_id;
    std::string plan_digest;
    std::string created_at;
    std::string install_id;
    std::filesystem::path target_root;
    LifecycleRoots roots;
    RecipeBinding recipe;
    std::vector<PayloadFile> files;
};

struct FileVerification {
    std::string relative_path;
    std::string status;
    std::string expected_sha256;
    std::string actual_sha256;
};

struct DirectoryVerification {
    std::string relative_path;
    std::string status;
};

struct VerificationReport {
    std::string report_id;
    std::string report_digest;
    std::string install_id;
    std::string installed_state_digest;
    std::string ownership_manifest_digest;
    std::string verified_at;
    std::string status;
    std::vector<FileVerification> files;
    std::vector<DirectoryVerification> directories;
    std::vector<std::string> unknown_paths;
    std::uint64_t missing_files = 0;
    std::uint64_t modified_files = 0;
};

struct InstallResult {
    usk::state::InstalledState installed_state;
    usk::state::OwnershipManifest ownership;
    VerificationReport verification;
    std::filesystem::path journal_path;
};

struct RepairPlan {
    std::string plan_id;
    std::string plan_digest;
    std::string created_at;
    std::string install_id;
    std::string installed_state_digest;
    std::string ownership_manifest_digest;
    std::string source_digest;
    std::string policy_digest;
    LifecycleRoots roots;
    std::vector<PayloadFile> replacement_files;
};

struct RepairResult {
    VerificationReport before;
    VerificationReport after;
    std::vector<std::string> repaired_files;
    std::vector<std::string> retained_unknown_paths;
    usk::state::InstalledState installed_state;
};

struct MovePlan {
    std::string plan_id;
    std::string plan_digest;
    std::string created_at;
    std::string install_id;
    std::string installed_state_digest;
    std::string ownership_manifest_digest;
    std::string policy_digest;
    std::filesystem::path old_root;
    std::filesystem::path new_root;
    std::filesystem::path staging_parent;
    LifecycleRoots roots;
    std::vector<PayloadFile> complete_files;
};

struct MoveResult {
    VerificationReport verification;
    usk::state::InstalledState installed_state;
    std::filesystem::path retained_old_root;
};

struct UninstallPlan {
    std::string plan_id;
    std::string plan_digest;
    std::string created_at;
    std::string install_id;
    std::string installed_state_digest;
    std::string ownership_manifest_digest;
    std::string policy_digest;
    LifecycleRoots roots;
    VerificationReport verification;
};

struct UninstallResult {
    std::vector<std::string> deleted_owned_files;
    std::vector<std::string> retained_changed_owned_files;
    std::vector<std::string> retained_unknown_paths;
    std::vector<std::string> retained_directories;
    bool target_removed = false;
    usk::state::InstalledState installed_state;
};

InstallPlan plan_install(
    std::string plan_id,
    std::string install_id,
    std::string created_at,
    std::filesystem::path target_root,
    LifecycleRoots roots,
    RecipeBinding recipe,
    std::vector<PayloadFile> files);

InstallResult apply_install(
    const InstallPlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at,
    LifecycleFaultInjector fault_injector = {});

InstallResult recover_install_finalization(
    const InstallPlan& plan,
    const std::string& transaction_id,
    const std::string& recovered_at);

VerificationReport verify_installed(
    const LifecycleRoots& roots,
    const std::string& install_id,
    const std::string& report_id,
    const std::string& verified_at);

RepairPlan plan_repair(
    const LifecycleRoots& roots,
    const std::string& install_id,
    std::string plan_id,
    std::string created_at,
    std::vector<PayloadFile> exact_source_files,
    std::string source_digest = {},
    std::string policy_digest = {});

RepairResult apply_repair(
    const RepairPlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at,
    LifecycleFaultInjector fault_injector = {});

MovePlan plan_move(
    const LifecycleRoots& roots,
    const std::string& install_id,
    std::string plan_id,
    std::string created_at,
    std::filesystem::path new_root,
    std::string policy_digest = {});

MoveResult apply_move(
    const MovePlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at,
    LifecycleFaultInjector fault_injector = {});

UninstallPlan plan_uninstall(
    const LifecycleRoots& roots,
    const std::string& install_id,
    std::string plan_id,
    std::string created_at,
    std::string policy_digest = {});

UninstallResult apply_uninstall(
    const UninstallPlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at,
    LifecycleFaultInjector fault_injector = {});

} // namespace usk::lifecycle

#endif
