#ifndef USK_LIFECYCLE_H
#define USK_LIFECYCLE_H

#include "usk_state_repository.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace usk::lifecycle {

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
    const std::string& applied_at);

VerificationReport verify_installed(
    const LifecycleRoots& roots,
    const std::string& install_id,
    const std::string& report_id,
    const std::string& verified_at);

} // namespace usk::lifecycle

#endif
