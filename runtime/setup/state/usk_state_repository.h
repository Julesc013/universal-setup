// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_STATE_REPOSITORY_H
#define USK_STATE_REPOSITORY_H

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace usk::state {

struct OwnedFile {
    std::string relative_path;
    std::string sha256;
    std::uint64_t size_bytes = 0;
};

struct OwnershipManifest {
    std::string manifest_id;
    std::string manifest_digest;
    std::string install_id;
    std::string target_root;
    std::string created_by_transaction_id;
    std::vector<OwnedFile> files;
    std::vector<std::string> directories;
};

struct Entrypoint {
    std::string entrypoint_id;
    std::string relative_path;
    std::string kind;
};

struct VerificationSummary {
    std::string report_id;
    std::string report_digest;
    std::string status;
    std::string verified_at;
};

struct InstalledState {
    std::string install_id;
    std::string product_id;
    std::string product_version;
    std::string recipe_digest;
    std::string source_archive_digest;
    std::string target_root;
    std::vector<std::string> component_selection;
    std::string ownership_manifest_ref;
    std::string ownership_manifest_digest;
    std::vector<Entrypoint> entrypoints;
    std::uint64_t setup_abi_major = 1;
    std::uint64_t setup_abi_minor = 0;
    std::string provider_revision;
    std::string transaction_id;
    std::string created_at;
    VerificationSummary last_verification;
    std::string audit_chain_id;
    std::string lifecycle_status;
};

class StateRepository {
public:
    explicit StateRepository(std::filesystem::path state_root);

    static void initialize_layout(const std::filesystem::path& state_root);

    OwnershipManifest write_ownership(OwnershipManifest manifest) const;
    OwnershipManifest read_ownership(const std::string& manifest_id) const;
    void write_installed(const InstalledState& state) const;
    InstalledState read_installed(const std::string& install_id) const;
    InstalledState read_installed_snapshot(
        const std::string& install_id,
        const std::string& transaction_id) const;

    const std::filesystem::path& root() const noexcept { return root_; }

private:
    std::filesystem::path root_;
};

} // namespace usk::state

#endif
