// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_LIVE_EVIDENCE_H
#define USK_LIVE_EVIDENCE_H

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace usk::evidence {

struct RepositoryRevision {
    std::string repository_id;
    std::string revision;
};

struct ContractVersion {
    std::string contract_id;
    std::string schema_version;
};

struct AutomatedFinding {
    std::string code;
    std::string severity;
    std::string classification;
    std::string details_digest;
};

struct LiveEvidenceInput {
    std::string packet_id;
    std::string captured_at;
    std::vector<RepositoryRevision> source_revisions;
    std::uint64_t setup_abi_major = 1;
    std::uint64_t setup_abi_minor = 0;
    std::string provider_revision;
    std::vector<ContractVersion> contract_versions;

    std::string source_id;
    std::string archive_digest;
    std::uint64_t archive_size_bytes = 0;
    std::string source_filesystem_identity_digest;
    std::string source_path_identity_digest;

    std::string recipe_id;
    std::string recipe_digest;
    std::string product_id;
    std::string product_version;

    std::string target_class;
    std::string target_identity_digest;
    std::string target_path_identity_digest;
    std::vector<std::string> persistent_effects;
    std::string filesystem_identity_digest;
    std::string filesystem_kind;
    bool filesystem_local = false;
    bool stable_ancestors = false;
    bool no_mount_redirection = false;
    bool no_replace_commit = false;

    std::string plan_id;
    std::string plan_digest;
    std::string operation;
    std::uint64_t expected_file_count = 0;
    std::uint64_t expected_byte_count = 0;

    std::string closure_status;
    std::uint64_t committed_file_count = 0;
    std::uint64_t committed_byte_count = 0;
    std::string committed_closure_digest;

    std::string installed_state_digest;
    std::string ownership_digest;
    std::string audit_chain_id;
    std::string audit_head_digest;
    std::string pre_target_snapshot_digest;
    std::string post_target_snapshot_digest;
    std::string recovery_status;
    std::string journal_digest;
    std::vector<AutomatedFinding> automated_findings;
};

struct EvidencePacket {
    std::string packet_id;
    std::string packet_digest;
    std::string canonical_json;
};

struct TargetSnapshot {
    std::string state;
    std::uint64_t file_count = 0;
    std::uint64_t directory_count = 0;
    std::uint64_t byte_count = 0;
    std::string snapshot_digest;
};

TargetSnapshot snapshot_target(
    const std::filesystem::path& target_root,
    std::uint64_t max_entries = 100000,
    std::uint64_t max_bytes = 64ull * 1024ull * 1024ull * 1024ull);

EvidencePacket build_pending_packet(LiveEvidenceInput input);

EvidencePacket record_operator_verdict(
    const EvidencePacket& pending_packet,
    std::string new_packet_id,
    std::string recorded_at,
    std::string verdict,
    std::string recorded_by,
    std::string statement_digest);

class EvidenceRepository {
public:
    explicit EvidenceRepository(std::filesystem::path evidence_root);

    static void initialize_layout(const std::filesystem::path& evidence_root);
    void write_new(const EvidencePacket& packet) const;
    EvidencePacket read_and_validate(const std::string& packet_id) const;

private:
    std::filesystem::path root_;
};

} // namespace usk::evidence

#endif
