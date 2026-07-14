// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_live_evidence.h"
#include "usk_json.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using usk::json::Value;

namespace {

usk::evidence::LiveEvidenceInput input()
{
    usk::evidence::LiveEvidenceInput value;
    value.packet_id = "evidence.install.1.pending";
    value.captured_at = "2026-07-14T12:00:00Z";
    value.source_revisions = {
        {"universal_setup", std::string(40, 'a')},
        {"factorio_launcher", std::string(40, 'c')},
        {"universal_launcher", std::string(40, 'b')}};
    value.setup_abi_major = 1;
    value.setup_abi_minor = 0;
    value.provider_revision = "provider.synthetic.1";
    value.contract_versions = {
        {"ownership_manifest", "usk.ownership_manifest.v1"},
        {"installed_state", "usk.installed_state.v1"},
        {"install_plan", "usk.install_plan.v1"}};
    value.source_id = "source.synthetic.1";
    value.archive_digest = std::string(64, '1');
    value.archive_size_bytes = 4096;
    value.source_filesystem_identity_digest = std::string(64, '2');
    value.source_path_identity_digest = std::string(64, '3');
    value.recipe_id = "recipe.synthetic.1";
    value.recipe_digest = std::string(64, '4');
    value.product_id = "synthetic.product";
    value.product_version = "1.0.0";
    value.target_class = "operator_acceptance";
    value.target_identity_digest = std::string(64, '5');
    value.target_path_identity_digest = std::string(64, '6');
    value.persistent_effects = {"write owned target", "write setup state", "append audit chain"};
    value.filesystem_identity_digest = std::string(64, '7');
    value.filesystem_kind = "local_test_filesystem";
    value.filesystem_local = true;
    value.stable_ancestors = true;
    value.no_mount_redirection = true;
    value.no_replace_commit = true;
    value.plan_id = "plan.install.1";
    value.plan_digest = std::string(64, '8');
    value.operation = "install_local";
    value.expected_file_count = 2;
    value.expected_byte_count = 42;
    value.closure_status = "committed";
    value.committed_file_count = 2;
    value.committed_byte_count = 42;
    value.committed_closure_digest = std::string(64, '9');
    value.installed_state_digest = std::string(64, 'a');
    value.ownership_digest = std::string(64, 'b');
    value.audit_chain_id = "audit.synthetic.1";
    value.audit_head_digest = std::string(64, 'c');
    value.pre_target_snapshot_digest = std::string(64, 'd');
    value.post_target_snapshot_digest = std::string(64, 'e');
    value.recovery_status = "not_required";
    value.journal_digest = std::string(64, 'f');
    value.automated_findings = {
        {"closure_verified", "info", "passed_check", std::string(64, '1')},
        {"target_policy_accepted", "info", "observed", std::string(64, '2')}};
    return value;
}

template <typename Callable>
bool refuses(Callable callable)
{
    try {
        callable();
        return false;
    } catch (const std::exception&) {
        return true;
    }
}

} // namespace

int main()
{
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path root = fs::temp_directory_path() / ("usk-live-evidence-" + std::to_string(nonce));
    std::error_code error;
    fs::create_directories(root, error);
    if (error) return 1;
    usk::evidence::EvidenceRepository::initialize_layout(root);
    usk::evidence::EvidenceRepository repository(root);

    const auto pending = usk::evidence::build_pending_packet(input());
    const Value pending_json = usk::json::parse(pending.canonical_json);
    if (pending.packet_digest.size() != 64 ||
        pending_json.at("operator_verdict").at("status").as_string() != "pending" ||
        pending_json.at("operator_verdict").at("verdict").type() != Value::Type::null_value ||
        pending_json.at("supersedes_packet_digest").type() != Value::Type::null_value ||
        pending_json.at("source_revisions").as_array().front().at("repository_id").as_string() !=
            "factorio_launcher") return 2;
    repository.write_new(pending);
    if (repository.read_and_validate(pending.packet_id).packet_digest != pending.packet_digest ||
        !refuses([&] { repository.write_new(pending); })) return 3;

    const auto accepted = usk::evidence::record_operator_verdict(
        pending, "evidence.install.1.verdict", "2026-07-14T12:30:00Z", "Pass",
        "operator.local", std::string(64, '0'));
    const Value accepted_json = usk::json::parse(accepted.canonical_json);
    if (accepted_json.at("operator_verdict").at("verdict").as_string() != "Pass" ||
        accepted_json.at("supersedes_packet_digest").as_string() != pending.packet_digest ||
        accepted.packet_digest == pending.packet_digest ||
        !refuses([&] { (void)usk::evidence::record_operator_verdict(
            accepted, "evidence.install.1.invalid", "2026-07-14T12:31:00Z", "Fail",
            "operator.local", std::string(64, '0')); })) return 4;
    repository.write_new(accepted);

    auto invalid = input();
    invalid.source_revisions.push_back(invalid.source_revisions.front());
    if (!refuses([&] { (void)usk::evidence::build_pending_packet(invalid); })) return 5;
    invalid = input();
    invalid.automated_findings.front().classification = "Pass";
    if (!refuses([&] { (void)usk::evidence::build_pending_packet(invalid); })) return 6;

    {
        std::ofstream output(root / "packets" / "evidence.install.1.pending.json",
            std::ios::binary | std::ios::trunc);
        output << pending.canonical_json.substr(0, pending.canonical_json.size() - 1) << " \n";
    }
    if (!refuses([&] { (void)repository.read_and_validate(pending.packet_id); })) return 7;

    fs::remove_all(root, error);
    return error ? 8 : 0;
}
