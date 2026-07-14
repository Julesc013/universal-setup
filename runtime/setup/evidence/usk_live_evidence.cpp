// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_live_evidence.h"

#include "usk_json.h"
#include "usk_record_io.h"

#include <algorithm>
#include <cctype>
#include <set>
#include <stdexcept>
#include <utility>

namespace fs = std::filesystem;
using usk::json::Value;

namespace {

bool lower_hex(const std::string& value, std::size_t size)
{
    return value.size() == size && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isdigit(ch) || (ch >= 'a' && ch <= 'f');
    });
}

bool sha256(const std::string& value) { return lower_hex(value, 64); }

void require_id(const std::string& value, const char* field)
{
    if (!usk::record_io::valid_identifier(value)) {
        throw std::runtime_error(std::string("live evidence identifier is invalid: ") + field);
    }
}

void require_sha(const std::string& value, const char* field, bool nullable = false)
{
    if ((!nullable || !value.empty()) && !sha256(value)) {
        throw std::runtime_error(std::string("live evidence digest is invalid: ") + field);
    }
}

Value nullable_string(const std::string& value)
{
    return value.empty() ? Value() : Value(value);
}

template <typename T, typename Key>
void sort_unique(std::vector<T>& values, Key key, const char* field)
{
    std::sort(values.begin(), values.end(), [&](const T& left, const T& right) {
        return key(left) < key(right);
    });
    for (std::size_t index = 1; index < values.size(); ++index) {
        if (key(values[index - 1]) == key(values[index])) {
            throw std::runtime_error(std::string("live evidence contains a duplicate: ") + field);
        }
    }
}

void validate_input(usk::evidence::LiveEvidenceInput& input)
{
    require_id(input.packet_id, "packet_id");
    require_id(input.provider_revision, "provider_revision");
    require_id(input.source_id, "source_id");
    require_id(input.recipe_id, "recipe_id");
    require_id(input.product_id, "product_id");
    require_id(input.plan_id, "plan_id");
    if (input.captured_at.empty() || input.product_version.empty() || input.product_version.size() > 128 ||
        input.setup_abi_major == 0 || input.source_revisions.empty() || input.source_revisions.size() > 32 ||
        input.contract_versions.empty() || input.contract_versions.size() > 64 ||
        input.persistent_effects.empty() || input.persistent_effects.size() > 128 ||
        input.automated_findings.size() > 1024) {
        throw std::runtime_error("live evidence required identity or capacity is invalid");
    }
    for (auto& revision : input.source_revisions) {
        require_id(revision.repository_id, "repository_id");
        if (!lower_hex(revision.revision, 40)) throw std::runtime_error("source revision is not an exact Git identity");
    }
    sort_unique(input.source_revisions, [](const auto& value) { return value.repository_id; }, "repository_id");
    for (auto& contract : input.contract_versions) {
        require_id(contract.contract_id, "contract_id");
        require_id(contract.schema_version, "schema_version");
    }
    sort_unique(input.contract_versions, [](const auto& value) { return value.contract_id; }, "contract_id");
    std::sort(input.persistent_effects.begin(), input.persistent_effects.end());
    if (std::adjacent_find(input.persistent_effects.begin(), input.persistent_effects.end()) !=
        input.persistent_effects.end()) throw std::runtime_error("persistent effects are duplicated");
    for (const std::string& effect : input.persistent_effects) {
        if (effect.empty() || effect.size() > 4096) throw std::runtime_error("persistent effect is invalid");
    }
    for (auto& finding : input.automated_findings) {
        require_id(finding.code, "finding.code");
        require_sha(finding.details_digest, "finding.details_digest");
        if (finding.severity != "info" && finding.severity != "warning" && finding.severity != "error") {
            throw std::runtime_error("automated finding severity is invalid");
        }
        const std::set<std::string> classifications = {
            "observed", "passed_check", "failed_check", "inconclusive_check"};
        if (classifications.count(finding.classification) == 0) {
            throw std::runtime_error("automated finding classification is invalid");
        }
    }
    sort_unique(input.automated_findings, [](const auto& value) { return value.code; }, "finding.code");

    for (const auto& digest : std::vector<std::pair<const std::string*, const char*>>{
             {&input.archive_digest, "archive_digest"},
             {&input.source_filesystem_identity_digest, "source_filesystem_identity_digest"},
             {&input.source_path_identity_digest, "source_path_identity_digest"},
             {&input.recipe_digest, "recipe_digest"},
             {&input.target_identity_digest, "target_identity_digest"},
             {&input.target_path_identity_digest, "target_path_identity_digest"},
             {&input.filesystem_identity_digest, "filesystem_identity_digest"},
             {&input.plan_digest, "plan_digest"},
             {&input.committed_closure_digest, "committed_closure_digest"},
             {&input.pre_target_snapshot_digest, "pre_target_snapshot_digest"},
             {&input.post_target_snapshot_digest, "post_target_snapshot_digest"}}) {
        require_sha(*digest.first, digest.second);
    }
    require_sha(input.installed_state_digest, "installed_state_digest", true);
    require_sha(input.ownership_digest, "ownership_digest", true);
    require_sha(input.audit_head_digest, "audit_head_digest", true);
    require_sha(input.journal_digest, "journal_digest", true);
    if ((!input.audit_chain_id.empty() && !usk::record_io::valid_identifier(input.audit_chain_id)) ||
        (input.target_class != "operator_acceptance" && input.target_class != "managed_portable") ||
        input.filesystem_kind.empty() || input.filesystem_kind.size() > 128) {
        throw std::runtime_error("live evidence target or filesystem identity is invalid");
    }
    const std::set<std::string> operations = {
        "install_local", "verify", "repair", "move", "uninstall", "recovery"};
    const std::set<std::string> closure_states = {
        "not_applicable", "not_committed", "committed", "retired", "removed", "recovery_required"};
    const std::set<std::string> recovery_states = {
        "not_required", "recovery_required", "recovered", "unproven"};
    if (operations.count(input.operation) == 0 || closure_states.count(input.closure_status) == 0 ||
        recovery_states.count(input.recovery_status) == 0) {
        throw std::runtime_error("live evidence operation state is invalid");
    }
}

Value pending_payload(const usk::evidence::LiveEvidenceInput& input)
{
    Value::Array revisions;
    for (const auto& revision : input.source_revisions) {
        revisions.emplace_back(Value::Object{{"repository_id", Value(revision.repository_id)},
            {"revision", Value(revision.revision)}});
    }
    Value::Array contracts;
    for (const auto& contract : input.contract_versions) {
        contracts.emplace_back(Value::Object{{"contract_id", Value(contract.contract_id)},
            {"schema_version", Value(contract.schema_version)}});
    }
    Value::Array effects;
    for (const auto& effect : input.persistent_effects) effects.emplace_back(effect);
    Value::Array findings;
    for (const auto& finding : input.automated_findings) {
        findings.emplace_back(Value::Object{{"classification", Value(finding.classification)},
            {"code", Value(finding.code)}, {"details_digest", Value(finding.details_digest)},
            {"severity", Value(finding.severity)}});
    }
    return Value(Value::Object{
        {"archive", Value(Value::Object{{"filesystem_identity_digest", Value(input.source_filesystem_identity_digest)},
            {"path_identity_digest", Value(input.source_path_identity_digest)}, {"sha256", Value(input.archive_digest)},
            {"size_bytes", Value(input.archive_size_bytes)}, {"source_id", Value(input.source_id)}})},
        {"automated_findings", Value(std::move(findings))}, {"captured_at", Value(input.captured_at)},
        {"committed_closure", Value(Value::Object{{"byte_count", Value(input.committed_byte_count)},
            {"closure_digest", Value(input.committed_closure_digest)}, {"file_count", Value(input.committed_file_count)},
            {"status", Value(input.closure_status)}})},
        {"contract_versions", Value(std::move(contracts))},
        {"filesystem", Value(Value::Object{{"capabilities", Value(Value::Object{
            {"local", Value(input.filesystem_local)}, {"no_mount_redirection", Value(input.no_mount_redirection)},
            {"no_replace_commit", Value(input.no_replace_commit)}, {"stable_ancestors", Value(input.stable_ancestors)}})},
            {"identity_digest", Value(input.filesystem_identity_digest)}, {"kind", Value(input.filesystem_kind)}})},
        {"operator_verdict", Value(Value::Object{{"recorded_at", Value()}, {"recorded_by", Value()},
            {"statement_digest", Value()}, {"status", Value("pending")}, {"verdict", Value()}})},
        {"packet_id", Value(input.packet_id)},
        {"plan", Value(Value::Object{{"expected_byte_count", Value(input.expected_byte_count)},
            {"expected_file_count", Value(input.expected_file_count)}, {"operation", Value(input.operation)},
            {"plan_digest", Value(input.plan_digest)}, {"plan_id", Value(input.plan_id)}})},
        {"recipe", Value(Value::Object{{"product_id", Value(input.product_id)},
            {"product_version", Value(input.product_version)}, {"recipe_digest", Value(input.recipe_digest)},
            {"recipe_id", Value(input.recipe_id)}})},
        {"recovery", Value(Value::Object{{"journal_digest", nullable_string(input.journal_digest)},
            {"status", Value(input.recovery_status)}})},
        {"schema", Value("usk.live_target_evidence_packet.v1")},
        {"setup_abi", Value(Value::Object{{"major", Value(input.setup_abi_major)},
            {"minor", Value(input.setup_abi_minor)}, {"provider_revision", Value(input.provider_revision)}})},
        {"snapshots", Value(Value::Object{{"post_target_digest", Value(input.post_target_snapshot_digest)},
            {"pre_target_digest", Value(input.pre_target_snapshot_digest)}})},
        {"source_revisions", Value(std::move(revisions))},
        {"state", Value(Value::Object{{"audit_chain_id", nullable_string(input.audit_chain_id)},
            {"audit_head_digest", nullable_string(input.audit_head_digest)},
            {"installed_state_digest", nullable_string(input.installed_state_digest)},
            {"ownership_digest", nullable_string(input.ownership_digest)}})},
        {"supersedes_packet_digest", Value()},
        {"target", Value(Value::Object{{"path_identity_digest", Value(input.target_path_identity_digest)},
            {"persistent_effects", Value(std::move(effects))}, {"target_class", Value(input.target_class)},
            {"target_identity_digest", Value(input.target_identity_digest)}})}});
}

usk::evidence::EvidencePacket finalize(Value payload)
{
    Value digest_payload = payload;
    digest_payload.as_object().erase("packet_digest");
    const std::string digest = usk::json::sha256_canonical(digest_payload);
    payload.as_object()["packet_digest"] = Value(digest);
    return {payload.at("packet_id").as_string(), digest, usk::json::canonical(payload)};
}

void validate_packet_identity(const usk::evidence::EvidencePacket& packet)
{
    require_id(packet.packet_id, "packet_id");
    require_sha(packet.packet_digest, "packet_digest");
    const Value document = usk::json::parse(packet.canonical_json);
    if (document.at("schema").as_string() != "usk.live_target_evidence_packet.v1" ||
        document.at("packet_id").as_string() != packet.packet_id ||
        document.at("packet_digest").as_string() != packet.packet_digest ||
        usk::json::canonical(document) != packet.canonical_json) {
        throw std::runtime_error("live evidence packet identity or canonical form is invalid");
    }
    Value payload = document;
    payload.as_object().erase("packet_digest");
    if (usk::json::sha256_canonical(payload) != packet.packet_digest) {
        throw std::runtime_error("live evidence packet digest does not match its canonical payload");
    }
}

} // namespace

namespace usk::evidence {

EvidencePacket build_pending_packet(LiveEvidenceInput input)
{
    validate_input(input);
    return finalize(pending_payload(input));
}

EvidencePacket record_operator_verdict(
    const EvidencePacket& pending_packet,
    std::string new_packet_id,
    std::string recorded_at,
    std::string verdict,
    std::string recorded_by,
    std::string statement_digest)
{
    validate_packet_identity(pending_packet);
    require_id(new_packet_id, "new_packet_id");
    require_id(recorded_by, "recorded_by");
    require_sha(statement_digest, "statement_digest");
    if (recorded_at.empty() || (verdict != "Pass" && verdict != "Fail" && verdict != "Inconclusive")) {
        throw std::runtime_error("operator verdict must be explicitly recorded as Pass, Fail, or Inconclusive");
    }
    Value document = usk::json::parse(pending_packet.canonical_json);
    const Value& current = document.at("operator_verdict");
    if (current.at("status").as_string() != "pending" || current.at("verdict").type() != Value::Type::null_value) {
        throw std::runtime_error("operator verdict can only derive from a pending evidence packet");
    }
    document.as_object().erase("packet_digest");
    document.as_object()["packet_id"] = Value(std::move(new_packet_id));
    document.as_object()["captured_at"] = Value(recorded_at);
    document.as_object()["supersedes_packet_digest"] = Value(pending_packet.packet_digest);
    document.as_object()["operator_verdict"] = Value(Value::Object{
        {"recorded_at", Value(std::move(recorded_at))}, {"recorded_by", Value(std::move(recorded_by))},
        {"statement_digest", Value(std::move(statement_digest))}, {"status", Value("recorded")},
        {"verdict", Value(std::move(verdict))}});
    return finalize(std::move(document));
}

EvidenceRepository::EvidenceRepository(fs::path evidence_root)
    : root_(fs::absolute(std::move(evidence_root)).lexically_normal())
{
    record_io::require_safe_directory(root_);
    record_io::require_safe_directory(root_ / "packets");
}

void EvidenceRepository::initialize_layout(const fs::path& evidence_root)
{
    record_io::require_safe_directory(evidence_root);
    record_io::create_directory_exclusive(evidence_root, "packets");
}

void EvidenceRepository::write_new(const EvidencePacket& packet) const
{
    validate_packet_identity(packet);
    record_io::write_new_durable_text(root_ / "packets" / (packet.packet_id + ".json"),
        packet.canonical_json + "\n");
}

EvidencePacket EvidenceRepository::read_and_validate(const std::string& packet_id) const
{
    require_id(packet_id, "packet_id");
    const std::string text = record_io::read_stable_text(
        root_ / "packets" / (packet_id + ".json"), 4u * 1024u * 1024u);
    const Value document = json::parse(text);
    const std::string canonical = json::canonical(document);
    if (canonical + "\n" != text && canonical + "\r\n" != text) {
        throw std::runtime_error("stored live evidence packet is not canonical");
    }
    EvidencePacket packet{packet_id, document.at("packet_digest").as_string(), canonical};
    validate_packet_identity(packet);
    return packet;
}

} // namespace usk::evidence
