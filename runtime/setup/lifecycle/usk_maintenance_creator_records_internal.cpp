// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_maintenance_creator_records_internal.h"
#include <set>
#include <stdexcept>
namespace usk::lifecycle::detail {
namespace {
using usk::json::Value;
Value closed_record(const std::string& text, const std::set<std::string>& fields) {
    json::ParseLimits limits;
    limits.max_bytes = 16u * 1024u * 1024u;
    limits.max_values = 2000000u;
    auto value = json::parse(text, limits);
    if (value.as_object().size() != fields.size())
        throw std::runtime_error("native maintenance custody fields differ");
    for (const auto& item : value.as_object())
        if (!fields.count(item.first))
            throw std::runtime_error("native maintenance custody field is unknown");
    if (json::canonical(value) + "\n" != text)
        throw std::runtime_error("native maintenance original protected record is not canonical");
    return value;
}
}
usk::json::Value decode_maintenance_original_custody_record(const std::string& text) {
    // The original reader selected its field family with the same bounded
    // schema parse before the complete canonical parse. Keep both bounds.
    json::ParseLimits limits;
    limits.max_bytes = 16u * 1024u * 1024u;
    limits.max_values = 2000000u;
    const auto schema = json::parse(text, limits).at("schema").as_string();
    const bool child = schema == "usk.publisher.maintenance_original_custody.v3" ||
        schema == "usk.publisher.maintenance_original_custody.v4";
    std::set<std::string> fields{"schema", "transaction_id", "operation", "plan_digest",
        "original_context_sha256", "original_lease_ownership", "worker_security", "process_boundary",
        "registration_sha256", "authenticated_client", "original_consumer_completion",
        "installed_root", "installed_root_journal_identity", "original_objects"};
    if (child) fields.insert("broker_readback");
    auto value = closed_record(text, fields);
    if (!child && schema != "usk.publisher.maintenance_original_custody.v2")
        throw std::runtime_error("native maintenance original custody schema is unsupported");
    return value;
}
usk::json::Value decode_maintenance_created_closure_record(const std::string& text,
    const std::string& transaction_id, const std::string& plan_digest) {
    auto created = closed_record(text, {"schema", "transaction_id", "plan_digest", "original_context_sha256",
        "original_admission_sha256", "lease_ownership_sha256", "transaction_snapshot_sha256", "source_context",
        "worker_security", "process_boundary", "registration_sha256", "authenticated_client", "root", "root_parent",
        "target_parent", "root_native_identity", "created_objects"});
    if (created.at("schema").as_string() != "usk.publisher.maintenance_created_closure.v2" ||
        created.at("transaction_id").as_string() != transaction_id ||
        created.at("plan_digest").as_string() != plan_digest)
        throw std::runtime_error("native maintenance created closure lost its actual original admission");
    return created;
}
void require_maintenance_created_closure_binding(const usk::json::Value& created,
    const usk::json::Value& original, const std::string& original_context_sha256,
    const std::string& original_admission_sha256, const std::string& lease_ownership_sha256) {
    if (created.at("original_context_sha256").as_string() != original_context_sha256 ||
        created.at("original_admission_sha256").as_string() != original_admission_sha256 ||
        created.at("lease_ownership_sha256").as_string() != lease_ownership_sha256)
        throw std::runtime_error("native maintenance created closure lost its actual original admission");
    for (const auto* name : {"worker_security", "process_boundary", "registration_sha256", "authenticated_client"})
        if (!json::equal_values(created.at(name), original.at(name)))
            throw std::runtime_error("native maintenance created closure changed its original provenance");
}
}
