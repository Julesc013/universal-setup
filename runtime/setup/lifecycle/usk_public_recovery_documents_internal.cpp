// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_public_recovery_documents_internal.h"
#include <utility>
#include <vector>

namespace usk::lifecycle::detail {
using usk::json::Value;
namespace {
Value string_array(const std::vector<std::string>& values)
{
    Value::Array result;
    for (const std::string& value : values) result.emplace_back(value);
    return Value(std::move(result));
}

Value bind_report_digest(Value document)
{
    Value::Object& object = document.as_object();
    object.erase("report_digest");
    const std::string digest = usk::json::sha256_canonical(document);
    object.emplace("report_digest", Value(digest));
    return document;
}

Value bind_plan_digest(Value document)
{
    Value::Object& object = document.as_object();
    object.erase("plan_digest");
    const std::string digest = usk::json::sha256_canonical(document);
    object.emplace("plan_digest", Value(digest));
    return document;
}

} // namespace

Value recovery_effects(const usk::transaction::RecoveryInspection& inspection)
{
    Value::Array effects;
    for (const std::string& action : inspection.available_actions) {
        if (action == "resume") {
            effects.emplace_back(Value::Object{{"kind", Value("resume_transition")},
                {"relative_path", Value(".")}, {"root_class", Value("setup_state")}});
        } else if (action == "rollback") {
            effects.emplace_back(Value::Object{{"kind", Value("delete_staged_path")},
                {"relative_path", Value(".")}, {"root_class", Value("staging")}});
        } else {
            if (inspection.staging_exists) {
                effects.emplace_back(Value::Object{{"kind", Value("retain_path")},
                    {"relative_path", Value(".")}, {"root_class", Value("staging")}});
            }
            if (inspection.target_exists) {
                effects.emplace_back(Value::Object{{"kind", Value("retain_path")},
                    {"relative_path", Value(".")}, {"root_class", Value("owned_target")}});
            }
            if (!inspection.staging_exists && !inspection.target_exists) {
                effects.emplace_back(Value::Object{{"kind", Value("retain_path")},
                    {"relative_path", Value(".")}, {"root_class", Value("setup_state")}});
            }
        }
    }
    return Value(std::move(effects));
}

Value recovery_report_document(const PublicRecoveryDocumentContext& bundle)
{
    return bind_report_digest(Value(Value::Object{
        {"available_actions", string_array(bundle.inspection.available_actions)},
        {"effects", recovery_effects(bundle.inspection)},
        {"journal_digest", Value(bundle.inspection.journal_digest)},
        {"journal_snapshot_sha256", Value(bundle.inspection.snapshot_sha256)},
        {"audit_chain_id", Value(bundle.audit_chain_id)},
        {"audit_chain_digest", bundle.audit_chain_digest.empty() ? Value() : Value(bundle.audit_chain_digest)},
        {"journal_id", Value("journal." + bundle.spec.transaction_id)},
        {"observed_state", Value(bundle.inspection.current_state)},
        {"recorded_at", Value(bundle.inspection.recorded_at)},
        {"report_digest", Value(std::string(64, '0'))},
        {"report_id", Value("recovery.inspect." + bundle.request_id)},
        {"schema", Value("usk.recovery_report.v1")}, {"selected_action", Value()},
        {"status", Value("inspection_only")}, {"transaction_id", Value(bundle.spec.transaction_id)}}));
}

Value recovery_plan_document(const PublicRecoveryDocumentContext& bundle,
    const std::string& created_at, const std::string& plan_id)
{
    return bind_plan_digest(Value(Value::Object{
        {"available_actions", string_array(bundle.inspection.available_actions)},
        {"created_at", Value(created_at)},
        {"effects", recovery_effects(bundle.inspection)}, {"install_id", Value(bundle.install_id)},
        {"journal_digest", Value(bundle.inspection.journal_digest)},
        {"journal_snapshot_sha256", Value(bundle.inspection.snapshot_sha256)},
        {"audit_chain_id", Value(bundle.audit_chain_id)},
        {"audit_chain_digest", bundle.audit_chain_digest.empty() ? Value() : Value(bundle.audit_chain_digest)},
        {"observed_state", Value(bundle.inspection.current_state)},
        {"operation", Value(bundle.spec.operation)}, {"plan_digest", Value(std::string(64, '0'))},
        {"plan_id", Value(plan_id)},
        {"revalidation", Value(Value::Object{{"immediately_before_apply", Value(true)},
            {"invalidate_on", Value(Value::Array{Value("journal"), Value("staging"),
                Value("target"), Value("policy")})}})},
        {"schema", Value("usk.recovery_plan.v1")}, {"status", Value("planned")},
        {"transaction_id", Value(bundle.spec.transaction_id)}}));
}

} // namespace usk::lifecycle::detail
