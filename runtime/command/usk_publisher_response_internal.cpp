// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_response_internal.h"
#include "usk_publisher_recovery_request_internal.h"
#include <set>
#include <stdexcept>

namespace usk::command::detail {
using usk::json::Value;
bool safe_id(const std::string& value)
{
    if (value.empty() || value.size() > 128) return false;
    for (const unsigned char ch : value) {
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
              (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-')) {
            return false;
        }
    }
    return true;
}

bool lower_hex(const std::string& value, std::size_t length)
{
    return value.size() == length &&
        value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

// These are diagnostics from the authenticated service, not reconstructed
// native exceptions or a grant to retry. Preserve the service's effects status.
const char* publisher_operation_error_code(const Value& observed)
{
    if (!observed.contains("error_code")) return nullptr;
    const auto& code = observed.at("error_code").as_string();
    if (code == "operation_conflict") return "operation_conflict";
    if (code == "operation_cancelled") return "operation_cancelled";
    if (code == "lease_stale") return "lease_stale";
    if (code == "state_revision_stale") return "state_revision_stale";
    if (code == "stale_plan") return "stale_plan";
    return nullptr;
}

Value publisher_operation_diagnostic(const Value& observed, const char* code)
{
    if (!code || !observed.contains("operation_inspection_ref")) return Value();
    const auto& reference = observed.at("operation_inspection_ref").as_string();
    const std::string prefix = "usk.operation-inspection.v1:";
    if (reference.compare(0, prefix.size(), prefix) != 0 ||
        !lower_hex(reference.substr(prefix.size()), 64))
        throw std::runtime_error("publisher operation inspection reference differs");
    return Value(Value::Object{
        {"schema", Value("usk.publisher_operation_diagnostic.v1")},
        {"error_code", Value(code)},
        {"inspection_reference", Value(reference)}});
}



Value public_native_recovery_document(const usk::json::Value& inspection,
    const usk::json::Value& binding, const usk::json::Value* plan_request) {
    using usk::json::Value;
    const bool compatible = binding.at("pending_kind").as_string().empty() ?
        (!binding.at("next_kind").as_string().empty() || binding.at("effects_complete").as_boolean()) :
        (binding.at("reconciliation").as_string() == "compatible_before_effect" ||
            binding.at("reconciliation").as_string() == "compatible_after_effect");
    const bool finalizable = compatible && binding.at("commit_started").as_boolean() &&
        binding.at("commit_confirmed").as_boolean() && (binding.at("observed_state").as_string() == "committing" ||
            binding.at("observed_state").as_string() == "committed" ||
            binding.at("observed_state").as_string() == "recovery_required");
    Value::Array actions, effects;
    if (finalizable) {
        actions.emplace_back("finalize");
        effects.emplace_back(Value::Object{{"kind", Value("resume_original_maintenance")},
            {"operation", inspection.at("operation")}});
    }
    Value result(Value::Object{
        {"schema", Value(plan_request ? "usk.recovery_plan.v2" : "usk.recovery_report.v2")},
        {"status", Value(plan_request ? "planned" : "inspection_only")},
        {"operation", inspection.at("operation")}, {"install_id", inspection.at("install_id")},
        {"transaction_id", inspection.at("transaction_id")}, {"original_plan_id", inspection.at("plan_id")},
        {"original_plan_digest", inspection.at("plan_digest")}, {"inspection_request_id", inspection.at("request_id")},
        {"target_root", inspection.at("target_root")}, {"native_binding", binding},
        {"available_actions", Value(std::move(actions))}, {"effects", Value(std::move(effects))}});
    if (plan_request) {
        result.as_object().emplace("created_at", plan_request->at("created_at"));
        result.as_object().emplace("plan_id", plan_request->at("recovery_plan_id"));
        result.as_object().emplace("plan_digest", Value(usk::json::sha256_canonical(result)));
    } else {
        result.as_object().emplace("recorded_at", binding.at("recorded_at"));
        result.as_object().emplace("report_id", Value("recovery.inspect." + inspection.at("request_id").as_string()));
        result.as_object().emplace("report_digest", Value(usk::json::sha256_canonical(result)));
    }
    return result;
}

void require_public_native_recovery_response(const Value& submitted, const Value& observed) {
    const auto* inspection = publisher_public_recovery_inspection(submitted);
    if (!inspection || inspection->at("operation").as_string() == "install_local")
        throw std::runtime_error("native public maintenance recovery family differs");
    const auto closed = [](const Value& value, const std::set<std::string>& fields) {
        if (value.as_object().size() != fields.size()) throw std::runtime_error("native recovery response is not closed");
        for (const auto& item : value.as_object()) if (!fields.count(item.first))
            throw std::runtime_error("native recovery response member is unknown");
    };
    closed(observed, {"schema", "status", "request_sha256", "operation", "install_id", "transaction_id",
        "service_name", "service_sid", "process_id", "recovery_response", "operation_admission", "registered_admission"});
    const auto process_id = observed.at("process_id").as_unsigned();
    const auto& admission = observed.at("registered_admission");
    if (observed.at("service_name").as_string().empty() || observed.at("service_sid").as_string().empty() ||
        process_id == 0u || process_id > 0xffffffffu ||
        admission.at("schema").as_string() != "usk.publisher_registered_admission_observation.v1" ||
        admission.at("service_name").as_string() != observed.at("service_name").as_string() ||
        admission.at("service_sid").as_string() != observed.at("service_sid").as_string() ||
        admission.at("process_id").as_unsigned() != process_id ||
        observed.at("operation_admission").type() != Value::Type::object)
        throw std::runtime_error("native recovery endpoint identity is incomplete");
    const auto& schema = submitted.at("schema").as_string();
    const bool plan = schema == "usk.recovery_plan_request.v1";
    const bool apply = schema == "usk.recovery_apply_request.v1";
    const auto& response = observed.at("recovery_response");
    closed(response, {"schema", "status", "payload"});
    const auto& payload = response.at("payload");
    std::set<std::string> fields{"schema", "status", "operation", "install_id", "transaction_id",
        "original_plan_id", "original_plan_digest", "inspection_request_id", "target_root",
        "native_binding", "available_actions", "effects"};
    if (plan) { fields.insert("created_at"); fields.insert("plan_id"); fields.insert("plan_digest"); }
    else { fields.insert("recorded_at"); fields.insert("report_id"); fields.insert("report_digest"); }
    if (apply) {
        fields.insert("reviewed_plan_id"); fields.insert("reviewed_plan_digest"); fields.insert("selected_action");
        fields.insert("completed_journal_snapshot_sha256"); fields.insert("completed_effect_history_sha256");
    }
    closed(payload, fields);
    if (observed.at("schema").as_string() != "usk.publisher_lab_service_observation.v1" ||
        observed.at("status").as_string() != "pass" ||
        observed.at("request_sha256").as_string() != usk::json::sha256_canonical(submitted) ||
        response.at("schema").as_string() != "usk.command_response.v1" || response.at("status").as_string() != "ok" ||
        payload.at("schema").as_string() != (plan ? "usk.recovery_plan.v2" : "usk.recovery_report.v2") ||
        payload.at("status").as_string() != (apply ? "completed" : plan ? "planned" : "inspection_only"))
        throw std::runtime_error("native recovery response framing differs");
    for (const auto* field : {"operation", "install_id", "transaction_id"}) {
        if (observed.at(field).as_string() != inspection->at(field).as_string() ||
            payload.at(field).as_string() != inspection->at(field).as_string())
            throw std::runtime_error("native recovery response operation differs");
    }
    if (payload.at("original_plan_id").as_string() != inspection->at("plan_id").as_string() ||
        payload.at("original_plan_digest").as_string() != inspection->at("plan_digest").as_string() ||
        payload.at("inspection_request_id").as_string() != inspection->at("request_id").as_string() ||
        payload.at("target_root").as_string() != inspection->at("target_root").as_string())
        throw std::runtime_error("native recovery original request binding differs");
    const auto& binding = payload.at("native_binding");
    closed(binding, {"schema", "original_intent_sha256", "original_custody_sha256", "original_plan_digest",
        "current_installed_revision", "lease_committed_records_sha256", "lease_committed_record_count",
        "lease_pending_names_sha256", "namespace_sha256", "object_count", "absent_original_files_sha256",
        "absent_original_directories_sha256", "journal_snapshot_sha256", "effect_history_sha256",
        "journal_digest", "recorded_at", "source_digest", "commit_started", "commit_confirmed",
        "observed_state", "pending_kind", "reconciliation", "next_kind", "effects_complete", "sealed"});
    if (binding.at("schema").as_string() != "usk.native_maintenance_inspection_binding.v1" ||
        binding.at("original_plan_digest").as_string() != inspection->at("plan_digest").as_string() ||
        binding.at("lease_committed_record_count").as_unsigned() == 0u ||
        binding.at("lease_committed_record_count").as_unsigned() > 4096u ||
        binding.at("object_count").as_unsigned() == 0u)
        throw std::runtime_error("native recovery observation binding differs");
    for (const auto* field : {"original_intent_sha256", "original_custody_sha256", "original_plan_digest",
        "current_installed_revision", "lease_committed_records_sha256", "lease_pending_names_sha256",
        "namespace_sha256", "absent_original_files_sha256", "absent_original_directories_sha256",
        "journal_snapshot_sha256", "effect_history_sha256", "journal_digest", "source_digest"})
        if (!lower_hex(binding.at(field).as_string(), 64u)) throw std::runtime_error("native recovery digest is absent");
    for (const auto* field : {"commit_started", "commit_confirmed", "effects_complete", "sealed"})
        (void)binding.at(field).as_boolean();
    for (const auto* field : {"recorded_at", "observed_state", "pending_kind", "reconciliation", "next_kind"})
        (void)binding.at(field).as_string();
    const auto& actions = payload.at("available_actions").as_array();
    const auto& effects = payload.at("effects").as_array();
    if (actions.size() > 1u || effects.size() != actions.size() ||
        (!actions.empty() && actions.front().as_string() != "finalize"))
        throw std::runtime_error("native recovery advertised an unsupported action");
    if (!effects.empty()) {
        closed(effects.front(), {"kind", "operation"});
        if (effects.front().at("kind").as_string() != "resume_original_maintenance" ||
            effects.front().at("operation").as_string() != inspection->at("operation").as_string())
            throw std::runtime_error("native recovery effect projection differs");
    }
    // Recreate the exact honest read-only document, rather than accepting a
    // resealed body with incompatible actions or changed pre-effect bindings.
    const Value* plan_request = plan ? &submitted : apply ? &submitted.at("plan_request") : nullptr;
    const auto expected = public_native_recovery_document(*inspection, binding, plan_request);
    if (!usk::json::equal_values(payload.at("available_actions"), expected.at("available_actions")) ||
        !usk::json::equal_values(payload.at("effects"), expected.at("effects")))
        throw std::runtime_error("native recovery action does not follow its observed predicates");
    if (apply) {
        if (payload.at("reviewed_plan_id").as_string() != expected.at("plan_id").as_string() ||
            payload.at("reviewed_plan_digest").as_string() != expected.at("plan_digest").as_string())
            throw std::runtime_error("native recovery completion changed its reviewed pre-effect plan");
    } else if (!usk::json::equal_values(payload, expected))
        throw std::runtime_error("native recovery document differs from its exact observed projection");
    const auto digest_field = plan ? "plan_digest" : "report_digest";
    auto body = payload; body.as_object().erase(digest_field);
    if (payload.at(digest_field).as_string() != usk::json::sha256_canonical(body))
        throw std::runtime_error("native recovery document seal differs");
    if (plan) {
        if (payload.at("plan_id").as_string() != submitted.at("recovery_plan_id").as_string() ||
            payload.at("created_at").as_string() != submitted.at("created_at").as_string())
            throw std::runtime_error("native recovery plan identity differs");
    } else if (payload.at("report_id").as_string() != "recovery.inspect." + inspection->at("request_id").as_string() ||
        payload.at("recorded_at").as_string() != (apply ? submitted.at("applied_at").as_string() : binding.at("recorded_at").as_string()))
        throw std::runtime_error("native recovery report identity differs");
    if (apply && (payload.at("reviewed_plan_id").as_string() != submitted.at("reviewed_plan_id").as_string() ||
        payload.at("reviewed_plan_digest").as_string() != submitted.at("reviewed_plan_digest").as_string() ||
        payload.at("selected_action").as_string() != submitted.at("selected_action").as_string() ||
        payload.at("selected_action").as_string() != "finalize" ||
        !lower_hex(payload.at("completed_journal_snapshot_sha256").as_string(), 64u) ||
        !lower_hex(payload.at("completed_effect_history_sha256").as_string(), 64u)))
        throw std::runtime_error("native recovery completion differs from reviewed invocation");
}

ValidatedPublisherResponse validate_publisher_response(const std::string& candidate_command,
    const Value& submitted, const std::string& response, bool retain_observation)
{
    std::string response_field;
    const bool public_recovery = candidate_command == "recovery.inspect" ||
        candidate_command == "recovery.plan" || candidate_command == "recovery.apply";
    if (public_recovery) response_field = "recovery_response";
    else if (candidate_command == "install_local.apply") response_field = "apply_response";
    else if (candidate_command == "installed.verify") response_field = "verify_response";
    else if (candidate_command == "install_local.recover") response_field = "recovery_installed_response";
    else if (candidate_command == "repair.apply" || candidate_command == "move.apply" ||
        candidate_command == "uninstall.apply") response_field = "apply_response";
    else if (candidate_command == "repair.recover" || candidate_command == "move.recover" ||
        candidate_command == "uninstall.recover") response_field = "recovery_response";
    else throw std::invalid_argument("publisher response command is unavailable");
    usk::json::ParseLimits limits;
    limits.max_bytes = publisher_response_max_bytes;
    limits.max_string_bytes = publisher_response_max_bytes / 2;
    const Value observed = usk::json::parse(response, limits);
    if (observed.at("schema").as_string() !=
            "usk.publisher_lab_service_observation.v1")
        throw std::runtime_error("candidate response schema differs");
    const std::string status = observed.at("status").as_string();
    if (status == "pass") {
        if (public_recovery) {
            require_public_native_recovery_response(submitted, observed);
            return {PublisherResponseDisposition::completed,
                retain_observation ? observed : observed.at("recovery_response"), nullptr};
        }
        const Value* public_response = &observed.at(response_field);
        if (candidate_command == "install_local.apply") {
            const bool direct_present = public_response->type() != Value::Type::null_value;
            const bool replay_present =
                observed.at("recovery_installed_response").type() !=
                Value::Type::null_value;
            if (direct_present == replay_present)
                throw std::runtime_error("candidate apply completion is ambiguous");
            if (replay_present)
                public_response = &observed.at("recovery_installed_response");
        }
        if (public_response->at("schema").as_string() !=
                "usk.command_response.v1" ||
            public_response->at("status").as_string() != "ok")
            throw std::runtime_error("candidate public response differs");
        if (!retain_observation) {
            const auto& payload = public_response->at("payload");
            if (candidate_command == "installed.verify") {
                if (payload.at("schema").as_string() != "usk.verification_report.v1" ||
                    payload.at("status").as_string() != "pass" ||
                    payload.at("install_id").as_string() != submitted.at("install_id").as_string() ||
                    payload.at("report_id").as_string() != submitted.at("report_id").as_string() ||
                    payload.at("verified_at").as_string() != submitted.at("verified_at").as_string() ||
                    payload.at("report_digest").as_string() != observed.at("bound_report_digest").as_string())
                    throw std::runtime_error("publisher verification binding differs");
            } else if (candidate_command == "repair.apply" || candidate_command == "move.apply" ||
                candidate_command == "uninstall.apply" || response_field == "recovery_response") {
                const auto operation = candidate_command.substr(0, candidate_command.find('.'));
                const bool recovery = response_field == "recovery_response";
                const auto install_id = recovery ? submitted.at("install_id").as_string() :
                    submitted.at("plan_request").at("install_id").as_string();
                auto digest_body = payload;
                digest_body.as_object().erase("report_digest");
                const auto report_status = payload.at("status").as_string();
                const bool completed = recovery ? report_status == "completed" : operation == "move" ? report_status == "new_committed_old_retained" :
                    (report_status == "completed" || (operation == "uninstall" && report_status == "retained_foreign_content"));
                if (observed.as_object().size() != 12 || !completed ||
                    observed.at("request_sha256").as_string() != usk::json::sha256_canonical(submitted) ||
                    observed.at("operation").as_string() != operation ||
                    observed.at("install_id").as_string() != install_id ||
                    observed.at("transaction_id").as_string() != submitted.at("transaction_id").as_string() ||
                    payload.at("schema").as_string() != (recovery ? "usk.maintenance_recovery_report.v1" : "usk." + operation + "_report.v1") ||
                    payload.at("install_id").as_string() != install_id ||
                    payload.at("transaction_id").as_string() != submitted.at("transaction_id").as_string() ||
                    (!recovery && payload.at("plan_id").as_string() != submitted.at("plan_request").at("plan_id").as_string()) ||
                    payload.at("report_id").as_string() != (recovery ? "recovery." : "") + operation + "." + submitted.at("transaction_id").as_string() ||
                    payload.at("report_digest").as_string() != usk::json::sha256_canonical(digest_body) ||
                    (!recovery && payload.at("completed_at").as_string() != submitted.at("applied_at").as_string()))
                    throw std::runtime_error("publisher maintenance binding differs");
                if (recovery && (payload.as_object().size() != 13 || payload.at("operation").as_string() != operation ||
                    !safe_id(payload.at("plan_id").as_string()) || payload.at("recorded_at").as_string().empty() ||
                    !lower_hex(payload.at("plan_digest").as_string(), 64) ||
                    !lower_hex(payload.at("transaction_snapshot_sha256").as_string(), 64) ||
                    !lower_hex(payload.at("effect_history_sha256").as_string(), 64) ||
                    !lower_hex(payload.at("source_digest").as_string(), 64)))
                    throw std::runtime_error("publisher maintenance recovery original result differs");
            } else {
                const std::string install_id = candidate_command == "install_local.apply" ?
                    submitted.at("plan_request").at("install_id").as_string() :
                    submitted.at("install_id").as_string();
                if (payload.at("schema").as_string() != "usk.installed_state.v1" ||
                    payload.at("lifecycle_status").as_string() != "installed" ||
                    payload.at("install_id").as_string() != install_id ||
                    payload.at("transaction_id").as_string() != submitted.at("transaction_id").as_string() ||
                    (candidate_command == "install_local.apply" &&
                     payload.at("created_at").as_string() != submitted.at("applied_at").as_string()))
                    throw std::runtime_error("publisher installation binding differs");
            }
        }
        return {PublisherResponseDisposition::completed,
            retain_observation ? observed : *public_response, nullptr};
    }
    if (status == "failed" && candidate_command == "installed.verify" &&
        observed.contains("verify_response")) {
        const auto& public_response = observed.at("verify_response");
        if (public_response.at("schema").as_string() !=
                "usk.command_response.v1" ||
            public_response.at("status").as_string() != "ok" ||
            public_response.at("payload").at("schema").as_string() !=
                "usk.verification_report.v1")
            throw std::runtime_error("candidate verification response differs");
        const std::string report_status =
            public_response.at("payload").at("status").as_string();
        if ((report_status != "fail" && report_status != "warn" &&
                report_status != "unknown") ||
            public_response.at("payload").at("report_digest").as_string() !=
                observed.at("bound_report_digest").as_string())
            throw std::runtime_error("candidate verification report differs");
        // A valid drift report is a completed diagnosis, not a refusal.
        if (!retain_observation) {
            const auto& report = public_response.at("payload");
            if (report.at("install_id").as_string() != submitted.at("install_id").as_string() ||
                report.at("report_id").as_string() != submitted.at("report_id").as_string() ||
                report.at("verified_at").as_string() != submitted.at("verified_at").as_string())
                throw std::runtime_error("publisher drift report binding differs");
        }
        return {PublisherResponseDisposition::completed,
            retain_observation ? observed : public_response, nullptr};
    }
    if (status == "failed") {
        const auto code = publisher_operation_error_code(observed);
        const auto diagnostic = publisher_operation_diagnostic(observed, code);
        return {PublisherResponseDisposition::refused, retain_observation ? observed : diagnostic,
            code ? code : "publisher_failed"};
    }
    if (status == "recovery_required") {
        const auto code = publisher_operation_error_code(observed);
        const auto diagnostic = publisher_operation_diagnostic(observed, code);
        return {PublisherResponseDisposition::recovery_required, retain_observation ? observed : diagnostic,
            code ? code : "recovery_required"};
    }
    throw std::runtime_error("publisher response status differs");
}
}
