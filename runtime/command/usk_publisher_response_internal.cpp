// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_response_internal.h"
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


ValidatedPublisherResponse validate_publisher_response(const std::string& candidate_command,
    const Value& submitted, const std::string& response, bool retain_observation)
{
    std::string response_field;
    if (candidate_command == "install_local.apply") response_field = "apply_response";
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
