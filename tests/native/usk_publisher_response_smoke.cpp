// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_response_internal.h"

#include <stdexcept>
#include <string>
#include <filesystem>
#include <utility>

namespace {
using usk::json::Value;
void require(bool condition) { if (!condition) throw std::runtime_error("native recovery response control failed"); }
void native_recovery_documents() {
    using usk::command::detail::require_public_native_recovery_response;
    const std::string sha(64u, 'a');
    const Value inspection(Value::Object{{"schema", Value("usk.recovery_inspect_request.v1")},
        {"request_id", Value("inspection.request")}, {"install_id", Value("product")}, {"transaction_id", Value("repair.tx")},
        {"plan_id", Value("original.plan")}, {"plan_digest", Value(sha)}, {"operation", Value("repair")},
        {"target_root", Value((std::filesystem::current_path() / "target").generic_u8string())}});
    const Value plan_request(Value::Object{{"schema", Value("usk.recovery_plan_request.v1")},
        {"inspection", inspection}, {"recovery_plan_id", Value("reviewed.recovery")}, {"created_at", Value("2026-10-20T00:00:00Z")}});
    Value apply(Value::Object{{"schema", Value("usk.recovery_apply_request.v1")}, {"plan_request", plan_request},
        {"reviewed_plan_id", Value("reviewed.recovery")}, {"reviewed_plan_digest", Value(sha)},
        {"selected_action", Value("finalize")}, {"applied_at", Value("2026-10-20T00:00:01Z")}, {"confirmation", Value("APPLY")}});
    Value binding(Value::Object{{"schema", Value("usk.native_maintenance_inspection_binding.v1")}});
    for (const auto* field : {"original_intent_sha256", "original_custody_sha256", "original_plan_digest",
        "current_installed_revision", "lease_committed_records_sha256", "lease_pending_names_sha256",
        "namespace_sha256", "absent_original_files_sha256", "absent_original_directories_sha256",
        "journal_snapshot_sha256", "effect_history_sha256", "journal_digest", "source_digest"})
        binding.as_object().emplace(field, Value(sha));
    for (const auto* field : {"commit_started", "commit_confirmed", "effects_complete", "sealed"})
        binding.as_object().emplace(field, Value(true));
    for (const auto* field : {"recorded_at", "observed_state", "pending_kind", "reconciliation", "next_kind"})
        binding.as_object().emplace(field, Value("observed"));
    binding.as_object().emplace("lease_committed_record_count", Value(static_cast<std::uint64_t>(2)));
    binding.as_object().emplace("object_count", Value(static_cast<std::uint64_t>(7)));
    binding.as_object().at("observed_state") = Value("committed");
    binding.as_object().at("recorded_at") = Value("2026-10-20T00:00:00Z");
    binding.as_object().at("pending_kind") = Value("");
    binding.as_object().at("next_kind") = Value("replace_file");
    binding.as_object().at("effects_complete") = Value(false);
    binding.as_object().at("sealed") = Value(false);
    const Value confirmed_binding = binding;
    // Replay both the established committed route and the actual hosted
    // after-publication/before-journal-completion state through all three
    // public response validators, including correctly resealed refusals.
    for (const bool pending_publication : {false, true}) {
        binding = confirmed_binding;
        if (pending_publication) {
            binding.as_object().at("commit_confirmed") = Value(false);
            binding.as_object().at("observed_state") = Value("committing");
            binding.as_object().at("pending_kind") = Value("publish_target");
            binding.as_object().at("next_kind") = Value("publish_target");
            binding.as_object().at("reconciliation") = Value("compatible_after_effect");
            for (const char* operation : {"move", "uninstall"}) {
                auto other = inspection; other.as_object().at("operation") = Value(operation);
                const auto doc = usk::command::detail::public_native_recovery_document(other, binding, nullptr);
                require(doc.at("available_actions").as_array().empty() && doc.at("effects").as_array().empty());
            }
        }
        const auto reviewed = usk::command::detail::public_native_recovery_document(inspection, binding, &plan_request);
        apply.as_object().at("reviewed_plan_digest") = reviewed.at("plan_digest");
        const auto seal = [](Value& payload, bool plan) {
            const auto* field = plan ? "plan_digest" : "report_digest";
            payload.as_object().erase(field);
            payload.as_object().emplace(field, Value(usk::json::sha256_canonical(payload)));
        };
        for (const Value& request : {inspection, plan_request, apply}) {
            const auto& schema = request.at("schema").as_string();
            const bool plan = schema == "usk.recovery_plan_request.v1";
            const bool applying = schema == "usk.recovery_apply_request.v1";
            Value payload(Value::Object{
                {"schema", Value(plan ? "usk.recovery_plan.v2" : "usk.recovery_report.v2")},
                {"status", Value(applying ? "completed" : plan ? "planned" : "inspection_only")},
                {"operation", inspection.at("operation")}, {"install_id", inspection.at("install_id")},
                {"transaction_id", inspection.at("transaction_id")}, {"original_plan_id", inspection.at("plan_id")},
                {"original_plan_digest", inspection.at("plan_digest")}, {"inspection_request_id", inspection.at("request_id")},
                {"target_root", inspection.at("target_root")}, {"native_binding", binding},
                {"available_actions", Value(Value::Array{Value("finalize")})},
                {"effects", Value(Value::Array{Value(Value::Object{{"kind", Value("resume_original_maintenance")},
                    {"operation", Value("repair")}})})}});
            if (plan) {
                payload.as_object().emplace("plan_id", request.at("recovery_plan_id"));
                payload.as_object().emplace("created_at", request.at("created_at"));
            } else {
                payload.as_object().emplace("report_id", Value("recovery.inspect.inspection.request"));
                payload.as_object().emplace("recorded_at", applying ? request.at("applied_at") : binding.at("recorded_at"));
            }
            if (applying) {
                for (const auto* field : {"reviewed_plan_id", "reviewed_plan_digest", "selected_action"})
                    payload.as_object().emplace(field, request.at(field));
                payload.as_object().emplace("completed_journal_snapshot_sha256", Value(sha));
                payload.as_object().emplace("completed_effect_history_sha256", Value(sha));
            }
            seal(payload, plan);
            Value response(Value::Object{{"schema", Value("usk.command_response.v1")}, {"status", Value("ok")}, {"payload", payload}});
            const Value admission(Value::Object{{"schema", Value("usk.publisher_registered_admission_observation.v1")},
                {"service_name", Value("service")}, {"service_sid", Value("sid")}, {"process_id", Value(static_cast<std::uint64_t>(99))}});
            Value observation(Value::Object{{"schema", Value("usk.publisher_lab_service_observation.v1")}, {"status", Value("pass")},
                {"request_sha256", Value(usk::json::sha256_canonical(request))}, {"operation", Value("repair")},
                {"install_id", Value("product")}, {"transaction_id", Value("repair.tx")}, {"service_name", Value("service")},
                {"service_sid", Value("sid")}, {"process_id", Value(static_cast<std::uint64_t>(99))},
                {"registered_admission", admission}, {"operation_admission", Value(Value::Object{})}, {"recovery_response", response}});
            require_public_native_recovery_response(request, observation);
            const auto candidate_command = plan ? "recovery.plan" : applying ? "recovery.apply" : "recovery.inspect";
            const auto result = usk::command::detail::validate_publisher_response(candidate_command, request, usk::json::canonical(observation));
            require(result.disposition == usk::command::detail::PublisherResponseDisposition::completed &&
                usk::json::equal_values(result.result, response));
            const auto refuses = [&](const Value& changed) {
                try { require_public_native_recovery_response(request, changed); }
                catch (const std::exception&) { return true; }
                return false;
            };
            for (const auto* field : {"operation", "install_id", "transaction_id", "original_plan_id", "original_plan_digest",
                "inspection_request_id", "target_root"}) {
                auto changed = observation;
                auto& changed_payload = changed.as_object().at("recovery_response").as_object().at("payload");
                changed_payload.as_object().at(field) = Value("different");
                seal(changed_payload, plan);
                require(refuses(changed));
            }
            for (const auto* field : {"request_sha256", "transaction_id", "operation"}) {
                auto changed = observation; changed.as_object().at(field) = Value("different"); require(refuses(changed));
            }
            auto changed = observation;
            auto& changed_payload = changed.as_object().at("recovery_response").as_object().at("payload");
            changed_payload.as_object().at("native_binding").as_object().erase("namespace_sha256");
            seal(changed_payload, plan); require(refuses(changed));
            changed = observation;
            auto& changed_again = changed.as_object().at("recovery_response").as_object().at("payload");
            changed_again.as_object().at("available_actions") = Value(Value::Array{Value("rollback")});
            seal(changed_again, plan); require(refuses(changed));
            // Correctly resealed controls distinguish semantic/plan association
            // checks from mere hashing of a changed body.
            changed = observation;
            auto& incompatible = changed.as_object().at("recovery_response").as_object().at("payload");
            incompatible.as_object().at("native_binding").as_object().at("commit_confirmed") = Value(false);
            if (pending_publication)
                incompatible.as_object().at("native_binding").as_object().at("reconciliation") = Value("compatible_before_effect");
            seal(incompatible, plan); require(refuses(changed));
            changed = observation;
            auto& pending = changed.as_object().at("recovery_response").as_object().at("payload");
            pending.as_object().at("native_binding").as_object().at("pending_kind") = Value("replace_file");
            pending.as_object().at("native_binding").as_object().at("reconciliation") = Value("indeterminate");
            seal(pending, plan); require(refuses(changed));
            if (pending_publication) {
                const auto refuse_pending = [&](const char* field, Value replacement) {
                    auto invalid = observation;
                    auto& doc = invalid.as_object().at("recovery_response").as_object().at("payload");
                    doc.as_object().at("native_binding").as_object().at(field) = std::move(replacement);
                    seal(doc, plan); require(refuses(invalid));
                };
                refuse_pending("commit_started", Value(false));
                refuse_pending("observed_state", Value("staging"));
                refuse_pending("observed_state", Value("recovery_required"));
                refuse_pending("pending_kind", Value("replace_file"));
                refuse_pending("pending_kind", Value(""));
                refuse_pending("next_kind", Value("replace_file"));
                refuse_pending("reconciliation", Value("indeterminate"));
                refuse_pending("effects_complete", Value(true));
                refuse_pending("sealed", Value(true));
            }
            if (applying) for (const auto* field : {"namespace_sha256", "current_installed_revision",
                "lease_committed_records_sha256", "effect_history_sha256"}) {
                changed = observation; auto& doc = changed.as_object().at("recovery_response").as_object().at("payload");
                doc.as_object().at("native_binding").as_object().at(field) = Value(std::string(64u, 'b'));
                seal(doc, false); require(refuses(changed));
            }
            if (applying) for (const auto* field : {"reviewed_plan_id", "reviewed_plan_digest", "selected_action",
                "completed_journal_snapshot_sha256", "completed_effect_history_sha256"}) {
                changed = observation; auto& doc = changed.as_object().at("recovery_response").as_object().at("payload");
                doc.as_object().at(field) = Value("different"); seal(doc, false); require(refuses(changed));
            }
        }
    }
}
}
int main()
{
    native_recovery_documents();
    using usk::json::Value;
    const Value request(Value::Object{
        {"schema", Value("usk.publisher_installed_verify_request.v1")},
        {"request_id", Value("verify.client-only")}, {"install_id", Value("example")},
        {"transaction_id", Value("install.example")}, {"report_id", Value("verify.example")},
        {"verified_at", Value("2026-10-19T00:00:00Z")}});
    const std::string digest(64u, 'a');
    const Value report(Value::Object{
        {"schema", Value("usk.verification_report.v1")}, {"status", Value("pass")},
        {"install_id", request.at("install_id")}, {"report_id", request.at("report_id")},
        {"verified_at", request.at("verified_at")}, {"report_digest", Value(digest)}});
    const Value command(Value::Object{{"schema", Value("usk.command_response.v1")},
        {"status", Value("ok")}, {"payload", report}, {"error", Value()}});
    Value observation(Value::Object{{"schema", Value("usk.publisher_lab_service_observation.v1")},
        {"status", Value("pass")}, {"request_sha256", Value(usk::json::sha256_canonical(request))},
        {"bound_report_digest", Value(digest)}, {"verify_response", command}});
    const auto result = usk::command::detail::validate_publisher_response(
        "installed.verify", request, usk::json::canonical(observation));
    if (result.disposition != usk::command::detail::PublisherResponseDisposition::completed ||
        result.error_code || !usk::json::equal_values(result.result, command)) return 1;

    observation.as_object().at("verify_response").as_object().at("payload").as_object().at("report_id") =
        Value("verify.another-report");
    try {
        (void)usk::command::detail::validate_publisher_response(
            "installed.verify", request, usk::json::canonical(observation));
    } catch (const std::runtime_error&) {
        return 0;
    }
    return 2;
}
