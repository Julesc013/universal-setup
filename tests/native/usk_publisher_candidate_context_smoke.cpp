// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_protected_install_publisher_internal.h"
#include "usk_public_lifecycle.h"
#include "usk_publisher_registration.h"
#include "usk_stable_file.h"
#include <iostream>

int main(int argc, char** argv)
{
    if (argc == 5 && std::string(argv[1]) == "--apply-probe") {
        try {
            usk::base::StableFile file{std::filesystem::path(argv[2])};
            if (!file.identity().size_bytes || file.identity().size_bytes > 1024u*1024u) return 5;
            const auto bytes=file.read(0,static_cast<std::size_t>(file.identity().size_bytes));
            file.verify_unchanged();
            const std::string request(bytes.begin(),bytes.end());
            int status=-1;
            char* raw=usk_public_lifecycle_command_json("install_local.apply",request.data(),request.size(),
                argv[3],argv[4],"operator_acceptance_candidate",&status);
            if (!raw) return 5;
            const std::string response(raw);
            usk_public_lifecycle_command_free(raw);
            std::cout << response << '\n';
            return status == 0 ? 0 : 2;
        } catch (const std::exception&) { return 5; }
    }
    if (argc != 1) return 5;
    using namespace usk::platform::windows;
    // Closed grammar only: an enrolled maintenance request has its own plan
    // identity and cannot inherit the original install envelope. No native
    // registration, effect scope or callback is activated by these values.
    for (const std::string operation : {"repair", "move", "uninstall"}) {
        using usk::json::Value;
        const Value plan(Value::Object{{"schema", Value("usk." + operation + "_plan_request.v1")},
            {"request_id", Value("request.distinct")}, {"plan_id", Value("plan.maintenance")},
            {"install_id", Value("install.original")}});
        const Value apply(Value::Object{{"schema", Value("usk." + operation + "_apply_request.v1")},
            {"plan_request", plan}, {"reviewed_plan_id", Value("plan.maintenance")},
            {"reviewed_plan_digest", Value(std::string(64, 'a'))}, {"transaction_id", Value("maintenance.original")},
            {"applied_at", Value("2026-10-06T00:00:00Z")}, {"confirmation", Value("APPLY")}});
        const Value envelope(Value::Object{{"schema", Value("usk.publisher.maintenance_reviewed_plan_envelope.v1")},
            {"activation", Value("operator_acceptance_candidate")}, {"state_root", Value("Q:\\setup")},
            {"acceptance_root", Value("Q:\\")}, {"plan_request", plan},
            {"reviewed_plan_digest", Value(std::string(64, 'a'))}, {"apply_request", apply}});
        const auto request = usk::json::canonical(apply);
        if (usk::json::canonical(parse_publisher_reviewed_operation_envelope(
                usk::json::canonical(envelope), request)) != usk::json::canonical(envelope)) return 7;
        for (const std::string field : {"schema", "activation", "state_root", "acceptance_root", "plan_request", "reviewed_plan_digest"}) {
            auto changed = envelope;
            if (field == "state_root" || field == "acceptance_root") {
                changed.as_object().erase(field);
                changed.as_object().emplace("unknown", Value("substituted"));
            } else if (field == "schema") changed.as_object().at(field) = Value("usk.publisher.lab_reviewed_plan_envelope.v2");
            else if (field == "plan_request") changed.as_object().at(field).as_object().at("install_id") = Value("install.other");
            else changed.as_object().at(field) = Value("substituted");
            bool refused = false;
            try { (void)parse_publisher_reviewed_operation_envelope(usk::json::canonical(changed), request); }
            catch (const std::exception&) { refused = true; }
            if (!refused) return 7;
        }
        auto changed_apply = apply;
        changed_apply.as_object().at("transaction_id") = Value("maintenance.other");
        bool refused = false;
        try { (void)parse_publisher_reviewed_operation_envelope(usk::json::canonical(envelope), usk::json::canonical(changed_apply)); }
        catch (const std::exception&) { refused = true; }
        if (!refused) return 7;
    }
    // Pure durable-binding fixture; these are not OS observations or a plan
    // acceptance test. A non-lab caller ID must survive, while substitutions
    // in either the request or durable operation fields must refuse.
    auto snapshot=usk::json::parse(R"({"schema":"usk.publisher.lab_reviewed_plan_snapshot.v3",
        "plan_digest":"digest","plan_envelope_sha256":"fixture","archive_sha256":"fixture",
        "archive_identity_digest":"fixture","entry_set_digest":"fixture","selected_file_set_digest":"fixture",
        "target_root":"fixture","setup_root":"fixture","transaction_id":"install.caller.1",
        "applied_at":"2026-09-26T00:00:00Z","policy_digest":"fixture","restart_policy_context":"fixture",
        "plan_request":{"request_id":"plan.1"},"planned_entries":[],
        "apply_request":{"schema":"usk.install_local_apply_request.v1","plan_request":{"request_id":"plan.1"},
        "reviewed_plan_id":"plan.1","reviewed_plan_digest":"digest","transaction_id":"install.caller.1",
        "applied_at":"2026-09-26T00:00:00Z","confirmation":"APPLY"}})");
    usk::lifecycle::require_candidate_snapshot_apply_binding(snapshot);
    for (const char* field : {"transaction_id","applied_at","reviewed_plan_id","reviewed_plan_digest","confirmation"}) {
        auto changed=snapshot;
        changed.as_object().at("apply_request").as_object().at(field)=usk::json::Value("substituted");
        bool refused=false;
        try { usk::lifecycle::require_candidate_snapshot_apply_binding(changed); }
        catch (const std::exception&) { refused=true; }
        if (!refused) return 3;
    }
    for (const char* field : {"transaction_id","applied_at"}) {
        auto changed=snapshot;
        changed.as_object().at(field)=usk::json::Value("substituted");
        bool refused=false;
        try { usk::lifecycle::require_candidate_snapshot_apply_binding(changed); }
        catch (const std::exception&) { refused=true; }
        if (!refused) return 4;
    }
    auto changed=snapshot;
    changed.as_object().at("apply_request").as_object().at("plan_request").as_object().at("request_id")=usk::json::Value("other.plan");
    bool refused=false;
    try { usk::lifecycle::require_candidate_snapshot_apply_binding(changed); }
    catch (const std::exception&) { refused=true; }
    if (!refused) return 5;
    CandidatePublisherConfiguration config;
    config.service_name=L"USK_NoService_Candidate_Context_Smoke";
    // Fixture spelling only; no such volume is opened if live service admission
    // correctly refuses this ordinary process.
    config.volume_root=L"\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\";
    bool provisioned=false, effects=false;
    config.prepare_disposable_boundary=[&](HANDLE,const std::string&) { provisioned=true; };
    try {
        (void)execute_candidate_restricted_publisher(config,effects);
        std::cerr << "ordinary process admitted a private publisher context\n";
        return 1;
    } catch (const std::exception&) {
        if (provisioned || effects) {
            std::cerr << "publisher touched a boundary before live service admission\n";
            return 2;
        }
    }
    // Authenticated requests without the optional consumer-read policy must
    // reach read-only platform/SCM admission. The service is deliberately
    // absent and the ordinary process must cause no target effects.
    for (const char* operation : {"apply", "recover", "verify"}) {
        auto ungranted = config;
        ungranted.prepare_disposable_boundary = {};
        ungranted.submitted_apply_request.reset();
        ungranted.submitted_recovery_request.reset();
        ungranted.submitted_verify_request.reset();
        if (std::string(operation) == "apply") ungranted.submitted_apply_request = "{}";
        if (std::string(operation) == "recover") {
            ungranted.recover_reviewed = true;
            ungranted.submitted_recovery_request = "{}";
        }
        if (std::string(operation) == "verify") {
            ungranted.verify_installed = true;
            ungranted.submitted_verify_request = "{}";
        }
        bool reached_admission = false;
        try { (void)execute_candidate_restricted_publisher(ungranted, effects); }
        catch (const std::exception& error) {
            const std::string diagnostic = error.what();
            reached_admission = diagnostic == "publisher SCM handle is unavailable" ||
                diagnostic == "publisher process is not the stable restricted SCM service" ||
                diagnostic == "publisher execution platform is outside the bound Windows x64 SDK profile";
        }
        if (!reached_admission || effects || provisioned) {
            std::cerr << "ungranted authenticated request did not reach read-only admission: " << operation << '\n';
            return 6;
        }
    }
    return 0;
}
