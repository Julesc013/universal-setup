// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_protected_install_publisher_internal.h"
#include <iostream>

int main()
{
    using namespace usk::platform::windows;
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
    return 0;
}
