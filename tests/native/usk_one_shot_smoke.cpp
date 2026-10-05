// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_one_shot.h"
#include "usk_json.h"
#include "usk_effect_dispatch.h"

#include <cstdint>
#include <ios>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

class BadAtEndBuffer final : public std::streambuf {
public:
    explicit BadAtEndBuffer(std::string bytes) : bytes_(std::move(bytes))
    {
        setg(bytes_.data(), bytes_.data(), bytes_.data() + bytes_.size());
    }
    void mark_bad_and_eof_on_end(std::istream& input) { owner_ = &input; }

protected:
    int_type underflow() override
    {
        if (gptr() != egptr()) return traits_type::to_int_type(*gptr());
        if (owner_ != nullptr) {
            owner_->setstate(std::ios::badbit | std::ios::eofbit);
            return traits_type::eof();
        }
        throw std::ios_base::failure("injected read failure");
    }

private:
    std::string bytes_;
    std::istream* owner_ = nullptr;
};

class FailOnFlushBuffer final : public std::stringbuf {
protected:
    int sync() override { return -1; }
};

bool refused_with(const std::string& request, const std::string& code)
{
    const auto result = usk::command::run_one_shot(request);
    if (result.exit_code == 0 || result.document.find("SECRET_CANARY") != std::string::npos ||
        result.diagnostic.find("SECRET_CANARY") != std::string::npos) return false;
    const auto parsed = usk::json::parse(result.document);
    return parsed.at("status").as_string() == "refused" &&
        parsed.at("error").at("code").as_string() == code;
}

bool frame_refused(const std::string& source)
{
    std::istringstream input(source);
    try {
        (void)usk::command::read_bounded_request(input, true);
    } catch (const std::runtime_error&) {
        return true;
    }
    return false;
}

bool publisher_capability_checks()
{
    using usk::json::Value;
    const std::string request = R"({"schema":"usk.oneshot_request.v1","request_id":"capability-1","command":"publisher.inspect","payload":{"schema":"usk.publisher_capability_request.v1","request_id":"capability-1"},"dry_run":true})";
    const std::string response = R"({"schema":"usk.publisher_capability.v1","provider_id":"windows_nt_x64_local_ntfs_service_sid_noreplace_v1","implementation":"partial","realization":"restricted_service","availability":false,"required_privilege":"SeBackupPrivilege_and_disk_read","permission":"registered_caller_observed","authority":"not_granted_by_discovery","qualification":"incomplete","qualification_scope":"registered_target_observation","support":"unsupported","recovery_ceiling":"candidate_source_free_restart","power_loss_qualified":false,"revalidation_required_before_effects":true,"execution_lease_held":false,"platform":{"os_family":"Windows NT","native_arch":"x64","process_arch":"x64","windows_build":20348,"minimum_windows_build":17763},"request_id":"capability-1","service_state":1,"effects":[],"binding":{"service_name":"USK_PUB_11111111111111111111111111111111","service_sid":"S-1-5-80-1-2-3-4-5","caller_sid":"S-1-5-21-1-2-3-1001","binary_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","registration_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","target_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","boundary_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","volume_guid_root":"\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\"}})";
    unsigned calls = 0;
    const auto transport = [&calls, &response](const std::string& forwarded) {
        ++calls;
        const auto payload = usk::json::parse(forwarded);
        if (payload.as_object().size() != 2 || payload.at("request_id").as_string() != "capability-1")
            throw std::runtime_error("inspection forwarding differs");
        return response;
    };
    const auto result = usk::command::run_publisher_one_shot(request, transport);
    const auto envelope = usk::json::parse(result.document);
    if (result.exit_code != 0 || calls != 1 || envelope.at("status").as_string() != "ok" ||
        usk::json::canonical(envelope.at("result")) != usk::json::canonical(usk::json::parse(response))) return false;
    // Every absent dimension must refuse instead of defaulting to available.
    const auto original = usk::json::parse(response);
    auto built_in_caller = original;
    built_in_caller.as_object().at("binding").as_object().at("caller_sid") = Value("S-1-5-21-1-2-3-500");
    const auto built_in_result = usk::command::run_publisher_one_shot(request,
        [&built_in_caller](const std::string&) { return usk::json::canonical(built_in_caller); });
    if (built_in_result.exit_code != 0 || usk::json::parse(built_in_result.document).at("result")
            .at("binding").at("caller_sid").as_string() != "S-1-5-21-1-2-3-500") return false;
    for (const auto& field : original.as_object()) {
        auto incomplete = original;
        incomplete.as_object().erase(field.first);
        const auto refused = usk::command::run_publisher_one_shot(request,
            [&incomplete](const std::string&) { return usk::json::canonical(incomplete); });
        if (refused.exit_code != 2 || usk::json::parse(refused.document).at("result").type() != Value::Type::null_value)
            return false;
    }
    for (const auto& field : {"availability", "power_loss_qualified", "execution_lease_held"}) {
        auto optimistic = original;
        optimistic.as_object().at(field) = Value(true);
        if (usk::command::run_publisher_one_shot(request,
            [&optimistic](const std::string&) { return usk::json::canonical(optimistic); }).exit_code != 2) return false;
    }
    for (const auto& field : {"request_id", "qualification", "support", "authority"}) {
        auto altered = original;
        altered.as_object().at(field) = Value("SECRET_CANARY");
        const auto refused = usk::command::run_publisher_one_shot(request,
            [&altered](const std::string&) { return usk::json::canonical(altered); });
        if (refused.exit_code != 2 || refused.document.find("SECRET_CANARY") != std::string::npos) return false;
    }
    for (const auto& field : original.at("binding").as_object()) {
        auto altered = original;
        altered.as_object().at("binding").as_object().erase(field.first);
        if (usk::command::run_publisher_one_shot(request,
            [&altered](const std::string&) { return usk::json::canonical(altered); }).exit_code != 2) return false;
    }
    for (const auto& field : {"native_arch", "process_arch", "os_family"}) {
        auto altered = original;
        altered.as_object().at("platform").as_object().at(field) = Value("unsupported");
        if (usk::command::run_publisher_one_shot(request,
            [&altered](const std::string&) { return usk::json::canonical(altered); }).exit_code != 2) return false;
    }
    for (const std::uint64_t build : {std::uint64_t{17762}, std::uint64_t{4294967296ULL}}) {
        auto altered = original;
        altered.as_object().at("platform").as_object().at("windows_build") = Value(build);
        if (usk::command::run_publisher_one_shot(request,
            [&altered](const std::string&) { return usk::json::canonical(altered); }).exit_code != 2) return false;
    }
    for (const auto& sid : {"S-1-123", "S-1-5-80-1", "S-1-5-80-1-2-3-4-4294967296",
            "S-1-5-80-01-2-3-4-5", "S-1-281474976710656-1", "S-1-5-21-"}) {
        for (const auto& field : {"caller_sid", "service_sid"}) {
            auto altered = original;
            altered.as_object().at("binding").as_object().at(field) = Value(sid);
            if (usk::command::run_publisher_one_shot(request,
                [&altered](const std::string&) { return usk::json::canonical(altered); }).exit_code != 2) return false;
        }
    }
    for (const auto& field : {"availability", "target", "activation"}) {
        auto claimed = usk::json::parse(request);
        claimed.as_object().at("payload").as_object().emplace(field, Value(true));
        const auto refused = usk::command::run_publisher_one_shot(usk::json::canonical(claimed), transport);
        if (refused.exit_code != 2 || calls != 1) return false;
    }
    auto mismatch = usk::json::parse(request);
    mismatch.as_object().at("payload").as_object().at("request_id") = Value("different");
    if (usk::command::run_publisher_one_shot(usk::json::canonical(mismatch), transport).exit_code != 2 || calls != 1)
        return false;
    mismatch.as_object().at("payload").as_object().at("request_id") = Value("capability-1");
    mismatch.as_object().at("dry_run") = Value(false);
    if (usk::command::run_publisher_one_shot(usk::json::canonical(mismatch), transport).exit_code != 2 || calls != 1)
        return false;
    if (usk::command::run_candidate_one_shot(request, transport).exit_code != 2 || calls != 1) return false;
    return usk::command::run_publisher_one_shot(request,
        [](const std::string&) -> std::string { throw std::runtime_error("observation unavailable"); }).exit_code == 2;
}

bool service_capability_checks()
{
    using usk::json::Value;
    const std::string request=R"({"schema":"usk.oneshot_request.v1","request_id":"service-capability-1","command":"publisher.observe","payload":{"schema":"usk.publisher_capability_request.v2","request_id":"service-capability-1"},"dry_run":false})";
    const auto cap=usk::json::parse(R"({"schema":"usk.publisher_capability.v2","request_id":"service-capability-1","provider_id":"windows_nt_x64_local_ntfs_service_sid_noreplace_v1","implementation":"partial","realization":"restricted_service","availability":false,"required_privilege":"none_for_registered_caller","permission":"registered_caller_observed","authority":"not_granted_by_discovery","qualification":"incomplete","qualification_scope":"service_admitted_target_observation","binding_provenance":"retained_controller_admission_and_current_disk_identity","support":"unsupported","recovery_ceiling":"candidate_source_free_restart","power_loss_qualified":false,"revalidation_required_before_effects":true,"execution_lease_held":false,"service_state":4,"effects":["service_start_may_occur","controller_guard_held_during_observation"],"platform":{"os_family":"Windows NT","native_arch":"x64","process_arch":"x64","windows_build":20348,"minimum_windows_build":17763},"binding":{"service_name":"USK_PUB_11111111111111111111111111111111","service_sid":"S-1-5-80-1-2-3-4-5","caller_sid":"S-1-5-21-1-2-3-1001","process_id":99,"binary_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","registration_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","target_admitted_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","volume_guid_root":"\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\","root_file_id":"0000000000000001:00000000000000000000000000000001","volume_serial":"1"}})");
    const auto& binding=cap.at("binding");
    const Value admitted(Value::Object{
        {"schema",Value("usk.publisher_registered_admission_observation.v1")},
        {"scope",Value("held_registered_service_image_and_controller_target_admission")},
        {"service_name",binding.at("service_name")},{"service_sid",binding.at("service_sid")},
        {"process_id",binding.at("process_id")},{"configured_caller_sid",binding.at("caller_sid")},
        {"publisher_image",Value(Value::Object{{"sha256",binding.at("binary_sha256")}})},
        {"registration_sha256",binding.at("registration_sha256")},
        {"target_admitted_sha256",binding.at("target_admitted_sha256")},
        {"target_identity",Value(Value::Object{{"volume_identity",Value(Value::Object{
            {"volume_root",binding.at("volume_guid_root")},{"root_file_id",binding.at("root_file_id")},
            {"volume_serial",binding.at("volume_serial")}})}})}});
    const Value response(Value::Object{
        {"schema",Value("usk.publisher_service_capability_observation.v1")},{"status",Value("observed")},
        {"request_id",cap.at("request_id")},{"service_name",binding.at("service_name")},
        {"service_sid",binding.at("service_sid")},{"process_id",binding.at("process_id")},
        {"registered_admission",admitted},{"capability_observation",cap}});
    int calls=0;
    const auto transport=[&](const std::string& input) {
        ++calls;
        if (usk::json::canonical(usk::json::parse(input)) !=
            usk::json::canonical(usk::json::parse(request).at("payload")))
            throw std::runtime_error("service capability forwarding differs");
        return usk::json::canonical(response);
    };
    const auto result=usk::command::run_publisher_one_shot(request,transport);
    if (result.exit_code != 0 || calls != 1 ||
        usk::json::canonical(usk::json::parse(result.document).at("result")) != usk::json::canonical(cap)) return false;
    const auto retained=usk::command::run_candidate_one_shot(request,transport);
    if (retained.exit_code != 0 || calls != 2 ||
        usk::json::canonical(usk::json::parse(retained.document).at("result")) !=
            usk::json::canonical(response)) return false;
    auto changed=usk::json::parse(request);
    changed.as_object()["dry_run"]=Value(true);
    if (usk::command::run_publisher_one_shot(usk::json::canonical(changed),transport).exit_code != 2 ||
        calls != 2) return false;
    changed=usk::json::parse(request);
    changed.as_object().at("payload").as_object()["request_id"]=Value("another-request");
    if (usk::command::run_publisher_one_shot(usk::json::canonical(changed),transport).exit_code != 2 ||
        calls != 2) return false;
    for (int mode=0; mode<8; ++mode) {
        auto invalid=response;
        auto& invalid_cap=invalid.as_object().at("capability_observation");
        if (mode==0) invalid_cap.as_object()["availability"]=Value(true);
        if (mode==1) invalid_cap.as_object()["effects"]=Value(Value::Array{});
        if (mode==2) invalid.as_object()["process_id"]=Value(std::uint64_t{100});
        if (mode==3) invalid.as_object().at("registered_admission").as_object()["configured_caller_sid"]=Value("S-1-5-21-1-2-3-1002");
        if (mode==4) invalid_cap.as_object().at("binding").as_object()["volume_serial"]=Value("2");
        if (mode==5) invalid_cap.as_object().at("binding").as_object()["volume_serial"]=Value("18446744073709551616");
        if (mode==6) invalid_cap.as_object()["binding_provenance"]=Value("fresh_boundary_security");
        if (mode==7) invalid_cap.as_object()["execution_lease_held"]=Value(true);
        const auto unknown=usk::command::run_publisher_one_shot(request,
            [&](const std::string&) {return usk::json::canonical(invalid);});
        if (unknown.exit_code != 5 || usk::json::parse(unknown.document).at("status").as_string() != "unknown")
            return false;
    }
    auto profile_request=usk::json::parse(request);
    profile_request.as_object().at("payload").as_object().at("schema")=Value("usk.publisher_capability_request.v3");
    const auto profile_input=usk::json::canonical(profile_request);
    auto profile_response=response;
    auto& profile=profile_response.as_object().at("capability_observation").as_object();
    profile.at("schema")=Value("usk.publisher_capability.v3");
    profile.at("availability")=Value(true);
    profile.at("qualification")=Value("qualified_for_scope");
    profile.at("support")=Value("supported_for_scope");
    profile.at("qualification_scope")=Value("registered_public_apply_v9_process_restart_replay_verify");
    profile.at("recovery_ceiling")=Value("source_free_process_restart_v9");
    profile.at("platform").as_object().emplace("sdk_version",Value("10.0.26100.0"));
    profile.emplace("qualification_bounds",Value(Value::Object{
        {"phase_schema",Value("usk.publisher.lab_phase_evidence.v9")},
        {"execution_schema",Value("usk.publisher_execution_observation.v6")},
        {"sdk_version",Value("10.0.26100.0")},{"qualified_windows_build",Value(std::uint64_t{20348})}}));
    if (usk::command::run_publisher_one_shot(profile_input,[&](const std::string&) {
        return usk::json::canonical(profile_response);}).exit_code != 0) return false;
    if (usk::command::run_candidate_one_shot(profile_input,[&](const std::string&) {
        return usk::json::canonical(profile_response);}).exit_code != 0) return false;
    if (usk::command::run_publisher_one_shot(profile_input,[&](const std::string&) {
        return usk::json::canonical(response);}).exit_code != 5) return false;
    if (usk::command::run_publisher_one_shot(request,[&](const std::string&) {
        return usk::json::canonical(profile_response);}).exit_code != 5) return false;
    for (int mode=0; mode<7; ++mode) {
        auto invalid=profile_response;
        auto& fields=invalid.as_object().at("capability_observation").as_object();
        if (mode==0) fields.at("execution_lease_held")=Value(true);
        if (mode==1) fields.at("power_loss_qualified")=Value(true);
        if (mode==2) fields.at("authority")=Value("granted");
        if (mode==3) fields.at("qualification_bounds").as_object().at("phase_schema")=Value("usk.publisher.lab_phase_evidence.v8");
        if (mode==4) fields.at("qualification_bounds").as_object().emplace("unbound",Value(true));
        if (mode==5) fields.at("platform").as_object().at("sdk_version")=Value("10.0.22621.0");
        if (mode==6) fields.at("platform").as_object().at("windows_build")=Value(std::uint64_t{22621});
        if (usk::command::run_publisher_one_shot(profile_input,[&](const std::string&) {
            return usk::json::canonical(invalid);}).exit_code != 5) return false;
    }
    for (int mode=0; mode<2; ++mode) {
        auto unavailable=profile_response;
        auto& fields=unavailable.as_object().at("capability_observation").as_object();
        fields.at("availability")=Value(false);
        fields.at("qualification")=Value("incomplete");
        fields.at("support")=Value("unsupported");
        if (mode==0) fields.at("platform").as_object().at("sdk_version")=Value("10.0.22621.0");
        if (mode==1) fields.at("platform").as_object().at("windows_build")=Value(std::uint64_t{22621});
        if (usk::command::run_publisher_one_shot(profile_input,[&](const std::string&) {
            return usk::json::canonical(unavailable);}).exit_code != 0) return false;
    }
    const auto lost=usk::command::run_publisher_one_shot(request,
        [](const std::string&) -> std::string {throw std::runtime_error("lost service observation reply");});
    return lost.exit_code==5 && usk::json::parse(lost.document).at("error").at("code").as_string()==
        "publisher_observation_unknown";
}

bool publisher_projection_checks()
{
    using usk::json::Value;
    const std::string request = R"({"schema":"usk.oneshot_request.v1","request_id":"public-1","command":"install_local.apply","payload":{"schema":"usk.install_local_apply_request.v1","plan_request":{"install_id":"example"},"transaction_id":"tx-1","applied_at":"2026-10-03T11:00:00Z"},"dry_run":false})";
    const std::string completed = R"({"schema":"usk.command_response.v1","status":"ok","payload":{"schema":"usk.installed_state.v1","install_id":"example","transaction_id":"tx-1","lifecycle_status":"installed","created_at":"2026-10-03T11:00:00Z"}})";
    const std::string prefix = R"({"schema":"usk.publisher_lab_service_observation.v1","status":"pass","private_phase_evidence":"NATIVE_CANARY","apply_response":)";
    const auto direct = prefix + completed + ",\"recovery_installed_response\":null}";
    const auto replay = prefix + "null,\"recovery_installed_response\":" + completed + "}";
    for (const auto& response : {direct, replay}) {
        const auto result = usk::command::run_publisher_one_shot(request,
            [&response](const std::string&) { return response; });
        const auto envelope = usk::json::parse(result.document);
        if (result.exit_code != 0 || result.document.find("NATIVE_CANARY") != std::string::npos ||
            envelope.at("result").at("schema").as_string() != "usk.command_response.v1" ||
            envelope.at("result").at("payload").at("transaction_id").as_string() != "tx-1")
            return false;
    }
    std::string wrong_transaction = direct;
    wrong_transaction.replace(wrong_transaction.find("tx-1"), 4, "tx-2");
    for (const auto& response : {wrong_transaction,
            prefix + completed + ",\"recovery_installed_response\":" + completed + "}",
            std::string("lost or malformed response")}) {
        const auto result = usk::command::run_publisher_one_shot(request,
            [&response](const std::string&) { return response; });
        if (result.exit_code != 5 ||
            usk::json::parse(result.document).at("status").as_string() != "unknown") return false;
    }
    const auto admission = usk::command::run_publisher_one_shot(request,
        [](const std::string&) -> std::string { throw usk::base::EffectRequestNotDispatched(); });
    if (admission.exit_code != 2 || usk::json::parse(admission.document).at("error").at("code").as_string() !=
            "publisher_admission_refused") return false;
    const auto lost = usk::command::run_publisher_one_shot(request,
        [](const std::string&) -> std::string { throw std::runtime_error("lost reply"); });
    if (lost.exit_code != 5 || usk::json::parse(lost.document).at("status").as_string() != "unknown") return false;
    const std::string reference = "usk.operation-inspection.v1:" + std::string(64, 'a');
    for (const auto status : {"failed", "recovery_required"}) {
        for (const auto code : {"operation_conflict", "operation_cancelled", "lease_stale", "state_revision_stale"}) {
            const Value observation(Value::Object{
                {"schema", Value("usk.publisher_lab_service_observation.v1")},
                {"status", Value(status)}, {"error_code", Value(code)},
                {"operation_inspection_ref", Value(reference)},
                {"error", Value("PRIVATE_ERROR_CANARY")}});
            const auto result = usk::command::run_publisher_one_shot(request,
                [&](const std::string&) { return usk::json::canonical(observation); });
            const auto projected = usk::json::parse(result.document);
            const bool recovery_required = std::string(status) == "recovery_required";
            if (result.exit_code != (recovery_required ? 5 : 4) ||
                projected.at("status").as_string() != (recovery_required ? "recovery_required" : "refused") ||
                projected.at("error").at("code").as_string() != code ||
                projected.at("result").at("inspection_reference").as_string() != reference ||
                projected.at("result").as_object().size() != 3 ||
                result.document.find("PRIVATE_ERROR_CANARY") != std::string::npos)
                return false;
        }
    }
    Value refused(Value::Object{
        {"schema", Value("usk.publisher_lab_service_observation.v1")},
        {"status", Value("failed")}, {"error_code", Value("operation_conflict")}});
    const auto without_reference = usk::command::run_publisher_one_shot(request,
        [&](const std::string&) { return usk::json::canonical(refused); });
    if (without_reference.exit_code != 4 ||
        usk::json::parse(without_reference.document).at("result").type() != Value::Type::null_value) return false;
    for (const auto& invalid : {Value("PRIVATE_REFERENCE_CANARY"),
            Value("usk.operation-inspection.v1:" + std::string(63, 'a')),
            Value("usk.operation-inspection.v1:" + std::string(64, 'A')), Value(false)}) {
        refused.as_object()["operation_inspection_ref"] = invalid;
        const auto result = usk::command::run_publisher_one_shot(request,
            [&](const std::string&) { return usk::json::canonical(refused); });
        if (result.exit_code != 5 ||
            usk::json::parse(result.document).at("status").as_string() != "unknown" ||
            result.document.find("PRIVATE_REFERENCE_CANARY") != std::string::npos) return false;
    }
    refused.as_object()["error_code"] = Value("unrecognized_native_code");
    const auto unrecognized = usk::command::run_publisher_one_shot(request,
        [&](const std::string&) { return usk::json::canonical(refused); });
    if (unrecognized.exit_code != 4 ||
        usk::json::parse(unrecognized.document).at("error").at("code").as_string() != "publisher_failed" ||
        usk::json::parse(unrecognized.document).at("result").type() != Value::Type::null_value) return false;
    const std::string recovery = R"({"schema":"usk.oneshot_request.v1","request_id":"recovery-1","command":"install_local.recover","payload":{"schema":"usk.publisher_recovery_request.v1","install_id":"example","transaction_id":"tx-1"},"dry_run":false})";
    const auto recovered = usk::command::run_publisher_one_shot(recovery,
        [&replay](const std::string&) { return replay; });
    if (recovered.exit_code != 0 || recovered.document.find("NATIVE_CANARY") != std::string::npos) return false;
    const std::string verify = R"({"schema":"usk.oneshot_request.v1","request_id":"verify-1","command":"installed.verify","payload":{"schema":"usk.publisher_installed_verify_request.v1","install_id":"example","transaction_id":"tx-1","report_id":"report-1","verified_at":"2026-10-03T11:00:00Z"},"dry_run":false})";
    std::string drift = R"({"schema":"usk.publisher_lab_service_observation.v1","status":"failed","bound_report_digest":"digest-1","private_phase_evidence":"NATIVE_CANARY","verify_response":{"schema":"usk.command_response.v1","status":"ok","payload":{"schema":"usk.verification_report.v1","status":"fail","install_id":"example","report_id":"report-1","verified_at":"2026-10-03T11:00:00Z","report_digest":"digest-1"}}})";
    const auto diagnosed = usk::command::run_publisher_one_shot(verify,
        [&drift](const std::string&) { return drift; });
    if (diagnosed.exit_code != 0 || diagnosed.document.find("NATIVE_CANARY") != std::string::npos ||
        usk::json::parse(diagnosed.document).at("result").at("payload").at("status").as_string() != "fail")
        return false;
    drift.replace(drift.find("report-1"), 8, "report-2");
    return usk::command::run_publisher_one_shot(verify,
        [&drift](const std::string&) { return drift; }).exit_code == 5;
}

} // namespace

int main()
{
    if (!publisher_projection_checks()) return 23;
    if (!publisher_capability_checks()) return 24;
    if (!service_capability_checks()) return 25;
    const std::string request =
        "{\"schema\":\"usk.oneshot_request.v1\",\"request_id\":\"probe-1\","
        "\"command\":\"command_graph.inspect\",\"payload\":{},\"dry_run\":true}";
    const auto result = usk::command::run_one_shot(request);
    if (result.exit_code != 0 || !result.diagnostic.empty()) return 1;
    const auto parsed = usk::json::parse(result.document);
    if (parsed.at("request_id").as_string() != "probe-1" ||
        parsed.at("status").as_string() != "ok" ||
        parsed.at("result").type() != usk::json::Value::Type::object) return 2;

    if (!refused_with(
            "{\"schema\":\"usk.oneshot_request.v1\",\"schema\":\"SECRET_CANARY\"}",
            "invalid_request") ||
        !refused_with(
            "{\"schema\":\"usk.oneshot_request.v1\",\"request_id\":\"x\","
            "\"command\":\"install_local.apply\",\"payload\":{},\"dry_run\":true}",
            "command_unavailable") ||
        !refused_with(
            "{\"schema\":\"usk.oneshot_request.v1\",\"request_id\":\"x\","
            "\"command\":\"policy.inspect\",\"payload\":{},\"dry_run\":false}",
            "invalid_request") ||
        !refused_with(
            "{\"schema\":\"usk.oneshot_request.v1\",\"request_id\":\"x\","
            "\"command\":\"policy.inspect\",\"payload\":{\"a\":1,\"a\":2},"
            "\"dry_run\":true}", "invalid_request")) return 3;

    const std::string candidate_request =
        "{\"schema\":\"usk.oneshot_request.v1\",\"request_id\":\"candidate-1\","
        "\"command\":\"install_local.apply\",\"payload\":{\"schema\":"
        "\"usk.install_local_apply_request.v1\"},\"dry_run\":false}";
    std::string forwarded;
    const auto admitted = usk::command::run_candidate_one_shot(candidate_request,
        [&forwarded](const std::string& request_body) {
            forwarded = request_body;
            return "{\"schema\":\"usk.publisher_lab_service_observation.v1\","
                "\"status\":\"pass\",\"apply_response\":{\"schema\":"
                "\"usk.command_response.v1\",\"status\":\"ok\"},"
                "\"recovery_installed_response\":null}";
        });
    if (admitted.exit_code != 0 || forwarded !=
            "{\"schema\":\"usk.install_local_apply_request.v1\"}" ||
        usk::json::parse(admitted.document).at("status").as_string() != "ok") return 15;
    const auto reentered = usk::command::run_candidate_one_shot(candidate_request,
        [](const std::string&) {
            return "{\"schema\":\"usk.publisher_lab_service_observation.v1\","
                "\"status\":\"pass\",\"apply_response\":null,"
                "\"recovery_installed_response\":{\"schema\":"
                "\"usk.command_response.v1\",\"status\":\"ok\"}}";
        });
    if (reentered.exit_code != 0 ||
        usk::json::parse(reentered.document).at("status").as_string() != "ok") return 21;
    const auto ambiguous = usk::command::run_candidate_one_shot(candidate_request,
        [](const std::string&) {
            return "{\"schema\":\"usk.publisher_lab_service_observation.v1\","
                "\"status\":\"pass\",\"apply_response\":{\"schema\":"
                "\"usk.command_response.v1\",\"status\":\"ok\"},"
                "\"recovery_installed_response\":{\"schema\":"
                "\"usk.command_response.v1\",\"status\":\"ok\"}}";
        });
    if (ambiguous.exit_code != 5 ||
        usk::json::parse(ambiguous.document).at("status").as_string() != "unknown") return 22;
    const auto unresolved = usk::command::run_candidate_one_shot(candidate_request,
        [](const std::string&) -> std::string { throw std::runtime_error("lost reply"); });
    if (unresolved.exit_code != 5 ||
        usk::json::parse(unresolved.document).at("status").as_string() != "unknown")
        return 16;
    const auto retained = usk::command::run_candidate_one_shot(candidate_request,
        [](const std::string&) {
            return "{\"schema\":\"usk.publisher_lab_service_observation.v1\","
                "\"status\":\"recovery_required\"}";
        });
    if (retained.exit_code != 5 ||
        usk::json::parse(retained.document).at("status").as_string() !=
            "recovery_required") return 17;
    const std::string verify_request =
        "{\"schema\":\"usk.oneshot_request.v1\",\"request_id\":\"verify-1\","
        "\"command\":\"installed.verify\",\"payload\":{\"schema\":"
        "\"usk.publisher_installed_verify_request.v1\"},\"dry_run\":false}";
    const auto drift = usk::command::run_candidate_one_shot(verify_request,
        [](const std::string&) {
            return "{\"schema\":\"usk.publisher_lab_service_observation.v1\","
                "\"status\":\"failed\",\"bound_report_digest\":\"digest\","
                "\"verify_response\":{\"schema\":\"usk.command_response.v1\","
                "\"status\":\"ok\",\"payload\":{\"schema\":"
                "\"usk.verification_report.v1\",\"status\":\"fail\","
                "\"report_digest\":\"digest\"}}}";
        });
    if (drift.exit_code != 0 ||
        usk::json::parse(drift.document).at("status").as_string() != "ok") return 19;
    const auto verify_refusal = usk::command::run_candidate_one_shot(verify_request,
        [](const std::string&) {
            return "{\"schema\":\"usk.publisher_lab_service_observation.v1\","
                "\"status\":\"failed\",\"error\":\"stale request\"}";
        });
    if (verify_refusal.exit_code != 4 ||
        usk::json::parse(verify_refusal.document).at("status").as_string() !=
            "refused") return 20;
    const auto unavailable = usk::command::run_candidate_one_shot(
        "{\"schema\":\"usk.oneshot_request.v1\",\"request_id\":\"candidate-1\","
        "\"command\":\"repair.apply\",\"payload\":{},\"dry_run\":false}",
        [&forwarded](const std::string&) { forwarded = "incorrectly dispatched"; return ""; });
    if (unavailable.exit_code == 0 || forwarded == "incorrectly dispatched" ||
        usk::json::parse(unavailable.document).at("error").at("code").as_string() !=
            "command_unavailable") return 18;

    const std::string plan_request =
        "{\"schema\":\"usk.oneshot_request.v1\",\"request_id\":\"plan-1\","
        "\"command\":\"install_local.plan\",\"payload\":{},\"dry_run\":true}";
    if (!refused_with(plan_request, "context_mismatch")) return 11;
    std::istringstream configuration(
        "{\"schema\":\"usk.oneshot_context.v1\",\"state_root\":\"C:/setup\","
        "\"authorized_acceptance_root\":\"C:/\","
        "\"target_policy_activation\":\"operator_acceptance_candidate\"}");
    const auto configured = usk::command::read_context_config(configuration);
    if (configured.state_root != "C:/setup") return 12;
    const auto legacy = usk::command::run_one_shot(plan_request, &configured);
    if (legacy.exit_code == 0 ||
        usk::json::parse(legacy.document).at("error").at("code").as_string() !=
            "protected_authority_required") return 12;
    for (int field = 0; field < 3; ++field) {
        auto invalid = configured;
        if (field == 0) invalid.state_root += std::string(1, '\0') + "other";
        if (field == 1) invalid.authorized_acceptance_root += std::string(1, '\0') + "other";
        if (field == 2) invalid.target_policy_activation += std::string(1, '\0') + "other";
        const auto denied = usk::command::run_one_shot(plan_request, &invalid);
        if (denied.exit_code == 0 ||
            usk::json::parse(denied.document).at("error").at("code").as_string() !=
                "invalid_context") return 14;
    }
    try {
        std::istringstream malformed(
            "{\"schema\":\"usk.oneshot_context.v1\",\"state_root\":\"C:/setup\","
            "\"authorized_acceptance_root\":\"C:/\","
            "\"target_policy_activation\":\"operator_acceptance_candidate\","
            "\"extra\":\"refuse\"}");
        (void)usk::command::read_context_config(malformed);
        return 13;
    } catch (const std::exception&) {
    }

    std::ostringstream frame;
    usk::command::write_result(frame, request, true);
    std::istringstream frame_input(frame.str());
    if (usk::command::read_bounded_request(frame_input, true) != request) return 4;
    if (!frame_refused(std::string("\x00\x10\x00\x01", 4)) ||
        !frame_refused(std::string("\x00\x00\x00\x05" "ab", 6)) ||
        !frame_refused(std::string("\x00\x00\x00\x02" "abx", 7))) return 5;

    std::istringstream oversized(std::string(usk::command::max_request_bytes + 1, 'x'));
    try {
        (void)usk::command::read_bounded_request(oversized, false);
        return 6;
    } catch (const std::runtime_error&) {
    }
    std::ostringstream plain;
    usk::command::write_result(plain, result.document, false);
    if (plain.str() != result.document + "\n") return 7;

    const std::string framed_request =
        std::string("\x00\x00\x00", 3) + static_cast<char>(request.size()) + request;
    BadAtEndBuffer bad_frame(framed_request);
    std::istream bad_frame_input(&bad_frame);
    try {
        (void)usk::command::read_bounded_request(bad_frame_input, true);
        return 8;
    } catch (const std::runtime_error&) {
    }
    BadAtEndBuffer bad_plain(request);
    std::istream bad_plain_input(&bad_plain);
    bad_plain.mark_bad_and_eof_on_end(bad_plain_input);
    try {
        (void)usk::command::read_bounded_request(bad_plain_input, false);
        return 9;
    } catch (const std::runtime_error&) {
    }
    FailOnFlushBuffer bad_output_buffer;
    std::ostream bad_output(&bad_output_buffer);
    try {
        usk::command::write_result(bad_output, result.document, false);
        return 10;
    } catch (const std::runtime_error&) {
    }
    return 0;
}
