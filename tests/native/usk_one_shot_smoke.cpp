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

bool publisher_projection_checks()
{
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
