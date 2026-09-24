// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_one_shot.h"
#include "usk_json.h"

#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

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

} // namespace

int main()
{
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
    return 0;
}
