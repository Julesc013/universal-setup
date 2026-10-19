// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_response_internal.h"

#include <stdexcept>
#include <string>

int main()
{
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
