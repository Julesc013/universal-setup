// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

// Test-only adapter: calls the real planner and app composition, never a service.
#include "usk_product_install.h"
#include "usk_effect_dispatch.h"
#include "usk_json.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

int main(int argc, char** argv)
{
    using usk::json::Value;
    if (argc != 6) return 2;
    unsigned calls = 0;
    unsigned plan_calls = 0, effect_calls = 0;
    Value submitted, response;
    int code = 2;
    bool refused = false;
    try {
        const auto read = [](const char* name) {
            std::ifstream file(name, std::ios::binary);
            if (!file) throw std::runtime_error("fixture unavailable");
            return std::string(std::istreambuf_iterator<char>(file), {});
        };
        std::ifstream context_input(argv[5], std::ios::binary);
        const auto context = usk::command::read_context_config(context_input);
        const std::string mode(argv[1]);
        const bool provider = mode.compare(0, 9, "provider-") == 0;
        const usk::command::CandidateTransport transport = [&](const std::string& text) -> std::string {
                    ++calls;
                    submitted = usk::json::parse(text);
                    if (submitted.at("schema").as_string() == "usk.install_local_plan_request.v1") {
                        ++plan_calls;
                        if (mode == "provider-unknown-plan") throw std::runtime_error("lost query response");
                        if (mode == "provider-query-refuse") throw usk::base::EffectRequestNotDispatched();
                        const Value query(Value::Object{{"schema", Value("usk.oneshot_request.v1")},
                            {"request_id", submitted.at("request_id")}, {"command", Value("install_local.plan")},
                            {"dry_run", Value(true)}, {"payload", submitted}});
                        const auto planned = usk::command::run_one_shot(usk::json::canonical(query), &context);
                        if (planned.exit_code) return "{\"schema\":\"usk.publisher_lab_service_observation.v1\",\"status\":\"failed\"}";
                        auto native = usk::json::parse(planned.document).at("result");
                        if (mode == "provider-bad-target") native.as_object().at("payload").as_object().at("target").as_object().at("root") = Value("other");
                        if (mode == "provider-stale") native.as_object().at("payload").as_object().at("planned_entries").as_array().back().as_object().at("sha256") = Value(std::string(64, 'a'));
                        const Value endpoint(Value::Object{{"schema", Value("usk.publisher_registered_admission_observation.v1")},
                            {"process_id", Value(std::uint64_t{47})}, {"service_name", Value("test-provider")}, {"service_sid", Value("test-service-sid")}});
                        return usk::json::canonical(Value(Value::Object{
                            {"schema", Value("usk.publisher_lab_service_observation.v1")}, {"status", Value("pass")},
                            {"service_name", Value("test-provider")}, {"service_sid", Value("test-service-sid")},
                            {"process_id", Value(mode == "provider-bad-pid" ? std::uint64_t{48} : std::uint64_t{47})},
                            {"registered_admission", endpoint}, {"plan_response", native},
                            {"request_sha256", Value(mode == "provider-bad-hash" ? std::string(64, 'a') : usk::json::sha256_canonical(submitted))}}));
                    }
                    ++effect_calls;
                    if (mode == "provider-unknown-apply") throw std::runtime_error("lost apply response");
                    if (std::string(argv[1]) == "unknown") throw std::runtime_error("lost response");
                    if (std::string(argv[1]) == "refuse") throw usk::base::EffectRequestNotDispatched();
                    return usk::json::canonical(Value(Value::Object{
                        {"schema", Value("usk.publisher_lab_service_observation.v1")}, {"status", Value("pass")},
                        {"recovery_installed_response", Value()},
                        {"apply_response", Value(Value::Object{
                            {"schema", Value("usk.command_response.v1")}, {"status", Value("ok")},
                            {"payload", Value(Value::Object{
                                {"schema", Value("usk.installed_state.v1")}, {"lifecycle_status", Value("installed")},
                                {"install_id", submitted.at("plan_request").at("install_id")},
                                {"transaction_id", submitted.at("transaction_id")},
                                {"created_at", submitted.at("applied_at")}})}})}}));
                };
        const auto result = mode == "plan" ?
            usk::command::plan_product_install(argv[2], read(argv[3]), context) : mode == "provider-plan" ?
            usk::command::plan_product_install(argv[2], read(argv[3]), transport) : provider ?
            usk::command::apply_product_install_registered(argv[2], read(argv[3]), read(argv[4]), transport) :
            usk::command::apply_product_install(argv[2], read(argv[3]), read(argv[4]), context, transport);
        code = result.exit_code;
        response = usk::json::parse(result.document);
    } catch (const std::exception&) { refused = true; }
    std::cout << usk::json::canonical(Value(Value::Object{
        {"code", Value(static_cast<std::uint64_t>(code))},
        {"calls", Value(static_cast<std::uint64_t>(calls))}, {"refused", Value(refused)},
        {"plan_calls", Value(static_cast<std::uint64_t>(plan_calls))}, {"effect_calls", Value(static_cast<std::uint64_t>(effect_calls))},
        {"submitted", submitted}, {"response", response}})) << '\n';
    return 0;
}
