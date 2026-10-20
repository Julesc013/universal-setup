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
        const auto result = std::string(argv[1]) == "plan" ?
            usk::command::plan_product_install(argv[2], read(argv[3]), context) :
            usk::command::apply_product_install(argv[2], read(argv[3]), read(argv[4]), context,
                [&](const std::string& text) -> std::string {
                    ++calls;
                    submitted = usk::json::parse(text);
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
                });
        code = result.exit_code;
        response = usk::json::parse(result.document);
    } catch (const std::exception&) { refused = true; }
    std::cout << usk::json::canonical(Value(Value::Object{
        {"code", Value(static_cast<std::uint64_t>(code))},
        {"calls", Value(static_cast<std::uint64_t>(calls))}, {"refused", Value(refused)},
        {"submitted", submitted}, {"response", response}})) << '\n';
    return 0;
}
