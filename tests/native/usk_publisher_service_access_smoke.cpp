// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_service_access.h"
#include <functional>
#include <iostream>
#include <stdexcept>
using usk::json::Value;
using namespace usk::platform::windows;
namespace {
const std::string client = "S-1-5-21-1-2-3-1001";
const std::string unrelated = "S-1-5-21-1-2-3-1002";
constexpr std::uint32_t query = READ_CONTROL | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS |
    SERVICE_ENUMERATE_DEPENDENTS | SERVICE_INTERROGATE | SERVICE_USER_DEFINED_CONTROL;
Value ace(const std::string& sid, std::uint32_t mask) {
    return Value(Value::Object{{"type", Value(std::uint64_t{0})}, {"flags", Value(std::uint64_t{0})},
        {"access_mask", Value(static_cast<std::uint64_t>(mask))}, {"sid", Value(sid)}});
}
Value policy() {
    return Value(Value::Object{{"schema", Value("usk.publisher_service_access.v1")},
        {"scope", Value("stored_service_owner_dacl")}, {"authorized_client_sid", Value(client)},
        {"owner_sid", Value("S-1-5-18")}, {"dacl_present", Value(true)}, {"dacl_protected", Value(false)},
        {"dacl_aces", Value(Value::Array{ace("S-1-5-18", SERVICE_ALL_ACCESS),
            ace("S-1-5-32-544", SERVICE_ALL_ACCESS), ace(client, query | SERVICE_START), ace(unrelated, query)})}});
}
void control(const std::function<void(Value&)>& alter) {
    auto value = policy(); alter(value);
    bool refused = false;
    try { require_publisher_service_access(value, client); }
    catch (const std::exception&) { refused = true; }
    if (!refused) throw std::runtime_error("service access admitted contradictory policy");
}
}
int main() {
    try {
        require_publisher_service_access(policy(), client);
        for (unsigned index = 0; index != 2; ++index) {
            const auto allowed = query | (index == 0 ? SERVICE_START : 0u);
            for (unsigned bit = 0; bit != 32; ++bit) {
                const auto right = std::uint32_t{1} << bit;
                if (right & allowed) continue;
                control([&](Value& value) {
                    value.as_object().at("dacl_aces").as_array()[index + 2].as_object().at("access_mask") =
                        Value(static_cast<std::uint64_t>(allowed | right));
                });
            }
        }
        control([](Value& value) { value.as_object().at("owner_sid") = Value(client); });
        control([](Value& value) { value.as_object().at("authorized_client_sid") = Value(unrelated); });
        control([](Value& value) { value.as_object().at("dacl_present") = Value(false); });
        control([](Value& value) { value.as_object().at("dacl_protected") = Value(std::uint64_t{0}); });
        control([](Value& value) { value.as_object().emplace("caller_admitted", Value(true)); });
        control([](Value& value) { value.as_object().at("dacl_aces").as_array().back().as_object().at("type") = Value(std::uint64_t{5}); });
        control([](Value& value) { value.as_object().at("dacl_aces").as_array().back().as_object().at("flags") = Value(std::uint64_t{16}); });
        auto denied = policy();
        auto& outside = denied.as_object().at("dacl_aces").as_array().back().as_object();
        outside.at("type") = Value(std::uint64_t{ACCESS_DENIED_ACE_TYPE});
        outside.at("access_mask") = Value(std::uint64_t{0xffffffffu});
        require_publisher_service_access(denied, client);
        std::cout << "closed service owner/DACL policy controls passed; hosted SCM qualification required\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
