// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_process_boundary.h"
#include "usk_publisher_execution_observation.h"
#include <functional>
#include <iostream>
#include <stdexcept>

using usk::json::Value;
using namespace usk::platform::windows;

namespace {
const std::string service_sid = "S-1-5-80-1-2-3-4-5";
const std::string consumer_sid = "S-1-5-21-1-2-3-1000";
const std::vector<ObservedTokenGroup> groups{
    {service_sid, SE_GROUP_ENABLED}, {"S-1-5-5-0-900", SE_GROUP_LOGON_ID | SE_GROUP_ENABLED}};
constexpr std::uint32_t query_rights = SYNCHRONIZE | READ_CONTROL |
    PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

Value ace(const std::string& sid, std::uint32_t mask) {
    return Value(Value::Object{{"type", Value(std::uint64_t{0})},
        {"flags", Value(std::uint64_t{0})}, {"access_mask", Value(static_cast<std::uint64_t>(mask))},
        {"sid", Value(sid)}});
}

Value boundary() {
    return Value(Value::Object{{"schema", Value("usk.publisher_process_boundary.v1")},
        {"scope", Value("stored_current_process_owner_dacl")}, {"process_id", Value(std::uint64_t{500})},
        {"owner_sid", Value("S-1-5-18")}, {"dacl_present", Value(true)}, {"dacl_protected", Value(false)},
        {"dacl_aces", Value(Value::Array{ace("S-1-5-18", PROCESS_ALL_ACCESS),
            ace(service_sid, PROCESS_ALL_ACCESS), ace(consumer_sid, query_rights)})}});
}
} // namespace

int main() {
    try {
        // Ordinary-process readback only: no SCM, descriptor changes or opens
        // against another process. These facts confer no publisher authority.
        const auto actual = observe_current_publisher_process_boundary();
        check(actual.as_object().size() == 7 && actual.at("process_id").as_unsigned() == GetCurrentProcessId() &&
            actual.at("dacl_present").as_boolean() && !actual.at("owner_sid").as_string().empty(),
            "current process owner/DACL facts were not observed");

        // Synthetic policy controls are separate from the native observation.
        require_publisher_process_boundary(boundary(), 500, service_sid, groups);
        for (const auto& owner : {std::string("S-1-5-18"), std::string("S-1-5-32-544"),
                                 service_sid, std::string("S-1-5-5-0-900")}) {
            auto value = boundary();
            value.as_object().at("owner_sid") = Value(owner);
            require_publisher_process_boundary(value, 500, service_sid, groups);
        }
        auto deny = boundary();
        auto denied = ace(consumer_sid, PROCESS_ALL_ACCESS);
        denied.as_object().at("type") = Value(std::uint64_t{1});
        deny.as_object().at("dacl_aces").as_array().push_back(denied);
        require_publisher_process_boundary(deny, 500, service_sid, groups);

        const auto refuses = [&](const std::function<void(Value&)>& change) {
            auto value = boundary();
            change(value);
            bool refused = false;
            try { require_publisher_process_boundary(value, 500, service_sid, groups); }
            catch (const std::exception&) { refused = true; }
            check(refused, "process boundary admitted an outside capability or contradictory record");
        };
        for (unsigned bit = 0; bit < 32; ++bit) {
            const std::uint32_t right = std::uint32_t{1} << bit;
            if (query_rights & right) continue;
            refuses([&](Value& value) {
                value.as_object().at("dacl_aces").as_array().back().as_object().at("access_mask") =
                    Value(static_cast<std::uint64_t>(query_rights | right));
            });
        }
        refuses([](Value& value) { value.as_object().at("process_id") = Value(true); });
        refuses([](Value& value) { value.as_object().at("owner_sid") = Value(consumer_sid); });
        refuses([](Value& value) { value.as_object().at("dacl_present") = Value(false); });
        refuses([](Value& value) {
            value.as_object().at("dacl_aces").as_array().back().as_object().at("flags") =
                Value(std::uint64_t{INHERITED_ACE});
        });
        bool refused = false;
        try {
            require_publisher_process_boundary(boundary(), 500, service_sid,
                {{"S-1-5-5-900", SE_GROUP_LOGON_ID | SE_GROUP_ENABLED}});
        } catch (const std::exception&) { refused = true; }
        check(refused, "process boundary admitted an invalid publisher logon SID");

        // Pure cross-record continuity controls; phase admission is separate.
        const Value earlier(Value::Object{{"schema", Value("usk.publisher_execution_observation.v2")},
            {"scope", Value("supplied_held_service_handles_and_process_owner_dacl")},
            {"platform", Value(Value::Object{})}, {"handles", Value(Value::Array{})},
            {"service", Value(Value::Object{{"process_id", Value(std::uint64_t{500})},
                {"token_id", Value("0000000000000500")}})}, {"process_boundary", boundary()}});
        require_publisher_execution_record_continuity(earlier, earlier);
        auto later = earlier;
        later.as_object().at("process_boundary").as_object().at("dacl_protected") = Value(true);
        refused = false;
        try { require_publisher_execution_record_continuity(earlier, later); }
        catch (const std::exception&) { refused = true; }
        check(refused, "same-worker prepared/visible process boundary changed");
        later = earlier;
        later.as_object().at("schema") = Value("usk.publisher_execution_observation.v1");
        later.as_object().at("scope") = Value("supplied_held_service_handles");
        later.as_object().erase("process_boundary");
        refused = false;
        try { require_publisher_execution_record_continuity(earlier, later); }
        catch (const std::exception&) { refused = true; }
        check(refused, "same-worker visible record downgraded its process boundary");
        later = earlier;
        later.as_object().at("service").as_object().at("process_id") = Value(std::uint64_t{600});
        later.as_object().at("service").as_object().at("token_id") = Value("0000000000000600");
        later.as_object().at("process_boundary").as_object().at("process_id") = Value(std::uint64_t{600});
        require_publisher_execution_record_continuity(earlier, later);
        std::cout << "actual read-only current process boundary and synthetic policy controls passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
