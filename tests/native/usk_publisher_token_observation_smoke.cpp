// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_token_observation.h"
#include "usk_publisher_execution_observation.h"

#include <windows.h>
#include <sddl.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <functional>

using usk::platform::windows::has_restricted_publisher_token_facts;
using usk::platform::windows::observe_current_publisher_token;
using usk::platform::windows::observe_current_restricted_publisher_service;
using usk::platform::windows::derive_ascii_publisher_service_sid;

namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

#if defined(_WIN64)
void execution_record_controls(const usk::json::Value& platform, const std::string& service_sid) {
    using usk::json::Value;
    using namespace usk::platform::windows;
    const std::wstring name = L"USK_Disposable_Execution_Record_Model";
    const std::vector<std::string> roles{"volume_root", "publication_root", "staging_anchor",
        "destination_parent", "state_anchor", "journal_anchor", "payload_root"};
    std::vector<std::pair<std::string, std::string>> bindings;
    Value::Array handles;
    for (std::size_t index = 0; index < roles.size(); ++index) {
        const std::string id = "0000000000001234:" + std::string(31, '0') + static_cast<char>('1' + index);
        bindings.emplace_back(roles[index], id);
        handles.emplace_back(Value::Object{{"role", Value(roles[index])}, {"file_id", Value(id)},
            {"handle_flags", Value(std::uint64_t{0})}});
    }
    const Value service(Value::Object{{"service_name", Value("USK_Disposable_Execution_Record_Model")},
        {"service_sid", Value(service_sid)}, {"service_sid_type", Value(std::uint64_t{3})},
        {"service_type", Value(std::uint64_t{16})}, {"service_state", Value(std::uint64_t{4})},
        {"process_id", Value(std::uint64_t{500})}, {"process_user_sid", Value("S-1-5-18")},
        {"thread_impersonating", Value(false)},
        {"process_groups", Value(Value::Array{Value(Value::Object{{"sid", Value(service_sid)},
            {"attributes", Value(std::uint64_t{4})}})})},
        {"process_restricted_sids", Value(Value::Array{Value(Value::Object{{"sid", Value(service_sid)},
            {"attributes", Value(std::uint64_t{0})}})})},
        {"token_id", Value("0000000000000123")}, {"authentication_id", Value("00000000000003e7")},
        {"modified_id", Value("0000000000000124")}, {"token_type", Value(std::uint64_t{1})}});
    const Value valid(Value::Object{{"schema", Value("usk.publisher_execution_observation.v1")},
        {"scope", Value("supplied_held_service_handles")}, {"phase", Value("sealed")},
        {"platform", platform}, {"service", service}, {"handles", Value(handles)}});
    // Pure parser controls: this structured record makes no native service claim.
    require_publisher_execution_phase(valid, name, service_sid, "sealed", bindings);
    const auto refuses = [&](const std::function<void(Value&)>& mutate) {
        auto invalid = valid;
        mutate(invalid);
        bool failed = false;
        try { require_publisher_execution_phase(invalid, name, service_sid, "sealed", bindings); }
        catch (const std::runtime_error&) { failed = true; }
        check(failed, "closed native execution parser accepted contradictory evidence");
    };
    refuses([](Value& v) { v.as_object().at("scope") = Value("all_system_handles"); });
    refuses([](Value& v) { v.as_object().at("phase") = Value("visible_bound"); });
    refuses([](Value& v) { v.as_object().emplace("extra", Value(true)); });
    refuses([](Value& v) { v.as_object().at("handles").as_array().pop_back(); });
    refuses([](Value& v) { v.as_object().at("handles").as_array()[0].as_object().at("handle_flags") = Value(std::uint64_t{1}); });
    refuses([](Value& v) { v.as_object().at("handles").as_array()[0].as_object().at("file_id") = Value("invalid"); });
    refuses([](Value& v) { v.as_object().at("platform").as_object().at("process_arch") = Value("x86"); });
    refuses([](Value& v) { v.as_object().at("platform").as_object().at("sdk_version") = Value(""); });
    refuses([](Value& v) { v.as_object().at("platform").as_object().at("windows_build") = Value(std::uint64_t{17762}); });
    refuses([](Value& v) { v.as_object().at("service").as_object().at("thread_impersonating") = Value(true); });
    refuses([](Value& v) { v.as_object().at("service").as_object().at("token_type") = Value(std::uint64_t{2}); });
    refuses([](Value& v) { v.as_object().at("service").as_object().at("token_id") = Value("0000000000000000"); });
    refuses([](Value& v) { v.as_object().at("service").as_object().at("process_restricted_sids") = Value(Value::Array{}); });
    for (const auto* invalid_sid : {"", "BA", "S-1-05-32-545", "S-1-5-32-4294967296"}) {
        refuses([&](Value& v) { v.as_object().at("service").as_object().at("process_groups").as_array().emplace_back(
            Value::Object{{"sid", Value(invalid_sid)}, {"attributes", Value(std::uint64_t{0})}}); });
    }
    auto later = valid;
    later.as_object().at("phase") = Value("publish_prepared");
    require_publisher_execution_worker_match(valid, later);
    later.as_object().at("service").as_object().at("modified_id") = Value("0000000000000125");
    bool changed_refused = false;
    try { require_publisher_execution_worker_match(valid, later); }
    catch (const std::runtime_error&) { changed_refused = true; }
    check(changed_refused, "changed worker token was accepted across phases");
}
#endif
} // namespace

int main() {
    try {
        // Independent published MS-LSAT vector, usable before registration.
        const auto known_sid = derive_ascii_publisher_service_sid(L"ALG");
        LPWSTR rendered = nullptr;
        check(ConvertSidToStringSidW(const_cast<unsigned char*>(known_sid.data()), &rendered) != FALSE,
            "derived known service SID could not be rendered");
        const std::wstring rendered_sid(rendered);
        LocalFree(rendered);
        check(rendered_sid == L"S-1-5-80-2387347252-3645287876-2469496166-3824418187-3586569773" &&
            known_sid == derive_ascii_publisher_service_sid(L"alg"),
            "service SID derivation differs from the published Windows mapping");
        const auto live_sid = derive_ascii_publisher_service_sid(L"RpcSs");
        unsigned char resolved[SECURITY_MAX_SID_SIZE]{};
        wchar_t domain[256]{};
        DWORD resolved_bytes = sizeof(resolved);
        DWORD domain_chars = 256;
        SID_NAME_USE use{};
        check(LookupAccountNameW(nullptr, L"NT SERVICE\\RpcSs", resolved,
                &resolved_bytes, domain, &domain_chars, &use) != FALSE &&
            EqualSid(resolved, const_cast<unsigned char*>(live_sid.data())),
            "derived service SID differs from live Windows account lookup");
        bool invalid_derivation_refused = false;
        try { (void)derive_ascii_publisher_service_sid(L"bad\\service"); }
        catch (const std::runtime_error&) { invalid_derivation_refused = true; }
        check(invalid_derivation_refused, "out-of-profile derivation name was accepted");
        const auto ordinary = observe_current_publisher_token();
        check(!ordinary.process_user_sid.empty() && !ordinary.current_thread_impersonating,
            "ordinary process token or thread state was not observed");
        check(ordinary.identity.token_id != 0 && ordinary.identity.authentication_id != 0 &&
            ordinary.identity.modified_id != 0 && ordinary.identity.token_type == TokenPrimary,
            "actual process token statistics identity was not observed");
        HANDLE held_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, GetCurrentProcessId());
        check(held_process != nullptr, "query-only held process token control is unavailable");
        const auto held_token = usk::platform::windows::observe_held_publisher_process_token(held_process);
        CloseHandle(held_process);
        check(held_token.process_user_sid == ordinary.process_user_sid &&
            held_token.identity.token_id == ordinary.identity.token_id &&
            held_token.identity.authentication_id == ordinary.identity.authentication_id &&
            held_token.identity.modified_id == ordinary.identity.modified_id &&
            held_token.identity.token_type == ordinary.identity.token_type && !held_token.current_thread_impersonating,
            "actual held-process token differs from the current primary token");
        HANDLE synchronization_only = OpenProcess(SYNCHRONIZE, FALSE, GetCurrentProcessId());
        check(synchronization_only != nullptr, "synchronize-only process control is unavailable");
        bool missing_query_refused = false;
        try { (void)usk::platform::windows::observe_held_publisher_process_token(synchronization_only); }
        catch (const std::runtime_error&) { missing_query_refused = true; }
        CloseHandle(synchronization_only);
        check(missing_query_refused, "primary-token observation accepted a process handle without query rights");
        const auto platform = usk::platform::windows::observe_publisher_execution_platform();
        check(platform.at("windows_build").as_unsigned() >= 17763 &&
            platform.at("sdk_version").as_string().compare(0, 5, "10.0.") == 0,
            "actual Windows build and selected build SDK were not bound");
        auto qualified_platform = platform;
        auto& qualified_fields = qualified_platform.as_object();
        qualified_fields.at("native_arch") = usk::json::Value("x64");
        qualified_fields.at("process_arch") = usk::json::Value("x64");
        qualified_fields.at("major_version") = usk::json::Value(std::uint64_t{10});
        qualified_fields.at("minor_version") = usk::json::Value(std::uint64_t{0});
        qualified_fields.at("windows_build") = usk::json::Value(std::uint64_t{20348});
        qualified_fields.at("sdk_version") = usk::json::Value("10.0.26100.0");
        check(usk::platform::windows::publisher_registered_execution_platform_qualified(qualified_platform),
            "exact registered production tuple was refused");
        for (int mode = 0; mode < 8; ++mode) {
            auto unsupported = qualified_platform;
            auto& fields = unsupported.as_object();
            if (mode == 0) fields.at("windows_build") = usk::json::Value(std::uint64_t{22621});
            if (mode == 1) fields.at("sdk_version") = usk::json::Value("10.0.22621.0");
            if (mode == 2) fields.at("process_arch") = usk::json::Value("x86");
            if (mode == 3) fields.at("major_version") = usk::json::Value(std::uint64_t{11});
            if (mode == 4) fields.at("sdk_version") = usk::json::Value("");
            if (mode == 5) fields.emplace("unbound", usk::json::Value(true));
            if (mode == 6) fields.at("windows_build") = usk::json::Value(true);
            if (mode == 7) fields.at("native_arch") = usk::json::Value("unsupported");
            check(!usk::platform::windows::publisher_registered_execution_platform_qualified(unsupported),
                "unqualified registered production tuple was admitted");
            if (mode < 2)
                usk::platform::windows::require_publisher_execution_platform(unsupported);
        }
        const std::string service_sid =
            "S-1-5-80-3180180915-1861177297-4117424284-3321057921-2519428456";
#if defined(_WIN64)
        execution_record_controls(platform, service_sid);
#else
        bool x86_refused = false;
        try { usk::platform::windows::require_publisher_execution_platform(platform); }
        catch (const std::runtime_error&) { x86_refused = true; }
        check(x86_refused, "Win32 process was accepted by the native x64 execution profile");
#endif
        check(!has_restricted_publisher_token_facts(ordinary, service_sid),
            "ordinary login was admitted as a restricted publisher service");
        bool absent_service_refused = false;
        try {
            (void)observe_current_restricted_publisher_service(
                L"USK_Disposable_Publisher_Uninstalled_4f83c63b");
        } catch (const std::runtime_error&) {
            absent_service_refused = true;
        }
        check(absent_service_refused,
            "uninstalled service was admitted as current restricted publisher");
        bool malformed_service_refused = false;
        try {
            (void)observe_current_restricted_publisher_service(L"bad\\service");
        } catch (const std::runtime_error&) {
            malformed_service_refused = true;
        }
        check(malformed_service_refused,
            "malformed service name was admitted");
        const usk::platform::windows::PublisherTokenObservation forged_system{
            "S-1-5-18", {{"S-1-1-0", SE_GROUP_ENABLED}}, {{"S-1-1-0", 0}}, false};
        check(!has_restricted_publisher_token_facts(forged_system, "S-1-1-0") &&
            !has_restricted_publisher_token_facts(forged_system, "S-1-5-18") &&
            !has_restricted_publisher_token_facts(forged_system, "S-1-5-80-1"),
            "non-service SID was accepted as the restricted publisher identity");
        usk::platform::windows::PublisherTokenObservation model_token{
            "S-1-5-18", {{service_sid, SE_GROUP_ENABLED}}, {{service_sid, 0}}, false};
        check(has_restricted_publisher_token_facts(model_token, service_sid),
            "closed predicate rejected the required service-token fact shape");
        model_token.process_groups.front().attributes = SE_GROUP_USE_FOR_DENY_ONLY;
        check(!has_restricted_publisher_token_facts(model_token, service_sid),
            "deny-only service group was admitted");
        model_token.process_groups.front().attributes = SE_GROUP_ENABLED;
        model_token.process_restricted_sids.clear();
        check(!has_restricted_publisher_token_facts(model_token, service_sid),
            "service SID absent from restricting list was admitted");
        check(ImpersonateSelf(SecurityImpersonation) != FALSE,
            "disposable thread impersonation setup failed");
        try {
            const auto impersonated = observe_current_publisher_token();
            check(impersonated.current_thread_impersonating &&
                impersonated.process_user_sid == ordinary.process_user_sid,
                "process token and thread impersonation were conflated");
            check(!has_restricted_publisher_token_facts(impersonated, service_sid),
                "impersonating thread was admitted");
        } catch (...) {
            RevertToSelf();
            throw;
        }
        check(RevertToSelf() != FALSE, "thread impersonation teardown failed");
        check(!observe_current_publisher_token().current_thread_impersonating,
            "thread impersonation remained after teardown");
        std::cout << "Windows publisher process/restricted token observation PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
