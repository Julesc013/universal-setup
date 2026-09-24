// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_token_observation.h"

#include <windows.h>

#include <iostream>
#include <stdexcept>
#include <string>

using usk::platform::windows::has_restricted_publisher_token_facts;
using usk::platform::windows::observe_current_publisher_token;

namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
} // namespace

int main() {
    try {
        const auto ordinary = observe_current_publisher_token();
        check(!ordinary.process_user_sid.empty() && !ordinary.current_thread_impersonating,
            "ordinary process token or thread state was not observed");
        const std::string service_sid =
            "S-1-5-80-3180180915-1861177297-4117424284-3321057921-2519428456";
        check(!has_restricted_publisher_token_facts(ordinary, service_sid),
            "ordinary login was admitted as a restricted publisher service");
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
