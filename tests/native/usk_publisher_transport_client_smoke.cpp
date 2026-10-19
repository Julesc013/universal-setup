// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_request_channel.h"
#include "usk_publisher_registered_client_internal.h"
#include "usk_effect_dispatch.h"

#include <stdexcept>
#include <string>

int main()
{
    using usk::json::Value;
    using namespace usk::platform::windows;
    // Binding data only: this does not authenticate an endpoint or send bytes.
    Value request(Value::Object{{"schema", Value("usk.publisher_capability_request.v2")},
        {"request_id", Value("client.link")}});
    const Value observed(Value::Object{
        {"schema", Value("usk.publisher_service_capability_observation.v1")},
        {"status", Value("observed")}, {"request_id", Value("client.link")},
        {"service_name", Value("USK_CLIENT_LINK")},
        {"service_sid", Value("S-1-5-80-1-2-3-4-5")},
        {"process_id", Value(static_cast<std::uint64_t>(7))},
        {"registered_admission", Value(Value::Object{})},
        {"capability_observation", Value(Value::Object{
            {"schema", Value("usk.publisher_capability.v2")}})}});
    const auto reply = usk::json::canonical(observed);
    const auto submitted = usk::json::canonical(request);
    require_publisher_response_binding(L"USK_CLIENT_LINK", submitted, reply, 7);
    try {
        require_publisher_response_binding(L"USK_CLIENT_LINK", submitted, reply, 8);
        return 1;
    } catch (const std::runtime_error&) {}
    request.as_object().at("request_id") = Value("another.request");
    try {
        require_publisher_response_binding(L"USK_CLIENT_LINK",
            usk::json::canonical(request), reply, 7);
        return 2;
    } catch (const std::runtime_error&) {}
    // Force the complete client transport link closure. An invalid timeout
    // refuses before SCM/pipe access; this test supplies no native authority.
    bool raw_refused = false;
    try {
        (void)submit_publisher_request(L"USK_CLIENT_LINK", submitted, 0);
    } catch (const PublisherRequestOutcomeUnknown&) {
        return 3;
    } catch (const std::runtime_error&) {
        raw_refused = true;
    }
    if (!raw_refused) return 4;
    // Force the registered-client/query closure too. This invalid generated
    // name is rejected before SCM and cannot select the privileged legacy path.
    try {
        (void)submit_service_admitted_publisher_request(L"invalid", submitted);
    } catch (const usk::base::EffectRequestNotDispatched&) {
        return 0;
    } catch (...) {
        return 5;
    }
    return 6;
}
