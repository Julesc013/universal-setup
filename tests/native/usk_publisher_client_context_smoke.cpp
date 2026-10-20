// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk/usk_publisher_client.h"
#include "usk_publisher_client_context_internal.h"
#include "usk_effect_dispatch.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <new>
#include <stdexcept>
#include <string>

namespace {
using usk::json::Value;
using namespace usk::command::detail;
Value request(const char* id) {
    return Value(Value::Object{{"schema", Value("usk.installed_verify_request.v1")},
        {"request_id", Value(id)}, {"install_id", Value("example")},
        {"report_id", Value(id)}, {"verified_at", Value("2026-10-19T00:00:00Z")}});
}
Value prepare(const std::string&, const Value& input) {
    return input;
}
std::string completion(const std::string& bytes) {
    const auto wire = usk::json::parse(bytes);
    const std::string digest(64u, 'a');
    const Value report(Value::Object{{"schema", Value("usk.verification_report.v1")},
        {"status", Value("pass")}, {"install_id", wire.at("install_id")},
        {"report_id", wire.at("report_id")}, {"verified_at", wire.at("verified_at")},
        {"report_digest", Value(digest)}});
    const Value response(Value::Object{{"schema", Value("usk.command_response.v1")},
        {"status", Value("ok")}, {"payload", report}, {"error", Value()}});
    return usk::json::canonical(Value(Value::Object{
        {"schema", Value("usk.publisher_lab_service_observation.v1")},
        {"status", Value("pass")}, {"request_sha256", Value(usk::json::sha256_canonical(wire))},
        {"bound_report_digest", Value(digest)}, {"verify_response", response}}));
}
PublisherClientResult execute(PublisherClientContext& context, const Value& input,
    const PublisherClientTransport& transport, const PublisherClientPrepare& preparer = prepare) {
    const auto bytes = usk::json::canonical(input);
    return context.execute("installed.verify", bytes.data(), bytes.size(), transport, preparer);
}
void require_condition(bool condition, int line) {
    if (!condition) throw std::runtime_error("publisher client ownership check failed at line " + std::to_string(line));
}
#define REQUIRE(condition) require_condition((condition), __LINE__)
struct Allocation { int live = 0; bool fail = false; };
void* allocate(void* opaque, usk_size bytes) {
    auto& a = *static_cast<Allocation*>(opaque);
    if (a.fail) return nullptr;
    void* result = std::malloc(static_cast<std::size_t>(bytes));
    if (result) ++a.live;
    return result;
}
void release(void* opaque, void* value) {
    if (value) { --static_cast<Allocation*>(opaque)->live; std::free(value); }
}
}

int main() {
    try {
        const std::string endpoint = "USK_PUB_" + std::string(32u, 'a');
        PublisherClientContext first(endpoint), second(endpoint);
        auto a = request("verify.a"), b = request("verify.b");
        auto good = execute(first, a, completion);
        REQUIRE(good.status == USK_STATUS_OK &&
            usk::json::parse(good.json).at("payload").at("report_id").as_string() == "verify.a");
        auto lost = execute(first, b, [](const std::string&) -> std::string { throw std::bad_alloc(); });
        const auto unknown_b = usk::json::parse(lost.json);
        REQUIRE(lost.status == USK_STATUS_ERROR && unknown_b.at("status").as_string() == "unknown" &&
            unknown_b.at("payload").at("report_id").as_string() == "verify.b");
        const std::string first_owned(lost.json);
        auto other = execute(second, a, [](const std::string&) -> std::string { throw std::runtime_error("lost reply"); });
        REQUIRE(usk::json::parse(other.json).at("payload").at("report_id").as_string() == "verify.a" &&
            std::string(lost.json) == first_owned);
        auto malformed = execute(first, a, [](const std::string&) { return std::string("{"); });
        REQUIRE(usk::json::parse(malformed.json).at("status").as_string() == "unknown");
        auto declined = execute(first, b, [](const std::string&) -> std::string {
            throw usk::base::EffectRequestNotDispatched(
                usk::base::EffectRequestNotDispatched::Reason::operation_conflict);
        });
        REQUIRE(usk::json::parse(declined.json).at("status").as_string() == "refused" &&
            usk::json::parse(declined.json).at("error").at("code").as_string() == "operation_conflict");
        int dispatched = 0;
        auto early = execute(first, a, [&dispatched](const std::string& bytes) {
            ++dispatched; return completion(bytes);
        }, [](const std::string&, const Value&) -> Value { throw std::bad_alloc(); });
        REQUIRE(dispatched == 0 && usk::json::parse(early.json).at("error").at("code").as_string() ==
            "publisher_request_not_dispatched");

        auto recovery = usk::json::parse(
            "{\"schema\":\"usk.recovery_apply_request.v1\",\"plan_request\":{\"schema\":\"usk.recovery_plan_request.v1\","
            "\"inspection\":{\"schema\":\"usk.recovery_inspect_request.v1\",\"request_id\":\"recovery.a\","
            "\"install_id\":\"example\",\"transaction_id\":\"install.example\",\"plan_id\":\"plan.example\","
            "\"plan_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"operation\":\"install_local\",\"target_root\":\"C:/product\"},\"recovery_plan_id\":\"recover.plan\","
            "\"created_at\":\"2026-10-19T00:00:00Z\"},\"reviewed_plan_id\":\"recover.plan\","
            "\"reviewed_plan_digest\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
            "\"selected_action\":\"rollback\",\"applied_at\":\"2026-10-19T00:00:00Z\",\"confirmation\":\"APPLY\"}");
#if !defined(_WIN32)
        // The registered transport is local; use this host's absolute path
        // grammar even when exercising only the pure fake transport.
        recovery.as_object().at("plan_request").as_object().at("inspection")
            .as_object().at("target_root") = Value("/product");
#endif
        const auto bytes = usk::json::canonical(recovery);
        bool full_request_observed = false;
        auto unknown_recovery = first.execute("recovery.apply", bytes.data(), bytes.size(),
            [&full_request_observed, &bytes](const std::string& sent) -> std::string {
                full_request_observed = sent == bytes;
                throw std::runtime_error("uncertain");
            },
            [](const std::string&, const Value& input) { return input; });
        const auto retained = usk::json::parse(unknown_recovery.json);
        REQUIRE(full_request_observed && retained.at("status").as_string() == "unknown" &&
            retained.at("payload").at("request_sha256").as_string() == usk::json::sha256_canonical(recovery) &&
            retained.at("payload").at("selected_action").as_string() == "rollback" &&
            retained.at("payload").at("reviewed_plan_digest").as_string() ==
                recovery.at("reviewed_plan_digest").as_string() &&
            !retained.at("payload").contains("request"));

        // Recognized malformed public recovery must fail before preparer or
        // transport callbacks. These are ordinary client checks, not grants.
        const auto inspection = [](Value& value) -> Value& {
            return value.as_object().at("plan_request").as_object().at("inspection");
        };
        const auto no_dispatch = [&](const Value& invalid) {
            int prepared = 0, dispatched = 0;
            const auto input = usk::json::canonical(invalid);
            const auto result = first.execute("recovery.apply", input.data(), input.size(),
                [&](const std::string&) -> std::string {
                    ++dispatched; throw std::runtime_error("unexpected dispatch");
                },
                [&](const std::string&, const Value& value) {
                    ++prepared; return value;
                });
            REQUIRE(result.status == USK_STATUS_INVALID_ARGUMENT && prepared == 0 && dispatched == 0);
        };
        auto invalid_recovery = recovery;
        inspection(invalid_recovery).as_object().erase("plan_id");
        no_dispatch(invalid_recovery);
        invalid_recovery = recovery;
        inspection(invalid_recovery).as_object().at("request_id") = Value("");
        no_dispatch(invalid_recovery);
        invalid_recovery = recovery;
        inspection(invalid_recovery).as_object().at("install_id") = Value("../other");
        no_dispatch(invalid_recovery);
        invalid_recovery = recovery;
        inspection(invalid_recovery).as_object().at("operation") = Value("other");
        no_dispatch(invalid_recovery);
        invalid_recovery = recovery;
        inspection(invalid_recovery).as_object().at("target_root") = Value("relative/product");
        no_dispatch(invalid_recovery);
        invalid_recovery = recovery;
        inspection(invalid_recovery).as_object().at("plan_digest") = Value(std::string(64u, 'X'));
        no_dispatch(invalid_recovery);
        invalid_recovery = recovery;
        inspection(invalid_recovery).as_object().emplace("unknown", Value(true));
        no_dispatch(invalid_recovery);
        invalid_recovery = recovery;
        inspection(invalid_recovery).as_object().at("operation") = Value("repair");
        inspection(invalid_recovery).as_object().emplace("install_plan_request", Value(Value::Object{}));
        no_dispatch(invalid_recovery);
        invalid_recovery = recovery;
        invalid_recovery.as_object().at("plan_request").as_object().at("schema") = Value("other");
        no_dispatch(invalid_recovery);
        invalid_recovery = recovery;
        invalid_recovery.as_object().at("plan_request").as_object().erase("created_at");
        no_dispatch(invalid_recovery);
        invalid_recovery = recovery;
        invalid_recovery.as_object().at("plan_request").as_object().at("recovery_plan_id") = Value("other.plan");
        no_dispatch(invalid_recovery);
        invalid_recovery = recovery;
        invalid_recovery.as_object().at("plan_request").as_object().at("inspection") = Value();
        no_dispatch(invalid_recovery);
        invalid_recovery = recovery;
        invalid_recovery.as_object().at("reviewed_plan_digest") = Value(std::string(63u, 'b'));
        no_dispatch(invalid_recovery);
        invalid_recovery = recovery;
        invalid_recovery.as_object().at("applied_at") = Value(std::string("date\0suffix", 11u));
        no_dispatch(invalid_recovery);
        for (const auto* operation : {"install_local", "repair", "move", "uninstall"}) {
            for (const auto* action : {"finalize", "rollback"}) {
                auto valid = recovery;
                inspection(valid).as_object().at("operation") = Value(operation);
                valid.as_object().at("selected_action") = Value(action);
                const auto input = usk::json::canonical(valid);
                bool observed = false;
                const auto result = first.execute("recovery.apply", input.data(), input.size(),
                    [&](const std::string& sent) -> std::string {
                        observed = sent == input;
                        throw std::runtime_error("reply unavailable after possible dispatch");
                    }, prepare);
                const auto response = usk::json::parse(result.json);
                REQUIRE(observed && result.status == USK_STATUS_ERROR &&
                    response.at("status").as_string() == "unknown" &&
                    response.at("payload").at("selected_action").as_string() == action &&
                    response.at("payload").at("operation").as_string() == operation &&
                    response.at("payload").at("reviewed_plan_digest").as_string() ==
                        valid.at("reviewed_plan_digest").as_string());
            }
        }

        usk_publisher_client_config_v1 config{};
        config.struct_size = sizeof(config);
        config.service_name = {endpoint.data(), endpoint.size()};
        usk_context* context = nullptr;
        auto bad = config; bad.struct_size = sizeof(config) - 1;
        REQUIRE(usk_context_create_publisher_v1(nullptr, &bad, &context) == USK_STATUS_INVALID_ARGUMENT && !context);
        REQUIRE(usk_abi_version_v1() == 0x00010000u);
        Allocation allocation;
        usk_allocator_v1 allocator{sizeof(allocator), &allocation, allocate, release};
        usk_config_v1 local{sizeof(local), nullptr, &allocator, nullptr, nullptr};
        const int created = usk_context_create_publisher_v1(&local, &config, &context);
#if defined(_WIN32)
        REQUIRE(created == USK_STATUS_OK && context && allocation.live == 1);
        usk_command_request_v1 invalid{};
        invalid.struct_size = sizeof(invalid);
        invalid.command_name = {"installed.verify", 16};
        invalid.json_payload = {"{}", 2};
        usk_command_response_v1 response{};
        response.struct_size = sizeof(response);
        REQUIRE(usk_command_execute_v1(context, &invalid, &response) == USK_STATUS_INVALID_ARGUMENT &&
            response.json_payload.data &&
            usk::json::parse(std::string(response.json_payload.data,
                static_cast<std::size_t>(response.json_payload.size))).at("error").at("code").as_string() ==
                "invalid_argument");
        usk_context_destroy_v1(context);
        REQUIRE(allocation.live == 0);
        context = nullptr; allocation.fail = true;
        REQUIRE(usk_context_create_publisher_v1(&local, &config, &context) == USK_STATUS_ERROR && !context &&
            allocation.live == 0);
#else
        REQUIRE(created == USK_STATUS_UNSUPPORTED_VERSION && !context && allocation.live == 0);
#endif
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what()); return 1;
    } catch (...) { return 2; }
}
