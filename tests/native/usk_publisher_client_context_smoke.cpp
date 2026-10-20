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

// Test executable only: dispatch can deny every later allocation, including
// reply decoding and output formatting. The owned fallback must still escape.
namespace { thread_local bool deny_plan_reply_allocations = false; }
void* operator new(std::size_t bytes) {
    if (deny_plan_reply_allocations) throw std::bad_alloc();
    if (void* memory = std::malloc(bytes ? bytes : 1)) return memory;
    throw std::bad_alloc();
}
void* operator new[](std::size_t bytes) { return ::operator new(bytes); }
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete[](void* memory) noexcept { ::operator delete(memory); }
void operator delete(void* memory, std::size_t) noexcept { ::operator delete(memory); }
void operator delete[](void* memory, std::size_t) noexcept { ::operator delete(memory); }

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
Value plan_request(const char* id) {
    auto value = usk::json::parse(R"({
        "schema":"usk.install_local_plan_request.v1","request_id":"plan.a",
        "created_at":"2026-10-21T00:00:00Z","install_id":"example",
        "required_commit_authority":"staged_child_bound_v1",
        "archive":{"path":"C:/input.zip","format":"zip","expected_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "strip_prefix":"payload/","budgets":{"max_entries":100,"max_uncompressed_bytes":1048576,
            "max_entry_bytes":1048576,"max_depth":16,"max_ratio":100,"max_elapsed_ms":1000}},
        "target":{"root":"C:/product","class":"operator_acceptance_candidate"},
        "recipe":{"product_id":"example","product_version":"1.0.0","recipe_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "provider_revision":"provider.1","components":["extra","core"],
            "entrypoints":[{"entrypoint_id":"app","relative_path":"app.exe","kind":"executable"}]}})");
    value.as_object().at("request_id") = Value(id);
    return value;
}
std::string plan_completion(const std::string& bytes) {
    const auto wire = usk::json::parse(bytes);
    // Controlled transport only. The hosted public-C consumer separately
    // establishes the full native plan and authenticated registered endpoint.
    const Value plan(Value::Object{{"schema", Value("usk.install_plan.v1")},
        {"operation", Value("install_local")}, {"status", Value("planned")},
        {"plan_id", wire.at("request_id")}, {"created_at", wire.at("created_at")},
        {"plan_digest", Value(std::string(64u, 'c'))},
        {"required_commit_authority", wire.at("required_commit_authority")},
        {"commit_authority_available", Value(false)},
        {"source", Value(Value::Object{{"path", wire.at("archive").at("path")}, {"sha256", wire.at("archive").at("expected_sha256")}})},
        {"target", wire.at("target")}, {"component_selection", wire.at("recipe").at("components")},
        {"input_identity", Value(Value::Object{{"recipe_digest", wire.at("recipe").at("recipe_digest")},
            {"provider_revision", wire.at("recipe").at("provider_revision")}, {"source_digest", wire.at("archive").at("expected_sha256")}})}});
    const Value endpoint(Value::Object{{"schema", Value("usk.publisher_registered_admission_observation.v1")},
        {"service_name", Value("test-provider")}, {"service_sid", Value("test-service-sid")},
        {"process_id", Value(std::uint64_t{47})}});
    return usk::json::canonical(Value(Value::Object{
        {"schema", Value("usk.publisher_lab_service_observation.v1")}, {"status", Value("pass")},
        {"service_name", endpoint.at("service_name")}, {"service_sid", endpoint.at("service_sid")},
        {"process_id", endpoint.at("process_id")}, {"registered_admission", endpoint},
        {"request_sha256", Value(usk::json::sha256_canonical(wire))},
        {"plan_response", Value(Value::Object{{"schema", Value("usk.command_response.v1")},
            {"status", Value("ok")}, {"payload", plan}, {"error", Value()}})}}));
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

        auto plan = plan_request("plan.a");
        const auto execute_plan = [&](const Value& input, const PublisherClientTransport& transport,
            const PublisherClientPrepare& preparer = prepare) {
            const auto input_bytes = usk::json::canonical(input);
            return first.execute("install_local.plan", input_bytes.data(), input_bytes.size(), transport, preparer);
        };
        bool plan_forwarded = false;
        const auto plan_ok = execute_plan(plan, [&](const std::string& sent) {
            plan_forwarded = sent == usk::json::canonical(plan);
            return plan_completion(sent);
        });
        REQUIRE(plan_forwarded && plan_ok.status == USK_STATUS_OK &&
            usk::json::equal_values(usk::json::parse(plan_ok.json),
                usk::json::parse(plan_completion(usk::json::canonical(plan))).at("plan_response")));
        plan.as_object().at("request_id") = Value("plan.b");
        plan.as_object().at("install_id") = Value("other-install");
        for (int fault = 0; fault < 3; ++fault) {
            const auto result = execute_plan(plan, [fault](const std::string& sent) {
                auto reply = usk::json::parse(plan_completion(sent));
                if (fault == 0) reply.as_object().at("request_sha256") = Value(std::string(64u, 'd'));
                else if (fault == 1) reply.as_object().at("plan_response").as_object().at("payload")
                    .as_object().at("component_selection").as_array().clear();
                else reply.as_object().at("registered_admission").as_object().at("process_id") = Value(std::uint64_t{48});
                return usk::json::canonical(reply);
            });
            const auto unknown = usk::json::parse(result.json);
            REQUIRE(result.status == USK_STATUS_ERROR && unknown.at("status").as_string() == "unknown" &&
                unknown.at("payload").at("request_id").as_string() == "plan.b" &&
                unknown.at("payload").at("install_id").as_string() == "other-install" &&
                unknown.at("payload").at("request_sha256").as_string() == usk::json::sha256_canonical(plan) &&
                !unknown.at("payload").contains("reviewed_plan_id"));
        }
        for (int fault = 0; fault < 3; ++fault) {
            int callbacks = 0;
            auto invalid_plan = plan;
            if (fault == 0) invalid_plan.as_object().at("archive").as_object().at("budgets")
                .as_object().at("max_entries") = Value(true);
            else if (fault == 1) invalid_plan.as_object().at("recipe").as_object().at("entrypoints")
                .as_array().front().as_object().emplace("unknown", Value(true));
            else invalid_plan.as_object().erase("required_commit_authority");
            const auto result = execute_plan(invalid_plan,
                [&](const std::string&) { ++callbacks; return std::string("{}"); },
                [&](const std::string&, const Value& input) { ++callbacks; return input; });
            REQUIRE(callbacks == 0 && result.status == USK_STATUS_INVALID_ARGUMENT);
        }
        dispatched = 0;
        const auto changed_plan = execute_plan(plan, [&](const std::string& sent) {
            ++dispatched; return plan_completion(sent);
        }, [](const std::string&, const Value& input) {
            auto changed = input;
            changed.as_object().at("recipe").as_object().at("components").as_array().clear();
            return changed;
        });
        REQUIRE(dispatched == 0 && changed_plan.status == USK_STATUS_ERROR &&
            usk::json::parse(changed_plan.json).at("error").at("code").as_string() == "publisher_request_not_dispatched");
        const auto lost_plan = execute_plan(plan, [](const std::string&) -> std::string {
            deny_plan_reply_allocations = true;
            throw std::bad_alloc();
        });
        deny_plan_reply_allocations = false;
        REQUIRE(lost_plan.status == USK_STATUS_ERROR &&
            usk::json::parse(lost_plan.json).at("status").as_string() == "unknown" &&
            usk::json::parse(lost_plan.json).at("payload").at("request_id").as_string() == "plan.b");

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

        // Query preparation uses the same public closed decoder and fresh
        // invocation buffer as apply. These fake transports establish only
        // preparation/uncertainty semantics, never native query completion.
        for (const auto* operation : {"install_local", "repair", "move", "uninstall"}) {
            for (const auto* command : {"recovery.inspect", "recovery.plan", "recovery.apply"}) {
                auto apply = recovery;
                auto& selected_inspection = inspection(apply);
                selected_inspection.as_object().at("operation") = Value(operation);
                selected_inspection.as_object().at("request_id") = Value(std::string(command) + "." + operation);
                const Value input = std::string(command) == "recovery.inspect" ? selected_inspection :
                    std::string(command) == "recovery.plan" ? apply.at("plan_request") : apply;
                const auto input_bytes = usk::json::canonical(input);
                const auto expected_inspection = selected_inspection;
                for (bool allocation : {false, true}) {
                    bool exact_wire = false;
                    auto result = first.execute(command, input_bytes.data(), input_bytes.size(),
                        [&](const std::string& sent) -> std::string {
                            exact_wire = sent == input_bytes;
                            if (allocation) throw std::bad_alloc();
                            return "{"; // Invalid reply after dispatch remains unknown.
                        }, prepare);
                    const auto response = usk::json::parse(result.json);
                    const auto& bound = response.at("payload");
                    REQUIRE(exact_wire && result.status == USK_STATUS_ERROR &&
                        response.at("status").as_string() == "unknown" &&
                        bound.at("command").as_string() == command &&
                        bound.at("request_sha256").as_string() == usk::json::sha256_canonical(input));
                    for (const auto* field : {"request_id", "install_id", "transaction_id", "operation", "plan_id", "plan_digest"})
                        REQUIRE(usk::json::equal_values(bound.at(field), expected_inspection.at(field)));
                    REQUIRE(!bound.contains("target_root") && !bound.contains("request"));
                    if (std::string(command) == "recovery.apply")
                        REQUIRE(bound.at("selected_action").as_string() == "rollback" &&
                            bound.at("reviewed_plan_digest").as_string() == input.at("reviewed_plan_digest").as_string());
                    else REQUIRE(!bound.contains("selected_action") && !bound.contains("reviewed_plan_digest"));
                    if (std::string(command) == "recovery.plan")
                        REQUIRE(bound.at("recovery_plan_id").as_string() == input.at("recovery_plan_id").as_string());
                }
                const auto pre_dispatch = [&](const PublisherClientPrepare& preparer) {
                    int dispatched = 0;
                    const auto result = first.execute(command, input_bytes.data(), input_bytes.size(),
                        [&](const std::string&) -> std::string {
                            ++dispatched; throw std::runtime_error("unexpected transport");
                        }, preparer);
                    REQUIRE(dispatched == 0 && result.status == USK_STATUS_ERROR &&
                        usk::json::parse(result.json).at("error").at("code").as_string() ==
                            "publisher_request_not_dispatched");
                };
                pre_dispatch([](const std::string&, const Value&) -> Value { throw std::bad_alloc(); });
                pre_dispatch([](const std::string&, const Value&) {
                    return Value(Value::Object{{"schema", Value("usk.publisher_maintenance_recovery_request.v1")},
                        {"request_id", Value("lookup")}, {"install_id", Value("example")},
                        {"transaction_id", Value("install.example")}});
                });
                pre_dispatch([](const std::string&, const Value& original) {
                    auto changed = original;
                    changed.as_object().emplace("adapter_annotation", Value(true));
                    return changed;
                });
                auto invalid = input;
                invalid.as_object().emplace("unknown", Value(true));
                const auto malformed_bytes = usk::json::canonical(invalid);
                int callbacks = 0;
                const auto malformed_result = first.execute(command, malformed_bytes.data(), malformed_bytes.size(),
                    [&](const std::string&) { ++callbacks; return std::string("{}"); },
                    [&](const std::string&, const Value& value) { ++callbacks; return value; });
                REQUIRE(callbacks == 0 && malformed_result.status == USK_STATUS_INVALID_ARGUMENT);
                // A malformed recognized root schema is invalid input, not
                // preparation uncertainty. Allocation remains a distinct error.
                for (int form = 0; form < 3; ++form) {
                    auto bad_schema = input;
                    if (form == 0) bad_schema.as_object().erase("schema");
                    else bad_schema.as_object().at("schema") =
                        form == 1 ? Value() : Value(std::uint64_t{1});
                    const auto invalid_schema_bytes = usk::json::canonical(bad_schema);
                    callbacks = 0;
                    const auto invalid_schema_result = first.execute(command,
                        invalid_schema_bytes.data(), invalid_schema_bytes.size(),
                        [&](const std::string&) { ++callbacks; return std::string("{}"); },
                        [&](const std::string&, const Value& value) { ++callbacks; return value; });
                    REQUIRE(callbacks == 0 && invalid_schema_result.status == USK_STATUS_INVALID_ARGUMENT &&
                        usk::json::parse(invalid_schema_result.json).at("error").at("code").as_string() ==
                            "invalid_argument");
                }
                REQUIRE(usk::json::canonical(input) == input_bytes);
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
        // The explicit provider context advertises its native response
        // version; an ordinary local context retains the public v1 contract.
        const auto recovery_graph = [&](usk_context* selected, const char* suffix) {
            const char* graph_command = "command_graph.inspect_v2";
            usk_command_request_v1 graph_request{};
            graph_request.struct_size = sizeof(graph_request);
            graph_request.command_name = {graph_command, static_cast<usk_size>(std::strlen(graph_command))};
            graph_request.json_payload = {"{}", 2};
            usk_command_response_v1 graph_response{};
            graph_response.struct_size = sizeof(graph_response);
            REQUIRE(usk_command_execute_v1(selected, &graph_request, &graph_response) == USK_STATUS_OK);
            const auto graph = usk::json::parse(std::string(graph_response.json_payload.data,
                static_cast<std::size_t>(graph_response.json_payload.size)));
            unsigned found = 0;
            for (const auto& command : graph.at("payload").at("commands").as_array()) {
                const auto name = command.at("command").as_string();
                if (name == "recovery.inspect" || name == "recovery.apply" || name == "recovery.plan") {
                    REQUIRE(command.at("response_schema").as_string() ==
                        std::string(name == "recovery.plan" ? "usk.recovery_plan." : "usk.recovery_report.") + suffix);
                    ++found;
                }
            }
            REQUIRE(found == 3);
        };
        recovery_graph(context, "v2");
        usk_context* ordinary = nullptr;
        REQUIRE(usk_context_create_v1(nullptr, &ordinary) == USK_STATUS_OK && ordinary);
        recovery_graph(ordinary, "v1");
        usk_context_destroy_v1(ordinary);
        // Both existing dry_run forms for a nonmutating C command must use
        // the configured endpoint, even with no local lifecycle roots.
        for (const int dry_run : {0, 1}) {
            const auto query = plan_request("sdk.plan");
            const auto query_bytes = usk::json::canonical(query);
            invalid.command_name = {"install_local.plan", 18};
            invalid.json_payload = {query_bytes.data(), static_cast<usk_size>(query_bytes.size())};
            invalid.dry_run = dry_run;
            REQUIRE(usk_command_execute_v1(context, &invalid, &response) == USK_STATUS_ERROR);
            const auto refused = usk::json::parse(std::string(response.json_payload.data,
                static_cast<std::size_t>(response.json_payload.size)));
            REQUIRE(refused.at("status").as_string() == "refused" &&
                refused.at("payload").at("command").as_string() == "install_local.plan" &&
                refused.at("payload").at("request_sha256").as_string() == usk::json::sha256_canonical(query));
        }
        invalid.dry_run = 0;
        // A publisher context owns recovery queries too: they may not fall
        // through into local filesystem inspection. The fixed fixture endpoint
        // has no registered backend; refusal must retain this public invocation.
        for (const auto* command : {"recovery.inspect", "recovery.plan"}) {
            const Value query = std::string(command) == "recovery.inspect" ?
                recovery.at("plan_request").at("inspection") : recovery.at("plan_request");
            const auto query_bytes = usk::json::canonical(query);
            invalid.command_name = {command, static_cast<usk_size>(std::strlen(command))};
            invalid.json_payload = {query_bytes.data(), static_cast<usk_size>(query_bytes.size())};
            REQUIRE(usk_command_execute_v1(context, &invalid, &response) == USK_STATUS_ERROR &&
                response.json_payload.data);
            const auto query_refused = usk::json::parse(std::string(response.json_payload.data,
                static_cast<std::size_t>(response.json_payload.size)));
            REQUIRE(query_refused.at("status").as_string() == "refused" &&
                query_refused.at("payload").at("command").as_string() == command &&
                query_refused.at("payload").at("request_sha256").as_string() == usk::json::sha256_canonical(query));
        }
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
