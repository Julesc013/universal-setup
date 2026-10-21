// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_one_shot.h"
#include "usk_publisher_client_context_internal.h"
#include "usk_publisher_response_internal.h"
#include "usk_json.h"
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

// Test-only allocation denial starts inside a fake admitted transport.
// No service, native authority, installation or recovery effect is created.
namespace { thread_local bool deny_allocations = false; }
void* operator new(std::size_t bytes) {
    if (deny_allocations) throw std::bad_alloc();
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
void require(bool condition, int line) {
    if (!condition) throw std::runtime_error("public one-shot recovery control failed at " + std::to_string(line));
}
#define REQUIRE(condition) require((condition), __LINE__)
struct ResetDenial { ~ResetDenial() { deny_allocations = false; } };

struct Fixture {
    Value inspection, plan, apply, binding;
    Fixture() {
        const std::string sha(64u, 'a');
        inspection = Value(Value::Object{{"schema", Value("usk.recovery_inspect_request.v1")},
            {"request_id", Value("inspection.current")}, {"install_id", Value("product")},
            {"transaction_id", Value("repair.tx")}, {"plan_id", Value("original.plan")},
            {"plan_digest", Value(sha)}, {"operation", Value("repair")},
            {"target_root", Value((std::filesystem::current_path() / "target").generic_u8string())}});
        plan = Value(Value::Object{{"schema", Value("usk.recovery_plan_request.v1")},
            {"inspection", inspection}, {"recovery_plan_id", Value("reviewed.recovery")},
            {"created_at", Value("2026-10-21T00:00:00Z")}});
        binding = Value(Value::Object{{"schema", Value("usk.native_maintenance_inspection_binding.v1")}});
        for (const auto* field : {"original_intent_sha256", "original_custody_sha256", "original_plan_digest",
                "current_installed_revision", "lease_committed_records_sha256", "lease_pending_names_sha256",
                "namespace_sha256", "absent_original_files_sha256", "absent_original_directories_sha256",
                "journal_snapshot_sha256", "effect_history_sha256", "journal_digest", "source_digest"})
            binding.as_object().emplace(field, Value(sha));
        for (const auto* field : {"commit_started", "commit_confirmed"})
            binding.as_object().emplace(field, Value(true));
        for (const auto* field : {"effects_complete", "sealed"})
            binding.as_object().emplace(field, Value(false));
        for (const auto* field : {"recorded_at", "observed_state", "pending_kind", "reconciliation", "next_kind"})
            binding.as_object().emplace(field, Value("observed"));
        binding.as_object().at("recorded_at") = Value("2026-10-21T00:00:00Z");
        binding.as_object().at("observed_state") = Value("committed");
        binding.as_object().at("pending_kind") = Value("");
        binding.as_object().at("next_kind") = Value("replace_file");
        binding.as_object().emplace("lease_committed_record_count", Value(std::uint64_t{2}));
        binding.as_object().emplace("object_count", Value(std::uint64_t{7}));
        const auto reviewed = usk::command::detail::public_native_recovery_document(inspection, binding, &plan);
        apply = Value(Value::Object{{"schema", Value("usk.recovery_apply_request.v1")}, {"plan_request", plan},
            {"reviewed_plan_id", plan.at("recovery_plan_id")}, {"reviewed_plan_digest", reviewed.at("plan_digest")},
            {"selected_action", Value("finalize")}, {"applied_at", Value("2026-10-21T00:00:01Z")},
            {"confirmation", Value("APPLY")}});
    }
    Value payload(const std::string& command) const {
        return command == "recovery.inspect" ? inspection : command == "recovery.plan" ? plan : apply;
    }
    std::string envelope(const std::string& command, const Value& input, bool read_only) const {
        return usk::json::canonical(Value(Value::Object{{"schema", Value("usk.oneshot_request.v1")},
            {"request_id", Value("outer.current")}, {"command", Value(command)},
            {"payload", input}, {"dry_run", Value(read_only)}}));
    }
    // Use the established codec to form test data. Existing response tests
    // qualify that codec; these controls test host routing and ownership only.
    Value reply(const std::string& command, const Value& request) const {
        const bool planning = command == "recovery.plan", applying = command == "recovery.apply";
        auto report = usk::command::detail::public_native_recovery_document(
            inspection, binding, planning ? &request : nullptr);
        if (applying) {
            report.as_object().at("status") = Value("completed");
            report.as_object().at("recorded_at") = request.at("applied_at");
            for (const auto* field : {"reviewed_plan_id", "reviewed_plan_digest", "selected_action"})
                report.as_object().emplace(field, request.at(field));
            for (const auto* field : {"completed_journal_snapshot_sha256", "completed_effect_history_sha256"})
                report.as_object().emplace(field, Value(std::string(64u, 'a')));
            report.as_object().erase("report_digest");
            report.as_object().emplace("report_digest", Value(usk::json::sha256_canonical(report)));
        }
        const Value response(Value::Object{{"schema", Value("usk.command_response.v1")},
            {"status", Value("ok")}, {"payload", report}});
        const Value admission(Value::Object{{"schema", Value("usk.publisher_registered_admission_observation.v1")},
            {"service_name", Value("service")}, {"service_sid", Value("sid")},
            {"process_id", Value(std::uint64_t{99})}});
        return Value(Value::Object{{"schema", Value("usk.publisher_lab_service_observation.v1")},
            {"status", Value("pass")}, {"request_sha256", Value(usk::json::sha256_canonical(request))},
            {"operation", inspection.at("operation")}, {"install_id", inspection.at("install_id")},
            {"transaction_id", inspection.at("transaction_id")}, {"service_name", Value("service")},
            {"service_sid", Value("sid")}, {"process_id", Value(std::uint64_t{99})},
            {"registered_admission", admission}, {"operation_admission", Value(Value::Object{})},
            {"recovery_response", response}});
    }
};

void controls() {
    Fixture f;
    for (const std::string command : {"recovery.inspect", "recovery.plan", "recovery.apply"}) {
        const bool read_only = command != "recovery.apply";
        const auto payload = f.payload(command);
        const auto sent = usk::json::canonical(payload);
        const auto input = f.envelope(command, payload, read_only);
        const auto reply = f.reply(command, payload);
        unsigned calls = 0;
        auto good = usk::command::run_publisher_one_shot(input, [&](const std::string& bytes) {
            REQUIRE(bytes == sent);
            ++calls;
            return usk::json::canonical(reply);
        });
        const auto projected = usk::json::parse(good.document);
        REQUIRE(calls == 1 && good.exit_code == 0 && projected.at("status").as_string() == "ok" &&
            projected.at("request_id").as_string() == "outer.current" &&
            usk::json::equal_values(projected.at("result"), reply.at("recovery_response")));

        // A correctly shaped observation for another request cannot complete.
        auto wrong = reply;
        wrong.as_object().at("request_sha256") = Value(std::string(64u, 'f'));
        auto mismatch = usk::command::run_publisher_one_shot(input,
            [&](const std::string&) { return usk::json::canonical(wrong); });
        REQUIRE(mismatch.exit_code == 5 && usk::json::parse(mismatch.document).at("status").as_string() == "unknown");

        const auto no_dispatch = [&](const std::string& rejected) {
            unsigned dispatched = 0;
            const auto r = usk::command::run_publisher_one_shot(rejected, [&](const std::string&) {
                ++dispatched; return usk::json::canonical(reply);
            });
            REQUIRE(dispatched == 0 && r.exit_code == 2 &&
                usk::json::parse(r.document).at("status").as_string() == "refused");
        };
        no_dispatch(f.envelope(command, payload, !read_only));
        auto malformed = payload;
        malformed.as_object().emplace("unexpected", Value(true));
        no_dispatch(f.envelope(command, malformed, read_only));
        auto private_route = usk::command::run_candidate_one_shot(input, [&](const std::string&) {
            ++calls; return usk::json::canonical(reply);
        });
        REQUIRE(calls == 1 && private_route.exit_code == 2);

        for (const auto* operation : {"install_local", "repair", "move", "uninstall"}) {
            for (const auto* action : {"finalize", "rollback"}) {
                auto current = f.apply;
                auto& inspection = current.as_object().at("plan_request").as_object().at("inspection");
                inspection.as_object().at("operation") = Value(operation);
                inspection.as_object().at("request_id") = Value(command + "." + operation + "." + action);
                current.as_object().at("selected_action") = Value(action);
                const Value selected = command == "recovery.inspect" ? inspection :
                    command == "recovery.plan" ? current.at("plan_request") : current;
                const auto bytes = usk::json::canonical(selected);
                const auto invocation = f.envelope(command, selected, read_only);

                // Compare the full owned uncertainty response with the SDK,
                // not just the host's outer status or current request ID.
                usk::command::detail::PublisherClientContext sdk("USK_PUB_" + std::string(32u, 'a'));
                const auto sdk_unknown = sdk.execute(command.c_str(), bytes.data(), bytes.size(),
                    [](const std::string&) -> std::string { throw std::runtime_error("lost reply"); },
                    [](const std::string&, const Value& value) { return value; });
                const auto expected = usk::json::parse(sdk_unknown.json);

                for (unsigned failure = 0; failure != 3; ++failure) {
                    std::string broken = "{";
                    usk::command::OneShotResult result;
                    bool exact_wire = false;
                    try {
                        ResetDenial reset;
                        result = usk::command::run_publisher_one_shot(invocation,
                            [&](const std::string& wire) -> std::string {
                                exact_wire = wire == bytes;
                                deny_allocations = true;
                                if (failure == 1) return std::move(broken);
                                if (failure == 2) throw 7;
                                throw std::bad_alloc();
                            });
                    } catch (...) { REQUIRE(false); }
                    REQUIRE(!deny_allocations && exact_wire && result.exit_code == 5);
                    const auto unknown = usk::json::parse(result.document);
                    REQUIRE(unknown.at("request_id").as_string() == "outer.current" &&
                        unknown.at("status").as_string() == "unknown" &&
                        usk::json::equal_values(unknown.at("result"), expected));
                }
            }
        }
    }
    std::puts("Public one-shot recovery PASS: full requests/v2 results; 72 post-dispatch allocation-denial controls; no native effects");
}
} // namespace

int main() {
    try { controls(); return 0; }
    catch (const std::exception& e) { std::fprintf(stderr, "%s\n", e.what()); return 1; }
}
