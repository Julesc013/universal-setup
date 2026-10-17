// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_install_lease.h"

#include <functional>
#include <limits>
#include <vector>

namespace {
using usk::json::Value;
using namespace usk::transaction;

template<class Error, class Action>
bool refuses(Action action)
{
    try { action(); } catch (const Error&) { return true; } catch (...) { return false; }
    return false;
}

Value reseal(Value value)
{
    value.as_object().erase("ownership_sha256");
    const auto sha = usk::json::sha256_canonical(value);
    value.as_object().emplace("ownership_sha256", Value(sha));
    return value;
}
} // namespace

int main()
{
    // Synthetic observations exercise the closed protocol. They grant no
    // native locking, protected namespace, publication or takeover authority.
    const Value root(Value::Object{{"file_id", Value(std::string(32, 'a'))},
        {"volume_serial", Value("18446744073709551615")}});
    const Value holder_a(Value::Object{{"process_id", Value(std::uint64_t{101})},
        {"process_creation_time", Value("00000000000000aa")}});
    Value holder_b = holder_a;
    holder_b.as_object().at("process_creation_time") = Value("00000000000000bb");
    const std::string revision_a(64, 'a'), revision_b(64, 'b'), revision_c(64, 'c');
    InstallLeaseRequest request{"org.example.setup", "install_local", "operation.1",
        "attempt.a", revision_a, false, std::string(64, 'd')};
    const auto first = derive_install_lease_ownership({}, request, root, holder_a, revision_a);
    require_install_lease_record(first);
    require_install_lease_start(first, revision_a);
    require_install_lease_fence(first, first, root, holder_a);
    if (!refuses<InstallLeaseStale>([&] {
            auto repeated_attempt = request;
            repeated_attempt.recovery = true;
            (void)derive_install_lease_ownership(first, repeated_attempt, root, holder_a,
                revision_a, InstallLeasePreviousHolder::ended);
        })) return 15;
    if (first.at("generation").as_unsigned() != 1 ||
        first.at("predecessor_sha256").type() != Value::Type::null_value) return 1;
    if (!refuses<InstallStateRevisionStale>([&] {
            (void)derive_install_lease_ownership({}, request, root, holder_a, revision_b);
        }) || !refuses<InstallStateRevisionStale>([&] {
            require_install_lease_start(first, revision_b);
        })) return 2;

    InstallLeaseRequest recovery = request;
    recovery.recovery = true;
    recovery.attempt_id = "attempt.b";
    for (const auto holder : {InstallLeasePreviousHolder::unknown, InstallLeasePreviousHolder::live}) {
        if (!refuses<InstallLeaseConflict>([&] {
                (void)derive_install_lease_ownership(first, recovery, root, holder_b, revision_a, holder);
            })) return 3;
    }
    auto changed_context = recovery;
    changed_context.operation_context_sha256 = std::string(64, 'e');
    if (!refuses<InstallLeaseConflict>([&] {
            (void)derive_install_lease_ownership(first, changed_context, root, holder_b, revision_a,
                InstallLeasePreviousHolder::ended);
        })) return 16;
    for (const auto holder : {InstallLeasePreviousHolder::ended, InstallLeasePreviousHolder::identity_reused}) {
        const auto restarted = derive_install_lease_ownership(first, recovery, root, holder_b, revision_a, holder);
        if (restarted.at("generation").as_unsigned() != 2) return 4;
        if (!refuses<InstallLeaseStale>([&] {
                require_install_lease_fence(first, restarted, root, holder_a);
            })) return 5;
    }
    // PID reuse cannot validate an older holder, even before another record
    // is written. Native observation must supply the process creation time.
    if (!refuses<InstallLeaseStale>([&] {
            require_install_lease_fence(first, first, root, holder_b);
        })) return 6;

    const auto handed_off = finish_install_lease_ownership(first, root, holder_a, revision_b, true);
    recovery.expected_state_revision = revision_b;
    const auto second = derive_install_lease_ownership(handed_off, recovery, root, holder_b, revision_b);
    require_install_lease_fence(second, second, root, holder_b);
    if (second.at("generation").as_unsigned() != 2 ||
        second.at("predecessor_sha256").as_string() != handed_off.at("ownership_sha256").as_string()) return 7;
    if (!refuses<InstallLeaseStale>([&] {
            require_install_lease_fence(first, second, root, holder_a);
        }) || !refuses<InstallLeaseStale>([&] {
            require_install_lease_start(handed_off, revision_b);
        })) return 8;
    InstallLeaseRequest changed = recovery;
    changed.operation_id = "operation.2";
    if (!refuses<InstallLeaseConflict>([&] {
            (void)derive_install_lease_ownership(handed_off, changed, root, holder_b, revision_b);
        })) return 9;
    changed = recovery;
    changed.expected_state_revision = revision_c;
    if (!refuses<InstallStateRevisionStale>([&] {
            (void)derive_install_lease_ownership(handed_off, changed, root, holder_b, revision_c);
        })) return 10;

    const auto completed = finish_install_lease_ownership(second, root, holder_b, revision_c, false);
    changed = {"org.example.setup", "repair", "operation.2", "attempt.c", revision_c, false, std::string(64, 'e')};
    const auto third = derive_install_lease_ownership(completed, changed, root, holder_b, revision_c);
    // Closed history association only; these synthetic records create no
    // protected native membership, actual ended holder or replay authority.
    const std::vector<Value> history{first, handed_off, second, completed, third};
    const auto old_result = select_completed_install_lease_history(history, first);
    const auto recovered_result = select_completed_install_lease_history(history, second);
    if (!old_result || !recovered_result ||
        usk::json::canonical(*old_result) != usk::json::canonical(completed) ||
        usk::json::canonical(*recovered_result) != usk::json::canonical(completed) ||
        select_completed_install_lease_history({first, handed_off, second}, first)) return 17;
    Value changed_original = first;
    changed_original.as_object().at("operation_context_sha256") = Value(std::string(64, 'f'));
    changed_original = reseal(std::move(changed_original));
    if (!refuses<InstallLeaseStale>([&] { (void)select_completed_install_lease_history(history, changed_original); }) ||
        !refuses<InstallLeaseStale>([&] { (void)select_completed_install_lease_history({first, handed_off, second, completed}, third); }) ||
        !refuses<InstallLeaseStale>([&] { (void)select_completed_install_lease_history(history, completed); }) ||
        !refuses<std::runtime_error>([&] { (void)select_completed_install_lease_history({first, second, handed_off, completed}, first); }))
        return 18;
    const auto third_completed = finish_install_lease_ownership(third, root, holder_b, revision_c, false);
    auto repeated_operation = request;
    repeated_operation.attempt_id = "attempt.after-completion";
    repeated_operation.expected_state_revision = revision_c;
    repeated_operation.operation_context_sha256 = std::string(64, 'f');
    const auto repeated = derive_install_lease_ownership(third_completed, repeated_operation, root, holder_b, revision_c);
    if (!refuses<InstallLeaseStale>([&] {
            (void)select_completed_install_lease_history({first, handed_off, second, completed, third, third_completed, repeated}, first);
        })) return 19;
    if (third.at("generation").as_unsigned() != 3 ||
        !refuses<InstallLeaseStale>([&] {
            require_install_lease_fence(second, completed, root, holder_b);
        })) return 11;
    Value replaced_root = root;
    replaced_root.as_object().at("file_id") = Value(std::string(32, 'b'));
    if (!refuses<InstallLeaseStale>([&] {
            require_install_lease_fence(third, third, replaced_root, holder_b);
        }) || !refuses<InstallLeaseStale>([&] {
            (void)derive_install_lease_ownership(completed, changed, replaced_root, holder_b, revision_c);
        })) return 12;

    const std::vector<std::function<void(Value&)>> corruptions{
        [](Value& x) { x.as_object().emplace("trusted", Value(true)); },
        [](Value& x) { x.as_object().emplace("expires_at", Value("past")); },
        [](Value& x) { x.as_object().at("schema") = Value("usk.installation_lease_ownership.v2"); },
        [](Value& x) { x.as_object().at("generation") = Value(std::uint64_t{0}); },
        [](Value& x) { x.as_object().at("generation") = Value(std::uint64_t{2}); },
        [](Value& x) { x.as_object().at("result_state_revision") = Value(std::string(64, 'a')); },
        [](Value& x) { x.as_object().at("status") = Value("expired"); },
        [](Value& x) { x.as_object().at("operation_context_sha256") = Value(""); },
        [](Value& x) { x.as_object().at("holder").as_object().at("process_id") = Value(std::uint64_t{0}); },
        [](Value& x) { x.as_object().at("holder").as_object().at("process_creation_time") = Value(std::string(16, '0')); },
        [](Value& x) { x.as_object().at("state_root_identity").as_object().at("volume_serial") = Value("018446744073709551615"); },
        [](Value& x) { x.as_object().at("state_root_identity").as_object().at("volume_serial") = Value("18446744073709551616"); },
    };
    for (const auto& corrupt : corruptions) {
        Value invalid = first;
        corrupt(invalid);
        invalid = reseal(std::move(invalid));
        if (!refuses<std::runtime_error>([&] { require_install_lease_record(invalid); })) return 13;
    }
    Value exhausted = completed;
    exhausted.as_object().at("generation") = Value(std::numeric_limits<std::uint64_t>::max());
    exhausted = reseal(std::move(exhausted));
    if (!refuses<std::runtime_error>([&] {
            (void)derive_install_lease_ownership(exhausted, changed, root, holder_b, revision_c);
        })) return 14;
    return 0;
}
