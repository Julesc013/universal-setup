// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_target_policy.h"

#include <array>
#include <filesystem>
#include <iostream>
#include <string>

namespace fs = std::filesystem;
using namespace usk::policy;

namespace {

TargetEvidence accepted_evidence()
{
    TargetEvidence evidence;
    evidence.target_class = TargetClass::operator_acceptance;
#ifdef _WIN32
    evidence.authorized_acceptance_root = "D:/FacMan-Live-Acceptance/M2";
    evidence.target_root = "D:/FacMan-Live-Acceptance/M2/synthetic-install";
#else
    evidence.authorized_acceptance_root = "/tmp/facman-live-acceptance/M2";
    evidence.target_root = "/tmp/facman-live-acceptance/M2/synthetic-install";
#endif
    evidence.target_state = TargetState::nonexistent;
    evidence.target_identity_digest = std::string(64, '1');
    evidence.filesystem_identity_digest = std::string(64, '2');
    evidence.filesystem_kind = "local_test_filesystem";
    evidence.persistent_effects = {"create target", "write ownership", "write audit"};
    evidence.required_bytes = 4096;
    evidence.available_bytes = 8192;
    evidence.explicitly_supplied = true;
    evidence.local_filesystem = true;
    evidence.path_components_stable = true;
    evidence.mount_redirection_absent = true;
    evidence.excluded_roots_absent = true;
    evidence.source_target_distinct = true;
    evidence.persistent_effects_complete = true;
    return evidence;
}

bool refusal(const TargetEvidence& evidence, const char* code,
             Activation activation = Activation::operator_acceptance_candidate)
{
    const TargetPolicyDecision result = evaluate_live_target(activation, evidence);
    return !result.accepted && result.code == code && result.target_binding_digest.size() == 64;
}

int run()
{
    const std::array<TargetClass, 9> classes = {
        TargetClass::fixture, TargetClass::disposable_test, TargetClass::operator_acceptance,
        TargetClass::managed_portable, TargetClass::imported, TargetClass::foreign_owned,
        TargetClass::steam_managed, TargetClass::per_user, TargetClass::system_wide};
    for (TargetClass value : classes) {
        const auto parsed = parse_target_class(target_class_name(value));
        if (!parsed || *parsed != value) return 10;
    }
    if (parse_target_class("unknown") || parse_activation("future") || parse_target_state("missing")) {
        return 11;
    }

    TargetEvidence evidence = accepted_evidence();
    const TargetPolicyDecision accepted = evaluate_live_target(
        Activation::operator_acceptance_candidate, evidence);
    if (!accepted.accepted || !accepted.code.empty() || accepted.target_binding_digest.size() != 64) return 12;
    if (!refusal(evidence, "live_target_acceptance_required", Activation::unavailable)) return 13;

    TargetEvidence changed = evidence;
    changed.target_class = TargetClass::managed_portable;
    if (!refusal(changed, "live_target_acceptance_required")) return 14;
    if (!evaluate_live_target(Activation::accepted_live_portable, changed).accepted) return 15;
    changed.target_class = TargetClass::steam_managed;
    if (!refusal(changed, "target_class_forbidden", Activation::accepted_live_portable)) return 16;

    changed = evidence; changed.explicitly_supplied = false;
    if (!refusal(changed, "target_not_explicit")) return 20;
    changed = evidence; changed.target_root = evidence.authorized_acceptance_root / "../escape";
    if (!refusal(changed, "target_outside_acceptance_root")) return 21;
    changed = evidence; changed.target_state = TargetState::nonempty;
    if (!refusal(changed, "target_not_empty")) return 22;
    changed = evidence; changed.local_filesystem = false;
    if (!refusal(changed, "target_filesystem_not_local")) return 23;
    changed = evidence; changed.path_components_stable = false;
    if (!refusal(changed, "target_path_redirected")) return 24;
    changed = evidence; changed.mount_redirection_absent = false;
    if (!refusal(changed, "target_mount_redirected")) return 25;
    changed = evidence; changed.excluded_roots_absent = false;
    if (!refusal(changed, "target_root_excluded")) return 26;
    changed = evidence; changed.available_bytes = 1024;
    if (!refusal(changed, "target_space_insufficient")) return 27;
    changed = evidence; changed.source_target_distinct = false;
    if (!refusal(changed, "source_target_same_object")) return 28;
    changed = evidence; changed.persistent_effects_complete = false;
    if (!refusal(changed, "target_effects_incomplete")) return 29;
    changed = evidence; changed.target_identity_digest = "unproven";
    if (!refusal(changed, "target_identity_unproven")) return 30;

    changed = evidence;
    changed.available_bytes += 1;
    const auto rebound = evaluate_live_target(Activation::operator_acceptance_candidate, changed);
    if (!rebound.accepted || rebound.target_binding_digest != accepted.target_binding_digest) return 31;
    return 0;
}

} // namespace

int main()
{
    const int result = run();
    if (result != 0) std::cerr << "usk-target-policy-smoke-stage=" << result << '\n';
    return result;
}
