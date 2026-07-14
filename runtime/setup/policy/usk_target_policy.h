// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_TARGET_POLICY_H
#define USK_TARGET_POLICY_H

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace usk::policy {

enum class TargetClass {
    fixture,
    disposable_test,
    operator_acceptance,
    managed_portable,
    imported,
    foreign_owned,
    steam_managed,
    per_user,
    system_wide,
};

enum class Activation {
    unavailable,
    operator_acceptance_candidate,
    accepted_live_portable,
};

enum class TargetState {
    nonexistent,
    empty,
    nonempty,
    unproven,
};

struct TargetEvidence {
    TargetClass target_class = TargetClass::foreign_owned;
    std::filesystem::path target_root;
    std::filesystem::path authorized_acceptance_root;
    TargetState target_state = TargetState::unproven;
    std::string target_identity_digest;
    std::string filesystem_identity_digest;
    std::string filesystem_kind;
    std::vector<std::string> persistent_effects;
    std::uint64_t required_bytes = 0;
    std::uint64_t available_bytes = 0;
    bool explicitly_supplied = false;
    bool local_filesystem = false;
    bool path_components_stable = false;
    bool mount_redirection_absent = false;
    bool excluded_roots_absent = false;
    bool source_target_distinct = false;
    bool persistent_effects_complete = false;
};

struct TargetPolicyDecision {
    bool accepted = false;
    std::string code;
    std::string detail;
    std::string target_binding_digest;
};

const char* target_class_name(TargetClass value) noexcept;
std::optional<TargetClass> parse_target_class(const std::string& value) noexcept;
const char* activation_name(Activation value) noexcept;
std::optional<Activation> parse_activation(const std::string& value) noexcept;
const char* target_state_name(TargetState value) noexcept;
std::optional<TargetState> parse_target_state(const std::string& value) noexcept;

TargetPolicyDecision evaluate_live_target(
    Activation activation,
    const TargetEvidence& evidence);

} // namespace usk::policy

#endif
