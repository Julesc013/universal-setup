// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_target_policy.h"

#include "usk_sha256.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <sstream>

namespace fs = std::filesystem;

namespace {

bool sha256(const std::string& value)
{
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isdigit(ch) || (ch >= 'a' && ch <= 'f');
    });
}

bool strictly_below(const fs::path& root, const fs::path& candidate)
{
    if (root.empty() || candidate.empty() || !root.is_absolute() || !candidate.is_absolute()) {
        return false;
    }
    const fs::path normalized_root = root.lexically_normal();
    const fs::path normalized_candidate = candidate.lexically_normal();
    if (normalized_root == normalized_candidate) return false;
    const fs::path relative = normalized_candidate.lexically_relative(normalized_root);
    if (relative.empty() || relative.is_absolute()) return false;
    for (const fs::path& part : relative) {
        if (part == "..") return false;
    }
    return true;
}

void append_field(std::ostringstream& output, const std::string& name, const std::string& value)
{
    output << name.size() << ':' << name << '=' << value.size() << ':' << value << '\n';
}

std::string binding_digest(
    usk::policy::Activation activation,
    const usk::policy::TargetEvidence& evidence)
{
    std::ostringstream payload;
    append_field(payload, "activation", usk::policy::activation_name(activation));
    append_field(payload, "target_class", usk::policy::target_class_name(evidence.target_class));
    append_field(payload, "target_root", evidence.target_root.lexically_normal().generic_u8string());
    append_field(payload, "acceptance_root", evidence.authorized_acceptance_root.lexically_normal().generic_u8string());
    append_field(payload, "target_state", usk::policy::target_state_name(evidence.target_state));
    append_field(payload, "target_identity_digest", evidence.target_identity_digest);
    append_field(payload, "filesystem_identity_digest", evidence.filesystem_identity_digest);
    append_field(payload, "filesystem_kind", evidence.filesystem_kind);
    append_field(payload, "required_bytes", std::to_string(evidence.required_bytes));
    append_field(payload, "available_bytes", std::to_string(evidence.available_bytes));
    append_field(payload, "explicitly_supplied", evidence.explicitly_supplied ? "true" : "false");
    append_field(payload, "local_filesystem", evidence.local_filesystem ? "true" : "false");
    append_field(payload, "path_components_stable", evidence.path_components_stable ? "true" : "false");
    append_field(payload, "mount_redirection_absent", evidence.mount_redirection_absent ? "true" : "false");
    append_field(payload, "excluded_roots_absent", evidence.excluded_roots_absent ? "true" : "false");
    append_field(payload, "source_target_distinct", evidence.source_target_distinct ? "true" : "false");
    append_field(payload, "persistent_effects_complete", evidence.persistent_effects_complete ? "true" : "false");
    for (const std::string& effect : evidence.persistent_effects) append_field(payload, "effect", effect);
    const std::string text = payload.str();
    usk::base::Sha256 digest;
    digest.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
    return digest.finish();
}

usk::policy::TargetPolicyDecision refuse(
    const char* code,
    const char* detail,
    usk::policy::Activation activation,
    const usk::policy::TargetEvidence& evidence)
{
    return {false, code, detail, binding_digest(activation, evidence)};
}

} // namespace

namespace usk::policy {

const char* target_class_name(TargetClass value) noexcept
{
    switch (value) {
    case TargetClass::fixture: return "fixture";
    case TargetClass::disposable_test: return "disposable_test";
    case TargetClass::operator_acceptance: return "operator_acceptance";
    case TargetClass::managed_portable: return "managed_portable";
    case TargetClass::imported: return "imported";
    case TargetClass::foreign_owned: return "foreign_owned";
    case TargetClass::steam_managed: return "steam_managed";
    case TargetClass::per_user: return "per_user";
    case TargetClass::system_wide: return "system_wide";
    }
    return "unknown";
}

std::optional<TargetClass> parse_target_class(const std::string& value) noexcept
{
    static constexpr std::array<TargetClass, 9> values = {
        TargetClass::fixture, TargetClass::disposable_test, TargetClass::operator_acceptance,
        TargetClass::managed_portable, TargetClass::imported, TargetClass::foreign_owned,
        TargetClass::steam_managed, TargetClass::per_user, TargetClass::system_wide};
    for (TargetClass candidate : values) {
        if (value == target_class_name(candidate)) return candidate;
    }
    return std::nullopt;
}

const char* activation_name(Activation value) noexcept
{
    switch (value) {
    case Activation::unavailable: return "unavailable";
    case Activation::operator_acceptance_candidate: return "operator_acceptance_candidate";
    case Activation::accepted_live_portable: return "accepted_live_portable";
    }
    return "unknown";
}

std::optional<Activation> parse_activation(const std::string& value) noexcept
{
    static constexpr std::array<Activation, 3> values = {
        Activation::unavailable,
        Activation::operator_acceptance_candidate,
        Activation::accepted_live_portable};
    for (Activation candidate : values) {
        if (value == activation_name(candidate)) return candidate;
    }
    return std::nullopt;
}

const char* target_state_name(TargetState value) noexcept
{
    switch (value) {
    case TargetState::nonexistent: return "nonexistent";
    case TargetState::empty: return "empty";
    case TargetState::nonempty: return "nonempty";
    case TargetState::unproven: return "unproven";
    }
    return "unknown";
}

std::optional<TargetState> parse_target_state(const std::string& value) noexcept
{
    static constexpr std::array<TargetState, 4> values = {
        TargetState::nonexistent, TargetState::empty, TargetState::nonempty, TargetState::unproven};
    for (TargetState candidate : values) {
        if (value == target_state_name(candidate)) return candidate;
    }
    return std::nullopt;
}

TargetPolicyDecision evaluate_live_target(
    Activation activation,
    const TargetEvidence& evidence)
{
    if (activation == Activation::unavailable) {
        return refuse("live_target_acceptance_required",
            "live portable setup is unavailable before an authorized M2 acceptance lane",
            activation, evidence);
    }
    if (evidence.target_class == TargetClass::managed_portable &&
        activation != Activation::accepted_live_portable) {
        return refuse("live_target_acceptance_required",
            "managed portable mutation requires a recorded human M2 Pass",
            activation, evidence);
    }
    if (evidence.target_class != TargetClass::operator_acceptance &&
        evidence.target_class != TargetClass::managed_portable) {
        return refuse("target_class_forbidden",
            "the selected target class is outside M2 live portable authority",
            activation, evidence);
    }
    if (!evidence.explicitly_supplied || evidence.target_root.empty() ||
        !evidence.target_root.is_absolute()) {
        return refuse("target_not_explicit",
            "the operator must explicitly supply an absolute target root",
            activation, evidence);
    }
    if (evidence.target_class == TargetClass::operator_acceptance &&
        !strictly_below(evidence.authorized_acceptance_root, evidence.target_root)) {
        return refuse("target_outside_acceptance_root",
            "operator-acceptance targets must remain below the authorized acceptance root",
            activation, evidence);
    }
    if (evidence.target_state != TargetState::nonexistent &&
        evidence.target_state != TargetState::empty) {
        return refuse("target_not_empty",
            "the selected install target must be nonexistent or proven empty",
            activation, evidence);
    }
    if (!evidence.local_filesystem || evidence.filesystem_kind.empty() ||
        !sha256(evidence.filesystem_identity_digest)) {
        return refuse("target_filesystem_not_local",
            "the target filesystem must be local and identity-bound",
            activation, evidence);
    }
    if (!evidence.path_components_stable) {
        return refuse("target_path_redirected",
            "a target path component is a link, reparse point, or unstable ancestor",
            activation, evidence);
    }
    if (!evidence.mount_redirection_absent) {
        return refuse("target_mount_redirected",
            "the target path crosses an unapproved mount redirection",
            activation, evidence);
    }
    if (!evidence.excluded_roots_absent) {
        return refuse("target_root_excluded",
            "the target is within a protected, cloud-synchronized, Steam, or foreign-owned root",
            activation, evidence);
    }
    if (evidence.required_bytes == 0 || evidence.available_bytes < evidence.required_bytes) {
        return refuse("target_space_insufficient",
            "available target space does not satisfy the reviewed plan requirement",
            activation, evidence);
    }
    if (!evidence.source_target_distinct) {
        return refuse("source_target_same_object",
            "the source archive and selected target must be distinct filesystem objects",
            activation, evidence);
    }
    if (!evidence.persistent_effects_complete || evidence.persistent_effects.empty()) {
        return refuse("target_effects_incomplete",
            "every persistent effect must be available for operator review",
            activation, evidence);
    }
    if (!sha256(evidence.target_identity_digest)) {
        return refuse("target_identity_unproven",
            "the selected target identity must be digest-bound",
            activation, evidence);
    }
    return {true, "", "live target satisfies the bounded M2 policy",
            binding_digest(activation, evidence)};
}

} // namespace usk::policy
