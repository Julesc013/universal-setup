// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_public_lifecycle.h"

#include "usk/usk_result.h"
#include "usk_archive_payload.h"
#include "usk_audit_repository.h"
#include "usk_json.h"
#include "usk_lifecycle.h"
#include "usk_live_evidence.h"
#include "usk_record_io.h"
#include "usk_sha256.h"
#include "usk_state_repository.h"
#include "usk_target_inspect.h"
#include "usk_transaction_session.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using usk::json::Value;

namespace {

constexpr std::size_t max_request_bytes = 1024u * 1024u;
constexpr std::uint64_t setup_overhead_bytes = 16u * 1024u * 1024u;

class PublicError final : public std::runtime_error {
public:
    PublicError(std::string code, std::string message)
        : std::runtime_error(std::move(message)), code_(std::move(code)) {}

    const std::string& code() const noexcept { return code_; }

private:
    std::string code_;
};

struct PublicConfig {
    fs::path setup_root;
    fs::path acceptance_root;
    usk::policy::Activation activation = usk::policy::Activation::unavailable;
};

struct InstallPlanBundle {
    usk::lifecycle::InstallPlan plan;
    usk::policy::InspectedTarget target;
    std::string source_identity_digest;
    std::string entry_set_digest;
    std::uint64_t archive_size = 0;
    std::uint64_t uncompressed_bytes = 0;
};

struct RepairPlanBundle {
    usk::lifecycle::RepairPlan plan;
    usk::state::InstalledState installed;
    usk::lifecycle::VerificationReport before;
};

struct MovePlanBundle {
    usk::lifecycle::MovePlan plan;
    usk::state::InstalledState installed;
    usk::policy::InspectedTarget destination;
};

struct UninstallPlanBundle {
    usk::lifecycle::UninstallPlan plan;
    usk::state::InstalledState installed;
};

struct RecoveryBundle {
    std::string install_id;
    std::string request_id;
    usk::transaction::TransactionSpec spec;
    usk::transaction::RecoveryInspection inspection;
};

void ensure_directory(const fs::path& parent, const std::string& name);
void initialize_setup_root(const PublicConfig& config);

void exact_members(const Value& value, std::initializer_list<const char*> names)
{
    if (value.type() != Value::Type::object) throw PublicError("invalid_argument", "request value must be an object");
    std::set<std::string> expected;
    for (const char* name : names) expected.insert(name);
    if (value.as_object().size() != expected.size()) {
        throw PublicError("invalid_argument", "request object has missing or unexpected members");
    }
    for (const auto& member : value.as_object()) {
        if (expected.count(member.first) == 0) {
            throw PublicError("invalid_argument", "request object has an unexpected member: " + member.first);
        }
    }
}

std::string required_string(const Value& value, const std::string& name)
{
    const std::string result = value.at(name).as_string();
    if (result.empty()) throw PublicError("invalid_argument", "request string is empty: " + name);
    return result;
}

bool same_or_below(const fs::path& root, const fs::path& candidate)
{
    if (root.empty() || candidate.empty()) return false;
    const fs::path absolute_root = fs::absolute(root).lexically_normal();
    const fs::path absolute_candidate = fs::absolute(candidate).lexically_normal();
    if (absolute_root == absolute_candidate) return true;
    const fs::path relative = absolute_candidate.lexically_relative(absolute_root);
    if (relative.empty() || relative.is_absolute()) return false;
    for (const fs::path& part : relative) if (part == "..") return false;
    return true;
}

std::string path_identity_digest(const fs::path& path)
{
    const std::string normalized = fs::absolute(path).lexically_normal().generic_u8string();
    usk::base::Sha256 digest;
    digest.update(reinterpret_cast<const unsigned char*>(normalized.data()), normalized.size());
    return digest.finish();
}

PublicConfig parse_config(
    const char* state_root,
    const char* authorized_acceptance_root,
    const char* target_policy_activation)
{
    if (state_root == nullptr || *state_root == '\0' ||
        authorized_acceptance_root == nullptr || *authorized_acceptance_root == '\0' ||
        target_policy_activation == nullptr || *target_policy_activation == '\0') {
        throw PublicError("live_target_acceptance_required",
            "public lifecycle commands require explicit setup-state, acceptance-root, and activation configuration");
    }
    const auto activation = usk::policy::parse_activation(target_policy_activation);
    if (!activation.has_value()) throw PublicError("invalid_argument", "target policy activation is invalid");
    const fs::path supplied_setup_root(state_root);
    const fs::path supplied_acceptance_root(authorized_acceptance_root);
    if (!supplied_setup_root.is_absolute() || !supplied_acceptance_root.is_absolute()) {
        throw PublicError("target_not_explicit", "setup-state and acceptance roots must be explicitly absolute");
    }
    PublicConfig result;
    result.setup_root = supplied_setup_root.lexically_normal();
    result.acceptance_root = supplied_acceptance_root.lexically_normal();
    result.activation = *activation;
    if (!result.setup_root.is_absolute() || !result.acceptance_root.is_absolute() ||
        !same_or_below(result.acceptance_root, result.setup_root) ||
        result.setup_root == result.acceptance_root) {
        throw PublicError("target_outside_acceptance_root",
            "the setup-owned state root must be strictly below the authorized acceptance root");
    }
    return result;
}

usk::lifecycle::LifecycleRoots lifecycle_roots(const PublicConfig& config)
{
    return {config.setup_root / "staging", config.setup_root / "state", config.setup_root / "audit"};
}

std::vector<std::string> directory_closure(const std::vector<usk::lifecycle::PayloadFile>& files)
{
    std::set<std::string> directories;
    for (const auto& file : files) {
        fs::path current = fs::path(file.relative_path).parent_path();
        while (!current.empty()) {
            directories.insert(current.generic_u8string());
            current = current.parent_path();
        }
    }
    std::vector<std::string> result(directories.begin(), directories.end());
    std::sort(result.begin(), result.end(), [](const std::string& left, const std::string& right) {
        const auto depth = [](const std::string& value) {
            return static_cast<std::size_t>(std::count(value.begin(), value.end(), '/'));
        };
        return std::make_pair(depth(left), left) < std::make_pair(depth(right), right);
    });
    return result;
}

Value string_array(const std::vector<std::string>& values)
{
    Value::Array result;
    for (const std::string& value : values) result.emplace_back(value);
    return Value(std::move(result));
}

Value response_ok(Value payload)
{
    return Value(Value::Object{
        {"error", Value()},
        {"payload", std::move(payload)},
        {"schema", Value("usk.command_response.v1")},
        {"status", Value("ok")}});
}

Value response_error(const std::string& status, const std::string& code, const std::string& message)
{
    return Value(Value::Object{
        {"error", Value(Value::Object{{"code", Value(code)}, {"message", Value(message)}})},
        {"payload", Value()},
        {"schema", Value("usk.command_response.v1")},
        {"status", Value(status)}});
}

std::string setup_root_marker(const PublicConfig& config)
{
    return usk::json::canonical(Value(Value::Object{
        {"acceptance_root", Value(config.acceptance_root.generic_u8string())},
        {"schema", Value("usk.setup_owned_root.v1")}})) + "\n";
}

PublicConfig require_setup_probe(const PublicConfig& config, const fs::path& source)
{
    std::error_code error;
    if (fs::exists(config.setup_root, error)) {
        if (error) throw PublicError("setup_state_root_unsafe", "cannot inspect setup-state root");
        usk::record_io::require_safe_directory(config.setup_root);
        try {
            if (usk::record_io::read_stable_text(
                    config.setup_root / ".usk-owned-root.v1.json", 64u * 1024u) != setup_root_marker(config)) {
                throw PublicError("setup_state_root_unsafe", "setup-state ownership marker is incompatible");
            }
        } catch (const PublicError&) {
            throw;
        } catch (const std::exception&) {
            throw PublicError("setup_state_root_unsafe", "existing setup-state root is not owned by this authority");
        }
    } else if (error) {
        throw PublicError("setup_state_root_unsafe", "cannot inspect setup-state root");
    }
    const fs::path probe = config.setup_root / ".usk-binding-probe";
    if (fs::exists(probe)) {
        throw PublicError("setup_state_root_unsafe", "the reserved setup-state binding probe path already exists");
    }
    const usk::policy::TargetInspectionRequest request{
        usk::policy::TargetClass::operator_acceptance,
        probe,
        config.acceptance_root,
        source,
        setup_overhead_bytes,
        {"create setup-owned state, staging, journal, and audit repositories under " +
         config.setup_root.generic_u8string()}};
    const auto inspected = usk::policy::inspect_and_evaluate_live_target(config.activation, request);
    if (!inspected.decision.accepted) {
        throw PublicError(inspected.decision.code, "setup-state authority refused: " + inspected.decision.detail);
    }
    return config;
}

Value archive_inspection_request(const Value& archive)
{
    exact_members(archive, {"path", "format", "expected_sha256", "strip_prefix", "budgets"});
    const Value& budgets = archive.at("budgets");
    exact_members(budgets, {"max_entries", "max_uncompressed_bytes", "max_entry_bytes",
                            "max_depth", "max_ratio", "max_elapsed_ms"});
    if (required_string(archive, "format") != "zip") {
        throw PublicError("invalid_argument", "public lifecycle currently accepts ZIP archives only");
    }
    return Value(Value::Object{
        {"archive_format", Value("zip")},
        {"archive_path", Value(required_string(archive, "path"))},
        {"budgets", budgets},
        {"schema", Value("usk.archive_inspect_request.v1")}});
}

std::string policy_digest(
    const usk::policy::InspectedTarget& target,
    const PublicConfig& config,
    const fs::path& source)
{
    const usk::policy::TargetInspectionRequest setup_request{
        usk::policy::TargetClass::operator_acceptance,
        config.setup_root / ".usk-binding-probe",
        config.acceptance_root,
        source,
        setup_overhead_bytes,
        {"create setup-owned state, staging, journal, and audit repositories under " +
         config.setup_root.generic_u8string()}};
    const auto setup = usk::policy::inspect_and_evaluate_live_target(config.activation, setup_request);
    if (!setup.decision.accepted) throw PublicError(setup.decision.code, setup.decision.detail);
    return usk::json::sha256_canonical(Value(Value::Object{
        {"activation", Value(usk::policy::activation_name(config.activation))},
        {"setup_binding_digest", Value(setup.decision.target_binding_digest)},
        {"target_binding_digest", Value(target.decision.target_binding_digest)}}));
}

InstallPlanBundle build_install_plan(const Value& request, const PublicConfig& config)
{
    exact_members(request, {"schema", "request_id", "created_at", "install_id", "archive", "target", "recipe"});
    if (required_string(request, "schema") != "usk.install_local_plan_request.v1") {
        throw PublicError("invalid_argument", "install plan request schema is incompatible");
    }
    const std::string plan_id = required_string(request, "request_id");
    const std::string install_id = required_string(request, "install_id");
    const Value& archive = request.at("archive");
    const Value inspection_request = archive_inspection_request(archive);
    const fs::path source_path(required_string(archive, "path"));
    if (!source_path.is_absolute()) {
        throw PublicError("invalid_argument", "source archive path must be explicitly absolute");
    }
    require_setup_probe(config, source_path);
    usk::archive::StoredArchivePayload payload = usk::archive::inspect_stored_payload(
        usk::json::canonical(inspection_request), archive.at("strip_prefix").as_string());
    if (payload.source_sha256 != required_string(archive, "expected_sha256")) {
        throw PublicError("source_drift", "source archive digest differs from the reviewed request");
    }
    if (payload.uncompressed_bytes > std::numeric_limits<std::uint64_t>::max() - setup_overhead_bytes) {
        throw PublicError("target_space_insufficient", "payload size cannot be represented safely");
    }

    const Value& target = request.at("target");
    exact_members(target, {"root", "class"});
    const auto target_class = usk::policy::parse_target_class(required_string(target, "class"));
    if (!target_class.has_value()) throw PublicError("target_class_forbidden", "target class is unknown");
    const fs::path target_root(required_string(target, "root"));
    if (same_or_below(config.setup_root, target_root) || same_or_below(target_root, config.setup_root)) {
        throw PublicError("target_root_excluded", "the install target and setup-state authority must be disjoint");
    }
    const usk::policy::TargetInspectionRequest target_request{
        *target_class,
        target_root,
        config.acceptance_root,
        source_path,
        payload.uncompressed_bytes + setup_overhead_bytes,
        {"create managed portable target " + fs::absolute(target_root).lexically_normal().generic_u8string(),
         "write exact installed-state, ownership, journal, and audit records under " +
             config.setup_root.generic_u8string()}};
    const auto inspected = usk::policy::inspect_and_evaluate_live_target(config.activation, target_request);
    if (!inspected.decision.accepted) throw PublicError(inspected.decision.code, inspected.decision.detail);
    if (inspected.evidence.target_state != usk::policy::TargetState::nonexistent) {
        throw PublicError("target_not_empty", "public install uses a no-replace policy and requires a nonexistent target");
    }

    const Value& recipe = request.at("recipe");
    exact_members(recipe, {"product_id", "product_version", "recipe_digest", "provider_revision",
                           "components", "entrypoints"});
    usk::lifecycle::RecipeBinding recipe_binding;
    recipe_binding.product_id = required_string(recipe, "product_id");
    recipe_binding.product_version = required_string(recipe, "product_version");
    recipe_binding.recipe_digest = required_string(recipe, "recipe_digest");
    recipe_binding.source_archive_digest = payload.source_sha256;
    recipe_binding.policy_digest = policy_digest(inspected, config, source_path);
    recipe_binding.provider_revision = required_string(recipe, "provider_revision");
    for (const Value& component : recipe.at("components").as_array()) {
        recipe_binding.components.push_back(component.as_string());
    }
    for (const Value& entrypoint : recipe.at("entrypoints").as_array()) {
        exact_members(entrypoint, {"entrypoint_id", "relative_path", "kind"});
        recipe_binding.entrypoints.push_back({required_string(entrypoint, "entrypoint_id"),
            required_string(entrypoint, "relative_path"), required_string(entrypoint, "kind")});
    }
    std::vector<usk::lifecycle::PayloadFile> files;
    for (auto& file : payload.files) {
        files.push_back({std::move(file.relative_path), std::move(file.bytes)});
    }
    InstallPlanBundle result;
    result.source_identity_digest = payload.source_identity_digest;
    result.entry_set_digest = payload.entry_set_digest;
    result.archive_size = payload.archive_size_bytes;
    result.uncompressed_bytes = payload.uncompressed_bytes;
    result.target = inspected;
    result.plan = usk::lifecycle::plan_install(plan_id, install_id,
        required_string(request, "created_at"), target_root, lifecycle_roots(config),
        std::move(recipe_binding), std::move(files));
    return result;
}

Value install_plan_document(const InstallPlanBundle& bundle, const fs::path& source_path)
{
    Value::Array entries;
    const std::vector<std::string> directories = directory_closure(bundle.plan.files);
    for (const std::string& directory : directories) {
        entries.emplace_back(Value::Object{{"entry_type", Value("directory")},
            {"relative_path", Value(directory)}, {"size_bytes", Value(std::uint64_t{0})}});
    }
    Value::Array effects;
    std::uint64_t effect_index = 0;
    for (const std::string& directory : directories) {
        effects.emplace_back(Value::Object{{"effect_id", Value("effect." + std::to_string(effect_index++))},
            {"kind", Value("create_directory")}, {"relative_path", Value(directory)},
            {"root_class", Value("owned_target")}});
    }
    for (const auto& file : bundle.plan.files) {
        usk::base::Sha256 digest;
        digest.update(file.bytes.data(), file.bytes.size());
        const std::string hash = digest.finish();
        entries.emplace_back(Value::Object{{"entry_type", Value("file")},
            {"relative_path", Value(file.relative_path)}, {"sha256", Value(hash)},
            {"size_bytes", Value(static_cast<std::uint64_t>(file.bytes.size()))}});
        effects.emplace_back(Value::Object{{"effect_id", Value("effect." + std::to_string(effect_index++))},
            {"kind", Value("write_file")}, {"relative_path", Value(file.relative_path)},
            {"root_class", Value("owned_target")}});
    }
    for (const auto& effect : std::vector<std::pair<const char*, const char*>>{
             {"write_journal", "transactions"}, {"write_installed_state", "installed"},
             {"write_audit", "chains"}}) {
        effects.emplace_back(Value::Object{{"effect_id", Value("effect." + std::to_string(effect_index++))},
            {"kind", Value(effect.first)}, {"relative_path", Value(effect.second)},
            {"root_class", Value(effect.first == std::string("write_audit") ? "audit" : "setup_state")}});
    }
    return Value(Value::Object{
        {"component_selection", string_array(bundle.plan.recipe.components)},
        {"created_at", Value(bundle.plan.created_at)},
        {"effects", Value(std::move(effects))},
        {"input_identity", Value(Value::Object{
            {"policy_digest", Value(bundle.plan.recipe.policy_digest)},
            {"provider_revision", Value(bundle.plan.recipe.provider_revision)},
            {"recipe_digest", Value(bundle.plan.recipe.recipe_digest)},
            {"source_digest", Value(bundle.plan.recipe.source_archive_digest)}})},
        {"operation", Value("install_local")},
        {"plan_digest", Value(bundle.plan.plan_digest)},
        {"plan_id", Value(bundle.plan.plan_id)},
        {"planned_entries", Value(std::move(entries))},
        {"refusal_policy", Value(Value::Object{
            {"refuse_elevation", Value(true)}, {"refuse_existing_target", Value(true)},
            {"refuse_installer_execution", Value(true)}, {"refuse_network", Value(true)},
            {"refuse_package_manager", Value(true)}, {"refuse_registry", Value(true)}})},
        {"revalidation", Value(Value::Object{
            {"immediately_before_apply", Value(true)},
            {"invalidate_on", Value(Value::Array{Value("source"), Value("recipe"), Value("target"),
                Value("policy"), Value("provider_revision")})}})},
        {"schema", Value("usk.install_plan.v1")},
        {"source", Value(Value::Object{
            {"filesystem_identity_digest", Value(bundle.source_identity_digest)},
            {"path", Value(fs::absolute(source_path).lexically_normal().generic_u8string())},
            {"path_identity_digest", Value(path_identity_digest(source_path))},
            {"sha256", Value(bundle.plan.recipe.source_archive_digest)},
            {"size_bytes", Value(bundle.archive_size)},
            {"source_id", Value("source." + bundle.plan.install_id)}})},
        {"status", Value("planned")},
        {"target", Value(Value::Object{
            {"classification", Value("operator_selected_owned_target")},
            {"filesystem", Value(Value::Object{
                {"capabilities", Value(Value::Object{
                    {"local", Value(bundle.target.evidence.local_filesystem)},
                    {"no_mount_redirection", Value(bundle.target.evidence.mount_redirection_absent)},
                    {"no_replace_commit", Value(true)},
                    {"stable_ancestors", Value(bundle.target.evidence.path_components_stable)}})},
                {"identity_digest", Value(bundle.target.evidence.filesystem_identity_digest)},
                {"kind", Value(bundle.target.evidence.filesystem_kind)}})},
            {"identity_digest", Value(bundle.target.evidence.target_identity_digest)},
            {"must_not_exist", Value(true)}, {"root", Value(bundle.plan.target_root.generic_u8string())},
            {"path_identity_digest", Value(path_identity_digest(bundle.plan.target_root))},
            {"pre_snapshot_digest", Value(usk::evidence::snapshot_target(bundle.plan.target_root).snapshot_digest)},
            {"scope", Value("portable")},
            {"volume_id", Value(bundle.target.evidence.filesystem_identity_digest)}})},
        {"totals", Value(Value::Object{
            {"directory_count", Value(static_cast<std::uint64_t>(directories.size()))},
            {"file_count", Value(static_cast<std::uint64_t>(bundle.plan.files.size()))},
            {"uncompressed_bytes", Value(bundle.uncompressed_bytes)}})}});
}

Value installed_document(const usk::state::InstalledState& state)
{
    Value::Array components;
    for (const auto& component : state.component_selection) components.emplace_back(component);
    Value::Array entrypoints;
    for (const auto& entrypoint : state.entrypoints) {
        entrypoints.emplace_back(Value::Object{{"entrypoint_id", Value(entrypoint.entrypoint_id)},
            {"kind", Value(entrypoint.kind)}, {"relative_path", Value(entrypoint.relative_path)}});
    }
    return Value(Value::Object{
        {"audit_chain_id", Value(state.audit_chain_id)},
        {"component_selection", Value(std::move(components))},
        {"created_at", Value(state.created_at)}, {"entrypoints", Value(std::move(entrypoints))},
        {"install_id", Value(state.install_id)},
        {"last_verification", Value(Value::Object{{"report_digest", Value(state.last_verification.report_digest)},
            {"report_id", Value(state.last_verification.report_id)}, {"status", Value(state.last_verification.status)},
            {"verified_at", Value(state.last_verification.verified_at)}})},
        {"lifecycle_status", Value(state.lifecycle_status)},
        {"ownership_manifest_digest", Value(state.ownership_manifest_digest)},
        {"ownership_manifest_ref", Value(state.ownership_manifest_ref)},
        {"product_id", Value(state.product_id)}, {"product_version", Value(state.product_version)},
        {"recipe_digest", Value(state.recipe_digest)}, {"schema", Value("usk.installed_state.v1")},
        {"setup_abi", Value(Value::Object{{"major", Value(state.setup_abi_major)},
            {"minor", Value(state.setup_abi_minor)}, {"provider_revision", Value(state.provider_revision)}})},
        {"source_archive_digest", Value(state.source_archive_digest)}, {"target_root", Value(state.target_root)},
        {"target_scope", Value("portable")}, {"transaction_id", Value(state.transaction_id)}});
}

Value verification_document(const usk::lifecycle::VerificationReport& report)
{
    Value::Array files;
    for (const auto& file : report.files) {
        Value::Object value{{"expected_sha256", Value(file.expected_sha256)},
            {"relative_path", Value(file.relative_path)}, {"status", Value(file.status)}};
        if (!file.actual_sha256.empty()) value.emplace("actual_sha256", Value(file.actual_sha256));
        files.emplace_back(std::move(value));
    }
    Value::Array directories;
    for (const auto& directory : report.directories) {
        directories.emplace_back(Value::Object{{"relative_path", Value(directory.relative_path)},
            {"status", Value(directory.status)}});
    }
    return Value(Value::Object{
        {"directories", Value(std::move(directories))}, {"files", Value(std::move(files))},
        {"install_id", Value(report.install_id)}, {"installed_state_digest", Value(report.installed_state_digest)},
        {"ownership_manifest_digest", Value(report.ownership_manifest_digest)},
        {"report_digest", Value(report.report_digest)}, {"report_id", Value(report.report_id)},
        {"schema", Value("usk.verification_report.v1")}, {"status", Value(report.status)},
        {"summary", Value(Value::Object{
            {"missing_files", Value(report.missing_files)}, {"modified_files", Value(report.modified_files)},
            {"owned_files", Value(static_cast<std::uint64_t>(report.files.size()))},
            {"unknown_paths", Value(static_cast<std::uint64_t>(report.unknown_paths.size()))}})},
        {"unknown_paths", string_array(report.unknown_paths)}, {"verified_at", Value(report.verified_at)}});
}

std::string ownership_id(const usk::state::InstalledState& installed)
{
    const std::string& reference = installed.ownership_manifest_ref;
    if (reference.rfind("ownership/", 0) != 0 || reference.size() <= 15 ||
        reference.substr(reference.size() - 5) != ".json") {
        throw PublicError("installed_state_invalid", "installed-state ownership reference is invalid");
    }
    return reference.substr(10, reference.size() - 15);
}

usk::state::InstalledState current_install(const PublicConfig& config, const std::string& install_id)
{
    require_setup_probe(config, config.setup_root / ".usk-owned-root.v1.json");
    return usk::state::StateRepository(lifecycle_roots(config).state_root).read_installed(install_id);
}

usk::policy::TargetClass current_target_class(const PublicConfig& config, const fs::path& target)
{
    return same_or_below(config.acceptance_root, target)
        ? usk::policy::TargetClass::operator_acceptance
        : usk::policy::TargetClass::managed_portable;
}

std::string operation_policy_digest(
    const PublicConfig& config,
    const fs::path& current_root,
    const fs::path& stable_source,
    const std::string& operation,
    const usk::policy::InspectedTarget* destination = nullptr)
{
    const fs::path probe = current_root / ".usk-operation-policy-probe";
    if (fs::exists(probe)) {
        throw PublicError("target_path_redirected", "the reserved managed-target policy probe already exists");
    }
    const auto current = usk::policy::inspect_and_evaluate_live_target(config.activation,
        usk::policy::TargetInspectionRequest{current_target_class(config, current_root), probe,
            config.acceptance_root, stable_source, 1,
            {operation + " exact recorded owned state under " + current_root.generic_u8string(),
             "retain and report unknown or changed content"}});
    if (!current.decision.accepted) {
        throw PublicError(current.decision.code, "managed target authority refused: " + current.decision.detail);
    }
    Value::Object binding{
        {"activation", Value(usk::policy::activation_name(config.activation))},
        {"current_target_binding_digest", Value(current.decision.target_binding_digest)},
        {"operation", Value(operation)}};
    if (destination != nullptr) {
        binding.emplace("destination_binding_digest", Value(destination->decision.target_binding_digest));
    }
    return usk::json::sha256_canonical(Value(std::move(binding)));
}

Value fixed_archive_inspection_request(const Value& archive)
{
    exact_members(archive, {"path", "format", "expected_sha256", "strip_prefix"});
    if (required_string(archive, "format") != "zip") {
        throw PublicError("invalid_argument", "repair currently accepts ZIP archives only");
    }
    return Value(Value::Object{
        {"archive_format", Value("zip")}, {"archive_path", Value(required_string(archive, "path"))},
        {"budgets", Value(Value::Object{
            {"max_depth", Value(std::uint64_t{64})}, {"max_elapsed_ms", Value(std::uint64_t{30000})},
            {"max_entries", Value(std::uint64_t{10000})},
            {"max_entry_bytes", Value(std::uint64_t{536870912})},
            {"max_ratio", Value(std::uint64_t{1000})},
            {"max_uncompressed_bytes", Value(std::uint64_t{536870912})}})},
        {"schema", Value("usk.archive_inspect_request.v1")}});
}

RepairPlanBundle build_repair_plan(const Value& request, const PublicConfig& config)
{
    exact_members(request, {"schema", "request_id", "plan_id", "install_id", "created_at", "archive"});
    if (required_string(request, "schema") != "usk.repair_plan_request.v1") {
        throw PublicError("invalid_argument", "repair plan request schema is incompatible");
    }
    const std::string install_id = required_string(request, "install_id");
    const auto installed = current_install(config, install_id);
    const Value& archive = request.at("archive");
    const fs::path source_path(required_string(archive, "path"));
    if (!source_path.is_absolute()) throw PublicError("invalid_argument", "repair source path must be absolute");
    auto payload = usk::archive::inspect_stored_payload(
        usk::json::canonical(fixed_archive_inspection_request(archive)),
        archive.at("strip_prefix").as_string());
    const std::string expected = required_string(archive, "expected_sha256");
    if (payload.source_sha256 != expected || expected != installed.source_archive_digest) {
        throw PublicError("source_drift", "repair requires the exact archive bound by installed state");
    }
    std::vector<usk::lifecycle::PayloadFile> files;
    for (auto& file : payload.files) files.push_back({std::move(file.relative_path), std::move(file.bytes)});
    const std::string policy = operation_policy_digest(
        config, installed.target_root, source_path, "repair");
    RepairPlanBundle result;
    result.installed = installed;
    result.plan = usk::lifecycle::plan_repair(lifecycle_roots(config), install_id,
        required_string(request, "plan_id"), required_string(request, "created_at"),
        std::move(files), payload.source_sha256, policy);
    result.before = usk::lifecycle::verify_installed(lifecycle_roots(config), install_id,
        "verify." + result.plan.plan_id + ".before", result.plan.created_at);
    return result;
}

std::string repair_reason(const std::string& status)
{
    if (status == "missing" || status == "modified") return status;
    return "wrong_type";
}

Value repair_plan_document(const RepairPlanBundle& bundle)
{
    Value::Array repairs;
    for (const auto& file : bundle.before.files) {
        if (file.status == "present") continue;
        repairs.emplace_back(Value::Object{{"expected_sha256", Value(file.expected_sha256)},
            {"reason", Value(repair_reason(file.status))}, {"relative_path", Value(file.relative_path)}});
    }
    return Value(Value::Object{
        {"before_verification_digest", Value(bundle.before.report_digest)},
        {"created_at", Value(bundle.plan.created_at)}, {"install_id", Value(bundle.plan.install_id)},
        {"installed_state_digest", Value(bundle.plan.installed_state_digest)},
        {"operation", Value("repair")}, {"ownership_manifest_digest", Value(bundle.plan.ownership_manifest_digest)},
        {"plan_digest", Value(bundle.plan.plan_digest)}, {"plan_id", Value(bundle.plan.plan_id)},
        {"pre_target_snapshot_digest", Value(
            usk::evidence::snapshot_target(bundle.installed.target_root).snapshot_digest)},
        {"recipe_digest", Value(bundle.installed.recipe_digest)}, {"repairs", Value(std::move(repairs))},
        {"retained_unknown_paths", string_array(bundle.before.unknown_paths)},
        {"revalidation", Value(Value::Object{{"immediately_before_apply", Value(true)},
            {"invalidate_on", Value(Value::Array{Value("source"), Value("recipe"), Value("target"),
                Value("installed_state"), Value("ownership_manifest"), Value("policy"),
                Value("provider_revision")})}})},
        {"schema", Value("usk.repair_plan.v1")}, {"source_digest", Value(bundle.plan.source_digest)},
        {"status", Value("planned")}});
}

Value report_ref(const usk::lifecycle::VerificationReport& report)
{
    return Value(Value::Object{{"report_digest", Value(report.report_digest)},
        {"report_id", Value(report.report_id)}, {"status", Value(report.status)}});
}

Value bind_report_digest(Value document)
{
    Value::Object& object = document.as_object();
    object.erase("report_digest");
    const std::string digest = usk::json::sha256_canonical(document);
    object.emplace("report_digest", Value(digest));
    return document;
}

Value repair_report_document(
    const RepairPlanBundle& bundle,
    const usk::lifecycle::RepairResult& result,
    const std::string& transaction_id,
    const std::string& completed_at)
{
    Value::Array repaired;
    for (const std::string& path : result.repaired_files) {
        const auto verification = std::find_if(result.before.files.begin(), result.before.files.end(),
            [&](const auto& file) { return file.relative_path == path; });
        const auto replacement = std::find_if(bundle.plan.replacement_files.begin(), bundle.plan.replacement_files.end(),
            [&](const auto& file) { return file.relative_path == path; });
        usk::base::Sha256 digest;
        digest.update(replacement->bytes.data(), replacement->bytes.size());
        repaired.emplace_back(Value::Object{{"prior_status", Value(repair_reason(verification->status))},
            {"relative_path", Value(path)}, {"sha256", Value(digest.finish())}});
    }
    return bind_report_digest(Value(Value::Object{
        {"after_verification_ref", report_ref(result.after)}, {"before_verification_ref", report_ref(result.before)},
        {"completed_at", Value(completed_at)}, {"install_id", Value(bundle.plan.install_id)},
        {"plan_id", Value(bundle.plan.plan_id)}, {"recipe_digest", Value(bundle.installed.recipe_digest)},
        {"repaired_files", Value(std::move(repaired))}, {"report_digest", Value(std::string(64, '0'))},
        {"report_id", Value("repair." + transaction_id)},
        {"retained_unknown_paths", string_array(result.retained_unknown_paths)},
        {"schema", Value("usk.repair_report.v1")}, {"source_digest", Value(bundle.plan.source_digest)},
        {"status", Value("completed")}, {"transaction_id", Value(transaction_id)}}));
}

MovePlanBundle build_move_plan(const Value& request, const PublicConfig& config)
{
    exact_members(request, {"schema", "request_id", "plan_id", "install_id", "created_at", "new_target"});
    if (required_string(request, "schema") != "usk.move_plan_request.v1") {
        throw PublicError("invalid_argument", "move plan request schema is incompatible");
    }
    MovePlanBundle result;
    result.installed = current_install(config, required_string(request, "install_id"));
    const Value& target = request.at("new_target");
    exact_members(target, {"root", "class"});
    const fs::path new_root(required_string(target, "root"));
    const auto target_class = usk::policy::parse_target_class(required_string(target, "class"));
    if (!new_root.is_absolute() || !target_class.has_value()) {
        throw PublicError("invalid_argument", "move destination must be an absolute classified target");
    }
    const auto roots = lifecycle_roots(config);
    const auto ownership = usk::state::StateRepository(roots.state_root).read_ownership(ownership_id(result.installed));
    std::uint64_t required_bytes = setup_overhead_bytes;
    for (const auto& file : ownership.files) {
        if (required_bytes > std::numeric_limits<std::uint64_t>::max() - file.size_bytes) {
            throw PublicError("target_space_insufficient", "move closure size cannot be represented safely");
        }
        required_bytes += file.size_bytes;
    }
    const fs::path marker = config.setup_root / ".usk-owned-root.v1.json";
    result.destination = usk::policy::inspect_and_evaluate_live_target(config.activation,
        usk::policy::TargetInspectionRequest{*target_class, new_root, config.acceptance_root, marker,
            required_bytes, {"copy and verify the complete managed closure to " + new_root.generic_u8string(),
                "retain the old root pending explicit later acceptance"}});
    if (!result.destination.decision.accepted) {
        throw PublicError(result.destination.decision.code, result.destination.decision.detail);
    }
    if (result.destination.evidence.target_state != usk::policy::TargetState::nonexistent) {
        throw PublicError("target_not_empty", "move destination must not exist");
    }
    const std::string policy = operation_policy_digest(config, result.installed.target_root,
        marker, "move", &result.destination);
    result.plan = usk::lifecycle::plan_move(roots, result.installed.install_id,
        required_string(request, "plan_id"), required_string(request, "created_at"), new_root, policy);
    return result;
}

Value operation_plan_document(
    const std::string& operation,
    const std::string& plan_id,
    const std::string& plan_digest,
    const std::string& created_at,
    const usk::state::InstalledState& installed,
    const std::string& installed_digest,
    const std::string& ownership_digest,
    const std::string& policy,
    const usk::lifecycle::LifecycleRoots& roots,
    const fs::path& destination,
    const std::vector<usk::lifecycle::PayloadFile>& files,
    const usk::lifecycle::VerificationReport* verification)
{
    Value::Array root_values{
        Value(Value::Object{{"classification", Value("managed_install")}, {"role", Value("current")},
            {"root", Value(installed.target_root)}}),
        Value(Value::Object{{"classification", Value("setup_owned")}, {"role", Value("staging")},
            {"root", Value(roots.staging_parent.generic_u8string())}}),
        Value(Value::Object{{"classification", Value("setup_owned")}, {"role", Value("setup_state")},
            {"root", Value(roots.state_root.generic_u8string())}}),
        Value(Value::Object{{"classification", Value("audit_owned")}, {"role", Value("audit")},
            {"root", Value(roots.audit_root.generic_u8string())}})};
    if (!destination.empty()) {
        root_values.emplace_back(Value::Object{{"classification", Value("operator_selected_owned_target")},
            {"must_not_exist", Value(true)}, {"role", Value("destination")},
            {"root", Value(destination.generic_u8string())}});
    }
    Value::Array effects;
    std::uint64_t index = 0;
    if (operation == "move") {
        for (const auto& file : files) {
            usk::base::Sha256 digest;
            digest.update(file.bytes.data(), file.bytes.size());
            effects.emplace_back(Value::Object{{"effect_id", Value("effect." + std::to_string(index++))},
                {"expected_sha256", Value(digest.finish())}, {"kind", Value("copy_owned_file")},
                {"ownership_required", Value(true)}, {"relative_path", Value(file.relative_path)},
                {"root_role", Value("destination")}});
        }
    } else if (operation == "uninstall" && verification != nullptr) {
        for (const auto& file : verification->files) {
            effects.emplace_back(Value::Object{{"effect_id", Value("effect." + std::to_string(index++))},
                {"expected_sha256", Value(file.expected_sha256)},
                {"kind", Value(file.status == "present" ? "delete_owned_file" : "retain_path")},
                {"ownership_required", Value(true)}, {"relative_path", Value(file.relative_path)},
                {"root_role", Value("current")}});
        }
        for (const std::string& path : verification->unknown_paths) {
            effects.emplace_back(Value::Object{{"effect_id", Value("effect." + std::to_string(index++))},
                {"kind", Value("retain_path")}, {"ownership_required", Value(true)},
                {"relative_path", Value(path)}, {"root_role", Value("current")}});
        }
    }
    effects.emplace_back(Value::Object{{"effect_id", Value("effect." + std::to_string(index++))},
        {"kind", Value("write_journal")}, {"ownership_required", Value(true)},
        {"relative_path", Value("transactions")}, {"root_role", Value("setup_state")}});
    effects.emplace_back(Value::Object{{"effect_id", Value("effect." + std::to_string(index++))},
        {"kind", Value("write_state")}, {"ownership_required", Value(true)},
        {"relative_path", Value("installed")}, {"root_role", Value("setup_state")}});
    effects.emplace_back(Value::Object{{"effect_id", Value("effect." + std::to_string(index))},
        {"kind", Value("write_audit")}, {"ownership_required", Value(true)},
        {"relative_path", Value("chains")}, {"root_role", Value("audit")}});
    return Value(Value::Object{
        {"created_at", Value(created_at)}, {"effects", Value(std::move(effects))},
        {"input_identity", Value(Value::Object{{"installed_state_digest", Value(installed_digest)},
            {"ownership_manifest_digest", Value(ownership_digest)}, {"policy_digest", Value(policy)},
            {"provider_revision", Value(installed.provider_revision)}, {"recipe_digest", Value(installed.recipe_digest)},
            {"source_digest", Value(installed.source_archive_digest)}})},
        {"install_id", Value(installed.install_id)}, {"operation", Value(operation)},
        {"plan_digest", Value(plan_digest)}, {"plan_id", Value(plan_id)},
        {"revalidation", Value(Value::Object{{"immediately_before_apply", Value(true)},
            {"invalidate_on", Value(Value::Array{Value("target"), Value("installed_state"),
                Value("ownership_manifest"), Value("policy"), Value("provider_revision")})}})},
        {"roots", Value(std::move(root_values))}, {"schema", Value("usk.operation_plan.v1")},
        {"status", Value("planned")},
        {"target_snapshots", Value(Value::Object{{"pre_target_digest", Value(
            usk::evidence::snapshot_target(destination.empty() ? fs::path(installed.target_root) : destination)
                .snapshot_digest)}})},
        {"unknown_file_policy", Value("retain_and_report")}});
}

Value move_report_document(
    const MovePlanBundle& bundle,
    const usk::lifecycle::MoveResult& result,
    const std::string& transaction_id,
    const std::string& completed_at)
{
    return bind_report_digest(Value(Value::Object{
        {"completed_at", Value(completed_at)}, {"install_id", Value(bundle.plan.install_id)},
        {"new_root", Value(bundle.plan.new_root.generic_u8string())},
        {"new_verification_ref", report_ref(result.verification)},
        {"old_root", Value(bundle.plan.old_root.generic_u8string())},
        {"old_root_status", Value("retired_retained")},
        {"phases", Value(Value::Array{
            Value(Value::Object{{"phase", Value("copy_to_staging")}, {"status", Value("completed")}}),
            Value(Value::Object{{"phase", Value("verify_closure")}, {"status", Value("completed")}}),
            Value(Value::Object{{"phase", Value("commit_new")}, {"status", Value("completed")}}),
            Value(Value::Object{{"phase", Value("update_references")}, {"status", Value("deferred")}}),
            Value(Value::Object{{"phase", Value("retire_old")}, {"status", Value("completed")}}),
            Value(Value::Object{{"phase", Value("accept_old_removal")}, {"status", Value("deferred")}}),
            Value(Value::Object{{"phase", Value("remove_old_owned_state")}, {"status", Value("deferred")}})})},
        {"plan_id", Value(bundle.plan.plan_id)}, {"reference_update_status", Value("not_started")},
        {"report_digest", Value(std::string(64, '0'))}, {"report_id", Value("move." + transaction_id)},
        {"schema", Value("usk.move_report.v1")}, {"status", Value("new_committed_old_retained")},
        {"transaction_id", Value(transaction_id)}}));
}

UninstallPlanBundle build_uninstall_plan(const Value& request, const PublicConfig& config)
{
    exact_members(request, {"schema", "request_id", "plan_id", "install_id", "created_at"});
    if (required_string(request, "schema") != "usk.uninstall_plan_request.v1") {
        throw PublicError("invalid_argument", "uninstall plan request schema is incompatible");
    }
    UninstallPlanBundle result;
    result.installed = current_install(config, required_string(request, "install_id"));
    const std::string policy = operation_policy_digest(config, result.installed.target_root,
        config.setup_root / ".usk-owned-root.v1.json", "uninstall");
    result.plan = usk::lifecycle::plan_uninstall(lifecycle_roots(config), result.installed.install_id,
        required_string(request, "plan_id"), required_string(request, "created_at"), policy);
    return result;
}

Value uninstall_report_document(
    const UninstallPlanBundle& bundle,
    const usk::lifecycle::UninstallResult& result,
    const std::string& transaction_id,
    const std::string& completed_at)
{
    const std::string status = result.target_removed ? "completed" : "retained_foreign_content";
    return bind_report_digest(Value(Value::Object{
        {"completed_at", Value(completed_at)}, {"deleted_owned_files", string_array(result.deleted_owned_files)},
        {"install_id", Value(bundle.plan.install_id)},
        {"ownership_manifest_digest", Value(bundle.plan.ownership_manifest_digest)},
        {"plan_id", Value(bundle.plan.plan_id)}, {"report_digest", Value(std::string(64, '0'))},
        {"report_id", Value("uninstall." + transaction_id)},
        {"retained_changed_owned_files", string_array(result.retained_changed_owned_files)},
        {"retained_directories", string_array(result.retained_directories)},
        {"retained_unknown_paths", string_array(result.retained_unknown_paths)},
        {"schema", Value("usk.uninstall_report.v1")}, {"source_archive_deleted", Value(false)},
        {"status", Value(status)}, {"transaction_id", Value(transaction_id)}}));
}

RecoveryBundle build_recovery_inspection(const Value& request, const PublicConfig& config)
{
    exact_members(request, {"schema", "request_id", "install_id", "transaction_id", "plan_id",
                            "plan_digest", "operation", "target_root"});
    if (required_string(request, "schema") != "usk.recovery_inspect_request.v1") {
        throw PublicError("invalid_argument", "recovery inspection request schema is incompatible");
    }
    const std::string operation = required_string(request, "operation");
    if (operation != "install_local" && operation != "repair" &&
        operation != "move" && operation != "uninstall") {
        throw PublicError("invalid_argument", "recovery operation is invalid");
    }
    const fs::path target(required_string(request, "target_root"));
    if (!target.is_absolute()) throw PublicError("invalid_argument", "recovery target root must be absolute");
    require_setup_probe(config, config.setup_root / ".usk-owned-root.v1.json");
    const auto roots = lifecycle_roots(config);
    RecoveryBundle result;
    result.install_id = required_string(request, "install_id");
    result.request_id = required_string(request, "request_id");
    result.spec = {required_string(request, "transaction_id"), required_string(request, "plan_id"),
        required_string(request, "plan_digest"), operation,
        operation == "move" ? target.parent_path() : roots.staging_parent,
        target, roots.state_root, roots.audit_root};
    result.inspection = usk::transaction::TransactionSession::inspect_recovery(result.spec);
    return result;
}

Value recovery_effects(const usk::transaction::RecoveryInspection& inspection)
{
    Value::Array effects;
    for (const std::string& action : inspection.available_actions) {
        if (action == "resume") {
            effects.emplace_back(Value::Object{{"kind", Value("resume_transition")},
                {"relative_path", Value(".")}, {"root_class", Value("setup_state")}});
        } else if (action == "rollback") {
            effects.emplace_back(Value::Object{{"kind", Value("delete_staged_path")},
                {"relative_path", Value(".")}, {"root_class", Value("staging")}});
        } else {
            effects.emplace_back(Value::Object{{"kind", Value("retain_path")},
                {"relative_path", Value(".")}, {"root_class", Value("owned_target")}});
        }
    }
    return Value(std::move(effects));
}

Value recovery_report_document(const RecoveryBundle& bundle)
{
    return bind_report_digest(Value(Value::Object{
        {"available_actions", string_array(bundle.inspection.available_actions)},
        {"effects", recovery_effects(bundle.inspection)},
        {"journal_digest", Value(bundle.inspection.journal_digest)},
        {"journal_id", Value("journal." + bundle.spec.transaction_id)},
        {"observed_state", Value(bundle.inspection.current_state)},
        {"recorded_at", Value(bundle.inspection.recorded_at)},
        {"report_digest", Value(std::string(64, '0'))},
        {"report_id", Value("recovery.inspect." + bundle.request_id)},
        {"schema", Value("usk.recovery_report.v1")}, {"selected_action", Value()},
        {"status", Value("inspection_only")}, {"transaction_id", Value(bundle.spec.transaction_id)}}));
}

Value bind_plan_digest(Value document)
{
    Value::Object& object = document.as_object();
    object.erase("plan_digest");
    const std::string digest = usk::json::sha256_canonical(document);
    object.emplace("plan_digest", Value(digest));
    return document;
}

Value recovery_plan_document(const Value& request, const PublicConfig& config)
{
    exact_members(request, {"schema", "inspection", "recovery_plan_id", "created_at"});
    if (required_string(request, "schema") != "usk.recovery_plan_request.v1") {
        throw PublicError("invalid_argument", "recovery plan request schema is incompatible");
    }
    const RecoveryBundle bundle = build_recovery_inspection(request.at("inspection"), config);
    return bind_plan_digest(Value(Value::Object{
        {"available_actions", string_array(bundle.inspection.available_actions)},
        {"created_at", Value(required_string(request, "created_at"))},
        {"effects", recovery_effects(bundle.inspection)}, {"install_id", Value(bundle.install_id)},
        {"journal_digest", Value(bundle.inspection.journal_digest)},
        {"observed_state", Value(bundle.inspection.current_state)},
        {"operation", Value(bundle.spec.operation)}, {"plan_digest", Value(std::string(64, '0'))},
        {"plan_id", Value(required_string(request, "recovery_plan_id"))},
        {"revalidation", Value(Value::Object{{"immediately_before_apply", Value(true)},
            {"invalidate_on", Value(Value::Array{Value("journal"), Value("staging"),
                Value("target"), Value("policy")})}})},
        {"schema", Value("usk.recovery_plan.v1")}, {"status", Value("planned")},
        {"transaction_id", Value(bundle.spec.transaction_id)}}));
}

Value live_evidence_capture(const Value& request, const PublicConfig& config)
{
    exact_members(request, {"schema", "request_id", "packet_id", "captured_at", "install_id",
                            "source_revisions", "contract_versions", "archive", "recipe_id",
                            "target", "plan", "transaction", "snapshots", "automated_findings"});
    if (required_string(request, "schema") != "usk.live_target_evidence_capture_request.v1") {
        throw PublicError("invalid_argument", "live evidence capture request schema is incompatible");
    }
    (void)required_string(request, "request_id");
    initialize_setup_root(config);
    const std::string install_id = required_string(request, "install_id");
    const auto roots = lifecycle_roots(config);
    usk::state::StateRepository state_repository(roots.state_root);
    const usk::state::InstalledState installed = state_repository.read_installed(install_id);

    const Value& archive = request.at("archive");
    exact_members(archive, {"source_id", "sha256", "size_bytes", "filesystem_identity_digest",
                            "path_identity_digest"});
    const std::string archive_digest = required_string(archive, "sha256");
    if (archive_digest != installed.source_archive_digest) {
        throw PublicError("source_changed", "evidence archive identity does not match installed state");
    }

    const Value& plan = request.at("plan");
    exact_members(plan, {"plan_id", "plan_digest", "operation", "expected_file_count",
                         "expected_byte_count"});
    const Value& transaction = request.at("transaction");
    exact_members(transaction, {"transaction_id", "staging_parent", "target_root"});
    const std::string transaction_id = required_string(transaction, "transaction_id");
    if (transaction_id != installed.transaction_id) {
        throw PublicError("state_changed", "evidence capture is not bound to the latest installed-state transaction");
    }
    const fs::path staging_parent(required_string(transaction, "staging_parent"));
    const fs::path transaction_target(required_string(transaction, "target_root"));
    if (!staging_parent.is_absolute() || !transaction_target.is_absolute() ||
        !same_or_below(config.acceptance_root, staging_parent) ||
        !same_or_below(config.acceptance_root, transaction_target)) {
        throw PublicError("target_outside_acceptance_root", "evidence transaction roots are outside acceptance authority");
    }
    const usk::transaction::TransactionSpec spec{
        transaction_id, required_string(plan, "plan_id"), required_string(plan, "plan_digest"),
        required_string(plan, "operation"), staging_parent, transaction_target,
        roots.state_root, roots.audit_root};
    const auto recovery = usk::transaction::TransactionSession::inspect_recovery(spec);

    const std::string ownership_reference = installed.ownership_manifest_ref;
    if (ownership_reference.rfind("ownership/", 0) != 0 || ownership_reference.size() <= 15 ||
        ownership_reference.substr(ownership_reference.size() - 5) != ".json") {
        throw PublicError("installed_state_invalid", "installed state has an invalid ownership reference");
    }
    const std::string ownership_id = ownership_reference.substr(10, ownership_reference.size() - 15);
    const usk::state::OwnershipManifest ownership = state_repository.read_ownership(ownership_id);
    if (ownership.manifest_digest != installed.ownership_manifest_digest) {
        throw PublicError("state_changed", "installed state and ownership no longer agree");
    }
    Value::Array closure;
    std::uint64_t closure_bytes = 0;
    for (const auto& file : ownership.files) {
        closure.emplace_back(Value::Object{{"relative_path", Value(file.relative_path)},
            {"sha256", Value(file.sha256)}, {"size_bytes", Value(file.size_bytes)}});
        if (file.size_bytes > std::numeric_limits<std::uint64_t>::max() - closure_bytes) {
            throw PublicError("capacity_exceeded", "owned closure byte count overflowed");
        }
        closure_bytes += file.size_bytes;
    }
    const std::string closure_digest = usk::json::sha256_canonical(Value(std::move(closure)));
    const std::string installed_digest = usk::json::sha256_canonical(installed_document(installed));
    const auto audit = usk::audit::AuditRepository(roots.audit_root).read_and_validate_chain(installed.audit_chain_id);
    if (audit.empty()) throw PublicError("audit_invalid", "installed state audit chain is empty");

    const Value& target = request.at("target");
    exact_members(target, {"class", "identity_digest", "path_identity_digest", "persistent_effects",
                           "filesystem"});
    const Value& filesystem = target.at("filesystem");
    exact_members(filesystem, {"identity_digest", "kind", "capabilities"});
    const Value& capabilities = filesystem.at("capabilities");
    exact_members(capabilities, {"local", "stable_ancestors", "no_mount_redirection",
                                 "no_replace_commit"});
    const Value& snapshots = request.at("snapshots");
    exact_members(snapshots, {"pre_target_digest", "post_target_digest"});

    usk::evidence::LiveEvidenceInput input;
    input.packet_id = required_string(request, "packet_id");
    input.captured_at = required_string(request, "captured_at");
    for (const Value& revision : request.at("source_revisions").as_array()) {
        exact_members(revision, {"repository_id", "revision"});
        input.source_revisions.push_back({required_string(revision, "repository_id"),
                                          required_string(revision, "revision")});
    }
    input.setup_abi_major = installed.setup_abi_major;
    input.setup_abi_minor = installed.setup_abi_minor;
    input.provider_revision = installed.provider_revision;
    for (const Value& contract : request.at("contract_versions").as_array()) {
        exact_members(contract, {"contract_id", "schema_version"});
        input.contract_versions.push_back({required_string(contract, "contract_id"),
                                            required_string(contract, "schema_version")});
    }
    input.source_id = required_string(archive, "source_id");
    input.archive_digest = archive_digest;
    input.archive_size_bytes = archive.at("size_bytes").as_unsigned();
    input.source_filesystem_identity_digest = required_string(archive, "filesystem_identity_digest");
    input.source_path_identity_digest = required_string(archive, "path_identity_digest");
    input.recipe_id = required_string(request, "recipe_id");
    input.recipe_digest = installed.recipe_digest;
    input.product_id = installed.product_id;
    input.product_version = installed.product_version;
    input.target_class = required_string(target, "class");
    input.target_identity_digest = required_string(target, "identity_digest");
    input.target_path_identity_digest = required_string(target, "path_identity_digest");
    for (const Value& effect : target.at("persistent_effects").as_array()) {
        input.persistent_effects.push_back(effect.as_string());
    }
    input.filesystem_identity_digest = required_string(filesystem, "identity_digest");
    input.filesystem_kind = required_string(filesystem, "kind");
    input.filesystem_local = capabilities.at("local").as_boolean();
    input.stable_ancestors = capabilities.at("stable_ancestors").as_boolean();
    input.no_mount_redirection = capabilities.at("no_mount_redirection").as_boolean();
    input.no_replace_commit = capabilities.at("no_replace_commit").as_boolean();
    input.plan_id = spec.plan_id;
    input.plan_digest = spec.plan_digest;
    input.operation = spec.operation;
    input.expected_file_count = plan.at("expected_file_count").as_unsigned();
    input.expected_byte_count = plan.at("expected_byte_count").as_unsigned();
    const bool removed = installed.lifecycle_status == "retired" && !fs::exists(installed.target_root);
    input.closure_status = removed ? "removed" :
        (recovery.current_state == "recovery_required" ? "recovery_required" : "committed");
    input.committed_file_count = removed ? 0 : static_cast<std::uint64_t>(ownership.files.size());
    input.committed_byte_count = removed ? 0 : closure_bytes;
    input.committed_closure_digest = removed ?
        usk::json::sha256_canonical(Value(Value::Array{})) : closure_digest;
    input.installed_state_digest = installed_digest;
    input.ownership_digest = ownership.manifest_digest;
    input.audit_chain_id = installed.audit_chain_id;
    input.audit_head_digest = audit.back().event_digest;
    input.pre_target_snapshot_digest = required_string(snapshots, "pre_target_digest");
    input.post_target_snapshot_digest = required_string(snapshots, "post_target_digest");
    const auto observed_post_snapshot = usk::evidence::snapshot_target(installed.target_root);
    if (observed_post_snapshot.snapshot_digest != input.post_target_snapshot_digest) {
        throw PublicError("target_changed", "post-operation target snapshot does not match current filesystem state");
    }
    input.recovery_status = recovery.current_state == "completed" ? "not_required" :
        (recovery.current_state == "recovery_required" ? "recovery_required" : "unproven");
    input.journal_digest = recovery.journal_digest;
    for (const Value& finding : request.at("automated_findings").as_array()) {
        exact_members(finding, {"code", "severity", "classification", "details_digest"});
        input.automated_findings.push_back({required_string(finding, "code"),
            required_string(finding, "severity"), required_string(finding, "classification"),
            required_string(finding, "details_digest")});
    }

    if (input.expected_file_count != ownership.files.size() ||
        (!removed && input.expected_byte_count != closure_bytes)) {
        throw PublicError("closure_changed", "reviewed plan totals do not match the setup-owned closure");
    }
    const auto packet = usk::evidence::build_pending_packet(std::move(input));
    ensure_directory(config.setup_root, "evidence");
    ensure_directory(config.setup_root / "evidence", "packets");
    usk::evidence::EvidenceRepository(config.setup_root / "evidence").write_new(packet);
    return usk::json::parse(packet.canonical_json);
}

Value operator_verdict_record(const Value& request, const PublicConfig& config)
{
    exact_members(request, {"schema", "request_id", "pending_packet_id", "new_packet_id",
                            "recorded_at", "verdict", "recorded_by", "statement_digest",
                            "confirmation"});
    if (required_string(request, "schema") != "usk.operator_verdict_record_request.v1" ||
        required_string(request, "confirmation") != "RECORD VERDICT") {
        throw PublicError("invalid_argument", "operator verdict schema or explicit confirmation is invalid");
    }
    (void)required_string(request, "request_id");
    initialize_setup_root(config);
    usk::evidence::EvidenceRepository repository(config.setup_root / "evidence");
    const auto pending = repository.read_and_validate(required_string(request, "pending_packet_id"));
    const auto recorded = usk::evidence::record_operator_verdict(
        pending, required_string(request, "new_packet_id"), required_string(request, "recorded_at"),
        required_string(request, "verdict"), required_string(request, "recorded_by"),
        required_string(request, "statement_digest"));
    repository.write_new(recorded);
    return usk::json::parse(recorded.canonical_json);
}

void ensure_directory(const fs::path& parent, const std::string& name)
{
    const fs::path child = parent / name;
    std::error_code error;
    if (fs::exists(child, error)) {
        if (error) throw PublicError("setup_state_root_unsafe", "cannot inspect setup-state directory");
        usk::record_io::require_safe_directory(child);
    } else {
        usk::record_io::create_directory_exclusive(parent, name);
    }
}

void initialize_setup_root(const PublicConfig& config)
{
    const std::string marker = setup_root_marker(config);
    std::error_code error;
    if (!fs::exists(config.setup_root, error)) {
        if (error) throw PublicError("setup_state_root_unsafe", "cannot inspect setup-state root");
        usk::record_io::require_safe_directory(config.setup_root.parent_path());
        usk::record_io::create_directory_exclusive(config.setup_root.parent_path(), config.setup_root.filename().string());
        usk::record_io::write_new_durable_text(config.setup_root / ".usk-owned-root.v1.json", marker);
    } else {
        usk::record_io::require_safe_directory(config.setup_root);
        const std::string actual = usk::record_io::read_stable_text(
            config.setup_root / ".usk-owned-root.v1.json", 64u * 1024u);
        if (actual != marker) throw PublicError("setup_state_root_unsafe", "setup-state ownership marker is missing or incompatible");
    }
    ensure_directory(config.setup_root, "state");
    ensure_directory(config.setup_root, "staging");
    ensure_directory(config.setup_root, "audit");
    const auto roots = lifecycle_roots(config);
    ensure_directory(roots.state_root, "ownership");
    ensure_directory(roots.state_root, "installed");
    ensure_directory(roots.state_root, "transactions");
    ensure_directory(roots.audit_root, "chains");
}

Value execute_command(const std::string& command, const Value& request, const PublicConfig& config)
{
    if (command == "live_evidence.capture") {
        return response_ok(live_evidence_capture(request, config));
    }
    if (command == "live_evidence.verdict.record") {
        return response_ok(operator_verdict_record(request, config));
    }
    if (command == "install_local.plan") {
        const InstallPlanBundle bundle = build_install_plan(request, config);
        return response_ok(install_plan_document(bundle, request.at("archive").at("path").as_string()));
    }
    if (command == "install_local.apply") {
        exact_members(request, {"schema", "plan_request", "reviewed_plan_id", "reviewed_plan_digest",
                                "transaction_id", "applied_at", "confirmation"});
        if (required_string(request, "schema") != "usk.install_local_apply_request.v1" ||
            required_string(request, "confirmation") != "APPLY") {
            throw PublicError("invalid_argument", "install apply schema or confirmation is invalid");
        }
        const InstallPlanBundle bundle = build_install_plan(request.at("plan_request"), config);
        if (required_string(request, "reviewed_plan_id") != bundle.plan.plan_id ||
            required_string(request, "reviewed_plan_digest") != bundle.plan.plan_digest) {
            throw PublicError("stale_plan", "reviewed install plan identity does not match immediate revalidation");
        }
        initialize_setup_root(config);
        const auto result = usk::lifecycle::apply_install(bundle.plan, bundle.plan.plan_digest,
            required_string(request, "transaction_id"), required_string(request, "applied_at"));
        return response_ok(installed_document(result.installed_state));
    }
    if (command == "installed.inspect") {
        exact_members(request, {"schema", "request_id", "install_id"});
        if (required_string(request, "schema") != "usk.installed_inspect_request.v1") {
            throw PublicError("invalid_argument", "installed inspect request schema is incompatible");
        }
        return response_ok(installed_document(usk::state::StateRepository(
            lifecycle_roots(config).state_root).read_installed(required_string(request, "install_id"))));
    }
    if (command == "installed.verify") {
        exact_members(request, {"schema", "request_id", "install_id", "report_id", "verified_at"});
        if (required_string(request, "schema") != "usk.installed_verify_request.v1") {
            throw PublicError("invalid_argument", "installed verify request schema is incompatible");
        }
        return response_ok(verification_document(usk::lifecycle::verify_installed(
            lifecycle_roots(config), required_string(request, "install_id"),
            required_string(request, "report_id"), required_string(request, "verified_at"))));
    }
    if (command == "repair.plan") {
        return response_ok(repair_plan_document(build_repair_plan(request, config)));
    }
    if (command == "repair.apply") {
        exact_members(request, {"schema", "plan_request", "reviewed_plan_id", "reviewed_plan_digest",
                                "transaction_id", "applied_at", "confirmation"});
        if (required_string(request, "schema") != "usk.repair_apply_request.v1" ||
            required_string(request, "confirmation") != "APPLY") {
            throw PublicError("invalid_argument", "repair apply schema or confirmation is invalid");
        }
        const RepairPlanBundle bundle = build_repair_plan(request.at("plan_request"), config);
        if (required_string(request, "reviewed_plan_id") != bundle.plan.plan_id ||
            required_string(request, "reviewed_plan_digest") != bundle.plan.plan_digest) {
            throw PublicError("stale_plan", "reviewed repair plan identity does not match immediate revalidation");
        }
        const std::string transaction_id = required_string(request, "transaction_id");
        const std::string applied_at = required_string(request, "applied_at");
        const auto result = usk::lifecycle::apply_repair(
            bundle.plan, bundle.plan.plan_digest, transaction_id, applied_at);
        return response_ok(repair_report_document(bundle, result, transaction_id, applied_at));
    }
    if (command == "move.plan") {
        const MovePlanBundle bundle = build_move_plan(request, config);
        usk::lifecycle::LifecycleRoots public_roots = bundle.plan.roots;
        public_roots.staging_parent = bundle.plan.staging_parent;
        return response_ok(operation_plan_document("move", bundle.plan.plan_id, bundle.plan.plan_digest,
            bundle.plan.created_at, bundle.installed, bundle.plan.installed_state_digest,
            bundle.plan.ownership_manifest_digest, bundle.plan.policy_digest, public_roots,
            bundle.plan.new_root, bundle.plan.complete_files, nullptr));
    }
    if (command == "move.apply") {
        exact_members(request, {"schema", "plan_request", "reviewed_plan_id", "reviewed_plan_digest",
                                "transaction_id", "applied_at", "confirmation"});
        if (required_string(request, "schema") != "usk.move_apply_request.v1" ||
            required_string(request, "confirmation") != "APPLY") {
            throw PublicError("invalid_argument", "move apply schema or confirmation is invalid");
        }
        const MovePlanBundle bundle = build_move_plan(request.at("plan_request"), config);
        if (required_string(request, "reviewed_plan_id") != bundle.plan.plan_id ||
            required_string(request, "reviewed_plan_digest") != bundle.plan.plan_digest) {
            throw PublicError("stale_plan", "reviewed move plan identity does not match immediate revalidation");
        }
        const std::string transaction_id = required_string(request, "transaction_id");
        const std::string applied_at = required_string(request, "applied_at");
        const auto result = usk::lifecycle::apply_move(
            bundle.plan, bundle.plan.plan_digest, transaction_id, applied_at);
        return response_ok(move_report_document(bundle, result, transaction_id, applied_at));
    }
    if (command == "uninstall.plan") {
        const UninstallPlanBundle bundle = build_uninstall_plan(request, config);
        return response_ok(operation_plan_document("uninstall", bundle.plan.plan_id, bundle.plan.plan_digest,
            bundle.plan.created_at, bundle.installed, bundle.plan.installed_state_digest,
            bundle.plan.ownership_manifest_digest, bundle.plan.policy_digest, bundle.plan.roots,
            {}, {}, &bundle.plan.verification));
    }
    if (command == "uninstall.apply") {
        exact_members(request, {"schema", "plan_request", "reviewed_plan_id", "reviewed_plan_digest",
                                "transaction_id", "applied_at", "confirmation"});
        if (required_string(request, "schema") != "usk.uninstall_apply_request.v1" ||
            required_string(request, "confirmation") != "APPLY") {
            throw PublicError("invalid_argument", "uninstall apply schema or confirmation is invalid");
        }
        const UninstallPlanBundle bundle = build_uninstall_plan(request.at("plan_request"), config);
        if (required_string(request, "reviewed_plan_id") != bundle.plan.plan_id ||
            required_string(request, "reviewed_plan_digest") != bundle.plan.plan_digest) {
            throw PublicError("stale_plan", "reviewed uninstall plan identity does not match immediate revalidation");
        }
        const bool changed_owned = std::any_of(bundle.plan.verification.files.begin(),
            bundle.plan.verification.files.end(), [](const auto& file) {
                return file.status == "modified" || file.status == "wrong_type" || file.status == "unreadable";
            });
        if (changed_owned || !bundle.plan.verification.unknown_paths.empty()) {
            throw PublicError("foreign_content_review_required",
                "uninstall refuses mutation while changed owned files or foreign content require operator review");
        }
        const std::string transaction_id = required_string(request, "transaction_id");
        const std::string applied_at = required_string(request, "applied_at");
        const auto result = usk::lifecycle::apply_uninstall(
            bundle.plan, bundle.plan.plan_digest, transaction_id, applied_at);
        return response_ok(uninstall_report_document(bundle, result, transaction_id, applied_at));
    }
    if (command == "recovery.inspect") {
        return response_ok(recovery_report_document(build_recovery_inspection(request, config)));
    }
    if (command == "recovery.plan") {
        return response_ok(recovery_plan_document(request, config));
    }
    throw PublicError("unsupported_command", "public lifecycle command is not implemented");
}

} // namespace

extern "C" char* usk_public_lifecycle_command_json(
    const char* command_name,
    const char* request_json,
    size_t request_size,
    const char* state_root,
    const char* authorized_acceptance_root,
    const char* target_policy_activation,
    int* out_command_status)
{
    if (out_command_status == nullptr) return nullptr;
    std::string response;
    try {
        if (command_name == nullptr || request_json == nullptr || request_size == 0 ||
            request_size > max_request_bytes) {
            throw PublicError("invalid_argument", "bounded public lifecycle command input is required");
        }
        const PublicConfig config = parse_config(
            state_root, authorized_acceptance_root, target_policy_activation);
        response = usk::json::canonical(execute_command(
            command_name, usk::json::parse(std::string(request_json, request_size)), config));
        *out_command_status = USK_STATUS_OK;
    } catch (const PublicError& error) {
        const bool invalid = error.code() == "invalid_argument";
        response = usk::json::canonical(response_error(
            invalid ? "invalid_argument" : "refused", error.code(), error.what()));
        *out_command_status = invalid ? USK_STATUS_INVALID_ARGUMENT : USK_STATUS_ERROR;
    } catch (const std::exception& error) {
        response = usk::json::canonical(response_error("refused", "lifecycle_refused", error.what()));
        *out_command_status = USK_STATUS_ERROR;
    }
    char* result = static_cast<char*>(std::malloc(response.size() + 1));
    if (result == nullptr) {
        *out_command_status = USK_STATUS_ERROR;
        return nullptr;
    }
    std::memcpy(result, response.c_str(), response.size() + 1);
    return result;
}

extern "C" void usk_public_lifecycle_command_free(char* value)
{
    std::free(value);
}
