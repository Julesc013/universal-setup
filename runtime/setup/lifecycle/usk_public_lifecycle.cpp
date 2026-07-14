// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_public_lifecycle.h"

#include "usk/usk_result.h"
#include "usk_archive_payload.h"
#include "usk_json.h"
#include "usk_lifecycle.h"
#include "usk_record_io.h"
#include "usk_sha256.h"
#include "usk_state_repository.h"
#include "usk_target_inspect.h"

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
            {"sha256", Value(bundle.plan.recipe.source_archive_digest)},
            {"size_bytes", Value(bundle.archive_size)},
            {"source_id", Value("source." + bundle.plan.install_id)}})},
        {"status", Value("planned")},
        {"target", Value(Value::Object{
            {"classification", Value("operator_selected_owned_target")},
            {"must_not_exist", Value(true)}, {"root", Value(bundle.plan.target_root.generic_u8string())},
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
