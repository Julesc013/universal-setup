// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_lifecycle.h"

#include "usk_audit_repository.h"
#include "usk_json.h"
#include "usk_record_io.h"
#include "usk_sha256.h"
#include "usk_stable_file.h"
#include "usk_transaction_session.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace fs = std::filesystem;
using usk::json::Value;

namespace {

bool sha256(const std::string& value)
{
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isdigit(ch) || (ch >= 'a' && ch <= 'f');
    });
}

std::string hash_bytes(const std::vector<unsigned char>& bytes)
{
    usk::base::Sha256 digest;
    digest.update(bytes.data(), bytes.size());
    return digest.finish();
}

std::string hash_text(const std::string& text)
{
    usk::base::Sha256 digest;
    digest.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
    return digest.finish();
}

std::string lowercase(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool safe_relative(const std::string& value)
{
    if (value.empty() || value.size() > 4096 || value.front() == '/' || value.front() == '\\' ||
        value.find('\\') != std::string::npos || value.find(':') != std::string::npos) return false;
    std::size_t start = 0;
    while (start < value.size()) {
        const std::size_t end = value.find('/', start);
        const std::string segment = value.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (segment.empty() || segment == "." || segment == ".." ||
            segment.back() == '.' || segment.back() == ' ') return false;
        const std::string base = lowercase(segment.substr(0, segment.find('.')));
        static const std::set<std::string> reserved = {
            "con", "prn", "aux", "nul", "clock$",
            "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
            "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"};
        if (reserved.count(base) != 0) return false;
        for (unsigned char ch : segment) if (ch < 0x20u || ch >= 0x7fu) return false;
        start = end == std::string::npos ? value.size() : end + 1;
    }
    return true;
}

bool valid_timestamp(const std::string& value)
{
    if (value.size() != 20 || value[4] != '-' || value[7] != '-' || value[10] != 'T' ||
        value[13] != ':' || value[16] != ':' || value[19] != 'Z') return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 4 || index == 7 || index == 10 || index == 13 || index == 16 || index == 19) continue;
        if (!std::isdigit(static_cast<unsigned char>(value[index]))) return false;
    }
    return true;
}

std::vector<std::string> directory_closure(const std::vector<usk::lifecycle::PayloadFile>& files)
{
    std::set<std::string> result;
    for (const auto& file : files) {
        fs::path parent = fs::path(file.relative_path).parent_path();
        while (!parent.empty()) {
            result.insert(parent.generic_string());
            parent = parent.parent_path();
        }
    }
    return {result.begin(), result.end()};
}

void validate_recipe(const usk::lifecycle::RecipeBinding& recipe)
{
    if (!usk::record_io::valid_identifier(recipe.product_id) || recipe.product_version.empty() ||
        !usk::record_io::valid_identifier(recipe.provider_revision) ||
        !sha256(recipe.recipe_digest) || !sha256(recipe.source_archive_digest) ||
        !sha256(recipe.policy_digest) || recipe.components.empty() || recipe.entrypoints.empty()) {
        throw std::runtime_error("lifecycle recipe binding is invalid");
    }
    std::set<std::string> components;
    for (const std::string& component : recipe.components) {
        if (!usk::record_io::valid_identifier(component) || !components.insert(component).second) {
            throw std::runtime_error("lifecycle component selection is invalid");
        }
    }
    std::set<std::string> entrypoints;
    for (const auto& entrypoint : recipe.entrypoints) {
        if (!usk::record_io::valid_identifier(entrypoint.entrypoint_id) ||
            !safe_relative(entrypoint.relative_path) ||
            (entrypoint.kind != "application" && entrypoint.kind != "tool" && entrypoint.kind != "server") ||
            !entrypoints.insert(entrypoint.entrypoint_id).second) {
            throw std::runtime_error("lifecycle entrypoint is invalid");
        }
    }
}

void normalize_files(std::vector<usk::lifecycle::PayloadFile>& files)
{
    if (files.empty()) throw std::runtime_error("lifecycle payload is empty");
    std::sort(files.begin(), files.end(), [](const auto& left, const auto& right) {
        return left.relative_path < right.relative_path;
    });
    std::set<std::string> folded;
    std::set<std::string> paths;
    for (const auto& file : files) {
        if (!safe_relative(file.relative_path) || !folded.insert(lowercase(file.relative_path)).second) {
            throw std::runtime_error("lifecycle payload path is unsafe or case-colliding");
        }
        paths.insert(file.relative_path);
    }
    for (const auto& file : files) {
        fs::path parent = fs::path(file.relative_path).parent_path();
        while (!parent.empty()) {
            if (paths.count(parent.generic_string()) != 0) {
                throw std::runtime_error("lifecycle payload descends through a file path");
            }
            parent = parent.parent_path();
        }
    }
}

Value plan_payload(const usk::lifecycle::InstallPlan& plan)
{
    Value::Array files;
    for (const auto& file : plan.files) {
        files.push_back(Value(Value::Object{
            {"relative_path", Value(file.relative_path)},
            {"sha256", Value(hash_bytes(file.bytes))},
            {"size_bytes", Value(static_cast<std::uint64_t>(file.bytes.size()))}}));
    }
    Value::Array components;
    for (const std::string& component : plan.recipe.components) components.push_back(Value(component));
    Value::Array entrypoints;
    for (const auto& entrypoint : plan.recipe.entrypoints) {
        entrypoints.push_back(Value(Value::Object{
            {"entrypoint_id", Value(entrypoint.entrypoint_id)},
            {"kind", Value(entrypoint.kind)},
            {"relative_path", Value(entrypoint.relative_path)}}));
    }
    return Value(Value::Object{
        {"audit_root", Value(fs::absolute(plan.roots.audit_root).lexically_normal().generic_string())},
        {"component_selection", Value(std::move(components))},
        {"created_at", Value(plan.created_at)},
        {"entrypoints", Value(std::move(entrypoints))},
        {"files", Value(std::move(files))},
        {"install_id", Value(plan.install_id)},
        {"operation", Value("install_local")},
        {"plan_id", Value(plan.plan_id)},
        {"policy_digest", Value(plan.recipe.policy_digest)},
        {"product_id", Value(plan.recipe.product_id)},
        {"product_version", Value(plan.recipe.product_version)},
        {"provider_revision", Value(plan.recipe.provider_revision)},
        {"recipe_digest", Value(plan.recipe.recipe_digest)},
        {"source_archive_digest", Value(plan.recipe.source_archive_digest)},
        {"staging_parent", Value(fs::absolute(plan.roots.staging_parent).lexically_normal().generic_string())},
        {"state_root", Value(fs::absolute(plan.roots.state_root).lexically_normal().generic_string())},
        {"target_root", Value(fs::absolute(plan.target_root).lexically_normal().generic_string())}});
}

void validate_plan(const usk::lifecycle::InstallPlan& plan)
{
    if (!usk::record_io::valid_identifier(plan.plan_id) ||
        !usk::record_io::valid_identifier(plan.install_id) || !valid_timestamp(plan.created_at) ||
        !sha256(plan.plan_digest)) throw std::runtime_error("install plan identity is invalid");
    validate_recipe(plan.recipe);
    std::vector<usk::lifecycle::PayloadFile> files = plan.files;
    normalize_files(files);
    if (files.size() != plan.files.size()) throw std::runtime_error("install plan payload changed");
    for (std::size_t index = 0; index < files.size(); ++index) {
        if (files[index].relative_path != plan.files[index].relative_path || files[index].bytes != plan.files[index].bytes) {
            throw std::runtime_error("install plan payload is not deterministic");
        }
    }
    std::set<std::string> owned;
    for (const auto& file : plan.files) owned.insert(file.relative_path);
    for (const auto& entrypoint : plan.recipe.entrypoints) {
        if (owned.count(entrypoint.relative_path) == 0) {
            throw std::runtime_error("install plan entrypoint is not an owned payload file");
        }
    }
    if (usk::json::sha256_canonical(plan_payload(plan)) != plan.plan_digest) {
        throw std::runtime_error("install plan digest does not bind its current inputs");
    }
}

std::string installed_digest(const usk::state::InstalledState& state)
{
    Value::Array components;
    for (const std::string& component : state.component_selection) components.push_back(Value(component));
    Value::Array entrypoints;
    for (const auto& entrypoint : state.entrypoints) {
        entrypoints.push_back(Value(Value::Object{{"entrypoint_id", Value(entrypoint.entrypoint_id)},
            {"kind", Value(entrypoint.kind)}, {"relative_path", Value(entrypoint.relative_path)}}));
    }
    return usk::json::sha256_canonical(Value(Value::Object{
        {"audit_chain_id", Value(state.audit_chain_id)}, {"component_selection", Value(std::move(components))},
        {"created_at", Value(state.created_at)}, {"entrypoints", Value(std::move(entrypoints))},
        {"install_id", Value(state.install_id)}, {"lifecycle_status", Value(state.lifecycle_status)},
        {"ownership_manifest_digest", Value(state.ownership_manifest_digest)},
        {"ownership_manifest_ref", Value(state.ownership_manifest_ref)}, {"product_id", Value(state.product_id)},
        {"product_version", Value(state.product_version)}, {"recipe_digest", Value(state.recipe_digest)},
        {"setup_abi", Value(Value::Object{{"major", Value(state.setup_abi_major)},
            {"minor", Value(state.setup_abi_minor)}, {"provider_revision", Value(state.provider_revision)}})},
        {"source_archive_digest", Value(state.source_archive_digest)}, {"target_root", Value(state.target_root)},
        {"target_scope", Value("portable")},
        {"transaction_id", Value(state.transaction_id)}}));
}

Value verification_payload(const usk::lifecycle::VerificationReport& report)
{
    Value::Array files;
    for (const auto& file : report.files) {
        Value::Object value{{"expected_sha256", Value(file.expected_sha256)},
            {"relative_path", Value(file.relative_path)}, {"status", Value(file.status)}};
        if (!file.actual_sha256.empty()) value.emplace("actual_sha256", Value(file.actual_sha256));
        files.push_back(Value(std::move(value)));
    }
    Value::Array directories;
    for (const auto& directory : report.directories) {
        directories.push_back(Value(Value::Object{{"relative_path", Value(directory.relative_path)},
                                                  {"status", Value(directory.status)}}));
    }
    Value::Array unknown;
    for (const std::string& path : report.unknown_paths) unknown.push_back(Value(path));
    return Value(Value::Object{
        {"directories", Value(std::move(directories))}, {"files", Value(std::move(files))},
        {"install_id", Value(report.install_id)}, {"installed_state_digest", Value(report.installed_state_digest)},
        {"ownership_manifest_digest", Value(report.ownership_manifest_digest)},
        {"report_id", Value(report.report_id)}, {"status", Value(report.status)},
        {"summary", Value(Value::Object{{"missing_files", Value(report.missing_files)},
            {"modified_files", Value(report.modified_files)},
            {"unknown_paths", Value(static_cast<std::uint64_t>(report.unknown_paths.size()))},
            {"owned_files", Value(static_cast<std::uint64_t>(report.files.size()))}})},
        {"unknown_paths", Value(std::move(unknown))}, {"verified_at", Value(report.verified_at)}});
}

usk::lifecycle::VerificationReport verify_manifest(
    const usk::state::InstalledState& state,
    const usk::state::OwnershipManifest& ownership,
    const std::string& report_id,
    const std::string& verified_at)
{
    usk::lifecycle::VerificationReport report;
    report.report_id = report_id;
    report.install_id = state.install_id;
    report.installed_state_digest = installed_digest(state);
    report.ownership_manifest_digest = ownership.manifest_digest;
    report.verified_at = verified_at;
    const fs::path root(state.target_root);
    std::set<std::string> expected;
    for (const auto& file : ownership.files) {
        expected.insert(file.relative_path);
        usk::lifecycle::FileVerification item{file.relative_path, {}, file.sha256, {}};
        const fs::path path = root / fs::path(file.relative_path);
        std::error_code error;
        if (!fs::exists(path, error)) {
            item.status = "missing";
            ++report.missing_files;
        } else if (!fs::is_regular_file(path, error) || fs::is_symlink(fs::symlink_status(path, error))) {
            item.status = "wrong_type";
            ++report.modified_files;
        } else {
            try {
                usk::base::StableFile actual(path);
                item.actual_sha256 = actual.sha256_hex();
                actual.verify_unchanged();
                if (actual.identity().size_bytes == file.size_bytes && item.actual_sha256 == file.sha256) {
                    item.status = "present";
                } else {
                    item.status = "modified";
                    ++report.modified_files;
                }
            } catch (const std::exception&) {
                item.status = "unreadable";
                ++report.modified_files;
            }
        }
        report.files.push_back(std::move(item));
    }
    for (const std::string& directory : ownership.directories) {
        expected.insert(directory);
        std::error_code error;
        const fs::path path = root / fs::path(directory);
        std::string status;
        if (!fs::exists(path, error)) status = "missing";
        else if (!fs::is_directory(path, error) || fs::is_symlink(fs::symlink_status(path, error))) status = "wrong_type";
        else status = "present";
        report.directories.push_back({directory, status});
    }
    if (!fs::is_directory(root) || fs::is_symlink(fs::symlink_status(root))) {
        report.status = "fail";
    } else {
        for (const fs::directory_entry& entry : fs::recursive_directory_iterator(
                 root, fs::directory_options::skip_permission_denied)) {
            const std::string relative = entry.path().lexically_relative(root).generic_string();
            if (expected.count(relative) == 0) report.unknown_paths.push_back(relative);
        }
        std::sort(report.unknown_paths.begin(), report.unknown_paths.end());
        report.unknown_paths.erase(std::unique(report.unknown_paths.begin(), report.unknown_paths.end()),
                                   report.unknown_paths.end());
        report.status = (report.missing_files != 0 || report.modified_files != 0) ? "fail" :
            (report.unknown_paths.empty() ? "pass" : "warn");
    }
    report.report_digest = usk::json::sha256_canonical(verification_payload(report));
    return report;
}

std::string ownership_id_from_ref(const std::string& reference)
{
    if (reference.rfind("ownership/", 0) != 0 || reference.size() <= 15 ||
        reference.substr(reference.size() - 5) != ".json") {
        throw std::runtime_error("installed-state ownership reference is malformed");
    }
    return reference.substr(10, reference.size() - 15);
}

std::pair<usk::state::InstalledState, usk::state::OwnershipManifest> load_current(
    const usk::lifecycle::LifecycleRoots& roots,
    const std::string& install_id)
{
    usk::state::StateRepository repository(roots.state_root);
    usk::state::InstalledState state = repository.read_installed(install_id);
    usk::state::OwnershipManifest ownership = repository.read_ownership(
        ownership_id_from_ref(state.ownership_manifest_ref));
    return {std::move(state), std::move(ownership)};
}

Value payload_files_value(const std::vector<usk::lifecycle::PayloadFile>& files)
{
    Value::Array result;
    for (const auto& file : files) {
        result.push_back(Value(Value::Object{{"relative_path", Value(file.relative_path)},
            {"sha256", Value(hash_bytes(file.bytes))},
            {"size_bytes", Value(static_cast<std::uint64_t>(file.bytes.size()))}}));
    }
    return Value(std::move(result));
}

Value verification_binding(const usk::lifecycle::VerificationReport& report)
{
    Value::Array files;
    for (const auto& file : report.files) {
        files.push_back(Value(Value::Object{{"actual_sha256", Value(file.actual_sha256)},
            {"expected_sha256", Value(file.expected_sha256)},
            {"relative_path", Value(file.relative_path)}, {"status", Value(file.status)}}));
    }
    Value::Array unknown;
    for (const std::string& path : report.unknown_paths) unknown.push_back(Value(path));
    return Value(Value::Object{{"files", Value(std::move(files))},
        {"status", Value(report.status)}, {"unknown_paths", Value(std::move(unknown))}});
}

Value repair_plan_payload(const usk::lifecycle::RepairPlan& plan)
{
    return Value(Value::Object{{"created_at", Value(plan.created_at)},
        {"audit_root", Value(fs::absolute(plan.roots.audit_root).lexically_normal().generic_string())},
        {"install_id", Value(plan.install_id)}, {"installed_state_digest", Value(plan.installed_state_digest)},
        {"operation", Value("repair")}, {"ownership_manifest_digest", Value(plan.ownership_manifest_digest)},
        {"plan_id", Value(plan.plan_id)}, {"replacement_files", payload_files_value(plan.replacement_files)},
        {"staging_parent", Value(fs::absolute(plan.roots.staging_parent).lexically_normal().generic_string())},
        {"state_root", Value(fs::absolute(plan.roots.state_root).lexically_normal().generic_string())}});
}

Value move_plan_payload(const usk::lifecycle::MovePlan& plan)
{
    return Value(Value::Object{{"audit_root", Value(fs::absolute(plan.roots.audit_root).lexically_normal().generic_string())},
        {"complete_files", payload_files_value(plan.complete_files)},
        {"created_at", Value(plan.created_at)}, {"install_id", Value(plan.install_id)},
        {"installed_state_digest", Value(plan.installed_state_digest)}, {"old_root", Value(plan.old_root.generic_string())},
        {"operation", Value("move")}, {"ownership_manifest_digest", Value(plan.ownership_manifest_digest)},
        {"plan_id", Value(plan.plan_id)}, {"new_root", Value(plan.new_root.generic_string())},
        {"staging_parent", Value(plan.staging_parent.generic_string())},
        {"state_root", Value(fs::absolute(plan.roots.state_root).lexically_normal().generic_string())}});
}

Value uninstall_plan_payload(const usk::lifecycle::UninstallPlan& plan)
{
    return Value(Value::Object{{"created_at", Value(plan.created_at)},
        {"audit_root", Value(fs::absolute(plan.roots.audit_root).lexically_normal().generic_string())},
        {"install_id", Value(plan.install_id)}, {"installed_state_digest", Value(plan.installed_state_digest)},
        {"operation", Value("uninstall")}, {"ownership_manifest_digest", Value(plan.ownership_manifest_digest)},
        {"plan_id", Value(plan.plan_id)}, {"state_root", Value(fs::absolute(plan.roots.state_root).lexically_normal().generic_string())},
        {"staging_parent", Value(fs::absolute(plan.roots.staging_parent).lexically_normal().generic_string())},
        {"verification", verification_binding(plan.verification)}});
}

std::vector<usk::lifecycle::PayloadFile> read_complete_tree(const fs::path& root)
{
    if (!fs::is_directory(root) || fs::is_symlink(fs::symlink_status(root))) {
        throw std::runtime_error("managed installation root is unavailable or linked");
    }
    std::vector<usk::lifecycle::PayloadFile> result;
    std::uint64_t total = 0;
    for (const fs::directory_entry& entry : fs::recursive_directory_iterator(root)) {
        if (entry.is_symlink()) throw std::runtime_error("managed installation contains a linked path");
        if (entry.is_directory()) continue;
        if (!entry.is_regular_file()) throw std::runtime_error("managed installation contains an unsupported file type");
        if (result.size() >= 100000) throw std::runtime_error("managed installation exceeds file-count budget");
        usk::base::StableFile file(entry.path());
        if (file.identity().size_bytes > (1ull << 32) || total > (1ull << 34) - file.identity().size_bytes) {
            throw std::runtime_error("managed installation exceeds fixture lifecycle byte budget");
        }
        total += file.identity().size_bytes;
        auto bytes = file.read(0, static_cast<std::size_t>(file.identity().size_bytes));
        file.verify_unchanged();
        result.push_back({entry.path().lexically_relative(root).generic_string(), std::move(bytes)});
    }
    normalize_files(result);
    return result;
}

void ensure_same_payload(
    const std::vector<usk::lifecycle::PayloadFile>& expected,
    const std::vector<usk::lifecycle::PayloadFile>& actual,
    const char* message)
{
    if (expected.size() != actual.size()) throw std::runtime_error(message);
    for (std::size_t index = 0; index < expected.size(); ++index) {
        if (expected[index].relative_path != actual[index].relative_path ||
            expected[index].bytes != actual[index].bytes) throw std::runtime_error(message);
    }
}

void remove_empty_owned_tree(const fs::path& root)
{
    if (!fs::exists(root)) return;
    usk::record_io::require_safe_directory(root);
    std::vector<fs::path> directories;
    for (const fs::directory_entry& entry : fs::recursive_directory_iterator(root)) {
        if (!entry.is_directory() || entry.is_symlink()) {
            throw std::runtime_error("setup-owned operation root contains unexpected content");
        }
        directories.push_back(entry.path());
    }
    std::sort(directories.begin(), directories.end(), [](const fs::path& left, const fs::path& right) {
        return left.native().size() > right.native().size();
    });
    for (const fs::path& directory : directories) {
        std::error_code error;
        if (!fs::remove(directory, error) || error) throw std::runtime_error("cannot remove empty setup-owned directory");
    }
    std::error_code error;
    if (!fs::remove(root, error) || error) throw std::runtime_error("cannot remove empty setup-owned operation root");
}

void remove_exact_file(const fs::path& path)
{
    std::error_code error;
    if (!fs::remove(path, error) || error) throw std::runtime_error("cannot remove exact lifecycle-owned file");
}

usk::state::InstalledState revised_state(
    const usk::state::InstalledState& prior,
    const usk::state::OwnershipManifest& ownership,
    const std::string& transaction_id,
    const std::string& created_at,
    const std::string& lifecycle_status,
    const usk::lifecycle::VerificationReport& verification)
{
    usk::state::InstalledState result = prior;
    result.target_root = ownership.target_root;
    result.ownership_manifest_ref = "ownership/" + ownership.manifest_id + ".json";
    result.ownership_manifest_digest = ownership.manifest_digest;
    result.transaction_id = transaction_id;
    result.created_at = created_at;
    result.lifecycle_status = lifecycle_status;
    result.last_verification = {
        verification.report_id, verification.report_digest, verification.status, verification.verified_at};
    return result;
}

} // namespace

namespace usk::lifecycle {

InstallPlan plan_install(
    std::string plan_id,
    std::string install_id,
    std::string created_at,
    fs::path target_root,
    LifecycleRoots roots,
    RecipeBinding recipe,
    std::vector<PayloadFile> files)
{
    InstallPlan plan;
    plan.plan_id = std::move(plan_id);
    plan.install_id = std::move(install_id);
    plan.created_at = std::move(created_at);
    plan.target_root = fs::absolute(std::move(target_root)).lexically_normal();
    plan.roots = std::move(roots);
    plan.roots.staging_parent = fs::absolute(plan.roots.staging_parent).lexically_normal();
    plan.roots.state_root = fs::absolute(plan.roots.state_root).lexically_normal();
    plan.roots.audit_root = fs::absolute(plan.roots.audit_root).lexically_normal();
    plan.recipe = std::move(recipe);
    plan.files = std::move(files);
    validate_recipe(plan.recipe);
    normalize_files(plan.files);
    plan.plan_digest = json::sha256_canonical(plan_payload(plan));
    validate_plan(plan);
    return plan;
}

InstallResult apply_install(
    const InstallPlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at)
{
    validate_plan(plan);
    if (reviewed_plan_digest != plan.plan_digest || !record_io::valid_identifier(transaction_id) ||
        !valid_timestamp(applied_at)) throw std::runtime_error("reviewed install plan or transaction identity is invalid");
    if (fs::exists(plan.target_root)) throw std::runtime_error("install target now exists; reviewed plan is invalid");
    record_io::require_safe_directory(plan.roots.staging_parent);
    record_io::require_safe_directory(plan.target_root.parent_path());
    state::StateRepository state_repository(plan.roots.state_root);
    audit::AuditRepository audit_repository(plan.roots.audit_root);
    const std::string chain_id = "audit." + plan.install_id;
    audit_repository.initialize_chain(chain_id);
    audit_repository.append(chain_id, audit::AuditInput{
        applied_at, "install_local", "validated", "pass", "plan", plan.plan_id,
        plan.plan_digest, transaction_id, plan.plan_id, "reviewed plan revalidated"});

    transaction::TransactionSession transaction(transaction::TransactionSpec{
        transaction_id, plan.plan_id, plan.plan_digest, "install_local",
        plan.roots.staging_parent, plan.target_root, plan.roots.state_root, plan.roots.audit_root});
    try {
        for (const PayloadFile& file : plan.files) transaction.stage_file(file.relative_path, file.bytes);
        transaction.mark_staged();
        transaction.mark_verified();
        transaction.commit_effect();

        state::OwnershipManifest ownership;
        ownership.manifest_id = "ownership." + plan.install_id + "." + transaction_id;
        ownership.install_id = plan.install_id;
        ownership.target_root = plan.target_root.string();
        ownership.created_by_transaction_id = transaction_id;
        ownership.directories = directory_closure(plan.files);
        for (const PayloadFile& file : plan.files) {
            ownership.files.push_back({file.relative_path, hash_bytes(file.bytes),
                                       static_cast<std::uint64_t>(file.bytes.size())});
        }
        ownership = state_repository.write_ownership(std::move(ownership));

        state::InstalledState installed;
        installed.install_id = plan.install_id;
        installed.product_id = plan.recipe.product_id;
        installed.product_version = plan.recipe.product_version;
        installed.recipe_digest = plan.recipe.recipe_digest;
        installed.source_archive_digest = plan.recipe.source_archive_digest;
        installed.target_root = plan.target_root.string();
        installed.component_selection = plan.recipe.components;
        installed.ownership_manifest_ref = "ownership/" + ownership.manifest_id + ".json";
        installed.ownership_manifest_digest = ownership.manifest_digest;
        installed.entrypoints = plan.recipe.entrypoints;
        installed.setup_abi_major = 1;
        installed.setup_abi_minor = 0;
        installed.provider_revision = plan.recipe.provider_revision;
        installed.transaction_id = transaction_id;
        installed.created_at = applied_at;
        installed.audit_chain_id = chain_id;
        installed.lifecycle_status = "installed";
        installed.last_verification = {"verify." + transaction_id,
            std::string(64, '0'), "fail", applied_at};
        VerificationReport verification = verify_manifest(
            installed, ownership, installed.last_verification.report_id, applied_at);
        if (verification.status != "pass") throw std::runtime_error("committed install closure failed verification");
        installed.last_verification = {
            verification.report_id, verification.report_digest, verification.status, applied_at};
        state_repository.write_installed(installed);
        audit_repository.append(chain_id, audit::AuditInput{
            applied_at, "install_local", "completed", "pass", "installation", plan.install_id,
            verification.report_digest, transaction_id, plan.plan_id, "managed portable install completed"});
        transaction.mark_committed();
        transaction.mark_completed();
        return {installed, ownership, verification, transaction.journal_path()};
    } catch (...) {
        if (transaction.current_state() == "committing" || transaction.current_state() == "committed") {
            try { transaction.mark_recovery_required(); } catch (...) {}
        }
        throw;
    }
}

InstallResult recover_install_finalization(
    const InstallPlan& plan,
    const std::string& transaction_id,
    const std::string& recovered_at)
{
    validate_plan(plan);
    if (!record_io::valid_identifier(transaction_id) || !valid_timestamp(recovered_at) ||
        recovered_at <= plan.created_at) {
        throw std::runtime_error("install recovery identity is invalid");
    }
    transaction::TransactionSpec spec{
        transaction_id, plan.plan_id, plan.plan_digest, "install_local",
        plan.roots.staging_parent, plan.target_root, plan.roots.state_root, plan.roots.audit_root};
    std::unique_ptr<transaction::TransactionSession> transaction =
        transaction::TransactionSession::resume_finalization(spec);
    if (transaction->current_state() == "recovery_required") transaction->resume_committing();

    state::StateRepository repository(plan.roots.state_root);
    state::OwnershipManifest expected;
    expected.manifest_id = "ownership." + plan.install_id + "." + transaction_id;
    expected.install_id = plan.install_id;
    expected.target_root = plan.target_root.string();
    expected.created_by_transaction_id = transaction_id;
    expected.directories = directory_closure(plan.files);
    for (const PayloadFile& file : plan.files) {
        expected.files.push_back({file.relative_path, hash_bytes(file.bytes),
                                  static_cast<std::uint64_t>(file.bytes.size())});
    }
    state::OwnershipManifest ownership;
    const fs::path ownership_path = plan.roots.state_root / "ownership" / (expected.manifest_id + ".json");
    if (fs::exists(ownership_path)) {
        ownership = repository.read_ownership(expected.manifest_id);
        if (ownership.install_id != expected.install_id || ownership.target_root != expected.target_root ||
            ownership.created_by_transaction_id != expected.created_by_transaction_id ||
            ownership.files.size() != expected.files.size() || ownership.directories != expected.directories) {
            throw std::runtime_error("existing recovery ownership record conflicts with the reviewed install");
        }
        for (std::size_t index = 0; index < ownership.files.size(); ++index) {
            if (std::tie(ownership.files[index].relative_path, ownership.files[index].sha256,
                         ownership.files[index].size_bytes) !=
                std::tie(expected.files[index].relative_path, expected.files[index].sha256,
                         expected.files[index].size_bytes)) {
                throw std::runtime_error("existing recovery ownership closure conflicts with the reviewed install");
            }
        }
    } else {
        ownership = repository.write_ownership(std::move(expected));
    }

    state::InstalledState installed;
    installed.install_id = plan.install_id;
    installed.product_id = plan.recipe.product_id;
    installed.product_version = plan.recipe.product_version;
    installed.recipe_digest = plan.recipe.recipe_digest;
    installed.source_archive_digest = plan.recipe.source_archive_digest;
    installed.target_root = plan.target_root.string();
    installed.component_selection = plan.recipe.components;
    installed.ownership_manifest_ref = "ownership/" + ownership.manifest_id + ".json";
    installed.ownership_manifest_digest = ownership.manifest_digest;
    installed.entrypoints = plan.recipe.entrypoints;
    installed.setup_abi_major = 1;
    installed.setup_abi_minor = 0;
    installed.provider_revision = plan.recipe.provider_revision;
    installed.transaction_id = transaction_id;
    installed.created_at = recovered_at;
    installed.audit_chain_id = "audit." + plan.install_id;
    installed.lifecycle_status = "installed";
    installed.last_verification = {
        "verify." + transaction_id + ".recovery", std::string(64, '0'), "fail", recovered_at};
    VerificationReport verification = verify_manifest(
        installed, ownership, installed.last_verification.report_id, recovered_at);
    if (verification.status != "pass") {
        transaction->mark_recovery_required();
        throw std::runtime_error("visible install target does not match the reviewed recovery plan");
    }
    installed.last_verification = {
        verification.report_id, verification.report_digest, verification.status, recovered_at};
    const fs::path snapshot_path = plan.roots.state_root / "installed" /
        (plan.install_id + "." + transaction_id + ".json");
    if (fs::exists(snapshot_path)) {
        const state::InstalledState existing = repository.read_installed_snapshot(plan.install_id, transaction_id);
        if (existing.ownership_manifest_digest != installed.ownership_manifest_digest ||
            existing.target_root != installed.target_root || existing.recipe_digest != installed.recipe_digest ||
            existing.source_archive_digest != installed.source_archive_digest) {
            throw std::runtime_error("existing recovery installed-state snapshot conflicts with the reviewed install");
        }
        installed = existing;
    } else {
        repository.write_installed(installed);
    }

    audit::AuditRepository audit_repository(plan.roots.audit_root);
    const auto chain = audit_repository.read_and_validate_chain(installed.audit_chain_id);
    const bool already_audited = std::any_of(chain.begin(), chain.end(), [&](const audit::AuditEvent& event) {
        return event.transaction_id == transaction_id && event.operation == "install_local" &&
            event.phase == "completed";
    });
    if (!already_audited) {
        audit_repository.append(installed.audit_chain_id, audit::AuditInput{
            recovered_at, "recovery", "completed", "pass", "installation", plan.install_id,
            verification.report_digest, transaction_id, plan.plan_id,
            "visible managed install finalization recovered"});
    }
    if (transaction->current_state() == "committing") transaction->mark_committed();
    if (transaction->current_state() == "committed") transaction->mark_completed();
    return {installed, ownership, verification, transaction->journal_path()};
}

VerificationReport verify_installed(
    const LifecycleRoots& roots,
    const std::string& install_id,
    const std::string& report_id,
    const std::string& verified_at)
{
    if (!record_io::valid_identifier(install_id) || !record_io::valid_identifier(report_id) ||
        !valid_timestamp(verified_at)) {
        throw std::runtime_error("verification identity is invalid");
    }
    state::StateRepository repository(roots.state_root);
    const state::InstalledState installed = repository.read_installed(install_id);
    const std::string ownership_id = installed.ownership_manifest_ref.substr(
        10, installed.ownership_manifest_ref.size() - 15);
    const state::OwnershipManifest ownership = repository.read_ownership(ownership_id);
    return verify_manifest(installed, ownership, report_id, verified_at);
}

RepairPlan plan_repair(
    const LifecycleRoots& roots,
    const std::string& install_id,
    std::string plan_id,
    std::string created_at,
    std::vector<PayloadFile> exact_source_files)
{
    if (!record_io::valid_identifier(install_id) || !record_io::valid_identifier(plan_id) ||
        !valid_timestamp(created_at)) {
        throw std::runtime_error("repair plan identity is invalid");
    }
    normalize_files(exact_source_files);
    auto current = load_current(roots, install_id);
    const VerificationReport before = verify_manifest(
        current.first, current.second, "verify." + plan_id + ".before", created_at);
    std::map<std::string, const PayloadFile*> sources;
    for (const PayloadFile& file : exact_source_files) sources.emplace(file.relative_path, &file);
    std::set<std::string> affected;
    for (const FileVerification& file : before.files) {
        const auto source = sources.find(file.relative_path);
        if (source == sources.end() || hash_bytes(source->second->bytes) != file.expected_sha256) {
            throw std::runtime_error("repair source does not reproduce the exact owned closure");
        }
        if (file.status != "present") affected.insert(file.relative_path);
    }
    if (sources.size() != current.second.files.size()) {
        throw std::runtime_error("repair source contains foreign or omitted files");
    }
    if (affected.empty()) throw std::runtime_error("repair plan has no missing or modified owned files");
    RepairPlan plan;
    plan.plan_id = std::move(plan_id);
    plan.created_at = std::move(created_at);
    plan.install_id = install_id;
    plan.installed_state_digest = installed_digest(current.first);
    plan.ownership_manifest_digest = current.second.manifest_digest;
    plan.roots = roots;
    for (const PayloadFile& file : exact_source_files) {
        if (affected.count(file.relative_path) != 0) plan.replacement_files.push_back(file);
    }
    plan.plan_digest = json::sha256_canonical(repair_plan_payload(plan));
    return plan;
}

RepairResult apply_repair(
    const RepairPlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at)
{
    if (reviewed_plan_digest != plan.plan_digest ||
        json::sha256_canonical(repair_plan_payload(plan)) != plan.plan_digest ||
        !record_io::valid_identifier(transaction_id) || !valid_timestamp(applied_at) ||
        plan.replacement_files.empty()) {
        throw std::runtime_error("reviewed repair plan is invalid or changed");
    }
    std::vector<PayloadFile> normalized = plan.replacement_files;
    normalize_files(normalized);
    ensure_same_payload(plan.replacement_files, normalized, "repair payload ordering or identity changed");
    auto current = load_current(plan.roots, plan.install_id);
    if (installed_digest(current.first) != plan.installed_state_digest ||
        current.second.manifest_digest != plan.ownership_manifest_digest) {
        throw std::runtime_error("installed state or ownership changed after repair planning");
    }
    if (applied_at <= current.first.created_at) {
        throw std::runtime_error("repair result timestamp must advance immutable state");
    }
    const VerificationReport before = verify_manifest(
        current.first, current.second, "verify." + transaction_id + ".before", applied_at);
    std::set<std::string> current_affected;
    for (const auto& file : before.files) if (file.status != "present") current_affected.insert(file.relative_path);
    std::set<std::string> planned_affected;
    for (const auto& file : plan.replacement_files) planned_affected.insert(file.relative_path);
    if (current_affected != planned_affected) throw std::runtime_error("repair effects changed after plan review");

    const fs::path install_root(current.first.target_root);
    const fs::path bundle = install_root.parent_path() / (".usk-repair-" + transaction_id);
    transaction::TransactionSession transaction(transaction::TransactionSpec{
        transaction_id, plan.plan_id, plan.plan_digest, "repair", plan.roots.staging_parent,
        bundle, plan.roots.state_root, plan.roots.audit_root});
    std::vector<fs::path> backups;
    try {
        for (const PayloadFile& file : plan.replacement_files) {
            transaction.stage_file(fs::path("payload") / file.relative_path, file.bytes);
        }
        transaction.mark_staged();
        transaction.mark_verified();
        transaction.commit_effect();
        for (const PayloadFile& file : plan.replacement_files) {
            const fs::path destination = install_root / file.relative_path;
            record_io::require_safe_directory(destination.parent_path());
            const fs::path replacement = bundle / "payload" / file.relative_path;
            if (fs::exists(destination)) {
                const fs::path backup = bundle / "backup" / file.relative_path;
                fs::create_directories(backup.parent_path());
                record_io::require_safe_directory(backup.parent_path());
                record_io::rename_no_replace(destination, backup);
                backups.push_back(backup);
                try {
                    record_io::rename_no_replace(replacement, destination);
                } catch (...) {
                    record_io::rename_no_replace(backup, destination);
                    backups.pop_back();
                    throw;
                }
            } else {
                record_io::rename_no_replace(replacement, destination);
            }
        }
        VerificationReport after = verify_manifest(
            current.first, current.second, "verify." + transaction_id + ".after", applied_at);
        if (after.status == "fail") throw std::runtime_error("repair did not restore the owned closure");

        state::StateRepository repository(plan.roots.state_root);
        state::OwnershipManifest ownership = current.second;
        ownership.manifest_id = "ownership." + plan.install_id + "." + transaction_id;
        ownership.created_by_transaction_id = transaction_id;
        ownership.manifest_digest.clear();
        ownership = repository.write_ownership(std::move(ownership));
        state::InstalledState installed = revised_state(
            current.first, ownership, transaction_id, applied_at, "verified", after);
        repository.write_installed(installed);
        audit::AuditRepository(plan.roots.audit_root).append(installed.audit_chain_id, audit::AuditInput{
            applied_at, "repair", "completed", after.status == "pass" ? "pass" : "warn",
            "installation", plan.install_id, after.report_digest, transaction_id, plan.plan_id,
            "owned repair effects verified; unknown content retained"});
        transaction.mark_committed();
        for (const fs::path& backup : backups) remove_exact_file(backup);
        remove_empty_owned_tree(bundle);
        transaction.mark_completed();
        return {before, after, {planned_affected.begin(), planned_affected.end()},
                after.unknown_paths, installed};
    } catch (...) {
        if (transaction.current_state() == "committing" || transaction.current_state() == "committed") {
            try { transaction.mark_recovery_required(); } catch (...) {}
        }
        throw;
    }
}

MovePlan plan_move(
    const LifecycleRoots& roots,
    const std::string& install_id,
    std::string plan_id,
    std::string created_at,
    fs::path new_root)
{
    if (!record_io::valid_identifier(install_id) || !record_io::valid_identifier(plan_id) ||
        !valid_timestamp(created_at)) {
        throw std::runtime_error("move plan identity is invalid");
    }
    auto current = load_current(roots, install_id);
    const VerificationReport before = verify_manifest(
        current.first, current.second, "verify." + plan_id + ".before", created_at);
    if (before.status == "fail") throw std::runtime_error("move refuses a damaged owned closure; repair first");
    MovePlan plan;
    plan.plan_id = std::move(plan_id);
    plan.created_at = std::move(created_at);
    plan.install_id = install_id;
    plan.installed_state_digest = installed_digest(current.first);
    plan.ownership_manifest_digest = current.second.manifest_digest;
    plan.old_root = fs::absolute(current.first.target_root).lexically_normal();
    plan.new_root = fs::absolute(std::move(new_root)).lexically_normal();
    plan.staging_parent = plan.new_root.parent_path();
    plan.roots = roots;
    record_io::require_safe_directory(plan.staging_parent);
    if (plan.old_root == plan.new_root || fs::exists(plan.new_root)) {
        throw std::runtime_error("move destination is identical or already exists");
    }
    plan.complete_files = read_complete_tree(plan.old_root);
    plan.plan_digest = json::sha256_canonical(move_plan_payload(plan));
    return plan;
}

MoveResult apply_move(
    const MovePlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at)
{
    if (reviewed_plan_digest != plan.plan_digest ||
        json::sha256_canonical(move_plan_payload(plan)) != plan.plan_digest ||
        !record_io::valid_identifier(transaction_id) || !valid_timestamp(applied_at) ||
        fs::exists(plan.new_root) ||
        plan.staging_parent != plan.new_root.parent_path()) {
        throw std::runtime_error("reviewed move plan is invalid, changed, or clobbering");
    }
    auto current = load_current(plan.roots, plan.install_id);
    if (installed_digest(current.first) != plan.installed_state_digest ||
        current.second.manifest_digest != plan.ownership_manifest_digest ||
        fs::absolute(current.first.target_root).lexically_normal() != plan.old_root) {
        throw std::runtime_error("installed state or ownership changed after move planning");
    }
    if (applied_at <= current.first.created_at) {
        throw std::runtime_error("move result timestamp must advance immutable state");
    }
    ensure_same_payload(plan.complete_files, read_complete_tree(plan.old_root),
                        "move source closure changed after plan review");
    transaction::TransactionSession transaction(transaction::TransactionSpec{
        transaction_id, plan.plan_id, plan.plan_digest, "move", plan.staging_parent,
        plan.new_root, plan.roots.state_root, plan.roots.audit_root});
    try {
        for (const PayloadFile& file : plan.complete_files) transaction.stage_file(file.relative_path, file.bytes);
        transaction.mark_staged();
        transaction.mark_verified();
        transaction.commit_effect();

        state::StateRepository repository(plan.roots.state_root);
        state::OwnershipManifest ownership = current.second;
        ownership.manifest_id = "ownership." + plan.install_id + "." + transaction_id;
        ownership.target_root = plan.new_root.string();
        ownership.created_by_transaction_id = transaction_id;
        ownership.manifest_digest.clear();
        ownership = repository.write_ownership(std::move(ownership));
        state::InstalledState provisional = current.first;
        provisional.target_root = plan.new_root.string();
        provisional.transaction_id = transaction_id;
        provisional.created_at = applied_at;
        provisional.ownership_manifest_ref = "ownership/" + ownership.manifest_id + ".json";
        provisional.ownership_manifest_digest = ownership.manifest_digest;
        provisional.lifecycle_status = "move_pending_acceptance";
        VerificationReport verification = verify_manifest(
            provisional, ownership, "verify." + transaction_id + ".new", applied_at);
        if (verification.status == "fail") throw std::runtime_error("move destination closure failed verification");
        state::InstalledState installed = revised_state(
            current.first, ownership, transaction_id, applied_at, "move_pending_acceptance", verification);
        repository.write_installed(installed);
        audit::AuditRepository(plan.roots.audit_root).append(installed.audit_chain_id, audit::AuditInput{
            applied_at, "move", "completed", verification.status == "pass" ? "pass" : "warn",
            "installation", plan.install_id, verification.report_digest, transaction_id, plan.plan_id,
            "new root verified; old root retained pending acceptance"});
        transaction.mark_committed();
        transaction.mark_completed();
        return {verification, installed, plan.old_root};
    } catch (...) {
        if (transaction.current_state() == "committing" || transaction.current_state() == "committed") {
            try { transaction.mark_recovery_required(); } catch (...) {}
        }
        throw;
    }
}

UninstallPlan plan_uninstall(
    const LifecycleRoots& roots,
    const std::string& install_id,
    std::string plan_id,
    std::string created_at)
{
    if (!record_io::valid_identifier(install_id) || !record_io::valid_identifier(plan_id) ||
        !valid_timestamp(created_at)) {
        throw std::runtime_error("uninstall plan identity is invalid");
    }
    auto current = load_current(roots, install_id);
    UninstallPlan plan;
    plan.plan_id = std::move(plan_id);
    plan.created_at = std::move(created_at);
    plan.install_id = install_id;
    plan.installed_state_digest = installed_digest(current.first);
    plan.ownership_manifest_digest = current.second.manifest_digest;
    plan.roots = roots;
    plan.verification = verify_manifest(
        current.first, current.second, "verify." + plan.plan_id + ".before", plan.created_at);
    plan.plan_digest = json::sha256_canonical(uninstall_plan_payload(plan));
    return plan;
}

UninstallResult apply_uninstall(
    const UninstallPlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at)
{
    if (reviewed_plan_digest != plan.plan_digest ||
        json::sha256_canonical(uninstall_plan_payload(plan)) != plan.plan_digest ||
        !record_io::valid_identifier(transaction_id) || !valid_timestamp(applied_at)) {
        throw std::runtime_error("reviewed uninstall plan is invalid or changed");
    }
    auto current = load_current(plan.roots, plan.install_id);
    if (installed_digest(current.first) != plan.installed_state_digest ||
        current.second.manifest_digest != plan.ownership_manifest_digest) {
        throw std::runtime_error("installed state or ownership changed after uninstall planning");
    }
    if (applied_at <= current.first.created_at) {
        throw std::runtime_error("uninstall result timestamp must advance immutable state");
    }
    const VerificationReport observed = verify_manifest(
        current.first, current.second, plan.verification.report_id, plan.created_at);
    if (json::canonical(verification_binding(observed)) !=
        json::canonical(verification_binding(plan.verification))) {
        throw std::runtime_error("installation closure changed after uninstall planning");
    }
    const fs::path install_root(current.first.target_root);
    const fs::path marker = install_root.parent_path() / (".usk-uninstall-" + transaction_id);
    transaction::TransactionSession transaction(transaction::TransactionSpec{
        transaction_id, plan.plan_id, plan.plan_digest, "uninstall", plan.roots.staging_parent,
        marker, plan.roots.state_root, plan.roots.audit_root});
    UninstallResult result;
    result.retained_unknown_paths = plan.verification.unknown_paths;
    try {
        transaction.stage_file("operation.marker", {'u', 'n', 'i', 'n', 's', 't', 'a', 'l', 'l'});
        transaction.mark_staged();
        transaction.mark_verified();
        transaction.commit_effect();
        for (const auto& file : current.second.files) {
            const fs::path path = install_root / file.relative_path;
            if (!fs::exists(path)) continue;
            bool exact = false;
            try {
                usk::base::StableFile actual(path);
                exact = actual.identity().size_bytes == file.size_bytes && actual.sha256_hex() == file.sha256;
                actual.verify_unchanged();
            } catch (const std::exception&) {
                exact = false;
            }
            if (!exact) {
                result.retained_changed_owned_files.push_back(file.relative_path);
                continue;
            }
            remove_exact_file(path);
            result.deleted_owned_files.push_back(file.relative_path);
        }
        std::vector<std::string> directories = current.second.directories;
        std::sort(directories.begin(), directories.end(), [](const std::string& left, const std::string& right) {
            return left.size() > right.size();
        });
        for (const std::string& relative : directories) {
            const fs::path path = install_root / relative;
            if (!fs::exists(path)) continue;
            std::error_code error;
            if (!fs::remove(path, error) || error) result.retained_directories.push_back(relative);
        }
        std::error_code root_error;
        result.target_removed = fs::remove(install_root, root_error) && !root_error;

        VerificationReport final_verification = plan.verification;
        final_verification.report_id = "verify." + transaction_id + ".uninstall";
        final_verification.verified_at = applied_at;
        final_verification.status = result.target_removed ? "pass" : "warn";
        final_verification.report_digest = json::sha256_canonical(verification_payload(final_verification));
        state::InstalledState installed = current.first;
        installed.transaction_id = transaction_id;
        installed.created_at = applied_at;
        installed.lifecycle_status = result.target_removed ? "retired" : "uninstall_blocked";
        installed.last_verification = {final_verification.report_id, final_verification.report_digest,
                                       final_verification.status, applied_at};
        state::StateRepository(plan.roots.state_root).write_installed(installed);
        audit::AuditRepository(plan.roots.audit_root).append(installed.audit_chain_id, audit::AuditInput{
            applied_at, "uninstall", "completed", result.target_removed ? "pass" : "warn",
            "installation", plan.install_id, final_verification.report_digest, transaction_id, plan.plan_id,
            "only exact recorded owned state removed; changed and unknown content retained"});
        transaction.mark_committed();
        remove_exact_file(marker / "operation.marker");
        remove_empty_owned_tree(marker);
        transaction.mark_completed();
        result.installed_state = std::move(installed);
        return result;
    } catch (...) {
        if (transaction.current_state() == "committing" || transaction.current_state() == "committed") {
            try { transaction.mark_recovery_required(); } catch (...) {}
        }
        throw;
    }
}

} // namespace usk::lifecycle
