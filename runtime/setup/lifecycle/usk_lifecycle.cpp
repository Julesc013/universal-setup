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
        for (unsigned char ch : segment) if (ch < 0x20u || ch >= 0x7fu) return false;
        start = end == std::string::npos ? value.size() : end + 1;
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
        !usk::record_io::valid_identifier(plan.install_id) || plan.created_at.empty() ||
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
        applied_at.empty()) throw std::runtime_error("reviewed install plan or transaction identity is invalid");
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

VerificationReport verify_installed(
    const LifecycleRoots& roots,
    const std::string& install_id,
    const std::string& report_id,
    const std::string& verified_at)
{
    if (!record_io::valid_identifier(install_id) || !record_io::valid_identifier(report_id) || verified_at.empty()) {
        throw std::runtime_error("verification identity is invalid");
    }
    state::StateRepository repository(roots.state_root);
    const state::InstalledState installed = repository.read_installed(install_id);
    const std::string ownership_id = installed.ownership_manifest_ref.substr(
        10, installed.ownership_manifest_ref.size() - 15);
    const state::OwnershipManifest ownership = repository.read_ownership(ownership_id);
    return verify_manifest(installed, ownership, report_id, verified_at);
}

} // namespace usk::lifecycle
