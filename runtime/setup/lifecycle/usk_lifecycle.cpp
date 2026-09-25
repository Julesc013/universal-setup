// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_lifecycle.h"
#include "usk_install_restart.h"

#include "usk_audit_repository.h"
#include "usk_json.h"
#include "usk_record_io.h"
#include "usk_replacement_session.h"
#include "usk_sha256.h"
#include "usk_stable_file.h"
#include "usk_transaction_session.h"
#include "usk_utf8_path.h"

#include <algorithm>
#include <cctype>
#include <array>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace fs = std::filesystem;
using usk::json::Value;

namespace {

constexpr std::size_t maximum_lifecycle_files = 4096;
constexpr std::size_t maximum_lifecycle_directories = 8192;
constexpr std::size_t maximum_verification_report_entries = 16384;
constexpr std::size_t maximum_verification_report_path_bytes = 4u * 1024u * 1024u;
constexpr std::size_t maximum_relative_path_bytes = 1024;
constexpr std::size_t maximum_total_path_bytes = 1024u * 1024u;
constexpr std::size_t maximum_closure_path_bytes = 2u * maximum_total_path_bytes;
constexpr std::uint64_t maximum_materialized_payload_bytes = 64ull * 1024ull * 1024ull;

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

void bind_payload_identity(usk::lifecycle::PayloadFile& file)
{
    if (file.reader) {
        if (!file.bytes.empty() || !sha256(file.sha256) ||
            file.stream_buffer_bytes !=
                usk::lifecycle::streaming_payload_buffer_bytes) {
            throw std::runtime_error("streaming lifecycle payload identity is invalid");
        }
        return;
    }
    const std::string actual_sha256 = hash_bytes(file.bytes);
    const std::uint64_t actual_size = static_cast<std::uint64_t>(file.bytes.size());
    if ((!file.sha256.empty() && file.sha256 != actual_sha256) ||
        (file.size_bytes != 0u && file.size_bytes != actual_size)) {
        throw std::runtime_error("materialized lifecycle payload identity is invalid");
    }
    file.sha256 = actual_sha256;
    file.size_bytes = actual_size;
}

void stage_payload_file(
    usk::transaction::TransactionSession& transaction,
    const std::filesystem::path& relative_path,
    const usk::lifecycle::PayloadFile& file,
    const usk::lifecycle::LifecycleCancellation& cancellation,
    const std::string& source_identity_digest = {})
{
    if (!file.reader) {
        transaction.stage_file(relative_path, file.bytes);
        return;
    }
    std::uint64_t offset = 0;
    const auto staged = transaction.stage_file_stream(
        relative_path,
        file.size_bytes,
        file.sha256,
        file.stream_buffer_bytes,
        [&](unsigned char* output, std::size_t capacity) -> std::size_t {
            if (cancellation && cancellation()) {
                throw std::runtime_error("lifecycle streaming operation was cancelled");
            }
            const std::size_t count = file.reader(offset, output, capacity);
            if (count > capacity ||
                count > file.size_bytes - std::min(offset, file.size_bytes)) {
                throw std::runtime_error("lifecycle payload reader exceeded its reviewed size");
            }
            offset += count;
            if (cancellation && cancellation()) {
                throw std::runtime_error("lifecycle streaming operation was cancelled");
            }
            return count;
        }, source_identity_digest);
    if (cancellation && cancellation()) {
        throw std::runtime_error("lifecycle streaming operation was cancelled");
    }
    if (staged.sha256 != file.sha256 || staged.size_bytes != file.size_bytes) {
        throw std::runtime_error("streamed lifecycle payload changed during staging");
    }
}

bool same_resource_observation(
    const usk::base::StableFileIdentity& identity,
    const usk::lifecycle::PreimageResourceObservation& observation)
{
    return identity.volume_id == observation.volume_id && identity.file_id == observation.file_id &&
        identity.modified_time_ns == observation.modified_time_ns &&
        identity.link_count == observation.link_count;
}

void stage_preimage_file(
    usk::transaction::TransactionSession& transaction,
    const fs::path& root,
    const std::string& root_identity,
    const usk::lifecycle::PreimageFile& preimage)
{
    if (usk::transaction::observe_directory_identity(root) != root_identity) {
        throw std::runtime_error("move source root identity changed during staging");
    }
    usk::record_io::require_safe_directory((root / preimage.relative_path).parent_path());
    auto source = std::make_shared<usk::base::StableFile>(root / preimage.relative_path);
    if (source->identity().size_bytes != preimage.size_bytes ||
        !same_resource_observation(source->identity(), preimage.resource)) {
        throw std::runtime_error("move source resource changed after plan review");
    }
    std::uint64_t offset = 0;
    const auto staged = transaction.stage_file_stream(preimage.relative_path, preimage.size_bytes,
        preimage.sha256, usk::lifecycle::streaming_payload_buffer_bytes,
        [source, &offset](unsigned char* output, std::size_t capacity) -> std::size_t {
            const std::size_t count = static_cast<std::size_t>(std::min<std::uint64_t>(
                capacity, source->identity().size_bytes - offset));
            if (count != 0) source->read_into(offset, output, count);
            offset += count;
            return count;
        });
    if (staged.sha256 != preimage.sha256 || staged.size_bytes != preimage.size_bytes ||
        offset != preimage.size_bytes) {
        throw std::runtime_error("streamed move staging result changed");
    }
    source->verify_unchanged();
    if (usk::transaction::observe_directory_identity(root) != root_identity) {
        throw std::runtime_error("move source root identity changed during staging");
    }
    usk::record_io::require_safe_directory((root / preimage.relative_path).parent_path());
}

void rollback_before_visibility(
    usk::transaction::TransactionSession& transaction) noexcept
{
    if (transaction.current_state() != "staging" &&
        transaction.current_state() != "staged" &&
        transaction.current_state() != "verified") {
        return;
    }
    try {
        transaction.rollback();
    } catch (...) {
        // The transaction records recovery_required before any rollback effect.
        // Preserve the original operation error while retaining durable recovery evidence.
    }
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
    std::size_t path_bytes = 0;
    for (const auto& file : files) {
        fs::path parent = fs::path(file.relative_path).parent_path();
        while (!parent.empty()) {
            const std::string relative = parent.generic_string();
            const bool inserted = result.insert(relative).second;
            if (inserted) {
                if (relative.size() > maximum_relative_path_bytes ||
                    relative.size() > maximum_total_path_bytes - path_bytes) {
                    throw std::runtime_error("lifecycle directory path memory exceeds budget");
                }
                path_bytes += relative.size();
            }
            if (result.size() > maximum_lifecycle_directories) {
                throw std::runtime_error("lifecycle directory closure exceeds budget");
            }
            parent = parent.parent_path();
        }
    }
    return {result.begin(), result.end()};
}

void require_payload_path_capacity(
    const fs::path& root,
    const std::vector<usk::lifecycle::PayloadFile>& files)
{
    usk::base::require_native_path_capacity(root, usk::base::NativePathKind::directory, "payload root");
    for (const auto& file : files) {
        usk::base::require_native_path_capacity(root / file.relative_path,
            usk::base::NativePathKind::file, "payload file");
    }
}

void require_preimage_path_capacity(
    const fs::path& root,
    const std::vector<usk::lifecycle::PreimageFile>& files)
{
    usk::base::require_native_path_capacity(root, usk::base::NativePathKind::directory, "preimage root");
    for (const auto& file : files) {
        usk::base::require_native_path_capacity(root / file.relative_path,
            usk::base::NativePathKind::file, "preimage file");
    }
}

void require_result_record_capacity(
    const usk::lifecycle::LifecycleRoots& roots,
    const std::string& install_id,
    const std::string& transaction_id,
    const std::string& audit_chain_id,
    bool writes_ownership = true)
{
    for (const fs::path& path : {roots.staging_parent, roots.state_root / "installed",
            roots.state_root / "ownership", roots.state_root / "transactions", roots.audit_root / "chains"}) {
        usk::base::require_native_path_capacity(path, usk::base::NativePathKind::directory, "setup record layout");
    }
    usk::audit::require_chain_path_capacity(roots.audit_root, audit_chain_id);
    if (transaction_id.empty()) return;
    if (!usk::record_io::valid_identifier(transaction_id)) {
        throw std::runtime_error("transaction identifier is invalid before path admission");
    }
    usk::base::require_native_path_capacity(roots.state_root / "installed" /
        (install_id + "." + transaction_id + ".json"), usk::base::NativePathKind::file, "installed-state snapshot");
    if (writes_ownership) {
        const std::string manifest_id = "ownership." + install_id + "." + transaction_id;
        if (!usk::record_io::valid_identifier(manifest_id)) {
            throw std::runtime_error("derived ownership identifier is invalid before filesystem effects");
        }
        usk::base::require_native_path_capacity(roots.state_root / "ownership" /
            (manifest_id + ".json"), usk::base::NativePathKind::file, "ownership record");
    }
}

void validate_recipe(const usk::lifecycle::RecipeBinding& recipe)
{
    if (!usk::record_io::valid_identifier(recipe.product_id) || recipe.product_version.empty() ||
        !usk::record_io::valid_identifier(recipe.provider_revision) ||
        !sha256(recipe.recipe_digest) || !sha256(recipe.source_archive_digest) ||
        !sha256(recipe.policy_digest) || recipe.components.empty() || recipe.entrypoints.empty()) {
        throw std::runtime_error("lifecycle recipe binding is invalid");
    }
    if ((!recipe.source_identity_digest.empty() || !recipe.entry_set_digest.empty()) &&
        (!sha256(recipe.source_identity_digest) || !sha256(recipe.entry_set_digest))) {
        throw std::runtime_error("lifecycle archive identity and entry-set binding is incomplete");
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

void validate_normalized_files(const std::vector<usk::lifecycle::PayloadFile>& files)
{
    if (files.empty() || files.size() > maximum_lifecycle_files) {
        throw std::runtime_error("lifecycle payload file count exceeds budget");
    }
    std::uint64_t retained_payload = 0;
    std::size_t path_bytes = 0;
    std::set<std::string> folded;
    std::set<std::string> paths;
    for (std::size_t index = 0; index < files.size(); ++index) {
        const auto& file = files[index];
        if (file.relative_path.size() > maximum_relative_path_bytes ||
            file.relative_path.size() > maximum_total_path_bytes - path_bytes) {
            throw std::runtime_error("lifecycle payload path memory exceeds budget");
        }
        path_bytes += file.relative_path.size();
        if (!safe_relative(file.relative_path) ||
            (index != 0 && files[index - 1].relative_path >= file.relative_path) ||
            !folded.insert(lowercase(file.relative_path)).second) {
            throw std::runtime_error("lifecycle payload path is unsafe, unordered, or case-colliding");
        }
        if (file.reader) {
            if (!file.bytes.empty() || !sha256(file.sha256) ||
                file.stream_buffer_bytes != usk::lifecycle::streaming_payload_buffer_bytes) {
                throw std::runtime_error("streaming lifecycle payload identity is invalid");
            }
        } else {
            if (file.bytes.size() > maximum_materialized_payload_bytes - retained_payload) {
                throw std::runtime_error("materialized lifecycle payload exceeds retained-byte budget");
            }
            retained_payload += file.bytes.size();
            if (file.size_bytes != file.bytes.size() || file.sha256 != hash_bytes(file.bytes)) {
                throw std::runtime_error("materialized lifecycle payload identity changed");
            }
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

void normalize_files(std::vector<usk::lifecycle::PayloadFile>& files)
{
    if (files.empty() || files.size() > maximum_lifecycle_files) {
        throw std::runtime_error("lifecycle payload file count exceeds budget");
    }
    std::uint64_t retained_payload = 0;
    for (auto& file : files) {
        if (!file.reader) {
            if (file.bytes.size() > maximum_materialized_payload_bytes - retained_payload) {
                throw std::runtime_error("materialized lifecycle payload exceeds retained-byte budget");
            }
            retained_payload += file.bytes.size();
        }
        bind_payload_identity(file);
    }
    std::sort(files.begin(), files.end(), [](const auto& left, const auto& right) {
        return left.relative_path < right.relative_path;
    });
    validate_normalized_files(files);
}

Value plan_payload(const usk::lifecycle::InstallPlan& plan)
{
    Value::Array files;
    for (const auto& file : plan.files) {
        files.push_back(Value(Value::Object{
            {"relative_path", Value(file.relative_path)},
            {"sha256", Value(file.sha256)},
            {"size_bytes", Value(file.size_bytes)}}));
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
    Value result(Value::Object{
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
    (void)usk::transaction::commit_authority_name(plan.required_commit_authority);
    if (plan.required_commit_authority == usk::transaction::CommitAuthorityRequirement::staged_child_bound_v1) {
        result.as_object().emplace("required_commit_authority", Value("staged_child_bound_v1"));
    }
    if (!plan.recipe.source_identity_digest.empty()) {
        result.as_object().emplace("source_identity_digest", Value(plan.recipe.source_identity_digest));
        result.as_object().emplace("entry_set_digest", Value(plan.recipe.entry_set_digest));
        result.as_object().emplace("restart_policy_context", Value(plan.recipe.restart_policy_context));
    }
    return result;
}

void validate_plan(const usk::lifecycle::InstallPlan& plan)
{
    if (!usk::record_io::valid_identifier(plan.plan_id) ||
        !usk::record_io::valid_identifier(plan.install_id) || !valid_timestamp(plan.created_at) ||
        !sha256(plan.plan_digest)) throw std::runtime_error("install plan identity is invalid");
    validate_recipe(plan.recipe);
    validate_normalized_files(plan.files);
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
    usk::lifecycle::require_install_path_capacity(plan);
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

std::string verification_digest(const usk::lifecycle::VerificationReport& report);

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
    std::size_t report_entries = 0;
    std::size_t report_path_bytes = 0;
    const auto charge_report_path = [&](const std::string& path) {
        if (report_entries >= maximum_verification_report_entries ||
            path.size() > maximum_verification_report_path_bytes - report_path_bytes) {
            throw std::runtime_error("lifecycle verification report exceeds entry/path budget");
        }
        ++report_entries;
        report_path_bytes += path.size();
    };
    for (const auto& file : ownership.files) {
        charge_report_path(file.relative_path);
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
        charge_report_path(directory);
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
            if (expected.count(relative) == 0) {
                charge_report_path(relative);
                report.unknown_paths.push_back(relative);
            }
        }
        std::sort(report.unknown_paths.begin(), report.unknown_paths.end());
        report.unknown_paths.erase(std::unique(report.unknown_paths.begin(), report.unknown_paths.end()),
                                   report.unknown_paths.end());
        report.status = (report.missing_files != 0 || report.modified_files != 0) ? "fail" :
            (report.unknown_paths.empty() ? "pass" : "warn");
    }
    report.report_digest = verification_digest(report);
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
            {"sha256", Value(file.sha256)},
            {"size_bytes", Value(file.size_bytes)}}));
    }
    return Value(std::move(result));
}

Value preimage_files_value(const std::vector<usk::lifecycle::PreimageFile>& files)
{
    Value::Array result;
    for (const auto& file : files) {
        result.push_back(Value(Value::Object{{"relative_path", Value(file.relative_path)},
            {"resource", Value(Value::Object{{"file_id", Value(file.resource.file_id)},
                {"link_count", Value(static_cast<std::uint64_t>(file.resource.link_count))},
                {"modified_time_ns", Value(file.resource.modified_time_ns)},
                {"volume_id", Value(file.resource.volume_id)}})},
            {"sha256", Value(file.sha256)}, {"size_bytes", Value(file.size_bytes)}}));
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
        {"policy_digest", Value(plan.policy_digest)}, {"source_digest", Value(plan.source_digest)},
        {"plan_id", Value(plan.plan_id)}, {"replacement_files", payload_files_value(plan.replacement_files)},
        {"staging_parent", Value(fs::absolute(plan.roots.staging_parent).lexically_normal().generic_string())},
        {"state_root", Value(fs::absolute(plan.roots.state_root).lexically_normal().generic_string())}});
}

Value move_plan_payload(const usk::lifecycle::MovePlan& plan)
{
    return Value(Value::Object{{"audit_root", Value(fs::absolute(plan.roots.audit_root).lexically_normal().generic_string())},
        {"complete_files", preimage_files_value(plan.complete_files)},
        {"created_at", Value(plan.created_at)}, {"install_id", Value(plan.install_id)},
        {"installed_state_digest", Value(plan.installed_state_digest)}, {"old_root", Value(plan.old_root.generic_string())},
        {"old_root_identity", Value(plan.old_root_identity)},
        {"operation", Value("move")}, {"ownership_manifest_digest", Value(plan.ownership_manifest_digest)},
        {"policy_digest", Value(plan.policy_digest)},
        {"plan_id", Value(plan.plan_id)}, {"new_root", Value(plan.new_root.generic_string())},
        {"staging_parent", Value(plan.staging_parent.generic_string())},
        {"state_root", Value(fs::absolute(plan.roots.state_root).lexically_normal().generic_string())}});
}

std::string payload_snapshot_digest(const std::vector<usk::lifecycle::PayloadFile>& files)
{
    std::set<std::string> directories;
    Value::Array entries;
    for (const auto& file : files) {
        fs::path parent = fs::path(file.relative_path).parent_path();
        while (!parent.empty()) {
            directories.insert(parent.generic_string());
            parent = parent.parent_path();
        }
        entries.emplace_back(Value::Object{{"relative_path", Value(file.relative_path)},
            {"sha256", Value(file.sha256)}, {"size_bytes", Value(file.size_bytes)},
            {"type", Value("file")}});
    }
    for (const auto& directory : directories) {
        entries.emplace_back(Value::Object{{"relative_path", Value(directory)},
            {"type", Value("directory")}});
    }
    std::sort(entries.begin(), entries.end(), [](const Value& left, const Value& right) {
        return left.at("relative_path").as_string() < right.at("relative_path").as_string();
    });
    return usk::json::sha256_canonical(Value(Value::Object{
        {"entries", Value(std::move(entries))}, {"schema", Value("usk.replacement_snapshot.v1")}}));
}

void hash_text(usk::base::Sha256& hash, const std::string& text)
{
    hash.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
}

std::string json_string(const std::string& value)
{
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.push_back('"');
    for (unsigned char ch : value) {
        switch (ch) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (ch < 0x20u) {
                result += "\\u00";
                result.push_back(hex[ch >> 4]);
                result.push_back(hex[ch & 0x0fu]);
            } else {
                result.push_back(static_cast<char>(ch));
            }
        }
    }
    result.push_back('"');
    return result;
}

std::string verification_digest(const usk::lifecycle::VerificationReport& report)
{
    // Keep the v1 canonical member order while hashing each member as it is
    // visited. A second JSON tree and its serialized text needlessly retain
    // the entire entry list alongside the ownership and verification reports.
    usk::base::Sha256 hash;
    const auto quoted = [&](const std::string& value) { hash_text(hash, json_string(value)); };
    hash_text(hash, "{\"directories\":[");
    for (std::size_t index = 0; index < report.directories.size(); ++index) {
        if (index != 0) hash_text(hash, ",");
        const auto& directory = report.directories[index];
        hash_text(hash, "{\"relative_path\":");
        quoted(directory.relative_path);
        hash_text(hash, ",\"status\":");
        quoted(directory.status);
        hash_text(hash, "}");
    }
    hash_text(hash, "],\"files\":[");
    for (std::size_t index = 0; index < report.files.size(); ++index) {
        if (index != 0) hash_text(hash, ",");
        const auto& file = report.files[index];
        if (!file.actual_sha256.empty()) {
            hash_text(hash, "{\"actual_sha256\":");
            quoted(file.actual_sha256);
            hash_text(hash, ",\"expected_sha256\":");
        } else {
            hash_text(hash, "{\"expected_sha256\":");
        }
        quoted(file.expected_sha256);
        hash_text(hash, ",\"relative_path\":");
        quoted(file.relative_path);
        hash_text(hash, ",\"status\":");
        quoted(file.status);
        hash_text(hash, "}");
    }
    hash_text(hash, "],\"install_id\":");
    quoted(report.install_id);
    hash_text(hash, ",\"installed_state_digest\":");
    quoted(report.installed_state_digest);
    hash_text(hash, ",\"ownership_manifest_digest\":");
    quoted(report.ownership_manifest_digest);
    hash_text(hash, ",\"report_id\":");
    quoted(report.report_id);
    hash_text(hash, ",\"status\":");
    quoted(report.status);
    hash_text(hash, ",\"summary\":{\"missing_files\":");
    hash_text(hash, std::to_string(report.missing_files));
    hash_text(hash, ",\"modified_files\":");
    hash_text(hash, std::to_string(report.modified_files));
    hash_text(hash, ",\"owned_files\":");
    hash_text(hash, std::to_string(report.files.size()));
    hash_text(hash, ",\"unknown_paths\":");
    hash_text(hash, std::to_string(report.unknown_paths.size()));
    hash_text(hash, "},\"unknown_paths\":[");
    for (std::size_t index = 0; index < report.unknown_paths.size(); ++index) {
        if (index != 0) hash_text(hash, ",");
        quoted(report.unknown_paths[index]);
    }
    hash_text(hash, "],\"verified_at\":");
    quoted(report.verified_at);
    hash_text(hash, "}");
    return hash.finish();
}

void hash_verification_binding(usk::base::Sha256& hash,
    const usk::lifecycle::VerificationReport& report)
{
    const auto quoted = [&](const std::string& value) { hash_text(hash, json_string(value)); };
    hash_text(hash, "{\"files\":[");
    for (std::size_t index = 0; index < report.files.size(); ++index) {
        if (index != 0) hash_text(hash, ",");
        const auto& file = report.files[index];
        hash_text(hash, "{\"actual_sha256\":");
        quoted(file.actual_sha256);
        hash_text(hash, ",\"expected_sha256\":");
        quoted(file.expected_sha256);
        hash_text(hash, ",\"relative_path\":");
        quoted(file.relative_path);
        hash_text(hash, ",\"status\":");
        quoted(file.status);
        hash_text(hash, "}");
    }
    hash_text(hash, "],\"status\":");
    quoted(report.status);
    hash_text(hash, ",\"unknown_paths\":[");
    for (std::size_t index = 0; index < report.unknown_paths.size(); ++index) {
        if (index != 0) hash_text(hash, ",");
        quoted(report.unknown_paths[index]);
    }
    hash_text(hash, "]}");
}

struct CanonicalPreimageEntry {
    std::string relative_path;
    std::string sha256;
    std::uint64_t size_bytes = 0;
    bool directory = false;
};

constexpr std::uint64_t maximum_preimage_files = maximum_lifecycle_files;
constexpr std::uint64_t maximum_preimage_entries =
    maximum_lifecycle_files + maximum_lifecycle_directories;
constexpr std::uint64_t maximum_preimage_file_bytes = 1ull << 32;
constexpr std::uint64_t maximum_preimage_logical_bytes = 1ull << 34;
constexpr std::uint64_t maximum_canonical_index_bytes = 64ull * 1024ull * 1024ull;

void charge_canonical_index(std::uint64_t& used, const CanonicalPreimageEntry& entry)
{
    constexpr std::uint64_t entry_overhead = 128;
    const std::uint64_t variable = static_cast<std::uint64_t>(entry.relative_path.size()) +
        static_cast<std::uint64_t>(entry.sha256.size());
    if (variable > std::numeric_limits<std::uint64_t>::max() - entry_overhead ||
        used > maximum_canonical_index_bytes - (variable + entry_overhead)) {
        throw std::runtime_error("managed installation exceeds canonical-index memory budget");
    }
    used += variable + entry_overhead;
}

std::string canonical_preimage_snapshot_digest(std::vector<CanonicalPreimageEntry> entries)
{
    std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
        return left.relative_path < right.relative_path;
    });
    usk::base::Sha256 hash;
    hash_text(hash, "{\"entries\":[");
    bool first = true;
    for (const auto& entry : entries) {
        if (!first) hash_text(hash, ",");
        first = false;
        if (entry.directory) {
            hash_text(hash, "{\"relative_path\":" + json_string(entry.relative_path) +
                ",\"type\":\"directory\"}");
        } else {
            hash_text(hash, "{\"relative_path\":" + json_string(entry.relative_path) +
                ",\"sha256\":" + json_string(entry.sha256) + ",\"size_bytes\":" +
                std::to_string(entry.size_bytes) + ",\"type\":\"file\"}");
        }
    }
    hash_text(hash, "],\"schema\":\"usk.replacement_snapshot.v1\"}");
    return hash.finish();
}

Value update_plan_payload(const usk::lifecycle::UpdatePlan& plan)
{
    Value::Array components;
    for (const auto& component : plan.recipe.components) components.emplace_back(component);
    Value::Array entrypoints;
    for (const auto& entrypoint : plan.recipe.entrypoints) {
        entrypoints.emplace_back(Value::Object{{"entrypoint_id", Value(entrypoint.entrypoint_id)},
            {"kind", Value(entrypoint.kind)}, {"relative_path", Value(entrypoint.relative_path)}});
    }
    return Value(Value::Object{
        {"components", Value(std::move(components))},
        {"created_at", Value(plan.created_at)},
        {"entrypoints", Value(std::move(entrypoints))},
        {"entry_set_digest", Value(plan.recipe.entry_set_digest)},
        {"install_id", Value(plan.install_id)},
        {"installed_state_digest", Value(plan.installed_state_digest)},
        {"new_files", payload_files_value(plan.new_complete_files)},
        {"new_product_id", Value(plan.recipe.product_id)},
        {"new_product_version", Value(plan.recipe.product_version)},
        {"new_provider_revision", Value(plan.recipe.provider_revision)},
        {"new_recipe_digest", Value(plan.recipe.recipe_digest)},
        {"new_snapshot_digest", Value(plan.new_snapshot_digest)},
        {"new_source_digest", Value(plan.recipe.source_archive_digest)},
        {"old_files", preimage_files_value(plan.old_complete_files)},
        {"old_root_identity", Value(plan.old_root_identity)},
        {"old_snapshot_digest", Value(plan.old_snapshot_digest)},
        {"operation", Value("update")},
        {"ownership_manifest_digest", Value(plan.ownership_manifest_digest)},
        {"plan_id", Value(plan.plan_id)},
        {"policy_digest", Value(plan.recipe.policy_digest)},
        {"required_commit_authority", Value("staged_child_bound_v1")},
        {"source_identity_digest", Value(plan.recipe.source_identity_digest)},
        {"state_root", Value(fs::absolute(plan.roots.state_root).lexically_normal().generic_string())},
        {"target_root", Value(plan.target_root.generic_string())},
        {"transition", Value(plan.transition)}});
}

std::string uninstall_plan_digest(const usk::lifecycle::UninstallPlan& plan)
{
    usk::base::Sha256 hash;
    const auto quoted = [&](const std::string& value) { hash_text(hash, json_string(value)); };
    const auto path = [&](const fs::path& value) {
        quoted(fs::absolute(value).lexically_normal().generic_string());
    };
    hash_text(hash, "{\"audit_root\":");
    path(plan.roots.audit_root);
    hash_text(hash, ",\"created_at\":");
    quoted(plan.created_at);
    hash_text(hash, ",\"install_id\":");
    quoted(plan.install_id);
    hash_text(hash, ",\"installed_state_digest\":");
    quoted(plan.installed_state_digest);
    hash_text(hash, ",\"operation\":\"uninstall\",\"ownership_manifest_digest\":");
    quoted(plan.ownership_manifest_digest);
    hash_text(hash, ",\"plan_id\":");
    quoted(plan.plan_id);
    hash_text(hash, ",\"policy_digest\":");
    quoted(plan.policy_digest);
    hash_text(hash, ",\"staging_parent\":");
    path(plan.roots.staging_parent);
    hash_text(hash, ",\"state_root\":");
    path(plan.roots.state_root);
    hash_text(hash, ",\"verification\":");
    hash_verification_binding(hash, plan.verification);
    hash_text(hash, "}");
    return hash.finish();
}

std::vector<usk::lifecycle::PreimageFile> read_complete_tree(
    const fs::path& root,
    std::string* snapshot_digest = nullptr,
    usk::lifecycle::LifecycleResourceObservation* observation = nullptr)
{
    if (!fs::is_directory(root) || fs::is_symlink(fs::symlink_status(root))) {
        throw std::runtime_error("managed installation root is unavailable or linked");
    }
    std::vector<usk::lifecycle::PreimageFile> result;
    std::vector<CanonicalPreimageEntry> index;
    std::uint64_t total = 0;
    std::uint64_t index_bytes = 0;
    std::size_t path_bytes = 0;
    std::size_t directories = 0;
    for (const fs::directory_entry& entry : fs::recursive_directory_iterator(root)) {
        if (index.size() >= maximum_preimage_entries) {
            throw std::runtime_error("managed installation exceeds entry-count budget");
        }
        if (entry.is_symlink()) throw std::runtime_error("managed installation contains a linked path");
        const std::string relative = entry.path().lexically_relative(root).generic_string();
        if (!safe_relative(relative)) throw std::runtime_error("managed installation contains an unsafe path");
        if (relative.size() > maximum_relative_path_bytes ||
            relative.size() > maximum_closure_path_bytes - path_bytes) {
            throw std::runtime_error("managed installation exceeds path memory budget");
        }
        path_bytes += relative.size();
        if (entry.is_directory()) {
            if (++directories > maximum_lifecycle_directories) {
                throw std::runtime_error("managed installation exceeds directory-count budget");
            }
            CanonicalPreimageEntry directory{relative, {}, 0, true};
            charge_canonical_index(index_bytes, directory);
            index.push_back(std::move(directory));
            continue;
        }
        if (!entry.is_regular_file()) throw std::runtime_error("managed installation contains an unsupported file type");
        if (result.size() >= maximum_preimage_files) throw std::runtime_error("managed installation exceeds file-count budget");
        usk::base::StableFile file(entry.path());
        if (file.identity().size_bytes > maximum_preimage_file_bytes ||
            total > maximum_preimage_logical_bytes - file.identity().size_bytes) {
            throw std::runtime_error("managed installation exceeds fixture lifecycle byte budget");
        }
        total += file.identity().size_bytes;
        const std::string digest = file.sha256_hex();
        file.verify_unchanged();
        const auto& identity = file.identity();
        usk::lifecycle::PreimageFile preimage{relative, digest, identity.size_bytes,
            {identity.volume_id, identity.file_id, identity.modified_time_ns, identity.link_count}};
        CanonicalPreimageEntry canonical{relative, digest, identity.size_bytes, false};
        charge_canonical_index(index_bytes, canonical);
        index.push_back(std::move(canonical));
        result.push_back(std::move(preimage));
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.relative_path < right.relative_path;
    });
    for (std::size_t index_number = 1; index_number < result.size(); ++index_number) {
        if (result[index_number - 1].relative_path == result[index_number].relative_path) {
            throw std::runtime_error("managed installation contains duplicate file paths");
        }
    }
    if (snapshot_digest != nullptr) *snapshot_digest = canonical_preimage_snapshot_digest(std::move(index));
    if (observation != nullptr) {
        observation->peak_payload_buffer = usk::lifecycle::streaming_payload_buffer_bytes;
        observation->peak_open_source_files = result.empty() ? 0u : 1u;
        observation->retained_payload = 0;
        observation->complete_payload_retained = false;
    }
    return result;
}

void ensure_same_preimage(
    const std::vector<usk::lifecycle::PreimageFile>& expected,
    const std::vector<usk::lifecycle::PreimageFile>& actual,
    const char* message)
{
    if (expected.size() != actual.size()) throw std::runtime_error(message);
    for (std::size_t index = 0; index < expected.size(); ++index) {
        if (expected[index].relative_path != actual[index].relative_path ||
            expected[index].sha256 != actual[index].sha256 ||
            expected[index].size_bytes != actual[index].size_bytes ||
            expected[index].resource.volume_id != actual[index].resource.volume_id ||
            expected[index].resource.file_id != actual[index].resource.file_id ||
            expected[index].resource.modified_time_ns != actual[index].resource.modified_time_ns ||
            expected[index].resource.link_count != actual[index].resource.link_count) {
            throw std::runtime_error(message);
        }
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

void require_install_path_capacity(const InstallPlan& plan, const std::string& transaction_id)
{
    require_result_record_capacity(plan.roots, plan.install_id, transaction_id, "audit." + plan.install_id);
    require_payload_path_capacity(plan.target_root, plan.files);
    if (!transaction_id.empty()) {
        transaction::require_path_capacity(transaction::TransactionSpec{
            transaction_id, plan.plan_id, plan.plan_digest, "install_local", plan.roots.staging_parent,
            plan.target_root, plan.roots.state_root, plan.roots.audit_root});
        require_payload_path_capacity(plan.roots.staging_parent / (".usk-stage-" + transaction_id), plan.files);
    }
}

InstallResult apply_install(
    const InstallPlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at,
    LifecycleFaultInjector fault_injector)
{
    return apply_install(
        plan, reviewed_plan_digest, transaction_id, applied_at,
        std::move(fault_injector), {});
}

InstallPlan plan_install(
    std::string plan_id,
    std::string install_id,
    std::string created_at,
    fs::path target_root,
    LifecycleRoots roots,
    RecipeBinding recipe,
    std::vector<PayloadFile> files,
    std::function<void()> validate_source,
    transaction::CommitAuthorityRequirement required_commit_authority)
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
    plan.validate_source = std::move(validate_source);
    plan.required_commit_authority = required_commit_authority;
    validate_recipe(plan.recipe);
    normalize_files(plan.files);
    plan.plan_digest = json::sha256_canonical(plan_payload(plan));
    validate_plan(plan);
    return plan;
}

static InstallResult apply_install_impl(
    const InstallPlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at,
    LifecycleFaultInjector fault_injector,
    LifecycleCancellation cancellation,
    const InstallRestartRequest* restart)
{
    validate_plan(plan);
    if (reviewed_plan_digest != plan.plan_digest || !record_io::valid_identifier(transaction_id) ||
        !valid_timestamp(applied_at)) throw std::runtime_error("reviewed install plan or transaction identity is invalid");
    transaction::require_commit_authority(plan.required_commit_authority);
    require_install_path_capacity(plan, transaction_id);
    if (fs::exists(plan.target_root)) throw std::runtime_error("install target now exists; reviewed plan is invalid");
    record_io::require_safe_directory(plan.roots.staging_parent);
    record_io::require_safe_directory(plan.target_root.parent_path());
    state::StateRepository state_repository(plan.roots.state_root);
    audit::AuditRepository audit_repository(plan.roots.audit_root);
    const std::string source_digest = install_stream_source_digest(plan);
    if (plan.validate_source) plan.validate_source();
    std::string chain_id = install_audit_chain_id(plan.install_id, transaction_id, restart != nullptr);
    audit::require_chain_path_capacity(plan.roots.audit_root, chain_id);
    std::unique_ptr<transaction::TransactionSession> transaction;
    bool replay_journal_attempted = false;
    const auto injector = [&](const std::string& state, const std::string& point) {
        if (restart != nullptr && state == "created" && point == "before_journal") {
            replay_journal_attempted = true;
        }
        if (fault_injector) fault_injector("install_local", "transaction." + state + "." + point);
    };
    try {
        if (restart != nullptr) {
            const auto context = inspect_install_replay(plan, *restart, transaction_id);
            transaction = transaction::TransactionSession::restart_streaming(context.prior_spec,
                transaction_id, restart->journal_snapshot_sha256, context.source_digest, injector);
            if (fault_injector) fault_injector("install_local", "before_replay_audit_create");
            create_install_replay_audit(plan, context, transaction_id, applied_at, fault_injector);
            if (fault_injector) fault_injector("install_local", "after_replay_audit_create");
        } else {
            bool has_current_install = false;
            state::InstalledState current_install;
            try {
                current_install = state_repository.read_installed(plan.install_id);
                has_current_install = true;
            } catch (const std::runtime_error& error) {
                if (std::string(error.what()) != "installed-state record does not exist") throw;
            }
            const bool has_initial_audit_chain = fs::exists(plan.roots.audit_root / "chains" / chain_id);
            if (!has_current_install) {
                if (has_initial_audit_chain) {
                    throw std::runtime_error("install identity has an incomplete existing audit generation");
                }
                audit_repository.initialize_chain(chain_id);
            } else {
                if (!fs::exists(plan.roots.audit_root / "chains" / current_install.audit_chain_id) ||
                    current_install.lifecycle_status != "retired" ||
                    applied_at <= current_install.created_at) {
                    throw std::runtime_error("install identity is not retired for a fresh transaction");
                }
                const auto prior_chain = audit_repository.read_and_validate_chain(current_install.audit_chain_id);
                if (prior_chain.empty() || prior_chain.back().operation != "uninstall" ||
                    prior_chain.back().phase != "completed" || prior_chain.back().status != "pass" ||
                    prior_chain.back().transaction_id != current_install.transaction_id ||
                    prior_chain.back().details_digest != current_install.last_verification.report_digest) {
                    throw std::runtime_error("retired install audit state is incompatible with a fresh transaction");
                }
                chain_id = next_install_audit_chain_id(plan.install_id, current_install.transaction_id);
                audit::require_chain_path_capacity(plan.roots.audit_root, chain_id);
                audit_repository.initialize_chain(chain_id);
            }
            const audit::AuditInput validated{
                applied_at, "install_local", "validated", "pass", "plan", plan.plan_id,
                plan.plan_digest, transaction_id, plan.plan_id, "reviewed plan revalidated"};
            audit_repository.append(chain_id, validated);
            transaction = std::make_unique<transaction::TransactionSession>(transaction::TransactionSpec{
                transaction_id, plan.plan_id, plan.plan_digest, "install_local",
                plan.roots.staging_parent, plan.target_root, plan.roots.state_root, plan.roots.audit_root,
                plan.required_commit_authority}, injector);
            if (!source_digest.empty()) transaction->bind_stream_source(source_digest, install_stream_source_context(plan));
        }
        for (const PayloadFile& file : plan.files) {
            stage_payload_file(*transaction, file.relative_path, file, cancellation,
                install_stream_entry_digest(source_digest, file));
        }
        transaction->mark_staged();
        transaction->mark_verified();
        if (cancellation && cancellation()) {
            throw std::runtime_error("lifecycle streaming operation was cancelled");
        }
        transaction->commit_effect();
        if (fault_injector) fault_injector("install_local", "after_target_commit");

        if (fault_injector) fault_injector("install_local", "before_ownership_commit");
        state::OwnershipManifest ownership;
        ownership.manifest_id = "ownership." + plan.install_id + "." + transaction_id;
        ownership.install_id = plan.install_id;
        ownership.target_root = plan.target_root.string();
        ownership.created_by_transaction_id = transaction_id;
        ownership.directories = directory_closure(plan.files);
        for (const PayloadFile& file : plan.files) {
            ownership.files.push_back(
                {file.relative_path, file.sha256, file.size_bytes});
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
        if (fault_injector) fault_injector("install_local", "before_installed_state_commit");
        state_repository.write_installed(installed);
        if (fault_injector) fault_injector("install_local", "before_audit_completion");
        audit_repository.append(chain_id, audit::AuditInput{
            applied_at, "install_local", "completed", "pass", "installation", plan.install_id,
            verification.report_digest, transaction_id, plan.plan_id, "managed portable install completed"});
        transaction->mark_committed();
        transaction->mark_completed();
        return {installed, ownership, verification, transaction->journal_path()};
    } catch (...) {
        if (transaction) {
            if (transaction->current_state() == "committing" || transaction->current_state() == "committed") {
                try { transaction->mark_recovery_required(); } catch (...) {}
            } else {
                rollback_before_visibility(*transaction);
            }
        }
        if (restart != nullptr && replay_journal_attempted) {
            try { throw; }
            catch (const std::exception& error) {
                throw RestartEffectsRetained(std::string("replay effects may exist; retain transaction ") +
                    transaction_id + ": " + error.what());
            }
            catch (...) { throw RestartEffectsRetained("replay effects may exist; retain transaction " + transaction_id); }
        }
        throw;
    }
}

InstallResult apply_install(const InstallPlan& plan, const std::string& reviewed_plan_digest,
    const std::string& transaction_id, const std::string& applied_at,
    LifecycleFaultInjector fault_injector, LifecycleCancellation cancellation) {
    return apply_install_impl(plan, reviewed_plan_digest, transaction_id, applied_at,
        std::move(fault_injector), std::move(cancellation), nullptr);
}
InstallResult restart_install(const InstallPlan& plan, const std::string& reviewed_plan_digest,
    const std::string& transaction_id, const std::string& applied_at, const InstallRestartRequest& restart,
    LifecycleFaultInjector fault_injector, LifecycleCancellation cancellation) {
    return apply_install_impl(plan, reviewed_plan_digest, transaction_id, applied_at,
        std::move(fault_injector), std::move(cancellation), &restart);
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
    require_install_path_capacity(plan, transaction_id);
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
        expected.files.push_back(
            {file.relative_path, file.sha256, file.size_bytes});
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
    installed.audit_chain_id = resolve_install_audit_chain_id(
        plan.roots, plan.install_id, transaction_id, transaction->is_stream_restart());
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
    std::vector<PayloadFile> exact_source_files,
    std::string source_digest,
    std::string policy_digest)
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
        if (source == sources.end() ||
            source->second->sha256 != file.expected_sha256) {
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
    plan.source_digest = source_digest.empty() ? std::string(64, '0') : std::move(source_digest);
    plan.policy_digest = policy_digest.empty() ? std::string(64, '0') : std::move(policy_digest);
    plan.roots = roots;
    for (PayloadFile& file : exact_source_files) {
        if (affected.count(file.relative_path) != 0) plan.replacement_files.push_back(std::move(file));
    }
    require_result_record_capacity(roots, install_id, {}, current.first.audit_chain_id);
    require_payload_path_capacity(fs::path(current.first.target_root), plan.replacement_files);
    plan.plan_digest = json::sha256_canonical(repair_plan_payload(plan));
    return plan;
}

RepairResult apply_repair(
    const RepairPlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at,
    LifecycleFaultInjector fault_injector)
{
    return apply_repair(
        plan, reviewed_plan_digest, transaction_id, applied_at,
        std::move(fault_injector), {});
}

RepairResult apply_repair(
    const RepairPlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at,
    LifecycleFaultInjector fault_injector,
    LifecycleCancellation cancellation)
{
    if (reviewed_plan_digest != plan.plan_digest ||
        json::sha256_canonical(repair_plan_payload(plan)) != plan.plan_digest ||
        !record_io::valid_identifier(transaction_id) || !valid_timestamp(applied_at) ||
        plan.replacement_files.empty()) {
        throw std::runtime_error("reviewed repair plan is invalid or changed");
    }
    validate_normalized_files(plan.replacement_files);
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
    require_result_record_capacity(plan.roots, plan.install_id, transaction_id, current.first.audit_chain_id);
    require_payload_path_capacity(install_root, plan.replacement_files);
    require_payload_path_capacity(bundle / "payload", plan.replacement_files);
    require_payload_path_capacity(bundle / "backup", plan.replacement_files);
    require_payload_path_capacity(plan.roots.staging_parent / (".usk-stage-" + transaction_id) / "payload",
        plan.replacement_files);
    transaction::TransactionSession transaction(transaction::TransactionSpec{
        transaction_id, plan.plan_id, plan.plan_digest, "repair", plan.roots.staging_parent,
        bundle, plan.roots.state_root, plan.roots.audit_root},
        [&](const std::string& state, const std::string& point) {
            if (fault_injector) fault_injector("repair", "transaction." + state + "." + point);
        });
    std::vector<fs::path> backups;
    try {
        for (const PayloadFile& file : plan.replacement_files) {
            stage_payload_file(
                transaction, fs::path("payload") / file.relative_path, file,
                cancellation);
        }
        transaction.mark_staged();
        transaction.mark_verified();
        if (cancellation && cancellation()) {
            throw std::runtime_error("lifecycle streaming operation was cancelled");
        }
        transaction.commit_effect();
        if (fault_injector) fault_injector("repair", "after_staging_commit");
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
            if (fault_injector) fault_injector("repair", "during_owned_replacement");
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
        if (fault_injector) fault_injector("repair", "before_installed_state_commit");
        repository.write_installed(installed);
        if (fault_injector) fault_injector("repair", "before_audit_completion");
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
        } else {
            rollback_before_visibility(transaction);
        }
        throw;
    }
}

MovePlan plan_move(
    const LifecycleRoots& roots,
    const std::string& install_id,
    std::string plan_id,
    std::string created_at,
    fs::path new_root,
    std::string policy_digest)
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
    plan.policy_digest = policy_digest.empty() ? std::string(64, '0') : std::move(policy_digest);
    plan.old_root = fs::absolute(current.first.target_root).lexically_normal();
    plan.new_root = fs::absolute(std::move(new_root)).lexically_normal();
    plan.staging_parent = plan.new_root.parent_path();
    plan.roots = roots;
    record_io::require_safe_directory(plan.staging_parent);
    if (plan.old_root == plan.new_root || fs::exists(plan.new_root)) {
        throw std::runtime_error("move destination is identical or already exists");
    }
    plan.old_root_identity = transaction::observe_directory_identity(plan.old_root);
    plan.complete_files = read_complete_tree(plan.old_root, nullptr, &plan.resource_observation);
    if (transaction::observe_directory_identity(plan.old_root) != plan.old_root_identity) {
        throw std::runtime_error("move source root changed during planning");
    }
    require_preimage_path_capacity(plan.new_root, plan.complete_files);
    require_result_record_capacity(roots, install_id, {}, current.first.audit_chain_id);
    plan.plan_digest = json::sha256_canonical(move_plan_payload(plan));
    return plan;
}

MoveResult apply_move(
    const MovePlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at,
    LifecycleFaultInjector fault_injector)
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
    if (transaction::observe_directory_identity(plan.old_root) != plan.old_root_identity) {
        throw std::runtime_error("move source root changed after plan review");
    }
    ensure_same_preimage(plan.complete_files, read_complete_tree(plan.old_root),
                        "move source closure changed after plan review");
    if (transaction::observe_directory_identity(plan.old_root) != plan.old_root_identity) {
        throw std::runtime_error("move source root changed during revalidation");
    }
    require_result_record_capacity(plan.roots, plan.install_id, transaction_id, current.first.audit_chain_id);
    require_preimage_path_capacity(plan.new_root, plan.complete_files);
    require_preimage_path_capacity(plan.staging_parent / (".usk-stage-" + transaction_id), plan.complete_files);
    transaction::TransactionSession transaction(transaction::TransactionSpec{
        transaction_id, plan.plan_id, plan.plan_digest, "move", plan.staging_parent,
        plan.new_root, plan.roots.state_root, plan.roots.audit_root},
        [&](const std::string& state, const std::string& point) {
            if (fault_injector) fault_injector("move", "transaction." + state + "." + point);
        });
    try {
        for (const PreimageFile& file : plan.complete_files) {
            stage_preimage_file(transaction, plan.old_root, plan.old_root_identity, file);
        }
        transaction.mark_staged();
        transaction.mark_verified();
        if (transaction::observe_directory_identity(plan.old_root) != plan.old_root_identity) {
            throw std::runtime_error("move source root changed before publication");
        }
        transaction.commit_effect();
        if (fault_injector) fault_injector("move", "after_destination_commit");

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
        if (fault_injector) fault_injector("move", "before_installed_state_commit");
        repository.write_installed(installed);
        if (fault_injector) fault_injector("move", "before_audit_completion");
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
        } else {
            // Before a stream intent the session owns cleanup; once intent is
            // durable TransactionSession deliberately retains staging for an
            // operator rather than recovering pathname deletion authority.
            rollback_before_visibility(transaction);
        }
        throw;
    }
}

UpdatePlan plan_update(
    const LifecycleRoots& roots,
    const std::string& install_id,
    std::string plan_id,
    std::string created_at,
    std::string transition,
    fs::path target_root,
    RecipeBinding new_recipe,
    std::vector<PayloadFile> new_complete_files,
    std::function<void()> validate_source)
{
    if (!record_io::valid_identifier(install_id) || !record_io::valid_identifier(plan_id) ||
        !valid_timestamp(created_at) || (transition != "upgrade" && transition != "downgrade")) {
        throw std::runtime_error("update plan identity or transition is invalid");
    }
    validate_recipe(new_recipe);
    auto current = load_current(roots, install_id);
    const fs::path installed_root = fs::absolute(current.first.target_root).lexically_normal();
    target_root = fs::absolute(std::move(target_root)).lexically_normal();
    if (target_root != installed_root || current.first.product_id != new_recipe.product_id ||
        current.first.product_version == new_recipe.product_version) {
        throw std::runtime_error("update requires the exact managed root, product, and a distinct version");
    }
    normalize_files(new_complete_files);
    if (new_complete_files.empty()) throw std::runtime_error("update replacement closure is empty");
    std::set<std::string> new_paths;
    for (const auto& file : new_complete_files) new_paths.insert(file.relative_path);
    for (const auto& entrypoint : new_recipe.entrypoints) {
        if (new_paths.count(entrypoint.relative_path) == 0u) {
            throw std::runtime_error("update entrypoint is absent from the replacement closure");
        }
    }
    UpdatePlan plan;
    plan.plan_id = std::move(plan_id);
    plan.created_at = std::move(created_at);
    plan.install_id = install_id;
    plan.transition = std::move(transition);
    plan.installed_state_digest = installed_digest(current.first);
    plan.ownership_manifest_digest = current.second.manifest_digest;
    plan.target_root = installed_root;
    plan.roots = roots;
    plan.recipe = std::move(new_recipe);
    plan.old_complete_files = read_complete_tree(installed_root, &plan.old_snapshot_digest);
    plan.new_complete_files = std::move(new_complete_files);
    plan.validate_source = std::move(validate_source);
    plan.old_root_identity = transaction::observe_directory_identity(installed_root);
    plan.new_snapshot_digest = payload_snapshot_digest(plan.new_complete_files);
    require_payload_path_capacity(plan.target_root, plan.new_complete_files);
    plan.plan_digest = json::sha256_canonical(update_plan_payload(plan));
    return plan;
}

UpdateResult apply_update(
    const UpdatePlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at,
    LifecycleFaultInjector fault_injector)
{
    (void)fault_injector;
    if (reviewed_plan_digest != plan.plan_digest ||
        json::sha256_canonical(update_plan_payload(plan)) != plan.plan_digest ||
        !record_io::valid_identifier(transaction_id) || !valid_timestamp(applied_at) ||
        plan.required_commit_authority != transaction::CommitAuthorityRequirement::staged_child_bound_v1) {
        throw std::runtime_error("reviewed update plan or transaction identity is invalid");
    }
    auto current = load_current(plan.roots, plan.install_id);
    if (installed_digest(current.first) != plan.installed_state_digest ||
        current.second.manifest_digest != plan.ownership_manifest_digest ||
        fs::absolute(current.first.target_root).lexically_normal() != plan.target_root ||
        transaction::observe_directory_identity(plan.target_root) != plan.old_root_identity) {
        throw std::runtime_error("installed state or whole-root preimage changed after update planning");
    }
    std::string current_snapshot_digest;
    ensure_same_preimage(plan.old_complete_files,
        read_complete_tree(plan.target_root, &current_snapshot_digest),
        "whole-root preimage changed after update planning");
    if (current_snapshot_digest != plan.old_snapshot_digest) {
        throw std::runtime_error("whole-root snapshot changed after update planning");
    }
    validate_normalized_files(plan.new_complete_files);
    if (payload_snapshot_digest(plan.new_complete_files) != plan.new_snapshot_digest ||
        applied_at <= current.first.created_at) {
        throw std::runtime_error("replacement closure or update timestamp is stale");
    }
    if (plan.validate_source) plan.validate_source();
    // A caller cannot downgrade the reviewed requirement. Current hosts have no
    // protected staged namespace publisher, so this throws before any journal,
    // staging, root rename, state, or audit effect.
    transaction::require_commit_authority(plan.required_commit_authority);
    throw std::logic_error("staged_child_bound_v1 returned without publication authority");
}

UninstallPlan plan_uninstall(
    const LifecycleRoots& roots,
    const std::string& install_id,
    std::string plan_id,
    std::string created_at,
    std::string policy_digest)
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
    plan.policy_digest = policy_digest.empty() ? std::string(64, '0') : std::move(policy_digest);
    plan.roots = roots;
    plan.verification = verify_manifest(
        current.first, current.second, "verify." + plan.plan_id + ".before", plan.created_at);
    require_result_record_capacity(roots, install_id, {}, current.first.audit_chain_id, false);
    plan.plan_digest = uninstall_plan_digest(plan);
    return plan;
}

UninstallResult apply_uninstall(
    const UninstallPlan& plan,
    const std::string& reviewed_plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at,
    LifecycleFaultInjector fault_injector)
{
    if (reviewed_plan_digest != plan.plan_digest ||
        uninstall_plan_digest(plan) != plan.plan_digest ||
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
    require_result_record_capacity(plan.roots, plan.install_id, transaction_id, current.first.audit_chain_id, false);
    for (const fs::path& path : {marker / "operation.marker",
            plan.roots.staging_parent / (".usk-stage-" + transaction_id) / "operation.marker"}) {
        base::require_native_path_capacity(path, base::NativePathKind::file, "uninstall operation marker");
    }
    transaction::TransactionSession transaction(transaction::TransactionSpec{
        transaction_id, plan.plan_id, plan.plan_digest, "uninstall", plan.roots.staging_parent,
        marker, plan.roots.state_root, plan.roots.audit_root},
        [&](const std::string& state, const std::string& point) {
            if (fault_injector) fault_injector("uninstall", "transaction." + state + "." + point);
        });
    UninstallResult result;
    result.retained_unknown_paths = plan.verification.unknown_paths;
    try {
        transaction.stage_file("operation.marker", {'u', 'n', 'i', 'n', 's', 't', 'a', 'l', 'l'});
        transaction.mark_staged();
        transaction.mark_verified();
        transaction.commit_effect();
        if (fault_injector) fault_injector("uninstall", "after_marker_commit");
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
            if (fault_injector) fault_injector("uninstall", "during_owned_file_removal");
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
        final_verification.report_digest = verification_digest(final_verification);
        state::InstalledState installed = current.first;
        installed.transaction_id = transaction_id;
        installed.created_at = applied_at;
        installed.lifecycle_status = result.target_removed ? "retired" : "uninstall_blocked";
        installed.last_verification = {final_verification.report_id, final_verification.report_digest,
                                       final_verification.status, applied_at};
        if (fault_injector) fault_injector("uninstall", "before_installed_state_commit");
        state::StateRepository(plan.roots.state_root).write_installed(installed);
        if (fault_injector) fault_injector("uninstall", "before_audit_completion");
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
