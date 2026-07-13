#include "usk_state_repository.h"

#include "usk_json.h"
#include "usk_record_io.h"

#include <algorithm>
#include <cctype>
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

bool safe_relative(const std::string& value)
{
    if (value.empty() || value.size() > 4096 || value.front() == '/' || value.front() == '\\' ||
        value.find('\\') != std::string::npos || value.find(':') != std::string::npos) return false;
    std::size_t start = 0;
    while (start < value.size()) {
        const std::size_t end = value.find('/', start);
        const std::string part = value.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (part.empty() || part == "." || part == "..") return false;
        start = end == std::string::npos ? value.size() : end + 1;
    }
    return true;
}

void exact_members(const Value& value, const std::set<std::string>& expected)
{
    const Value::Object& object = value.as_object();
    std::set<std::string> actual;
    for (const auto& member : object) actual.insert(member.first);
    if (actual != expected) throw std::runtime_error("durable record member set is incompatible");
}

Value owned_file_value(const usk::state::OwnedFile& file)
{
    return Value(Value::Object{
        {"relative_path", Value(file.relative_path)},
        {"sha256", Value(file.sha256)},
        {"size_bytes", Value(file.size_bytes)}});
}

Value ownership_payload(const usk::state::OwnershipManifest& manifest)
{
    Value::Array files;
    for (const auto& file : manifest.files) files.push_back(owned_file_value(file));
    Value::Array directories;
    for (const std::string& directory : manifest.directories) {
        directories.push_back(Value(Value::Object{{"relative_path", Value(directory)}}));
    }
    return Value(Value::Object{
        {"created_by_transaction_id", Value(manifest.created_by_transaction_id)},
        {"directories", Value(std::move(directories))},
        {"files", Value(std::move(files))},
        {"install_id", Value(manifest.install_id)},
        {"manifest_id", Value(manifest.manifest_id)},
        {"schema", Value("usk.ownership_manifest.v1")},
        {"target_root", Value(manifest.target_root)}});
}

Value ownership_document(const usk::state::OwnershipManifest& manifest)
{
    Value result = ownership_payload(manifest);
    result.as_object().emplace("manifest_digest", Value(manifest.manifest_digest));
    return result;
}

void validate_ownership(usk::state::OwnershipManifest& manifest)
{
    if (!usk::record_io::valid_identifier(manifest.manifest_id) ||
        !usk::record_io::valid_identifier(manifest.install_id) ||
        !usk::record_io::valid_identifier(manifest.created_by_transaction_id) ||
        manifest.target_root.empty() || manifest.target_root.size() > 32768) {
        throw std::runtime_error("ownership identity is invalid");
    }
    std::sort(manifest.files.begin(), manifest.files.end(), [](const auto& left, const auto& right) {
        return left.relative_path < right.relative_path;
    });
    std::sort(manifest.directories.begin(), manifest.directories.end());
    std::string previous;
    for (const auto& file : manifest.files) {
        if (!safe_relative(file.relative_path) || !sha256(file.sha256) || file.relative_path == previous) {
            throw std::runtime_error("ownership file closure is invalid or duplicated");
        }
        previous = file.relative_path;
    }
    previous.clear();
    std::set<std::string> directory_set;
    for (const std::string& directory : manifest.directories) {
        if (!safe_relative(directory) || directory == previous) {
            throw std::runtime_error("ownership directory closure is invalid or duplicated");
        }
        directory_set.insert(directory);
        previous = directory;
    }
    for (const auto& file : manifest.files) {
        if (directory_set.count(file.relative_path) != 0) {
            throw std::runtime_error("ownership path cannot be both a file and directory");
        }
        fs::path parent = fs::path(file.relative_path).parent_path();
        while (!parent.empty()) {
            if (directory_set.count(parent.generic_string()) == 0) {
                throw std::runtime_error("ownership directory closure omits a file parent");
            }
            parent = parent.parent_path();
        }
    }
}

usk::state::OwnershipManifest parse_ownership(const Value& value)
{
    exact_members(value, {"schema", "manifest_id", "manifest_digest", "install_id", "target_root",
                          "created_by_transaction_id", "files", "directories"});
    if (value.at("schema").as_string() != "usk.ownership_manifest.v1") {
        throw std::runtime_error("ownership schema is incompatible");
    }
    usk::state::OwnershipManifest result;
    result.manifest_id = value.at("manifest_id").as_string();
    result.manifest_digest = value.at("manifest_digest").as_string();
    result.install_id = value.at("install_id").as_string();
    result.target_root = value.at("target_root").as_string();
    result.created_by_transaction_id = value.at("created_by_transaction_id").as_string();
    for (const Value& item : value.at("files").as_array()) {
        exact_members(item, {"relative_path", "sha256", "size_bytes"});
        result.files.push_back({item.at("relative_path").as_string(), item.at("sha256").as_string(),
                                item.at("size_bytes").as_unsigned()});
    }
    for (const Value& item : value.at("directories").as_array()) {
        exact_members(item, {"relative_path"});
        result.directories.push_back(item.at("relative_path").as_string());
    }
    validate_ownership(result);
    if (!sha256(result.manifest_digest) ||
        usk::json::sha256_canonical(ownership_payload(result)) != result.manifest_digest) {
        throw std::runtime_error("ownership manifest digest does not match its canonical payload");
    }
    return result;
}

Value installed_document(const usk::state::InstalledState& state)
{
    Value::Array components;
    for (const std::string& component : state.component_selection) components.push_back(Value(component));
    Value::Array entrypoints;
    for (const auto& entrypoint : state.entrypoints) {
        entrypoints.push_back(Value(Value::Object{
            {"entrypoint_id", Value(entrypoint.entrypoint_id)},
            {"kind", Value(entrypoint.kind)},
            {"relative_path", Value(entrypoint.relative_path)}}));
    }
    return Value(Value::Object{
        {"audit_chain_id", Value(state.audit_chain_id)},
        {"component_selection", Value(std::move(components))},
        {"created_at", Value(state.created_at)},
        {"entrypoints", Value(std::move(entrypoints))},
        {"install_id", Value(state.install_id)},
        {"last_verification", Value(Value::Object{
            {"report_digest", Value(state.last_verification.report_digest)},
            {"report_id", Value(state.last_verification.report_id)},
            {"status", Value(state.last_verification.status)},
            {"verified_at", Value(state.last_verification.verified_at)}})},
        {"lifecycle_status", Value(state.lifecycle_status)},
        {"ownership_manifest_digest", Value(state.ownership_manifest_digest)},
        {"ownership_manifest_ref", Value(state.ownership_manifest_ref)},
        {"product_id", Value(state.product_id)},
        {"product_version", Value(state.product_version)},
        {"recipe_digest", Value(state.recipe_digest)},
        {"schema", Value("usk.installed_state.v1")},
        {"setup_abi", Value(Value::Object{
            {"major", Value(state.setup_abi_major)},
            {"minor", Value(state.setup_abi_minor)},
            {"provider_revision", Value(state.provider_revision)}})},
        {"source_archive_digest", Value(state.source_archive_digest)},
        {"target_root", Value(state.target_root)},
        {"target_scope", Value("portable")},
        {"transaction_id", Value(state.transaction_id)}});
}

const std::set<std::string> installed_members = {
    "schema", "install_id", "product_id", "product_version", "recipe_digest",
    "source_archive_digest", "target_root", "target_scope", "component_selection",
    "ownership_manifest_ref", "ownership_manifest_digest", "entrypoints", "setup_abi",
    "transaction_id", "created_at", "last_verification", "audit_chain_id", "lifecycle_status"};

void validate_installed(const usk::state::InstalledState& state)
{
    if (!usk::record_io::valid_identifier(state.install_id) ||
        !usk::record_io::valid_identifier(state.product_id) ||
        !usk::record_io::valid_identifier(state.transaction_id) ||
        !usk::record_io::valid_identifier(state.audit_chain_id) ||
        !usk::record_io::valid_identifier(state.provider_revision) ||
        state.product_version.empty() || state.target_root.empty() || state.created_at.empty() ||
        !sha256(state.recipe_digest) || !sha256(state.source_archive_digest) ||
        !sha256(state.ownership_manifest_digest) || !sha256(state.last_verification.report_digest) ||
        state.setup_abi_major == 0 || state.component_selection.empty() || state.entrypoints.empty()) {
        throw std::runtime_error("installed-state identity or required binding is invalid");
    }
    const std::set<std::string> verification_status = {"pass", "warn", "fail"};
    const std::set<std::string> lifecycle = {"installed", "verified", "repair_required",
        "move_pending_acceptance", "uninstall_blocked", "recovery_required", "retired"};
    if (verification_status.count(state.last_verification.status) == 0 ||
        lifecycle.count(state.lifecycle_status) == 0) throw std::runtime_error("installed-state status is invalid");
    std::set<std::string> components;
    for (const std::string& component : state.component_selection) {
        if (!usk::record_io::valid_identifier(component) || !components.insert(component).second) {
            throw std::runtime_error("installed-state component selection is invalid");
        }
    }
    std::set<std::string> entrypoint_ids;
    for (const auto& entrypoint : state.entrypoints) {
        if (!usk::record_io::valid_identifier(entrypoint.entrypoint_id) ||
            !safe_relative(entrypoint.relative_path) ||
            (entrypoint.kind != "application" && entrypoint.kind != "tool" && entrypoint.kind != "server") ||
            !entrypoint_ids.insert(entrypoint.entrypoint_id).second) {
            throw std::runtime_error("installed-state entrypoint is invalid");
        }
    }
    if (state.ownership_manifest_ref.rfind("ownership/", 0) != 0 ||
        state.ownership_manifest_ref.size() <= 15 ||
        state.ownership_manifest_ref.substr(state.ownership_manifest_ref.size() - 5) != ".json" ||
        !usk::record_io::valid_identifier(state.ownership_manifest_ref.substr(
            10, state.ownership_manifest_ref.size() - 15))) {
        throw std::runtime_error("installed-state ownership reference is not repository-local and exact");
    }
}

usk::state::InstalledState parse_installed(const Value& value)
{
    exact_members(value, installed_members);
    if (value.at("schema").as_string() != "usk.installed_state.v1" ||
        value.at("target_scope").as_string() != "portable") {
        throw std::runtime_error("installed-state schema or scope is incompatible");
    }
    usk::state::InstalledState result;
    result.install_id = value.at("install_id").as_string();
    result.product_id = value.at("product_id").as_string();
    result.product_version = value.at("product_version").as_string();
    result.recipe_digest = value.at("recipe_digest").as_string();
    result.source_archive_digest = value.at("source_archive_digest").as_string();
    result.target_root = value.at("target_root").as_string();
    for (const Value& component : value.at("component_selection").as_array()) {
        result.component_selection.push_back(component.as_string());
    }
    result.ownership_manifest_ref = value.at("ownership_manifest_ref").as_string();
    result.ownership_manifest_digest = value.at("ownership_manifest_digest").as_string();
    for (const Value& item : value.at("entrypoints").as_array()) {
        exact_members(item, {"entrypoint_id", "relative_path", "kind"});
        result.entrypoints.push_back({item.at("entrypoint_id").as_string(),
                                      item.at("relative_path").as_string(),
                                      item.at("kind").as_string()});
    }
    const Value& abi = value.at("setup_abi");
    exact_members(abi, {"major", "minor", "provider_revision"});
    result.setup_abi_major = abi.at("major").as_unsigned();
    result.setup_abi_minor = abi.at("minor").as_unsigned();
    result.provider_revision = abi.at("provider_revision").as_string();
    result.transaction_id = value.at("transaction_id").as_string();
    result.created_at = value.at("created_at").as_string();
    const Value& verification = value.at("last_verification");
    exact_members(verification, {"report_id", "report_digest", "status", "verified_at"});
    result.last_verification = {verification.at("report_id").as_string(),
        verification.at("report_digest").as_string(), verification.at("status").as_string(),
        verification.at("verified_at").as_string()};
    result.audit_chain_id = value.at("audit_chain_id").as_string();
    result.lifecycle_status = value.at("lifecycle_status").as_string();
    validate_installed(result);
    return result;
}

} // namespace

namespace usk::state {

StateRepository::StateRepository(fs::path state_root) : root_(fs::absolute(std::move(state_root)).lexically_normal())
{
    record_io::require_safe_directory(root_);
}

void StateRepository::initialize_layout(const fs::path& state_root)
{
    record_io::require_safe_directory(state_root);
    record_io::create_directory_exclusive(state_root, "ownership");
    record_io::create_directory_exclusive(state_root, "installed");
}

OwnershipManifest StateRepository::write_ownership(OwnershipManifest manifest) const
{
    record_io::require_safe_directory(root_ / "ownership");
    validate_ownership(manifest);
    manifest.manifest_digest = json::sha256_canonical(ownership_payload(manifest));
    record_io::write_new_durable_text(
        root_ / "ownership" / (manifest.manifest_id + ".json"),
        json::canonical(ownership_document(manifest)) + "\n");
    return manifest;
}

OwnershipManifest StateRepository::read_ownership(const std::string& manifest_id) const
{
    if (!record_io::valid_identifier(manifest_id)) throw std::runtime_error("ownership lookup id is invalid");
    const std::string text = record_io::read_stable_text(root_ / "ownership" / (manifest_id + ".json"),
                                                         16u * 1024u * 1024u);
    const Value document = json::parse(text);
    const std::string canonical = json::canonical(document);
    if (canonical + "\n" != text && canonical + "\r\n" != text) {
        throw std::runtime_error("ownership record is not canonical");
    }
    OwnershipManifest result = parse_ownership(document);
    if (result.manifest_id != manifest_id && result.install_id != manifest_id) {
        throw std::runtime_error("ownership lookup identity mismatch");
    }
    return result;
}

void StateRepository::write_installed(const InstalledState& state) const
{
    record_io::require_safe_directory(root_ / "installed");
    validate_installed(state);
    const std::string ownership_record_id = state.ownership_manifest_ref.substr(
        10, state.ownership_manifest_ref.size() - 15);
    const OwnershipManifest ownership = read_ownership(ownership_record_id);
    if (ownership.manifest_digest != state.ownership_manifest_digest ||
        ownership.install_id != state.install_id || ownership.target_root != state.target_root) {
        throw std::runtime_error("installed state does not bind the exact ownership manifest");
    }
    record_io::write_new_durable_text(
        root_ / "installed" / (state.install_id + "." + state.transaction_id + ".json"),
        json::canonical(installed_document(state)) + "\n");
}

InstalledState StateRepository::read_installed(const std::string& install_id) const
{
    if (!record_io::valid_identifier(install_id)) throw std::runtime_error("installed-state lookup id is invalid");
    const fs::path directory = root_ / "installed";
    record_io::require_safe_directory(directory);
    std::vector<InstalledState> candidates;
    for (const fs::directory_entry& entry : fs::directory_iterator(directory)) {
        const std::string name = entry.path().filename().string();
        if (!entry.is_regular_file() || entry.is_symlink() ||
            name.size() <= 5 || name.substr(name.size() - 5) != ".json") {
            throw std::runtime_error("installed-state repository contains an unsafe entry");
        }
        const std::string text = record_io::read_stable_text(entry.path(), 4u * 1024u * 1024u);
        const Value document = json::parse(text);
        const std::string canonical = json::canonical(document);
        if (canonical + "\n" != text && canonical + "\r\n" != text) {
            throw std::runtime_error("installed-state record is not canonical");
        }
        InstalledState candidate = parse_installed(document);
        const std::string expected = candidate.install_id + "." + candidate.transaction_id + ".json";
        const std::string legacy = candidate.install_id + ".json";
        if (name != expected && name != legacy) {
            throw std::runtime_error("installed-state filename does not bind its record identity");
        }
        if (candidate.install_id == install_id) candidates.push_back(std::move(candidate));
    }
    if (candidates.empty()) throw std::runtime_error("installed-state record does not exist");
    std::sort(candidates.begin(), candidates.end(), [](const InstalledState& left, const InstalledState& right) {
        return std::tie(left.created_at, left.transaction_id) < std::tie(right.created_at, right.transaction_id);
    });
    InstalledState result = std::move(candidates.back());
    const std::string ownership_record_id = result.ownership_manifest_ref.substr(
        10, result.ownership_manifest_ref.size() - 15);
    const OwnershipManifest ownership = read_ownership(ownership_record_id);
    if (ownership.manifest_digest != result.ownership_manifest_digest ||
        ownership.install_id != result.install_id || ownership.target_root != result.target_root) {
        throw std::runtime_error("installed-state ownership binding no longer validates");
    }
    return result;
}

InstalledState StateRepository::read_installed_snapshot(
    const std::string& install_id,
    const std::string& transaction_id) const
{
    if (!record_io::valid_identifier(install_id) || !record_io::valid_identifier(transaction_id)) {
        throw std::runtime_error("installed-state snapshot identity is invalid");
    }
    const fs::path path = root_ / "installed" / (install_id + "." + transaction_id + ".json");
    const std::string text = record_io::read_stable_text(path, 4u * 1024u * 1024u);
    const Value document = json::parse(text);
    const std::string canonical = json::canonical(document);
    if (canonical + "\n" != text && canonical + "\r\n" != text) {
        throw std::runtime_error("installed-state snapshot is not canonical");
    }
    InstalledState result = parse_installed(document);
    if (result.install_id != install_id || result.transaction_id != transaction_id) {
        throw std::runtime_error("installed-state snapshot lookup identity mismatch");
    }
    const std::string ownership_record_id = result.ownership_manifest_ref.substr(
        10, result.ownership_manifest_ref.size() - 15);
    const OwnershipManifest ownership = read_ownership(ownership_record_id);
    if (ownership.manifest_digest != result.ownership_manifest_digest ||
        ownership.install_id != result.install_id || ownership.target_root != result.target_root) {
        throw std::runtime_error("installed-state snapshot ownership binding no longer validates");
    }
    return result;
}

} // namespace usk::state
