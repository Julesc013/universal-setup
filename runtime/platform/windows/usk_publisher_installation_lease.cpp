// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_installation_lease.h"
#if defined(_WIN32)
#include "usk_publisher_anchor_create.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_handle_observation.h"
#include "usk_publisher_metadata.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_token_observation.h"
#include "usk_publisher_tree_observation.h"
#include "usk_publisher_volume_stream_observation.h"
#include "usk_record_io.h"
#include <algorithm>
#include <atomic>
#include <filesystem>
#include <iomanip>
#include <map>
#include <optional>
#include <sstream>
#include <set>
#include <tuple>
#include <utility>

namespace usk::platform::windows {
namespace {
using usk::json::Value;
using namespace usk::transaction;
constexpr std::size_t record_limit = 16384;
constexpr std::size_t history_limit = 4096;
class Handle final {
public:
    explicit Handle(HANDLE value) : value_(value) {
        if (!value || value == INVALID_HANDLE_VALUE) throw std::runtime_error("lease handle unavailable");
    }
    ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    HANDLE get() const { return value_; }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE)) {}
private:
    HANDLE value_;
};
std::string creation_time(HANDLE process) {
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(process, &creation, &exit, &kernel, &user))
        throw std::runtime_error("lease holder birth time unavailable");
    const std::uint64_t time = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) |
        creation.dwLowDateTime;
    std::ostringstream result;
    result << std::hex << std::setfill('0') << std::setw(16) << time;
    return result.str();
}
std::optional<PublisherDirectoryEntry> child(HANDLE parent, const std::wstring& name) {
    std::optional<PublisherDirectoryEntry> found;
    for (const auto& entry : observe_publisher_directory_entries(parent)) {
        if (CompareStringOrdinal(entry.name.c_str(), -1, name.c_str(), -1, TRUE) == CSTR_EQUAL) {
            if (entry.name != name || found) throw std::runtime_error("lease child spelling is ambiguous");
            found = entry;
        }
    }
    return found;
}
Value root_identity(HANDLE root, const std::string& sid) {
    const auto facts = observe_publisher_directory_handle(root);
    require_publisher_object_security_shape(facts, sid);
    require_publisher_stream_shape(root);
    return observe_publisher_lease_root_identity(root);
}
std::wstring record_name(const Value& record) {
    std::wostringstream result;
    result << L"g" << std::setfill(L'0') << std::setw(20) << record.at("generation").as_unsigned()
        << (record.at("status").as_string() == "active" ? L"-active.json" : L"-terminal.json");
    return result.str();
}
bool equal(const Value& left, const Value& right) {
    return usk::json::canonical(left) == usk::json::canonical(right);
}
const char* operation_name(PublisherOperationKind kind) {
    switch (kind) {
    case PublisherOperationKind::install_local: return "install_local";
    case PublisherOperationKind::repair: return "repair";
    case PublisherOperationKind::move: return "move";
    case PublisherOperationKind::uninstall: return "uninstall";
    }
    throw std::runtime_error("publisher operation kind invalid");
}
std::size_t context_limit(PublisherOperationKind kind) {
    return kind == PublisherOperationKind::install_local ? 4u * 1024u * 1024u : 16u * 1024u * 1024u;
}
void exact_fields(const Value& value, const std::set<std::string>& fields) {
    if (value.as_object().size() != fields.size()) throw InstallLeaseStale();
    for (const auto& item : value.as_object())
        if (!fields.count(item.first)) throw InstallLeaseStale();
}
bool sha256(const std::string& text) {
    return text.size() == 64 && text.find_first_not_of("0123456789abcdef") == std::string::npos;
}
void require_root_data(const Value& value) {
    exact_fields(value, {"file_id", "volume_serial"});
    const auto& id = value.at("file_id").as_string();
    const auto& serial = value.at("volume_serial").as_string();
    if (id.size() != 32 || id.find_first_not_of("0123456789abcdef") != std::string::npos ||
        id == std::string(32, '0') || serial.empty() ||
        serial.find_first_not_of("0123456789") != std::string::npos ||
        std::to_string(std::stoull(serial)) != serial) throw InstallLeaseStale();
}
void require_original_state_data(const Value& installed, const Value& ownership,
    const std::string& install_id) {
    exact_fields(installed, {"schema", "install_id", "product_id", "product_version", "recipe_digest",
        "source_archive_digest", "target_root", "target_scope", "component_selection", "ownership_manifest_ref",
        "ownership_manifest_digest", "entrypoints", "setup_abi", "transaction_id", "created_at",
        "last_verification", "audit_chain_id", "lifecycle_status"});
    exact_fields(ownership, {"schema", "manifest_id", "manifest_digest", "install_id", "target_root",
        "created_by_transaction_id", "files", "directories"});
    auto unsealed = ownership;
    unsealed.as_object().erase("manifest_digest");
    if (installed.at("schema").as_string() != "usk.installed_state.v1" ||
        ownership.at("schema").as_string() != "usk.ownership_manifest.v1" ||
        installed.at("install_id").as_string() != install_id ||
        ownership.at("install_id").as_string() != install_id ||
        !usk::record_io::valid_identifier(installed.at("transaction_id").as_string()) ||
        !usk::record_io::valid_identifier(ownership.at("manifest_id").as_string()) ||
        installed.at("ownership_manifest_ref").as_string() !=
            "ownership/" + ownership.at("manifest_id").as_string() + ".json" ||
        installed.at("ownership_manifest_digest").as_string() != ownership.at("manifest_digest").as_string() ||
        ownership.at("manifest_digest").as_string() != usk::json::sha256_canonical(unsealed) ||
        installed.at("target_scope").as_string() != "portable" ||
        installed.at("target_root").as_string().empty() ||
        installed.at("target_root").as_string() != ownership.at("target_root").as_string())
        throw InstallLeaseStale();
}
std::string installed_plan_digest(Value installed) {
    // The lifecycle's installed_digest deliberately excludes mutable read-only
    // verification observations and the document schema; retain that contract.
    installed.as_object().erase("schema");
    installed.as_object().erase("last_verification");
    return usk::json::sha256_canonical(installed);
}
std::wstring generation_name(std::uint64_t generation) {
    std::wostringstream result;
    result << L"g" << std::setfill(L'0') << std::setw(20) << generation;
    return result.str();
}
Value bootstrap_tree_facts(const PublisherTreeObservation& tree) {
    const auto streams = [](const std::vector<PublisherStreamObservation>& observed) {
        Value::Array result;
        for (const auto& stream : observed) {
            if (stream.size < 0 || stream.allocation_size < 0) throw InstallLeaseStale();
            result.emplace_back(Value::Object{
                {"name", Value(std::filesystem::path(stream.name).u8string())},
                {"size", Value(static_cast<std::uint64_t>(stream.size))},
                {"allocation_size", Value(static_cast<std::uint64_t>(stream.allocation_size))}});
        }
        return Value(std::move(result));
    };
    const auto object = [](const PublisherHandleObservation& observed) {
        auto result = publisher_handle_observation_json(observed);
        result.as_object().erase("native_name");
        return result;
    };
    Value::Array entries;
    for (const auto& entry : tree.descendants) entries.emplace_back(Value::Object{
        {"relative_path", Value(std::filesystem::path(entry.relative_path).u8string())},
        {"object", object(entry.object)}, {"bytes", Value(entry.size)},
        {"sha256", Value(entry.sha256)}, {"streams", streams(entry.streams)}});
    return Value(Value::Object{{"root", object(tree.root)},
        {"root_streams", streams(tree.root_streams)}, {"entries", Value(std::move(entries))}});
}
std::string read_held_text(HANDLE handle, const std::string& sid, std::size_t limit, bool allow_empty = false) {
    const auto before = observe_publisher_file_handle(handle);
    require_publisher_object_security_shape(before, sid);
    require_publisher_stream_shape(handle);
    LARGE_INTEGER size{};
    FILE_BASIC_INFO basic{};
    if (!GetFileSizeEx(handle, &size) || !GetFileInformationByHandleEx(handle, FileBasicInfo,
            &basic, sizeof(basic)) || size.QuadPart < 0 || (!allow_empty && size.QuadPart == 0) ||
            static_cast<std::uint64_t>(size.QuadPart) > limit)
        throw std::runtime_error("lease record size exceeds budget");
    std::string text(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    if (!ReadFile(handle, text.data(), static_cast<DWORD>(text.size()), &read, nullptr) ||
        read != text.size()) throw std::runtime_error("lease record read failed");
    LARGE_INTEGER after_size{};
    FILE_BASIC_INFO after_basic{};
    if (!GetFileSizeEx(handle, &after_size) || !GetFileInformationByHandleEx(handle, FileBasicInfo,
            &after_basic, sizeof(after_basic)) || after_size.QuadPart != size.QuadPart ||
        after_basic.LastWriteTime.QuadPart != basic.LastWriteTime.QuadPart ||
        after_basic.ChangeTime.QuadPart != basic.ChangeTime.QuadPart ||
        !equal(publisher_handle_observation_json(before),
            publisher_handle_observation_json(observe_publisher_file_handle(handle))))
        throw std::runtime_error("lease record changed during read");
    return text;
}
std::string read_text(HANDLE parent, const PublisherDirectoryEntry& entry, const std::string& sid,
    std::size_t limit) {
    Handle file(open_publisher_listed_child(parent, entry));
    return read_held_text(file.get(), sid, limit);
}
Value read_record(HANDLE parent, const PublisherDirectoryEntry& entry, const std::string& sid) {
    const auto text = read_text(parent, entry, sid, record_limit);
    const auto value = usk::json::parse(text);
    require_install_lease_record(value);
    if (usk::json::canonical(value) + "\n" != text || record_name(value) != entry.name)
        throw std::runtime_error("lease record encoding or name differs");
    return value;
}
} // namespace

void require_publisher_bootstrap_prefix_shape(const PublisherTreeObservation& tree) {
    if (tree.descendants.size() > 5) throw InstallLeaseStale();
    const std::vector<std::wstring> order{L"staging", L"destination", L"state", L"journal"};
    std::set<std::wstring> present;
    bool snapshot_present = false;
    for (const auto& entry : tree.descendants) {
        if ((entry.object.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if (std::find(order.begin(), order.end(), entry.relative_path) == order.end() ||
                !present.insert(entry.relative_path).second) throw InstallLeaseStale();
        } else {
            if (entry.relative_path != L"journal/lab-reviewed-plan.json" || snapshot_present ||
                entry.size > 4u * 1024u * 1024u) throw InstallLeaseStale();
            snapshot_present = true;
        }
    }
    bool missing = false;
    for (const auto& name : order) {
        if (!present.count(name)) missing = true;
        else if (missing) throw InstallLeaseStale();
    }
    if (snapshot_present && present.size() != order.size()) throw InstallLeaseStale();
}

Value observe_publisher_lease_root_identity(HANDLE root) {
    const auto facts = observe_publisher_directory_handle(root);
    const auto volume = observe_local_ntfs_volume_handle(root);
    // The publisher observer encodes serial:128-bit-id. This protocol stores
    // the same facts in separate, lossless fields; never narrow the serial.
    if (facts.file_id.size() != 49 || facts.file_id[16] != ':')
        throw std::runtime_error("lease native root identity encoding differs");
    return Value(Value::Object{{"file_id", Value(facts.file_id.substr(17))},
        {"volume_serial", Value(std::to_string(volume.file_id_volume_serial))}});
}

Value observe_publisher_install_state_bindings(HANDLE state_root,
    const std::string& install_id, const std::string& service_sid) {
    if (!usk::record_io::valid_identifier(install_id)) throw std::runtime_error("lease install ID invalid");
    (void)root_identity(state_root, service_sid);
    const auto listed = child(state_root, L"installed");
    if (!listed) throw std::runtime_error("lease installed-state directory unavailable");
    Handle installed(open_publisher_listed_child(state_root, *listed));
    (void)root_identity(installed.get(), service_sid);
    const auto entries = observe_publisher_directory_entries(installed.get());
    if (entries.size() > history_limit) throw std::runtime_error("lease state revision budget exhausted");
    std::map<std::wstring, Value> bindings;
    for (const auto& entry : entries) {
        const auto text = read_text(installed.get(), entry, service_sid, 4u * 1024u * 1024u);
        const auto document = usk::json::parse(text);
        const auto& id = document.at("install_id").as_string();
        const auto& transaction = document.at("transaction_id").as_string();
        const std::string expected = id + "." + transaction + ".json";
        if (document.at("schema").as_string() != "usk.installed_state.v1" ||
            !usk::record_io::valid_identifier(id) || !usk::record_io::valid_identifier(transaction) ||
            (entry.name != std::wstring(expected.begin(), expected.end()) &&
                entry.name != std::wstring(id.begin(), id.end()) + L".json") ||
            usk::json::canonical(document) + "\n" != text)
            throw std::runtime_error("lease installed-state binding is invalid");
        if (id == install_id && !bindings.emplace(entry.name, Value(usk::json::sha256_canonical(document))).second)
            throw std::runtime_error("lease installed-state binding is duplicated");
    }
    Value::Array values;
    for (const auto& [name, digest] : bindings)
        values.emplace_back(Value::Object{{"record", Value(std::filesystem::path(name).u8string())}, {"sha256", digest}});
    return Value(std::move(values));
}
std::string observe_publisher_install_state_revision(HANDLE state_root,
    const std::string& install_id, const std::string& service_sid) {
    return usk::json::sha256_canonical(observe_publisher_install_state_bindings(state_root, install_id, service_sid));
}

bool require_publisher_initial_install_state_revision(HANDLE volume,
    const std::wstring& volume_root, const std::wstring& setup_component,
    const PublisherInstallOperationGuard& guard, const std::string& install_id,
    const std::string& service_sid) {
    guard.require_owned(volume_root, install_id);
    const std::filesystem::path component(setup_component);
    if (setup_component.empty() || component.has_root_path() ||
        component.filename() != component || setup_component == L"." || setup_component == L".." ||
        setup_component.find(L':') != std::wstring::npos || setup_component.find(L'\0') != std::wstring::npos)
        throw std::runtime_error("lease setup component is invalid");
    const auto volume_identity = root_identity(volume, service_sid);
    const auto setup_entry = child(volume, setup_component);
    const auto empty_revision = usk::json::sha256_canonical(Value(Value::Array{}));
    std::string revision = empty_revision;
    if (setup_entry) {
        Handle setup(open_publisher_listed_child(volume, *setup_entry));
        const auto setup_identity = root_identity(setup.get(), service_sid);
        const auto state_entry = child(setup.get(), L"state");
        if (!state_entry) throw std::runtime_error("lease existing state root unavailable");
        Handle state(open_publisher_listed_child(setup.get(), *state_entry));
        const auto state_identity = root_identity(state.get(), service_sid);
        revision = observe_publisher_install_state_revision(state.get(), install_id, service_sid);
        // Check current path bindings as well as the retained read handles.
        const auto current_setup_entry = child(volume, setup_component);
        if (!current_setup_entry) throw InstallLeaseStale();
        Handle current_setup(open_publisher_listed_child(volume, *current_setup_entry));
        const auto current_state_entry = child(current_setup.get(), L"state");
        if (!current_state_entry) throw InstallLeaseStale();
        Handle current_state(open_publisher_listed_child(current_setup.get(), *current_state_entry));
        if (!equal(setup_identity, root_identity(current_setup.get(), service_sid)) ||
            !equal(state_identity, root_identity(current_state.get(), service_sid))) throw InstallLeaseStale();
    } else if (child(volume, setup_component)) {
        throw InstallLeaseStale();
    }
    guard.require_owned(volume_root, install_id);
    if (!equal(volume_identity, root_identity(volume, service_sid))) throw InstallLeaseStale();
    if (revision != empty_revision) throw InstallStateRevisionStale();
    return setup_entry.has_value();
}

Value observe_publisher_lease_holder() {
    return Value(Value::Object{{"process_id", Value(static_cast<std::uint64_t>(GetCurrentProcessId()))},
        {"process_creation_time", Value(creation_time(GetCurrentProcess()))}});
}
InstallLeasePreviousHolder observe_publisher_previous_lease_holder(const Value& holder) {
    if (holder.as_object().size() != 2) throw std::runtime_error("lease holder fields differ");
    const auto pid = holder.at("process_id").as_unsigned();
    if (!pid || pid > MAXDWORD) throw std::runtime_error("lease holder PID invalid");
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
        FALSE, static_cast<DWORD>(pid));
    if (!process) return GetLastError() == ERROR_INVALID_PARAMETER ?
        InstallLeasePreviousHolder::ended : InstallLeasePreviousHolder::unknown;
    Handle owned(process);
    if (creation_time(process) != holder.at("process_creation_time").as_string())
        return InstallLeasePreviousHolder::identity_reused;
    const DWORD status = WaitForSingleObject(process, 0);
    if (status == WAIT_OBJECT_0) return InstallLeasePreviousHolder::ended;
    return status == WAIT_TIMEOUT ? InstallLeasePreviousHolder::live : InstallLeasePreviousHolder::unknown;
}

void require_publisher_maintenance_snapshot_binding(const Value& snapshot,
    PublisherOperationKind kind, const std::string& install_id,
    const std::string& operation_id, const std::string& revision) {
    if (kind == PublisherOperationKind::install_local ||
        !usk::record_io::valid_identifier(install_id) || !usk::record_io::valid_identifier(operation_id) ||
        !sha256(revision) || revision == usk::json::sha256_canonical(Value(Value::Array{})))
        throw InstallLeaseStale();
    const std::string operation = operation_name(kind);
    const auto schema = snapshot.at("schema").as_string();
    const bool original_bindings = schema == "usk.publisher.maintenance_reviewed_snapshot.v2";
    std::set<std::string> snapshot_fields{"schema", "operation", "install_id", "operation_id", "initial_state_revision",
        "reviewed_plan", "apply_request", "installed_state", "ownership_manifest", "volume_root_identity",
        "setup_root_identity", "state_root_identity", "setup_component", "installed_record", "ownership_record"};
    if (original_bindings) snapshot_fields.insert("installed_record_bindings");
    exact_fields(snapshot, snapshot_fields);
    const auto& plan = snapshot.at("reviewed_plan");
    const auto& request = snapshot.at("apply_request");
    const auto& installed = snapshot.at("installed_state");
    const auto& ownership = snapshot.at("ownership_manifest");
    switch (kind) {
    case PublisherOperationKind::repair:
        exact_fields(plan, {"created_at", "audit_root", "install_id", "installed_state_digest", "operation",
            "ownership_manifest_digest", "policy_digest", "source_digest", "plan_id", "replacement_files",
            "staging_parent", "state_root"});
        (void)plan.at("replacement_files").as_array();
        if (!sha256(plan.at("source_digest").as_string())) throw InstallLeaseStale();
        break;
    case PublisherOperationKind::move:
        exact_fields(plan, {"audit_root", "complete_files", "created_at", "install_id", "installed_state_digest",
            "old_root", "old_root_identity", "operation", "ownership_manifest_digest", "policy_digest",
            "plan_id", "new_root", "staging_parent", "state_root"});
        (void)plan.at("complete_files").as_array();
        break;
    case PublisherOperationKind::uninstall:
        exact_fields(plan, {"audit_root", "created_at", "install_id", "installed_state_digest", "operation",
            "ownership_manifest_digest", "plan_id", "policy_digest", "staging_parent", "state_root", "verification"});
        (void)plan.at("verification").as_object();
        break;
    default: throw InstallLeaseStale();
    }
    if (!usk::record_io::valid_identifier(plan.at("plan_id").as_string()) ||
        !sha256(plan.at("policy_digest").as_string())) throw InstallLeaseStale();
    require_original_state_data(installed, ownership, install_id);
    const auto component = std::filesystem::u8path(snapshot.at("setup_component").as_string());
    const auto& installed_record = snapshot.at("installed_record").as_string();
    if (!is_publisher_canonical_component(component.wstring()) || component.filename() != component ||
        (installed_record != install_id + ".json" && installed_record !=
            install_id + "." + installed.at("transaction_id").as_string() + ".json") ||
        snapshot.at("ownership_record").as_string() != ownership.at("manifest_id").as_string() + ".json")
        throw InstallLeaseStale();
    exact_fields(request, {"schema", "plan_request", "reviewed_plan_id", "reviewed_plan_digest",
        "transaction_id", "applied_at", "confirmation"});
    if ((schema != "usk.publisher.maintenance_reviewed_snapshot.v1" && !original_bindings) ||
        snapshot.at("operation").as_string() != operation ||
        snapshot.at("install_id").as_string() != install_id ||
        snapshot.at("operation_id").as_string() != operation_id ||
        snapshot.at("initial_state_revision").as_string() != revision ||
        plan.at("operation").as_string() != operation || plan.at("install_id").as_string() != install_id ||
        plan.at("installed_state_digest").as_string() != installed_plan_digest(installed) ||
        plan.at("ownership_manifest_digest").as_string() != ownership.at("manifest_digest").as_string() ||
        request.at("schema").as_string() != "usk." + operation + "_apply_request.v1" ||
        request.at("confirmation").as_string() != "APPLY" ||
        request.at("plan_request").at("install_id").as_string() != install_id ||
        request.at("reviewed_plan_id").as_string() != plan.at("plan_id").as_string() ||
        request.at("reviewed_plan_digest").as_string() != usk::json::sha256_canonical(plan) ||
        request.at("transaction_id").as_string() != operation_id ||
        request.at("applied_at").as_string().empty()) throw InstallLeaseStale();
    if (original_bindings) {
        const auto& bindings = snapshot.at("installed_record_bindings");
        if (bindings.as_array().empty() || bindings.as_array().size() > history_limit ||
            usk::json::sha256_canonical(bindings) != revision) throw InstallLeaseStale();
        std::string previous;
        bool selected = false;
        for (const auto& item : bindings.as_array()) {
            exact_fields(item, {"record", "sha256"});
            const auto& name = item.at("record").as_string();
            const auto& digest = item.at("sha256").as_string();
            if (name <= previous || !sha256(digest)) throw InstallLeaseStale();
            if (name != install_id + ".json") {
                const auto prefix = install_id + ".";
                if (name.size() <= prefix.size() + 5 || name.compare(0, prefix.size(), prefix) != 0 ||
                    name.substr(name.size() - 5) != ".json" ||
                    !usk::record_io::valid_identifier(name.substr(prefix.size(), name.size() - prefix.size() - 5)))
                    throw InstallLeaseStale();
            }
            if (name == installed_record) {
                if (selected || digest != usk::json::sha256_canonical(installed)) throw InstallLeaseStale();
                selected = true;
            }
            previous = name;
        }
        if (!selected) throw InstallLeaseStale();
    }
    for (const auto* root : {"volume_root_identity", "setup_root_identity", "state_root_identity"}) {
        require_root_data(snapshot.at(root));
        if (snapshot.at(root).at("volume_serial").as_string() !=
            snapshot.at("volume_root_identity").at("volume_serial").as_string()) throw InstallLeaseStale();
    }
    if (equal(snapshot.at("volume_root_identity"), snapshot.at("setup_root_identity")) ||
        equal(snapshot.at("volume_root_identity"), snapshot.at("state_root_identity")) ||
        equal(snapshot.at("setup_root_identity"), snapshot.at("state_root_identity"))) throw InstallLeaseStale();
}

struct PublisherMaintenanceStateSnapshot::Impl {
    HANDLE volume;
    std::wstring volume_root, setup_component, installed_name, ownership_name;
    const PublisherInstallOperationGuard& guard;
    std::string install_id, service_sid, revision, installed_text, ownership_text;
    std::unique_ptr<Handle> setup, state, installed_directory, ownership_directory,
        installed_file, ownership_file;
    Value volume_facts, setup_facts, state_facts, installed_directory_facts, ownership_directory_facts,
        installed_facts, ownership_facts, installed, ownership, installed_bindings;
    Impl(HANDLE root, const std::wstring& root_name, const std::wstring& component,
        const std::wstring& service, const PublisherInstallOperationGuard& held, const std::string& id,
        const Value* original = nullptr)
        : volume(root), volume_root(root_name), setup_component(component), guard(held), install_id(id) {
        guard.require_owned(volume_root, install_id);
        if (!is_publisher_canonical_component(component) || !usk::record_io::valid_identifier(id))
            throw InstallLeaseStale();
        service_sid = observe_current_restricted_publisher_service(service).service_sid;
        volume_facts = directory_facts(volume);
        setup = open_directory(volume, component);
        state = open_directory(setup->get(), L"state");
        installed_directory = open_directory(state->get(), L"installed");
        ownership_directory = open_directory(state->get(), L"ownership");
        setup_facts = directory_facts(setup->get());
        state_facts = directory_facts(state->get());
        installed_directory_facts = directory_facts(installed_directory->get());
        ownership_directory_facts = directory_facts(ownership_directory->get());
        installed_bindings = observe_publisher_install_state_bindings(state->get(), install_id, service_sid);
        const auto current_revision = usk::json::sha256_canonical(installed_bindings);
        if (original && original->contains("installed_record_bindings"))
            installed_bindings = original->at("installed_record_bindings");
        revision = original ? original->at("initial_state_revision").as_string() : current_revision;
        if (original &&
            (!equal(root_identity(volume, service_sid), original->at("volume_root_identity")) ||
             !equal(root_identity(setup->get(), service_sid), original->at("setup_root_identity")) ||
             !equal(root_identity(state->get(), service_sid), original->at("state_root_identity"))))
            throw InstallLeaseStale();
        std::tuple<std::string, std::string> selected;
        bool found = false;
        for (const auto& entry : observe_publisher_directory_entries(installed_directory->get())) {
            const auto text = read_text(installed_directory->get(), entry, service_sid, 4u * 1024u * 1024u);
            const auto document = usk::json::parse(text);
            if (document.at("install_id").as_string() != install_id) continue;
            if (original && entry.name != std::filesystem::u8path(original->at("installed_record").as_string()).wstring())
                continue;
            const auto order = std::make_tuple(document.at("created_at").as_string(),
                document.at("transaction_id").as_string());
            if (!found || selected < order) {
                selected = order; found = true; installed = document;
                installed_name = entry.name; installed_text = text;
            }
        }
        if (!found) throw InstallStateRevisionStale();
        if (original && !equal(installed, original->at("installed_state"))) throw InstallLeaseStale();
        installed_file = open_file(installed_directory->get(), installed_name);
        installed_facts = file_facts(installed_file->get());
        if (read_from_start(installed_file->get()) != installed_text) throw InstallLeaseStale();
        const auto& ref = installed.at("ownership_manifest_ref").as_string();
        if (ref.rfind("ownership/", 0) != 0 || ref.size() <= 15 ||
            ref.substr(ref.size() - 5) != ".json" ||
            !usk::record_io::valid_identifier(ref.substr(10, ref.size() - 15))) throw InstallLeaseStale();
        ownership_name = std::filesystem::u8path(ref).filename().wstring();
        ownership_file = open_file(ownership_directory->get(), ownership_name);
        ownership_facts = file_facts(ownership_file->get());
        ownership_text = read_from_start(ownership_file->get());
        ownership = usk::json::parse(ownership_text);
        if (usk::json::canonical(ownership) + "\n" != ownership_text) throw InstallLeaseStale();
        require_original_state_data(installed, ownership, install_id);
        if (original) {
            if (!equal(ownership, original->at("ownership_manifest"))) throw InstallLeaseStale();
            require_custody();
        } else require_initial_revision();
    }
    Value directory_facts(HANDLE handle) const {
        (void)root_identity(handle, service_sid);
        return publisher_handle_observation_json(observe_publisher_directory_handle(handle));
    }
    Value file_facts(HANDLE handle) const {
        const auto facts = observe_publisher_file_handle(handle);
        require_publisher_object_security_shape(facts, service_sid);
        require_publisher_stream_shape(handle);
        return publisher_handle_observation_json(facts);
    }
    std::unique_ptr<Handle> open_directory(HANDLE parent, const std::wstring& name) const {
        const auto entry = child(parent, name);
        if (!entry || !(entry->attributes & FILE_ATTRIBUTE_DIRECTORY)) throw InstallLeaseStale();
        Handle acquired(open_publisher_listed_child(parent, *entry));
        auto result = std::make_unique<Handle>(std::move(acquired));
        (void)directory_facts(result->get());
        return result;
    }
    std::unique_ptr<Handle> open_file(HANDLE parent, const std::wstring& name) const {
        const auto entry = child(parent, name);
        if (!entry || (entry->attributes & FILE_ATTRIBUTE_DIRECTORY)) throw InstallLeaseStale();
        Handle acquired(open_publisher_listed_child(parent, *entry));
        auto result = std::make_unique<Handle>(std::move(acquired));
        (void)file_facts(result->get());
        return result;
    }
    std::string read_from_start(HANDLE handle) const {
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN)) throw InstallLeaseStale();
        return read_held_text(handle, service_sid, 4u * 1024u * 1024u);
    }
    void require_custody() const {
        guard.require_owned(volume_root, install_id);
        if (!equal(directory_facts(volume), volume_facts)) throw InstallLeaseStale();
        const auto link = [&](HANDLE parent, const std::wstring& name, HANDLE retained,
                              const Value& expected, bool regular) {
            auto current = regular ? open_file(parent, name) : open_directory(parent, name);
            const auto held_facts = regular ? file_facts(retained) : directory_facts(retained);
            const auto fresh_facts = regular ? file_facts(current->get()) : directory_facts(current->get());
            if (!equal(held_facts, expected) || !equal(fresh_facts, expected)) throw InstallLeaseStale();
        };
        link(volume, setup_component, setup->get(), setup_facts, false);
        link(setup->get(), L"state", state->get(), state_facts, false);
        link(state->get(), L"installed", installed_directory->get(), installed_directory_facts, false);
        link(state->get(), L"ownership", ownership_directory->get(), ownership_directory_facts, false);
        link(installed_directory->get(), installed_name, installed_file->get(), installed_facts, true);
        link(ownership_directory->get(), ownership_name, ownership_file->get(), ownership_facts, true);
        if (read_from_start(installed_file->get()) != installed_text ||
            read_from_start(ownership_file->get()) != ownership_text) throw InstallLeaseStale();
        guard.require_owned(volume_root, install_id);
    }
    void require_initial_revision() const {
        require_custody();
        if (observe_publisher_install_state_revision(state->get(), install_id, service_sid) != revision)
            throw InstallStateRevisionStale();
        require_custody();
    }
};
PublisherMaintenanceStateSnapshot::PublisherMaintenanceStateSnapshot(HANDLE volume,
    const std::wstring& root, const std::wstring& setup_component, const std::wstring& service,
    const PublisherInstallOperationGuard& guard, const std::string& install_id)
    : impl_(std::make_unique<Impl>(volume, root, setup_component, service, guard, install_id)) {}
PublisherMaintenanceStateSnapshot::~PublisherMaintenanceStateSnapshot() = default;
PublisherMaintenanceStateSnapshot::PublisherMaintenanceStateSnapshot(HANDLE volume, const std::wstring& root,
    const std::wstring& service, const PublisherInstallOperationGuard& guard, const Value& original)
    : impl_(std::make_unique<Impl>(volume, root,
        std::filesystem::u8path(original.at("setup_component").as_string()).wstring(), service, guard,
        original.at("install_id").as_string(), &original)) {}
HANDLE PublisherMaintenanceStateSnapshot::setup_root() const { impl_->require_custody(); return impl_->setup->get(); }
HANDLE PublisherMaintenanceStateSnapshot::state_root() const { impl_->require_custody(); return impl_->state->get(); }
const std::string& PublisherMaintenanceStateSnapshot::initial_state_revision() const { impl_->require_custody(); return impl_->revision; }
const Value& PublisherMaintenanceStateSnapshot::installed_state() const { impl_->require_custody(); return impl_->installed; }
const Value& PublisherMaintenanceStateSnapshot::ownership_manifest() const { impl_->require_custody(); return impl_->ownership; }
void PublisherMaintenanceStateSnapshot::require_custody() const { impl_->require_custody(); }
void PublisherMaintenanceStateSnapshot::require_initial_revision() const { impl_->require_initial_revision(); }
Value PublisherMaintenanceStateSnapshot::reviewed_snapshot(PublisherOperationKind kind,
    const std::string& operation_id, const Value& plan, const Value& request) const {
    impl_->require_initial_revision();
    Value value(Value::Object{{"schema", Value("usk.publisher.maintenance_reviewed_snapshot.v2")},
        {"operation", Value(operation_name(kind))}, {"install_id", Value(impl_->install_id)},
        {"operation_id", Value(operation_id)}, {"initial_state_revision", Value(impl_->revision)},
        {"reviewed_plan", plan}, {"apply_request", request}, {"installed_state", impl_->installed},
        {"ownership_manifest", impl_->ownership},
        {"setup_component", Value(std::filesystem::path(impl_->setup_component).u8string())},
        {"installed_record", Value(std::filesystem::path(impl_->installed_name).u8string())},
        {"ownership_record", Value(std::filesystem::path(impl_->ownership_name).u8string())},
        {"installed_record_bindings", impl_->installed_bindings},
        {"volume_root_identity", root_identity(impl_->volume, impl_->service_sid)},
        {"setup_root_identity", root_identity(impl_->setup->get(), impl_->service_sid)},
        {"state_root_identity", root_identity(impl_->state->get(), impl_->service_sid)}});
    require_publisher_maintenance_snapshot_binding(value, kind, impl_->install_id, operation_id, impl_->revision);
    impl_->require_initial_revision();
    return value;
}

struct PublisherInstallOperationContext::Impl {
    HANDLE volume;
    std::wstring volume_root, service_name;
    const PublisherInstallOperationGuard& guard;
    std::string install_id, operation_id, service_sid;
    PublisherOperationKind kind;
    std::wstring install_name, context_name, roots_name;
    std::vector<unsigned char> descriptor;
    std::unique_ptr<Handle> operations, records, pending, file;
    Value volume_identity, original, file_facts;
    FILE_BASIC_INFO file_basic{};
    LARGE_INTEGER file_size{};
    std::unique_ptr<Handle> roots_file;
    Value roots_record, roots_facts;
    FILE_BASIC_INFO roots_basic{};
    LARGE_INTEGER roots_size{};

    Impl(HANDLE held_volume, const std::wstring& root, const std::wstring& service,
        const PublisherInstallOperationGuard& held, const std::string& install,
        const std::string& operation, PublisherOperationKind operation_kind)
        : volume(held_volume), volume_root(root), service_name(service), guard(held), install_id(install), operation_id(operation), kind(operation_kind) {
        (void)operation_name(kind);
        guard.require_owned(volume_root, install_id);
        if (!usk::record_io::valid_identifier(install_id) || !usk::record_io::valid_identifier(operation_id))
            throw std::runtime_error("operation context identity invalid");
        service_sid = observe_current_restricted_publisher_service(service).service_sid;
        volume_identity = root_identity(volume, service_sid);
        descriptor = make_publisher_directory_security_descriptor(std::wstring(service_sid.begin(), service_sid.end()));
        const auto install_sha = usk::json::sha256_canonical(Value(install_id));
        const auto operation_sha = usk::json::sha256_canonical(Value(operation_id));
        install_name = L"install-" + std::wstring(install_sha.begin(), install_sha.end());
        context_name = L"operation-" + std::wstring(operation_sha.begin(), operation_sha.end()) + L".json";
        roots_name = L"operation-" + std::wstring(operation_sha.begin(), operation_sha.end()) + L"-roots.json";
        operations = directory(volume, L"installation-operations", false);
        if (!operations) return;
        records = directory(operations->get(), install_name, false);
        if (!records) return;
        pending = directory(records->get(), L"pending", false);
        const auto entry = child(records->get(), context_name);
        if (!entry) {
            if (child(records->get(), roots_name)) throw InstallLeaseStale();
            return;
        }
        if (!pending) throw std::runtime_error("operation context pending root unavailable");
        const auto text = read_text(records->get(), *entry, service_sid, context_limit(kind));
        original = usk::json::parse(text);
        const std::set<std::string> fields{"schema", "install_id", "operation", "operation_id",
            "volume_root_identity", "initial_state_revision", "reviewed_snapshot", "context_sha256"};
        if (original.as_object().size() != fields.size()) throw std::runtime_error("operation context fields differ");
        for (const auto& item : original.as_object())
            if (!fields.count(item.first)) throw std::runtime_error("operation context field unknown");
        auto unsealed = original;
        unsealed.as_object().erase("context_sha256");
        const bool install_context = kind == PublisherOperationKind::install_local;
        if (original.at("schema").as_string() != (install_context ?
                "usk.installation_operation_context.v1" : "usk.installation_operation_context.v2") ||
            original.at("install_id").as_string() != install_id ||
            original.at("operation").as_string() != operation_name(kind) ||
            original.at("operation_id").as_string() != operation_id ||
            !equal(original.at("volume_root_identity"), volume_identity) ||
            original.at("context_sha256").as_string() != usk::json::sha256_canonical(unsealed) ||
            (install_context && original.at("initial_state_revision").as_string() !=
                usk::json::sha256_canonical(Value(Value::Array{}))) ||
            original.at("reviewed_snapshot").type() != Value::Type::object ||
            usk::json::canonical(original) + "\n" != text)
            throw std::runtime_error("operation context binding differs");
        if (!install_context) {
            require_publisher_maintenance_snapshot_binding(original.at("reviewed_snapshot"), kind,
                install_id, operation_id, original.at("initial_state_revision").as_string());
            if (!equal(original.at("reviewed_snapshot").at("volume_root_identity"), volume_identity))
                throw InstallLeaseStale();
        }
        bind_file(*entry);
        if (read_held_text(file->get(), service_sid, context_limit(kind)) != text)
            throw std::runtime_error("operation context retained-handle readback differs");
        fence();
        load_roots();
    }
    std::unique_ptr<Handle> directory(HANDLE parent, const std::wstring& name, bool create) {
        guard.require_owned(volume_root, install_id);
        (void)root_identity(parent, service_sid);
        const auto entry = child(parent, name);
        if (!entry && !create) return {};
        if (!entry && observe_publisher_directory_entries(parent).size() >= history_limit)
            throw std::runtime_error("operation context directory budget exhausted");
        auto result = std::make_unique<Handle>(entry ? open_publisher_listed_child(parent, *entry, true, false, true) :
            create_record_directory_relative_with_descriptor(parent, name, descriptor));
        (void)root_identity(result->get(), service_sid);
        return result;
    }
    void bind_file(const PublisherDirectoryEntry& entry) {
        file = std::make_unique<Handle>(open_publisher_listed_child(records->get(), entry));
        const auto facts = observe_publisher_file_handle(file->get());
        require_publisher_object_security_shape(facts, service_sid);
        require_publisher_stream_shape(file->get());
        file_facts = publisher_handle_observation_json(facts);
        if (!GetFileSizeEx(file->get(), &file_size) || !GetFileInformationByHandleEx(file->get(), FileBasicInfo,
                &file_basic, sizeof(file_basic))) throw std::runtime_error("operation context file facts unavailable");
    }
    void fence() const {
        guard.require_owned(volume_root, install_id);
        if (!file || !equal(volume_identity, root_identity(volume, service_sid))) throw InstallLeaseStale();
        const auto link = [&](HANDLE parent, const std::wstring& name, HANDLE retained, bool regular) {
            const auto entry = child(parent, name);
            if (!entry) throw InstallLeaseStale();
            Handle current(open_publisher_listed_child(parent, *entry));
            const auto held = regular ? observe_publisher_file_handle(retained) : observe_publisher_directory_handle(retained);
            const auto fresh = regular ? observe_publisher_file_handle(current.get()) : observe_publisher_directory_handle(current.get());
            require_publisher_object_security_shape(held, service_sid);
            require_publisher_object_security_shape(fresh, service_sid);
            require_publisher_stream_shape(current.get());
            if (!equal(publisher_handle_observation_json(held), publisher_handle_observation_json(fresh)))
                throw InstallLeaseStale();
        };
        link(volume, L"installation-operations", operations->get(), false);
        link(operations->get(), install_name, records->get(), false);
        link(records->get(), L"pending", pending->get(), false);
        link(records->get(), context_name, file->get(), true);
        LARGE_INTEGER size{};
        FILE_BASIC_INFO basic{};
        if (!GetFileSizeEx(file->get(), &size) || !GetFileInformationByHandleEx(file->get(), FileBasicInfo,
                &basic, sizeof(basic)) || size.QuadPart != file_size.QuadPart ||
            basic.LastWriteTime.QuadPart != file_basic.LastWriteTime.QuadPart ||
            basic.ChangeTime.QuadPart != file_basic.ChangeTime.QuadPart ||
            !equal(file_facts, publisher_handle_observation_json(observe_publisher_file_handle(file->get()))))
            throw InstallLeaseStale();
        if (roots_file) {
            link(records->get(), roots_name, roots_file->get(), true);
            LARGE_INTEGER root_size{};
            FILE_BASIC_INFO root_basic{};
            if (!GetFileSizeEx(roots_file->get(), &root_size) || !GetFileInformationByHandleEx(
                    roots_file->get(), FileBasicInfo, &root_basic, sizeof(root_basic)) ||
                root_size.QuadPart != roots_size.QuadPart ||
                root_basic.LastWriteTime.QuadPart != roots_basic.LastWriteTime.QuadPart ||
                root_basic.ChangeTime.QuadPart != roots_basic.ChangeTime.QuadPart ||
                !equal(roots_facts, publisher_handle_observation_json(observe_publisher_file_handle(roots_file->get()))))
                throw InstallLeaseStale();
            const auto& snapshot = original.at("reviewed_snapshot");
            const auto setup_name = kind == PublisherOperationKind::install_local ?
                std::filesystem::u8path(snapshot.at("setup_root").as_string()).filename().wstring() :
                std::filesystem::u8path(snapshot.at("setup_component").as_string()).wstring();
            const auto setup_entry = child(volume, setup_name);
            if (!setup_entry) throw InstallLeaseStale();
            Handle setup(open_publisher_listed_child(volume, *setup_entry));
            const auto state_entry = child(setup.get(), L"state");
            if (!state_entry) throw InstallLeaseStale();
            Handle state(open_publisher_listed_child(setup.get(), *state_entry));
            if (!equal(roots_record.at("setup_root_identity"), root_identity(setup.get(), service_sid)) ||
                !equal(roots_record.at("state_root_identity"), root_identity(state.get(), service_sid)))
                throw InstallLeaseStale();
        }
    }
    void load_roots() {
        const auto entry = child(records->get(), roots_name);
        if (!entry) return;
        roots_file = std::make_unique<Handle>(open_publisher_listed_child(records->get(), *entry));
        roots_facts = publisher_handle_observation_json(observe_publisher_file_handle(roots_file->get()));
        if (!GetFileSizeEx(roots_file->get(), &roots_size) || !GetFileInformationByHandleEx(
                roots_file->get(), FileBasicInfo, &roots_basic, sizeof(roots_basic))) throw InstallLeaseStale();
        const auto text = read_held_text(roots_file->get(), service_sid, record_limit);
        roots_record = usk::json::parse(text);
        const std::set<std::string> fields{"schema", "install_id", "operation_id", "context_sha256",
            "setup_root_identity", "state_root_identity", "roots_sha256"};
        if (roots_record.as_object().size() != fields.size()) throw InstallLeaseStale();
        for (const auto& item : roots_record.as_object())
            if (!fields.count(item.first)) throw InstallLeaseStale();
        auto unsealed = roots_record;
        unsealed.as_object().erase("roots_sha256");
        if (roots_record.at("schema").as_string() != "usk.installation_operation_roots.v1" ||
            roots_record.at("install_id").as_string() != install_id ||
            roots_record.at("operation_id").as_string() != operation_id ||
            roots_record.at("context_sha256").as_string() != original.at("context_sha256").as_string() ||
            roots_record.at("roots_sha256").as_string() != usk::json::sha256_canonical(unsealed) ||
            usk::json::canonical(roots_record) + "\n" != text) throw InstallLeaseStale();
        fence();
    }
    void bind_roots(HANDLE setup, HANDLE state) {
        fence();
        if (kind != PublisherOperationKind::install_local &&
            (!equal(root_identity(setup, service_sid), original.at("reviewed_snapshot").at("setup_root_identity")) ||
             !equal(root_identity(state, service_sid), original.at("reviewed_snapshot").at("state_root_identity"))))
            throw InstallLeaseStale();
        Value wanted(Value::Object{{"schema", Value("usk.installation_operation_roots.v1")},
            {"install_id", Value(install_id)}, {"operation_id", Value(operation_id)},
            {"context_sha256", original.at("context_sha256")},
            {"setup_root_identity", root_identity(setup, service_sid)},
            {"state_root_identity", root_identity(state, service_sid)}});
        wanted.as_object().emplace("roots_sha256", Value(usk::json::sha256_canonical(wanted)));
        if (roots_file) {
            if (!equal(wanted, roots_record)) throw InstallLeaseStale();
            return;
        }
        if (observe_publisher_directory_entries(records->get()).size() >= history_limit ||
            observe_publisher_directory_entries(pending->get()).size() >= history_limit)
            throw std::runtime_error("operation root binding budget exhausted");
        const auto text = usk::json::canonical(wanted) + "\n";
        static std::atomic<std::uint64_t> sequence{0};
        const auto temporary = L"roots-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(++sequence);
        Handle output(create_file_relative_with_descriptor(pending->get(), temporary, descriptor));
        DWORD written = 0;
        require_current_publisher_effect_fence();
        if (!WriteFile(output.get(), text.data(), static_cast<DWORD>(text.size()), &written, nullptr) ||
            written != text.size() || !FlushFileBuffers(output.get())) throw std::runtime_error("operation roots write or flush failed");
        publish_publisher_record_no_replace(output.get(), records->get(), roots_name, service_sid);
        load_roots();
        if (!roots_file || !equal(wanted, roots_record)) throw InstallLeaseStale();
    }
    std::wstring bootstrap_name(const Value& reservation, const wchar_t* record_kind) const {
        return context_name.substr(0, context_name.size() - 5) + record_kind +
            generation_name(reservation.at("ownership").at("generation").as_unsigned());
    }
    Value reservation_for(const Value& ownership) const {
        require_install_lease_record(ownership);
        if (!roots_file || ownership.at("status").as_string() != "active" ||
            ownership.at("install_id").as_string() != install_id ||
            ownership.at("operation").as_string() != "install_local" ||
            ownership.at("operation_id").as_string() != operation_id ||
            ownership.at("operation_context_sha256").as_string() != roots_record.at("roots_sha256").as_string() ||
            !equal(ownership.at("state_root_identity"), roots_record.at("state_root_identity"))) throw InstallLeaseStale();
        Value result(Value::Object{{"schema", Value("usk.publication_bootstrap_reservation.v1")},
            {"install_id", Value(install_id)}, {"operation_id", Value(operation_id)},
            {"context_sha256", original.at("context_sha256")},
            {"roots_sha256", roots_record.at("roots_sha256")},
            {"volume_root_identity", volume_identity}, {"ownership", ownership},
            {"publication_absent", Value(true)}});
        result.as_object().emplace("reservation_sha256", Value(usk::json::sha256_canonical(result)));
        return result;
    }
    void require_reserved_native_ownership(const Value& reservation) const {
        const auto& ownership = reservation.at("ownership");
        if (!equal(reservation, reservation_for(ownership))) throw InstallLeaseStale();
        const auto setup_name = std::filesystem::u8path(original.at("reviewed_snapshot").at("setup_root").as_string()).filename().wstring();
        const auto open = [&](HANDLE parent, const std::wstring& name) {
            const auto entry = child(parent, name);
            if (!entry) throw InstallLeaseStale();
            return std::make_unique<Handle>(open_publisher_listed_child(parent, *entry));
        };
        auto setup = open(volume, setup_name);
        auto state = open(setup->get(), L"state");
        auto leases = open(state->get(), L"leases");
        auto history = open(leases->get(), install_name);
        const auto entry = child(history->get(), record_name(ownership));
        if (!entry || !equal(read_record(history->get(), *entry, service_sid), ownership)) throw InstallLeaseStale();
    }
    std::vector<Value> reservations() const {
        fence();
        const auto prefix = context_name.substr(0, context_name.size() - 5) + L"-bootstrap-";
        std::map<std::uint64_t, Value> ordered;
        for (const auto& entry : observe_publisher_directory_entries(records->get())) {
            if (entry.name.compare(0, prefix.size(), prefix) != 0) continue;
            const auto text = read_text(records->get(), entry, service_sid, record_limit);
            auto value = usk::json::parse(text);
            require_reserved_native_ownership(value);
            if (text != usk::json::canonical(value) + "\n" ||
                entry.name != bootstrap_name(value, L"-bootstrap-") + L".json" ||
                !ordered.emplace(value.at("ownership").at("generation").as_unsigned(), value).second)
                throw InstallLeaseStale();
        }
        if (ordered.size() > 64) throw std::runtime_error("publication bootstrap attempt budget exhausted");
        std::vector<Value> result;
        for (auto& item : ordered) result.push_back(std::move(item.second));
        return result;
    }
    PublisherTreeObservation partial_tree(HANDLE publication) const {
        const auto tree = observe_publisher_tree(publication);
        require_publisher_tree_security_shape(tree, service_sid);
        require_publisher_stream_shape(tree.root_streams, true);
        require_publisher_bootstrap_prefix_shape(tree);
        for (const auto& entry : tree.descendants) {
            const bool directory_entry = (entry.object.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            require_publisher_stream_shape(entry.streams, directory_entry);
            if (!directory_entry) {
                const auto journal_entry = child(publication, L"journal");
                if (!journal_entry) throw InstallLeaseStale();
                Handle journal(open_publisher_listed_child(publication, *journal_entry));
                const auto record_entry = child(journal.get(), L"lab-reviewed-plan.json");
                if (!record_entry) throw InstallLeaseStale();
                Handle record(open_publisher_listed_child(journal.get(), *record_entry));
                const auto bytes = read_held_text(record.get(), service_sid, 4u * 1024u * 1024u, true);
                const auto expected = usk::json::canonical(original.at("reviewed_snapshot")) + "\n";
                if (bytes.size() > expected.size() || expected.compare(0, bytes.size(), bytes) != 0)
                    throw InstallLeaseStale();
            }
        }
        require_publisher_tree_phase_match(tree, observe_publisher_tree(publication));
        return tree;
    }
    bool bootstrap_resume_required() const {
        if (kind != PublisherOperationKind::install_local) throw InstallLeaseStale();
        const auto history = reservations();
        if (history.empty()) return false; // Older partial roots are retained; no invented reservation.
        const auto publication_entry = child(volume, L"publication");
        if (!publication_entry) return true;
        Handle publication(open_publisher_listed_child(volume, *publication_entry));
        // A candidate or prepared record belongs to existing staged recovery,
        // never the pre-candidate bootstrap preservation path.
        const auto staging_entry = child(publication.get(), L"staging");
        if (staging_entry) {
            Handle staging(open_publisher_listed_child(publication.get(), *staging_entry));
            if (child(staging.get(), L"candidate")) return false;
        }
        const auto journal_entry = child(publication.get(), L"journal");
        if (journal_entry) {
            Handle journal(open_publisher_listed_child(publication.get(), *journal_entry));
            if (child(journal.get(), L"lab-prepared-evidence.json")) return false;
        }
        (void)partial_tree(publication.get());
        return true;
    }
    Value read_bootstrap_record(const std::wstring& name) const {
        const auto entry = child(records->get(), name);
        if (!entry) throw InstallLeaseStale();
        const auto text = read_text(records->get(), *entry, service_sid, 4u * 1024u * 1024u);
        const auto value = usk::json::parse(text);
        if (text != usk::json::canonical(value) + "\n") throw InstallLeaseStale();
        return value;
    }
    void write_bootstrap_record(const std::wstring& name, const Value& value) {
        fence();
        if (child(records->get(), name)) {
            if (!equal(read_bootstrap_record(name), value)) throw InstallLeaseStale();
            return;
        }
        if (observe_publisher_directory_entries(records->get()).size() >= history_limit ||
            observe_publisher_directory_entries(pending->get()).size() >= history_limit) throw InstallLeaseStale();
        const auto text = usk::json::canonical(value) + "\n";
        if (text.size() > 4u * 1024u * 1024u) throw InstallLeaseStale();
        static std::atomic<std::uint64_t> sequence{0};
        const auto temporary = L"bootstrap-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(++sequence);
        Handle output(create_file_relative_with_descriptor(pending->get(), temporary, descriptor));
        DWORD written = 0;
        require_current_publisher_effect_fence();
        if (!WriteFile(output.get(), text.data(), static_cast<DWORD>(text.size()), &written, nullptr) ||
            written != text.size() || !FlushFileBuffers(output.get())) throw InstallLeaseStale();
        publish_publisher_record_no_replace(output.get(), records->get(), name, service_sid);
        if (!equal(read_bootstrap_record(name), value)) throw InstallLeaseStale();
    }
    void prepare_publication(const PublisherInstallationLease& lease) {
        if (kind != PublisherOperationKind::install_local) throw InstallLeaseStale();
        fence();
        lease.require_start();
        const auto current = reservation_for(lease.ownership());
        auto history = reservations();
        for (std::size_t index = 0; index < history.size(); ++index) {
            const auto& reserved = history[index];
            const auto move_name = bootstrap_name(reserved, L"-preserve-") + L".json";
            const auto retained_name = bootstrap_name(reserved, L"-retained-");
            const auto move_entry = child(records->get(), move_name);
            const auto retained_entry = child(records->get(), retained_name);
            const bool latest = index + 1 == history.size();
            if (!move_entry && !retained_entry && !latest) throw InstallLeaseStale();
            if (move_entry || retained_entry) {
                if (!move_entry) throw InstallLeaseStale();
                const auto move = read_bootstrap_record(move_name);
                auto unsealed = move;
                unsealed.as_object().erase("preservation_sha256");
                if (move.at("schema").as_string() == "usk.publication_bootstrap_absence.v1") {
                    Value absent(Value::Object{{"schema", Value("usk.publication_bootstrap_absence.v1")},
                        {"install_id", Value(install_id)}, {"operation_id", Value(operation_id)},
                        {"reservation_sha256", reserved.at("reservation_sha256")},
                        {"closing_ownership", move.at("closing_ownership")}, {"publication_absent", Value(true)}});
                    absent.as_object().emplace("preservation_sha256", Value(usk::json::sha256_canonical(absent)));
                    const auto closing = reservation_for(move.at("closing_ownership"));
                    require_reserved_native_ownership(closing);
                    if (!equal(move, absent) || retained_entry ||
                        closing.at("ownership").at("generation").as_unsigned() <= reserved.at("ownership").at("generation").as_unsigned())
                        throw InstallLeaseStale();
                    continue;
                }
                if (move.as_object().size() != 10 || move.at("schema").as_string() != "usk.publication_bootstrap_preservation.v1" ||
                    move.at("reservation_sha256").as_string() != reserved.at("reservation_sha256").as_string() ||
                    move.at("install_id").as_string() != install_id || move.at("operation_id").as_string() != operation_id ||
                    !equal(move.at("destination_parent_identity"), root_identity(records->get(), service_sid)) ||
                    move.at("destination_name").as_string() != std::filesystem::path(retained_name).u8string() ||
                    move.at("source_name").as_string() != "publication" ||
                    move.at("preservation_sha256").as_string() != usk::json::sha256_canonical(unsealed)) throw InstallLeaseStale();
                if (retained_entry) {
                    Handle retained(open_publisher_listed_child(records->get(), *retained_entry));
                    if (!equal(move.at("tree"), bootstrap_tree_facts(partial_tree(retained.get()))) ||
                        move.at("source_root_identity").as_string() != observe_publisher_directory_handle(retained.get()).file_id)
                        throw InstallLeaseStale();
                    continue;
                }
                if (!latest) throw InstallLeaseStale();
            }
            if (!latest) continue;
            const auto publication_entry = child(volume, L"publication");
            if (!publication_entry) {
                if (move_entry) throw InstallLeaseStale();
                if (!equal(reserved.at("ownership"), lease.ownership())) {
                    Value absent(Value::Object{{"schema", Value("usk.publication_bootstrap_absence.v1")},
                        {"install_id", Value(install_id)}, {"operation_id", Value(operation_id)},
                        {"reservation_sha256", reserved.at("reservation_sha256")},
                        {"closing_ownership", lease.ownership()}, {"publication_absent", Value(true)}});
                    absent.as_object().emplace("preservation_sha256", Value(usk::json::sha256_canonical(absent)));
                    write_bootstrap_record(move_name, absent);
                }
                continue;
            }
            if (equal(reserved.at("ownership"), lease.ownership())) throw InstallLeaseStale();
            const auto previous_holder = observe_publisher_previous_lease_holder(reserved.at("ownership").at("holder"));
            if (previous_holder != InstallLeasePreviousHolder::ended && previous_holder != InstallLeasePreviousHolder::identity_reused)
                throw InstallLeaseConflict();
            Handle publication(open_publisher_listed_child(volume, *publication_entry, false, true));
            const auto tree = partial_tree(publication.get());
            Value move(Value::Object{{"schema", Value("usk.publication_bootstrap_preservation.v1")},
                {"install_id", Value(install_id)}, {"operation_id", Value(operation_id)},
                {"reservation_sha256", reserved.at("reservation_sha256")},
                {"source_name", Value("publication")}, {"source_root_identity", Value(tree.root.file_id)},
                {"destination_parent_identity", root_identity(records->get(), service_sid)},
                {"destination_name", Value(std::filesystem::path(retained_name).u8string())},
                {"tree", bootstrap_tree_facts(tree)}});
            move.as_object().emplace("preservation_sha256", Value(usk::json::sha256_canonical(move)));
            write_bootstrap_record(move_name, move);
            lease.require_start();
            require_publisher_tree_phase_match(tree, partial_tree(publication.get()));
            const auto parent = observe_publisher_directory_handle(records->get());
            (void)probe_publisher_bound_rename_no_replace(publication.get(), records->get(), retained_name, tree.root, parent);
            require_publisher_tree_phase_match(tree, partial_tree(publication.get()), parent.native_name + L"\\" + retained_name);
            if (child(volume, L"publication")) throw InstallLeaseStale();
        }
        lease.require_start();
        if (child(volume, L"publication")) throw InstallLeaseStale();
        if (history.size() >= 64 && (history.empty() || !equal(history.back(), current)))
            throw std::runtime_error("publication bootstrap attempt budget exhausted");
        write_bootstrap_record(bootstrap_name(current, L"-bootstrap-") + L".json", current);
    }
    void prepare(const Value& snapshot, const std::string& revision) {
        guard.require_owned(volume_root, install_id);
        const bool install_context = kind == PublisherOperationKind::install_local;
        if (install_context && revision != usk::json::sha256_canonical(Value(Value::Array{})))
            throw InstallStateRevisionStale();
        if (!install_context) {
            require_publisher_maintenance_snapshot_binding(snapshot, kind, install_id, operation_id, revision);
            if (!equal(snapshot.at("volume_root_identity"), volume_identity)) throw InstallLeaseStale();
        }
        if (file) {
            fence();
            if (!equal(original.at("reviewed_snapshot"), snapshot) ||
                original.at("initial_state_revision").as_string() != revision) throw InstallLeaseConflict();
            return;
        }
        if (!equal(volume_identity, root_identity(volume, service_sid))) throw InstallLeaseStale();
        Value value(Value::Object{{"schema", Value(install_context ?
                "usk.installation_operation_context.v1" : "usk.installation_operation_context.v2")},
            {"install_id", Value(install_id)}, {"operation", Value(operation_name(kind))},
            {"operation_id", Value(operation_id)}, {"volume_root_identity", volume_identity},
            {"initial_state_revision", Value(revision)}, {"reviewed_snapshot", snapshot}});
        value.as_object().emplace("context_sha256", Value(usk::json::sha256_canonical(value)));
        const auto text = usk::json::canonical(value) + "\n";
        if (text.size() > context_limit(kind)) throw std::runtime_error("operation context record budget exhausted");
        if (!operations) operations = directory(volume, L"installation-operations", true);
        if (!records) records = directory(operations->get(), install_name, true);
        if (!pending) pending = directory(records->get(), L"pending", true);
        if (observe_publisher_directory_entries(records->get()).size() >= history_limit ||
            observe_publisher_directory_entries(pending->get()).size() >= history_limit)
            throw std::runtime_error("operation context history budget exhausted");
        static std::atomic<std::uint64_t> sequence{0};
        const auto temporary = L"context-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(++sequence);
        Handle output(create_file_relative_with_descriptor(pending->get(), temporary, descriptor));
        DWORD written = 0;
        require_current_publisher_effect_fence();
        if (!WriteFile(output.get(), text.data(), static_cast<DWORD>(text.size()), &written, nullptr) ||
            written != text.size() || !FlushFileBuffers(output.get()))
            throw std::runtime_error("operation context write or flush failed");
        publish_publisher_record_no_replace(output.get(), records->get(), context_name, service_sid);
        const auto entry = child(records->get(), context_name);
        if (!entry || read_text(records->get(), *entry, service_sid, context_limit(kind)) != text)
            throw std::runtime_error("operation context durable readback differs");
        original = std::move(value);
        bind_file(*entry);
        if (read_held_text(file->get(), service_sid, context_limit(kind)) != text)
            throw std::runtime_error("operation context retained-handle readback differs");
        fence();
    }
};
PublisherInstallOperationContext::PublisherInstallOperationContext(HANDLE volume, const std::wstring& root,
    const std::wstring& service, const PublisherInstallOperationGuard& guard,
    const std::string& install_id, const std::string& operation_id)
    : PublisherInstallOperationContext(volume, root, service, guard, install_id, operation_id,
        PublisherOperationKind::install_local) {}
PublisherInstallOperationContext::PublisherInstallOperationContext(HANDLE volume, const std::wstring& root,
    const std::wstring& service, const PublisherInstallOperationGuard& guard,
    const std::string& install_id, const std::string& operation_id, PublisherOperationKind kind)
    : impl_(std::make_unique<Impl>(volume, root, service, guard, install_id, operation_id, kind)) {}
PublisherInstallOperationContext::~PublisherInstallOperationContext() = default;
bool PublisherInstallOperationContext::exists() const { return bool(impl_->file); }
void PublisherInstallOperationContext::prepare(const Value& snapshot, const std::string& revision) {
    if (impl_->kind != PublisherOperationKind::install_local) throw InstallLeaseStale();
    impl_->prepare(snapshot, revision);
}
void PublisherInstallOperationContext::prepare_maintenance(const PublisherMaintenanceStateSnapshot& state,
    const Value& plan, const Value& request) {
    if (impl_->kind == PublisherOperationKind::install_local) throw InstallLeaseStale();
    const auto snapshot = state.reviewed_snapshot(impl_->kind, impl_->operation_id, plan, request);
    state.require_initial_revision();
    impl_->prepare(snapshot, state.initial_state_revision());
    state.require_initial_revision();
    impl_->bind_roots(state.setup_root(), state.state_root());
    state.require_initial_revision();
}
std::unique_ptr<PublisherMaintenanceStateSnapshot> PublisherInstallOperationContext::restore_maintenance_state() const {
    if (impl_->kind == PublisherOperationKind::install_local) throw InstallLeaseStale();
    impl_->fence();
    // The private constructor receives only this context's held immutable
    // original snapshot. Arbitrary request JSON cannot select older custody.
    return std::unique_ptr<PublisherMaintenanceStateSnapshot>(new PublisherMaintenanceStateSnapshot(
        impl_->volume, impl_->volume_root, impl_->service_name,
        impl_->guard, impl_->original.at("reviewed_snapshot")));
}
void PublisherInstallOperationContext::bind_state_roots(HANDLE setup, HANDLE state) {
    impl_->bind_roots(setup, state);
}
std::string PublisherInstallOperationContext::lease_binding_sha256() const {
    impl_->fence();
    if (!impl_->roots_file) throw InstallLeaseStale();
    return impl_->roots_record.at("roots_sha256").as_string();
}
const Value& PublisherInstallOperationContext::record() const { impl_->fence(); return impl_->original; }
bool PublisherInstallOperationContext::bootstrap_resume_required() const { return impl_->bootstrap_resume_required(); }
void PublisherInstallOperationContext::prepare_publication(const PublisherInstallationLease& lease) {
    impl_->prepare_publication(lease);
}
void PublisherInstallOperationContext::require_fence() const { impl_->fence(); }

struct PublisherInstallationLease::Impl {
    HANDLE state_root;
    std::wstring volume_root;
    const PublisherInstallOperationGuard& guard;
    InstallLeaseRequest request;
    std::function<std::string()> observe_revision;
    std::string service_sid;
    std::vector<unsigned char> descriptor;
    std::unique_ptr<Handle> leases, records, pending;
    Value root, holder, active;
    std::wstring state_name, records_name;
    bool terminal = false;

    Impl(HANDLE state, const std::wstring& volume, const std::wstring& service,
        const PublisherInstallOperationGuard& held, const InstallLeaseRequest& wanted,
        const std::function<std::string()>& revision)
        : state_root(state), volume_root(volume), guard(held), request(wanted), observe_revision(revision) {
        guard.require_owned(volume_root, request.install_id);
        if (!observe_revision) throw std::runtime_error("lease state observation unavailable");
        const auto current_service = observe_current_restricted_publisher_service(service);
        service_sid = current_service.service_sid;
        root = root_identity(state_root, service_sid);
        state_name = observe_publisher_directory_handle(state_root).native_name;
        holder = observe_publisher_lease_holder();
        // Validate the complete request and reviewed revision before creating
        // the journal. These observations are repeated after durable ownership.
        const auto observed_revision = observe_revision();
        (void)derive_install_lease_ownership({}, request, root, holder, observed_revision);
        descriptor = make_publisher_directory_security_descriptor(
            std::wstring(service_sid.begin(), service_sid.end()));
        leases = directory(state_root, L"leases");
        const std::string digest = usk::json::sha256_canonical(Value(request.install_id));
        records_name = L"install-" + std::wstring(digest.begin(), digest.end());
        records = directory(leases->get(), records_name);
        pending = directory(records->get(), L"pending");
        const auto previous = latest();
        const auto previous_holder = previous && previous->at("status").as_string() == "active" ?
            observe_publisher_previous_lease_holder(previous->at("holder")) : InstallLeasePreviousHolder::unknown;
        active = derive_install_lease_ownership(previous, request, root, holder, observed_revision, previous_holder);
        append(active);
        fence();
        require_install_lease_start(active, observe_revision());
    }

    std::unique_ptr<Handle> directory(HANDLE parent, const std::wstring& name) {
        guard.require_owned(volume_root, request.install_id);
        (void)root_identity(parent, service_sid);
        const auto entry = child(parent, name);
        auto result = std::make_unique<Handle>(entry ? open_publisher_listed_child(parent, *entry, true, false, true) :
            create_record_directory_relative_with_descriptor(parent, name, descriptor));
        (void)root_identity(result->get(), service_sid);
        return result;
    }

    std::optional<Value> latest() const {
        guard.require_owned(volume_root, request.install_id);
        if (!equal(root, root_identity(state_root, service_sid)) ||
            observe_publisher_directory_handle(state_root).native_name != state_name) throw InstallLeaseStale();
        (void)root_identity(leases->get(), service_sid);
        (void)root_identity(records->get(), service_sid);
        (void)root_identity(pending->get(), service_sid);
        const auto require_link = [&](HANDLE parent, const std::wstring& name, HANDLE retained) {
            const auto entry = child(parent, name);
            if (!entry) throw InstallLeaseStale();
            Handle current(open_publisher_listed_child(parent, *entry));
            const auto held_facts = observe_publisher_directory_handle(retained);
            const auto current_facts = observe_publisher_directory_handle(current.get());
            if (!equal(publisher_handle_observation_json(held_facts), publisher_handle_observation_json(current_facts)))
                throw InstallLeaseStale();
        };
        require_link(state_root, L"leases", leases->get());
        require_link(leases->get(), records_name, records->get());
        require_link(records->get(), L"pending", pending->get());
        const auto entries = observe_publisher_directory_entries(records->get());
        if (entries.size() > history_limit + 1) throw std::runtime_error("lease history budget exhausted");
        std::map<std::wstring, Value> history;
        for (const auto& entry : entries) {
            if (entry.name == L"pending") continue;
            auto value = read_record(records->get(), entry, service_sid);
            if (value.at("install_id").as_string() != request.install_id ||
                !equal(value.at("state_root_identity"), root) ||
                !history.emplace(entry.name, std::move(value)).second)
                throw std::runtime_error("lease history identity differs");
        }
        std::optional<Value> previous;
        for (const auto& [name, value] : history) {
            (void)name;
            Value expected;
            if (value.at("status").as_string() == "active") {
                InstallLeaseRequest transition{request.install_id, value.at("operation").as_string(),
                    value.at("operation_id").as_string(), value.at("attempt_id").as_string(),
                    value.at("expected_state_revision").as_string(), true,
                    value.at("operation_context_sha256").as_string()};
                expected = derive_install_lease_ownership(previous, transition, root, value.at("holder"),
                    transition.expected_state_revision, InstallLeasePreviousHolder::ended);
            } else {
                if (!previous) throw std::runtime_error("lease history starts at terminal state");
                expected = finish_install_lease_ownership(*previous, root, previous->at("holder"),
                    value.at("result_state_revision").as_string(), value.at("status").as_string() == "handoff");
            }
            if (!equal(value, expected)) throw std::runtime_error("lease history transition differs");
            previous = value;
        }
        return previous;
    }

    void append(const Value& value) {
        guard.require_owned(volume_root, request.install_id);
        const auto required_slots = value.at("status").as_string() == "active" ? 2u : 1u;
        if (observe_publisher_directory_entries(records->get()).size() > history_limit + 1 - required_slots ||
            observe_publisher_directory_entries(pending->get()).size() >= history_limit)
            throw std::runtime_error("lease journal budget exhausted; recovery retained");
        const std::string text = usk::json::canonical(value) + "\n";
        if (text.size() > record_limit) throw std::runtime_error("lease record budget exhausted");
        static std::atomic<std::uint64_t> sequence{0};
        const std::wstring temporary = L"record-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(++sequence);
        Handle file(create_file_relative_with_descriptor(pending->get(), temporary, descriptor));
        DWORD written = 0;
        require_current_publisher_effect_fence();
        if (!WriteFile(file.get(), text.data(), static_cast<DWORD>(text.size()), &written, nullptr) ||
            written != text.size() || !FlushFileBuffers(file.get()))
            throw std::runtime_error("lease pending record write or flush failed");
        publish_publisher_record_no_replace(file.get(), records->get(), record_name(value), service_sid);
        const auto current = latest();
        if (!current || !equal(*current, value)) throw std::runtime_error("lease durable readback differs");
    }
    void fence() const {
        if (terminal) throw InstallLeaseStale();
        const auto current = latest();
        if (!current) throw InstallLeaseStale();
        require_install_lease_fence(active, *current, root_identity(state_root, service_sid),
            observe_publisher_lease_holder());
    }
};

PublisherInstallationLease::PublisherInstallationLease(HANDLE state, const std::wstring& volume,
    const std::wstring& service, const PublisherInstallOperationGuard& guard,
    const InstallLeaseRequest& request, const std::function<std::string()>& revision)
    : impl_(std::make_unique<Impl>(state, volume, service, guard, request, revision)) {}
PublisherInstallationLease::~PublisherInstallationLease() = default;
void PublisherInstallationLease::require_start() const {
    impl_->fence();
    require_install_lease_start(impl_->active, impl_->observe_revision());
}
void PublisherInstallationLease::require_fence() const { impl_->fence(); }
const Value& PublisherInstallationLease::ownership() const { return impl_->active; }
void PublisherInstallationLease::finish(bool handoff) {
    impl_->fence();
    const auto terminal = finish_install_lease_ownership(impl_->active,
        root_identity(impl_->state_root, impl_->service_sid), observe_publisher_lease_holder(),
        impl_->observe_revision(), handoff);
    impl_->append(terminal);
    impl_->active = terminal;
    impl_->terminal = true;
}
} // namespace usk::platform::windows
#endif
