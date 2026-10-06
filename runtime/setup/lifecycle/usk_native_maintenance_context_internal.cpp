// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_native_maintenance_context_internal.h"
#if defined(_WIN32)
#include "usk_publisher_anchor_create.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_execution_observation.h"
#include "usk_publisher_metadata.h"
#include "usk_publisher_process_boundary.h"
#include "usk_publisher_registration.h"
#include "usk_publisher_request_channel.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_tree_observation.h"
#include "usk_publisher_worker_security.h"
#include "usk_record_io.h"
#include "usk_sha256.h"
#include <algorithm>
#include <array>
#include <iomanip>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace usk::lifecycle::detail {
namespace fs = std::filesystem;
using usk::json::Value;
using namespace usk::platform::windows;
namespace {
bool equal(const Value& a, const Value& b) { return json::canonical(a) == json::canonical(b); }
bool same(const PublisherHandleObservation& a, const PublisherHandleObservation& b) {
    return equal(publisher_handle_observation_json(a), publisher_handle_observation_json(b));
}
class Held final {
public:
    Held() = default;
    ~Held() { if (value != INVALID_HANDLE_VALUE && value) CloseHandle(value); }
    Held(const Held&) = delete;
    Held& operator=(const Held&) = delete;
    HANDLE value = INVALID_HANDLE_VALUE;
};
std::optional<PublisherDirectoryEntry> child(HANDLE parent, const std::wstring& name) {
    std::optional<PublisherDirectoryEntry> result;
    for (const auto& entry : observe_publisher_directory_entries(parent)) {
        if (CompareStringOrdinal(entry.name.c_str(), -1, name.c_str(), -1, TRUE) != CSTR_EQUAL) continue;
        if (entry.name != name || result) throw std::runtime_error("native maintenance child name is ambiguous");
        result = entry;
    }
    return result;
}
std::string journal_identity(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info)) throw std::runtime_error("native maintenance journal identity unavailable");
    std::ostringstream text;
    text << std::hex << std::setfill('0') << std::setw(16) << info.dwVolumeSerialNumber << ':' <<
        std::setw(16) << ((static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow);
    return text.str();
}
}
struct NativeMaintenanceContext::Impl {
    struct Entry {
        Held handle;
        Entry* parent = nullptr;
        std::wstring name;
        PublisherHandleObservation facts{};
        bool directory = true, created = false, complete = false;
        std::uint64_t size = 0;
        std::string sha256, stream_identity;
    };
    HANDLE volume;
    const std::wstring volume_root, service_name;
    const PublisherInstallOperationGuard& guard;
    const PublisherMaintenanceStateSnapshot& original_state;
    const PublisherInstallOperationContext& original_context;
    const PublisherInstallationLease& lease;
    const RegisteredPublisherAdmission& admission;
    const PublisherRequestChannel& channel;
    const transaction::TransactionSpec spec;
    HANDLE cancel_event;
    PublisherServiceObservation service;
    Value worker, process_boundary, registration, selection, client;
    PublisherHandleObservation volume_facts;
    PublisherVolumeObservation volume_observation;
    std::vector<unsigned char> descriptor;
    std::map<fs::path, std::unique_ptr<Entry>> directories;
    std::map<fs::path, std::unique_ptr<Entry>> files;
    Entry* staging_parent = nullptr;
    Entry* target_parent = nullptr;
    Entry* staging = nullptr;
    bool publication_attempted = false;
    transaction::detail::NativeMaintenanceTransactionOperations operations;
    std::function<void()> effect_fence;
    std::unique_ptr<PublisherMetadataSession> metadata;

    Impl(HANDLE boundary, const std::wstring& root, const std::wstring& service_label,
        const PublisherInstallOperationGuard& installation_guard,
        const PublisherMaintenanceStateSnapshot& state,
        const PublisherInstallOperationContext& context, const PublisherInstallationLease& active_lease,
        const RegisteredPublisherAdmission& registered, const PublisherRequestChannel& authenticated,
        const transaction::TransactionSpec& transaction_spec, HANDLE cancel)
        : volume(boundary), volume_root(root), service_name(service_label), guard(installation_guard),
          original_state(state), original_context(context), lease(active_lease), admission(registered),
          channel(authenticated), spec(transaction_spec), cancel_event(cancel) {
        const auto& snapshot = original_context.record().at("reviewed_snapshot");
        if (snapshot.at("schema").as_string() != "usk.publisher.maintenance_reviewed_snapshot.v2" ||
            !admission.has_selected_reviewed_operation() ||
            !equal(admission.selected_reviewed_envelope().at("apply_request"), snapshot.at("apply_request")))
            throw std::runtime_error("native maintenance lacks its exact original reviewed request");
        const auto& plan = snapshot.at("reviewed_plan");
        if (spec.operation != snapshot.at("operation").as_string() ||
            spec.transaction_id != snapshot.at("operation_id").as_string() ||
            spec.plan_id != plan.at("plan_id").as_string() || spec.plan_digest != json::sha256_canonical(plan) ||
            normalized(spec.state_root) != normalized(fs::u8path(plan.at("state_root").as_string())) ||
            normalized(spec.audit_root) != normalized(fs::u8path(plan.at("audit_root").as_string())) ||
            normalized(spec.staging_parent) != normalized(fs::u8path(plan.at("staging_parent").as_string())) ||
            spec.required_commit_authority != transaction::CommitAuthorityRequirement::legacy_observed)
            throw std::runtime_error("native maintenance transaction differs from the original reviewed plan");
        const auto installed_root = normalized(fs::u8path(snapshot.at("installed_state").at("target_root").as_string()));
        const fs::path expected_target = spec.operation == "move" ? fs::u8path(plan.at("new_root").as_string()) :
            installed_root.parent_path() / ((spec.operation == "repair" ? ".usk-repair-" : ".usk-uninstall-") + spec.transaction_id);
        if ((spec.operation != "repair" && spec.operation != "move" && spec.operation != "uninstall") ||
            normalized(spec.target_root) != normalized(expected_target) ||
            normalized(spec.state_root.parent_path()).filename().u8string() != snapshot.at("setup_component").as_string())
            throw std::runtime_error("native maintenance operation target differs from its original action");
        original_state.require_initial_revision();
        original_context.require_fence();
        lease.require_start();
        if (!equal(original_state.installed_state(), snapshot.at("installed_state")) ||
            !equal(original_state.ownership_manifest(), snapshot.at("ownership_manifest")) ||
            original_state.initial_state_revision() != snapshot.at("initial_state_revision").as_string() ||
            !equal(observe_publisher_lease_root_identity(volume), snapshot.at("volume_root_identity")) ||
            !equal(observe_publisher_lease_root_identity(original_state.setup_root()), snapshot.at("setup_root_identity")) ||
            !equal(observe_publisher_lease_root_identity(original_state.state_root()), snapshot.at("state_root_identity")))
            throw std::runtime_error("native maintenance borrowed state differs from its original native intent");
        service = observe_current_restricted_publisher_service(service_name);
        volume_facts = observe_publisher_directory_handle(volume);
        require_publisher_object_security_shape(volume_facts, service.service_sid);
        volume_observation = observe_local_ntfs_volume_handle(volume);
        registration = admission.evidence();
        selection = admission.selected_reviewed_operation_observation();
        const auto& target = registration.at("target_identity").at("volume_identity");
        if (registration.at("service_name").as_string() != fs::path(service_name).u8string() ||
            registration.at("service_sid").as_string() != service.service_sid ||
            registration.at("process_id").as_unsigned() != service.process_id ||
            target.at("volume_root").as_string() != fs::path(volume_root).u8string() ||
            target.at("root_file_id").as_string() != volume_facts.file_id ||
            target.at("volume_serial").as_string() != std::to_string(volume_observation.file_id_volume_serial))
            throw std::runtime_error("native maintenance registration differs from its held volume/service");
        client = channel.observe_authenticated_object_access(volume).at("client");
        if (client.at("user_sid").as_string() != registration.at("configured_caller_sid").as_string())
            throw std::runtime_error("native maintenance authenticated caller differs from registration");
        process_boundary = observe_current_publisher_process_boundary();
        require_publisher_process_boundary(process_boundary, service.process_id, service.service_sid, service.token.process_groups);
        worker = observe_settled_publisher_worker_security(service, cancel_event);
        descriptor = make_publisher_directory_security_descriptor(std::wstring(service.service_sid.begin(), service.service_sid.end()));
        const auto setup_component = fs::u8path(snapshot.at("setup_component").as_string());
        if (relative_volume_path(spec.state_root) != setup_component / "state" ||
            relative_volume_path(spec.audit_root) != setup_component / "audit" ||
            (spec.operation != "move" && relative_volume_path(spec.staging_parent) != setup_component / "staging"))
            throw std::runtime_error("native maintenance metadata paths do not name the original held setup roots");
        staging_parent = &open_directory(spec.staging_parent);
        target_parent = &open_directory(spec.target_root.parent_path());
        require_authority(spec);
        effect_fence = [this] { require_authority(spec); };
        operations.require_authority = [this](const auto& s) { require_authority(s); };
        operations.create_staging_root = [this](const auto& s, const auto& p) { create_staging(s, p); };
        operations.ensure_stream_parent = [this](const auto& s, const auto& p) { ensure_parent(s, p); };
        operations.open_stream = [this](const auto& s, const auto& p, auto size, const auto& sha) { return open_stream(s, p, size, sha); };
        operations.require_stream = [this](const auto& s, auto h) { require_stream(s, h); };
        operations.finish_stream = [this](const auto& s, auto h, const auto& id, auto size, const auto& sha) { finish_stream(s, h, id, size, sha); };
        operations.commit = [this](const auto& s, const auto& p, const auto& id, const auto& closure) { commit(s, p, id, closure); };
    }
    static fs::path normalized(const fs::path& path) { return fs::absolute(path).lexically_normal(); }
    fs::path relative_volume_path(const fs::path& path) const {
        const auto absolute = normalized(path);
        const auto drive = absolute.root_name().wstring() + L"\\";
        wchar_t mapped[128]{};
        if (drive.size() != 3 || drive[1] != L':' ||
            !GetVolumeNameForVolumeMountPointW(drive.c_str(), mapped, static_cast<DWORD>(std::size(mapped))) ||
            CompareStringOrdinal(mapped, -1, volume_root.c_str(), -1, TRUE) != CSTR_EQUAL)
            throw std::runtime_error("native maintenance public path lost its admitted volume mapping");
        for (const auto& component : absolute.relative_path())
            if (!is_publisher_canonical_component(component.wstring()))
                throw std::runtime_error("native maintenance path has an unsafe component");
        return absolute.relative_path();
    }
    void require_client_read_only(HANDLE handle, const PublisherHandleObservation& facts) const {
        auto access = channel.observe_authenticated_object_access(handle);
        if (!equal(access.at("client"), client) || !equal(access.at("native_object"), publisher_handle_observation_json(facts)))
            throw std::runtime_error("native maintenance authenticated object binding changed");
        access.as_object().erase("client"); access.as_object().erase("native_object");
        access.as_object().emplace("client_sha256", Value(json::sha256_canonical(client)));
        access.as_object().emplace("native_object_sha256", Value(json::sha256_canonical(publisher_handle_observation_json(facts))));
        require_publisher_authenticated_object_access(access, client, publisher_handle_observation_json(facts));
        constexpr DWORD mutation = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD |
            FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER;
        for (const auto& [name, check] : access.at("checks").as_object())
            if (name == "maximum_allowed" ? (check.at("granted").as_unsigned() & mutation) != 0 :
                check.at("allowed").as_boolean() || check.at("granted").as_unsigned() != 0)
                throw std::runtime_error("native maintenance caller retains object mutation rights");
    }
    PublisherHandleObservation facts(HANDLE handle, bool directory) const {
        const auto observed = directory ? observe_publisher_directory_handle(handle) : observe_publisher_file_handle(handle);
        require_publisher_object_security_shape(observed, service.service_sid);
        require_publisher_stream_shape(handle);
        observe_publisher_noninheritable_handle_flags(handle);
        if (observe_local_ntfs_volume_handle(handle).file_id_volume_serial != volume_observation.file_id_volume_serial)
            throw std::runtime_error("native maintenance object changed volume");
        require_client_read_only(handle, observed);
        return observed;
    }
    void require_entry(const Entry& entry) const {
        if (!same(facts(entry.handle.value, entry.directory), entry.facts))
            throw std::runtime_error("native maintenance retained object changed");
        const HANDLE parent = entry.parent ? entry.parent->handle.value : volume;
        if (entry.parent) require_entry(*entry.parent);
        const auto listed = child(parent, entry.name);
        if (!listed) throw std::runtime_error("native maintenance retained child is absent");
        Held independent;
        independent.value = open_publisher_listed_child(parent, *listed);
        if (!same(facts(independent.value, entry.directory), entry.facts))
            throw std::runtime_error("native maintenance retained parent link changed");
    }
    Entry& open_directory(const fs::path& path) {
        fs::path key;
        Entry* parent = nullptr;
        for (const auto& part : relative_volume_path(path)) {
            key /= part;
            auto found = directories.find(key);
            if (found != directories.end()) { parent = found->second.get(); require_entry(*parent); continue; }
            auto entry = std::make_unique<Entry>();
            entry->parent = parent; entry->name = part.wstring();
            // Allocate the owner and map node before opening a native handle.
            auto inserted = directories.emplace(key, std::move(entry));
            auto& held = *inserted.first->second;
            const HANDLE parent_handle = parent ? parent->handle.value : volume;
            const auto listed = child(parent_handle, held.name);
            if (!listed || !(listed->attributes & FILE_ATTRIBUTE_DIRECTORY))
                throw std::runtime_error("native maintenance required protected directory is absent");
            held.handle.value = open_publisher_listed_child(parent_handle, *listed, true, false, true);
            held.facts = facts(held.handle.value, true);
            require_entry(held); parent = &held;
        }
        if (!parent) throw std::runtime_error("native maintenance refuses using the volume as an operation parent");
        return *parent;
    }
    void require_authority(const transaction::TransactionSpec& supplied) const {
        if (supplied.transaction_id != spec.transaction_id || supplied.plan_id != spec.plan_id || supplied.plan_digest != spec.plan_digest ||
            supplied.operation != spec.operation || normalized(supplied.staging_parent) != normalized(spec.staging_parent) ||
            normalized(supplied.target_root) != normalized(spec.target_root) || normalized(supplied.state_root) != normalized(spec.state_root) ||
            normalized(supplied.audit_root) != normalized(spec.audit_root) || supplied.required_commit_authority != spec.required_commit_authority)
            throw std::runtime_error("native maintenance callback received a different transaction");
        if (GetCurrentProcessId() != service.process_id || (cancel_event && WaitForSingleObject(cancel_event, 0) != WAIT_TIMEOUT))
            throw std::runtime_error("native maintenance worker stopped or changed");
        guard.require_owned(volume_root, original_context.record().at("install_id").as_string());
        original_context.require_fence(); original_state.require_custody(); lease.require_fence();
        const auto& ownership = lease.ownership();
        const auto& snapshot = original_context.record().at("reviewed_snapshot");
        transaction::require_install_lease_record(ownership);
        if (ownership.at("install_id").as_string() != snapshot.at("install_id").as_string() ||
            ownership.at("operation").as_string() != spec.operation ||
            ownership.at("operation_id").as_string() != spec.transaction_id ||
            ownership.at("operation_context_sha256").as_string() != original_context.lease_binding_sha256() ||
            ownership.at("expected_state_revision").as_string() != snapshot.at("initial_state_revision").as_string() ||
            !equal(ownership.at("state_root_identity"), snapshot.at("state_root_identity")))
            throw transaction::InstallLeaseStale();
        if (!same(observe_publisher_directory_handle(volume), volume_facts) ||
            !equal(admission.evidence(), registration) || !equal(admission.selected_reviewed_operation_observation(), selection))
            throw std::runtime_error("native maintenance held registration or boundary changed");
        const auto current_worker = observe_current_publisher_worker_security();
        require_publisher_worker_security(current_worker, service);
        const auto current_process = observe_current_publisher_process_boundary();
        require_publisher_process_boundary(current_process, service.process_id, service.service_sid, service.token.process_groups);
        if (!equal(current_worker, worker) || !equal(current_process, process_boundary))
            throw std::runtime_error("native maintenance frozen worker security changed");
        if (observe_publisher_install_state_revision(original_state.state_root(),
            original_context.record().at("install_id").as_string(), service.service_sid) != original_state.initial_state_revision())
            throw transaction::InstallStateRevisionStale();
        (void)relative_volume_path(spec.state_root); (void)relative_volume_path(spec.target_root);
        require_client_read_only(volume, volume_facts);
        if (staging_parent) require_entry(*staging_parent);
        if (target_parent) require_entry(*target_parent);
    }
    fs::path staging_relative(const fs::path& path) const {
        const auto root = normalized(spec.staging_parent / (".usk-stage-" + spec.transaction_id));
        const auto relative = normalized(path).lexically_relative(root);
        if (relative.empty()) throw std::runtime_error("native maintenance stream escaped staging");
        if (relative != fs::path(".")) for (const auto& component : relative)
            if (!is_publisher_canonical_component(component.wstring())) throw std::runtime_error("native maintenance stream component refused");
        return relative;
    }
    Entry& create_directory(Entry& parent, const fs::path& relative, const std::wstring& name) {
        require_entry(parent);
        const auto key = relative_volume_path(spec.staging_parent / (".usk-stage-" + spec.transaction_id)) / relative;
        if (directories.count(key) || child(parent.handle.value, name)) throw std::runtime_error("native maintenance create-only directory exists");
        auto entry = std::make_unique<Entry>(); entry->parent = &parent; entry->name = name; entry->created = true;
        auto inserted = directories.emplace(key.lexically_normal(), std::move(entry));
        auto& held = *inserted.first->second;
        held.handle.value = create_staged_directory_relative_with_descriptor(parent.handle.value, name, descriptor);
        held.facts = facts(held.handle.value, true); require_entry(held);
        return held;
    }
    void create_staging(const transaction::TransactionSpec& s, const fs::path& path) {
        require_authority(s);
        if (staging || publication_attempted || staging_relative(path) != fs::path("."))
            throw std::runtime_error("native maintenance staging creation is not the original root");
        staging = &create_directory(*staging_parent, {}, path.filename().wstring());
        require_authority(s);
    }
    void ensure_parent(const transaction::TransactionSpec& s, const fs::path& path) {
        require_authority(s);
        if (!staging || publication_attempted) throw std::runtime_error("native maintenance staging parent unavailable");
        Entry* parent = staging;
        fs::path relative;
        for (const auto& part : staging_relative(path)) {
            if (part == fs::path(".")) continue;
            relative /= part;
            const auto key = (relative_volume_path(spec.staging_parent / (".usk-stage-" + spec.transaction_id)) / relative).lexically_normal();
            const auto found = directories.find(key);
            parent = found == directories.end() ? &create_directory(*parent, relative, part.wstring()) : found->second.get();
            require_entry(*parent);
        }
        require_authority(s);
    }
    std::intptr_t open_stream(const transaction::TransactionSpec& s, const fs::path& path, std::uint64_t size, const std::string& sha) {
        require_authority(s);
        const auto relative = staging_relative(path);
        if (!staging || publication_attempted || relative == fs::path(".") || files.count(relative) ||
            files.size() >= 100000u || sha.size() != 64 || sha.find_first_not_of("0123456789abcdef") != std::string::npos)
            throw std::runtime_error("native maintenance stream is not a new staged file");
        const auto parent_key = (relative_volume_path(spec.staging_parent / (".usk-stage-" + spec.transaction_id)) / relative.parent_path()).lexically_normal();
        const auto found = directories.find(parent_key);
        if (found == directories.end()) throw std::runtime_error("native maintenance stream parent lacks creation custody");
        auto entry = std::make_unique<Entry>();
        entry->parent = found->second.get(); entry->name = path.filename().wstring(); entry->directory = false;
        entry->created = true; entry->size = size; entry->sha256 = sha;
        auto inserted = files.emplace(relative, std::move(entry)); auto& held = *inserted.first->second;
        require_entry(*held.parent);
        held.handle.value = create_file_relative_with_descriptor(held.parent->handle.value, held.name, descriptor);
        held.facts = facts(held.handle.value, false);
        held.stream_identity = transaction::stream_output_identity(reinterpret_cast<std::intptr_t>(held.handle.value));
        require_entry(held); require_authority(s);
        return reinterpret_cast<std::intptr_t>(held.handle.value);
    }
    Entry& stream(std::intptr_t handle) const {
        for (const auto& item : files) if (reinterpret_cast<std::intptr_t>(item.second->handle.value) == handle) return *item.second;
        throw std::runtime_error("native maintenance stream handle is outside engine custody");
    }
    void require_stream(const transaction::TransactionSpec& s, std::intptr_t handle) const {
        require_authority(s); const auto& entry = stream(handle);
        if (publication_attempted || !entry.created || entry.directory) throw std::runtime_error("native maintenance stream is unavailable for staging");
        require_entry(entry);
        if (transaction::stream_output_identity(handle) != entry.stream_identity)
            throw std::runtime_error("native maintenance stream creation identity changed");
    }
    void require_bytes(const Entry& entry) const {
        require_entry(entry);
        FILE_STANDARD_INFO before{}, after{}; FILE_BASIC_INFO first{}, last{};
        LARGE_INTEGER zero{};
        if (!GetFileInformationByHandleEx(entry.handle.value, FileStandardInfo, &before, sizeof(before)) ||
            !GetFileInformationByHandleEx(entry.handle.value, FileBasicInfo, &first, sizeof(first)) || before.DeletePending ||
            before.Directory || before.EndOfFile.QuadPart < 0 || static_cast<std::uint64_t>(before.EndOfFile.QuadPart) != entry.size ||
            !SetFilePointerEx(entry.handle.value, zero, nullptr, FILE_BEGIN)) throw std::runtime_error("native maintenance held stream size/position changed");
        base::Sha256 hash; std::array<unsigned char, 64u * 1024u> buffer{}; std::uint64_t consumed = 0;
        while (consumed < entry.size) {
            const auto requested = static_cast<DWORD>(std::min<std::uint64_t>(buffer.size(), entry.size - consumed)); DWORD read = 0;
            if (!ReadFile(entry.handle.value, buffer.data(), requested, &read, nullptr) || !read || read > requested)
                throw std::runtime_error("native maintenance held stream read unavailable");
            hash.update(buffer.data(), read); consumed += read;
        }
        if (hash.finish() != entry.sha256 || !GetFileInformationByHandleEx(entry.handle.value, FileStandardInfo, &after, sizeof(after)) ||
            !GetFileInformationByHandleEx(entry.handle.value, FileBasicInfo, &last, sizeof(last)) || after.DeletePending ||
            after.EndOfFile.QuadPart != before.EndOfFile.QuadPart || last.LastWriteTime.QuadPart != first.LastWriteTime.QuadPart ||
            last.ChangeTime.QuadPart != first.ChangeTime.QuadPart) throw std::runtime_error("native maintenance held stream bytes changed");
        require_entry(entry);
    }
    void finish_stream(const transaction::TransactionSpec& s, std::intptr_t handle, const std::string& id, std::uint64_t size, const std::string& sha) {
        require_stream(s, handle); auto& entry = stream(handle);
        if (entry.complete || id != entry.stream_identity || size != entry.size || sha != entry.sha256 ||
            !FlushFileBuffers(entry.handle.value)) throw std::runtime_error("native maintenance stream completion differs from its reviewed creation");
        require_bytes(entry); entry.complete = true; require_authority(s);
    }
    void commit(const transaction::TransactionSpec& s, const fs::path& path, const std::string& id,
        const transaction::CommitClosureObservation& closure) {
        require_authority(s);
        if (!staging || publication_attempted || staging_relative(path) != fs::path(".") ||
            journal_identity(staging->handle.value) != id || closure.empty())
            throw std::runtime_error("native maintenance commit lacks its original created root/closure");
        std::vector<PublisherExpectedFile> expected;
        std::vector<transaction::CommitClosureFile> journal_files;
        Value::Array created;
        for (const auto& item : files) {
            const auto& entry = *item.second;
            if (!entry.created || !entry.complete) throw std::runtime_error("native maintenance commit has an incomplete creation");
            require_bytes(entry); expected.push_back({item.first.generic_wstring(), entry.size, entry.sha256});
            journal_files.push_back({item.first, entry.sha256, entry.size, entry.stream_identity});
        }
        for (const auto& item : directories) if (item.second->created) require_entry(*item.second);
        const auto sealed = observe_publisher_tree(staging->handle.value);
        require_publisher_tree_security_shape(sealed, service.service_sid);
        require_publisher_tree_exact_file_closure(sealed, expected);
        if (transaction::observe_commit_closure(path, journal_files) != closure)
            throw std::runtime_error("native maintenance generic closure differs from the held created tree");
        for (const auto& object : sealed.descendants) created.push_back(Value(Value::Object{
            {"relative_path", Value(fs::path(object.relative_path).generic_u8string())},
            {"object", publisher_handle_observation_json(object.object)},
            {"size_bytes", Value(object.size)}, {"sha256", Value(object.sha256)}}));
        // This record describes this worker's held creations, not a recovered
        // handle or a callback assertion. It precedes the native publication.
        const Value custody(Value::Object{{"schema", Value("usk.publisher.maintenance_created_closure.v1")},
            {"transaction_id", Value(spec.transaction_id)}, {"plan_digest", Value(spec.plan_digest)},
            {"original_context_sha256", Value(original_context.lease_binding_sha256())},
            {"lease_ownership_sha256", Value(json::sha256_canonical(lease.ownership()))},
            {"worker_security", worker}, {"process_boundary", process_boundary},
            {"registration_sha256", Value(json::sha256_canonical(registration))},
            {"authenticated_client", client}, {"root", publisher_handle_observation_json(sealed.root)},
            {"created_objects", Value(std::move(created))}});
        const auto text = json::canonical(custody) + "\n";
        if (text.size() > 16u * 1024u * 1024u) throw std::runtime_error("native maintenance created closure exceeds its durable bound");
        const auto custody_path = spec.state_root / "transactions" / (spec.transaction_id + ".native-maintenance-created.json");
        record_io::write_new_durable_text(custody_path, text);
        if (record_io::read_stable_text(custody_path, 16u * 1024u * 1024u) != text)
            throw std::runtime_error("native maintenance created closure readback differs");
        require_authority(s);
        require_publisher_tree_phase_match(sealed, observe_publisher_tree(staging->handle.value));
        // Prepare every retained object's known namespace postimage before
        // calling native rename. Allocation failure therefore precedes it.
        const auto new_name = target_parent->facts.native_name + L"\\" + spec.target_root.filename().wstring();
        std::vector<std::pair<Entry*, PublisherHandleObservation>> after;
        for (const auto& item : directories) if (item.second->created) {
            auto fact = item.second->facts; fact.native_name.replace(0, sealed.root.native_name.size(), new_name);
            after.emplace_back(item.second.get(), std::move(fact));
        }
        for (const auto& item : files) {
            auto fact = item.second->facts; fact.native_name.replace(0, sealed.root.native_name.size(), new_name);
            after.emplace_back(item.second.get(), std::move(fact));
        }
        auto next_component = spec.target_root.filename().wstring();
        // Latch before any possible issued call. An unconfirmed rename leaves
        // every handle in this owner and grants neither a retry nor cleanup.
        publication_attempted = true;
        (void)probe_publisher_bound_rename_no_replace(staging->handle.value, target_parent->handle.value,
            next_component, sealed.root, target_parent->facts, [&] { require_authority(s); });
        staging->parent = target_parent; staging->name.swap(next_component);
        for (auto& item : after) item.first->facts = std::move(item.second);
        require_publisher_tree_phase_match(sealed, observe_publisher_tree(staging->handle.value), new_name);
        for (const auto& item : directories) if (item.second->created) require_entry(*item.second);
        for (const auto& item : files) require_bytes(*item.second);
        require_authority(s);
    }
};
NativeMaintenanceContext::NativeMaintenanceContext(HANDLE volume, const std::wstring& root, const std::wstring& service,
    const PublisherInstallOperationGuard& guard, const PublisherMaintenanceStateSnapshot& state,
    const PublisherInstallOperationContext& context, const PublisherInstallationLease& lease,
    const RegisteredPublisherAdmission& admission, const PublisherRequestChannel& channel,
    const transaction::TransactionSpec& spec, HANDLE cancel)
    : impl_(std::make_unique<Impl>(volume, root, service, guard, state, context, lease, admission, channel, spec, cancel)) {
    fence_ = std::make_unique<ScopedPublisherEffectFence>(impl_->effect_fence);
    impl_->metadata = std::make_unique<PublisherMetadataSession>(volume, root,
        fs::path(root) / fs::u8path(context.record().at("reviewed_snapshot").at("setup_component").as_string()),
        service, true, Impl::normalized(spec.state_root.parent_path()));
    scope_.reset(new transaction::detail::ScopedNativeMaintenanceTransaction(impl_->operations));
}
NativeMaintenanceContext::~NativeMaintenanceContext() {
    scope_.reset();
    impl_->metadata.reset();
    fence_.reset();
}
}
#endif
