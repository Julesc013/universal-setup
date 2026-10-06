// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_native_maintenance_context_internal.h"
#if defined(_WIN32)
#include "usk_publisher_anchor_create.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_execution_observation.h"
#include "usk_publisher_metadata.h"
#include "usk_publisher_maintenance_mutation.h"
#include "usk_publisher_process_boundary.h"
#include "usk_publisher_registration.h"
#include "usk_publisher_request_channel.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_tree_observation.h"
#include "usk_publisher_worker_security.h"
#include "usk_record_io.h"
#include "usk_sha256.h"
#include "usk_maintenance_recovery_internal.h"
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
    ~Held() { if (!close_attempted && value != INVALID_HANDLE_VALUE && value) CloseHandle(value); }
    Held(const Held&) = delete;
    Held& operator=(const Held&) = delete;
    HANDLE value = INVALID_HANDLE_VALUE;
    void close_observer_once() {
        if (close_attempted || value == INVALID_HANDLE_VALUE || !value)
            throw std::runtime_error("native maintenance observer is unavailable for release");
        close_attempted = true;
        if (!CloseHandle(value))
            throw std::runtime_error("native maintenance observer close was not confirmed; retained recovery required");
        value = INVALID_HANDLE_VALUE;
    }
private:
    // A failed observer close is quarantined through worker disposal. Its
    // numeric value is never used again and the destructor never retries it.
    bool close_attempted = false;
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
    std::map<fs::path, std::unique_ptr<Entry>> original_files;
    std::map<fs::path, Entry*> original_directories;
    Entry* installed_root = nullptr;
    std::string original_root_identity;
    bool payload_failed = false;
    std::set<std::string> attempted_payload_histories;
    Entry* staging_parent = nullptr;
    Entry* target_parent = nullptr;
    Entry* staging = nullptr;
    bool publication_attempted = false, publication_confirmed = false;
    fs::path installed_record_path, prepared_record_path;
    Entry* installed_parent = nullptr;
    std::unique_ptr<Entry> installed_postimage_file;
    PublisherHandleObservation installed_record_facts;
    Value installed_postimage_bindings;
    std::string installed_record_text, installed_record_sha256, prepared_transaction_sha256, prepared_history_sha256;
    bool installed_prepared = false, installed_issue_active = false, installed_confirmed = false, installed_uncertain = false;
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
        installed_record_path = normalized(spec.state_root / "installed" /
            (snapshot.at("install_id").as_string() + "." + spec.transaction_id + ".json"));
        require_authority(spec);
        effect_fence = [this] { require_authority(spec); };
        operations.require_authority = [this](const auto& s) { require_authority(s); };
        operations.create_staging_root = [this](const auto& s, const auto& p) { create_staging(s, p); };
        operations.ensure_stream_parent = [this](const auto& s, const auto& p) { ensure_parent(s, p); };
        operations.open_stream = [this](const auto& s, const auto& p, auto size, const auto& sha) { return open_stream(s, p, size, sha); };
        operations.require_stream = [this](const auto& s, auto h) { require_stream(s, h); };
        operations.finish_stream = [this](const auto& s, auto h, const auto& id, auto size, const auto& sha) { finish_stream(s, h, id, size, sha); };
        operations.commit = [this](const auto& s, const auto& p, const auto& id, const auto& closure) { commit(s, p, id, closure); };
        operations.apply_payload = [this](const auto& s, const auto& history) { return apply_payload(s, history); };
        admit_original_payload();
        require_authority(spec);
    }
    static fs::path normalized(const fs::path& path) { return fs::absolute(path).lexically_normal(); }
    static fs::path owned_relative(const std::string& value) {
        const auto relative = fs::u8path(value);
        if (value.empty() || value.size() > 4096u || relative.has_root_path())
            throw std::runtime_error("native maintenance owned path is not a bounded relative path");
        for (const auto& component : relative)
            if (!is_publisher_canonical_component(component.wstring()))
                throw std::runtime_error("native maintenance owned path contains an unsafe component");
        return relative;
    }
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
        if (installed_uncertain || payload_failed)
            throw std::runtime_error("native maintenance effect is uncertain; no further effects");
        const auto current_bindings = observe_publisher_install_state_bindings(original_state.state_root(),
            original_context.record().at("install_id").as_string(), service.service_sid);
        const bool original_revision = equal(current_bindings, snapshot.at("installed_record_bindings"));
        const bool postimage_revision = installed_prepared && equal(current_bindings, installed_postimage_bindings);
        if (installed_confirmed ? !postimage_revision :
            (installed_issue_active ? (!original_revision && !postimage_revision) : !original_revision))
            throw transaction::InstallStateRevisionStale();
        require_installed_custody();
        (void)relative_volume_path(spec.state_root); (void)relative_volume_path(spec.target_root);
        require_client_read_only(volume, volume_facts);
        if (staging_parent) require_entry(*staging_parent);
        if (target_parent) require_entry(*target_parent);
    }
    void require_installed_custody() const {
        if (!installed_postimage_file || installed_postimage_file->handle.value == INVALID_HANDLE_VALUE) return;
        const auto observed = facts(installed_postimage_file->handle.value, false);
        const bool pending = same(observed, installed_postimage_file->facts);
        const bool published = same(observed, installed_record_facts);
        if (installed_confirmed ? !published : (installed_issue_active ? (!pending && !published) : !pending))
            throw std::runtime_error("native maintenance installed creation custody changed");
        if (installed_parent) require_entry(*installed_parent);
    }
    void require_installed_bytes() const {
        require_installed_custody();
        const HANDLE file = installed_postimage_file->handle.value;
        FILE_STANDARD_INFO size{}; FILE_BASIC_INFO first{}, last{};
        LARGE_INTEGER zero{};
        if (!GetFileInformationByHandleEx(file, FileStandardInfo, &size, sizeof(size)) ||
            size.EndOfFile.QuadPart < 0 || static_cast<std::uint64_t>(size.EndOfFile.QuadPart) != installed_record_text.size() ||
            !GetFileInformationByHandleEx(file, FileBasicInfo, &first, sizeof(first)) ||
            !SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
            throw std::runtime_error("native maintenance installed bytes are unavailable");
        base::Sha256 hash;
        std::array<unsigned char, 64u * 1024u> bytes{};
        std::size_t remaining = installed_record_text.size();
        while (remaining) {
            const DWORD wanted = static_cast<DWORD>(std::min(remaining, bytes.size()));
            DWORD count = 0;
            if (!ReadFile(file, bytes.data(), wanted, &count, nullptr) || count != wanted)
                throw std::runtime_error("native maintenance installed bytes changed");
            hash.update(bytes.data(), count); remaining -= count;
        }
        if (hash.finish() != installed_record_sha256 ||
            !GetFileInformationByHandleEx(file, FileBasicInfo, &last, sizeof(last)) ||
            first.LastWriteTime.QuadPart != last.LastWriteTime.QuadPart || first.ChangeTime.QuadPart != last.ChangeTime.QuadPart)
            throw std::runtime_error("native maintenance installed byte postimage changed");
        require_installed_custody();
    }
    void metadata_prepare(const fs::path& path, const std::string& text) {
        require_authority(spec);
        if (normalized(path).parent_path() != installed_record_path.parent_path()) return;
        if (normalized(path) != installed_record_path || installed_prepared || !publication_confirmed)
            throw std::runtime_error("native maintenance refuses an unrelated or repeated installed publication");
        const auto tx = transaction::TransactionSession::inspect_recovery(spec);
        const auto history = transaction::MaintenanceEffectJournal::inspect(spec, tx.stream_source_digest, true);
        const auto& snapshot = original_context.record().at("reviewed_snapshot");
        const auto source = json::parse(history.source_context);
        const auto artifact = read_maintenance_reviewed_plan(spec);
        const auto next = inspect_maintenance_continuation(spec);
        if (tx.stream_source_context != history.source_context || history.pending_kind != "write_installed" ||
            !next.pending || next.next_kind != "write_installed" || next.history_digest != history.journal_digest ||
            !equal(artifact.at("reviewed_plan"), snapshot.at("reviewed_plan")) ||
            source.at("install_id").as_string() != snapshot.at("install_id").as_string() ||
            source.at("original_installed_transaction_id").as_string() != snapshot.at("installed_state").at("transaction_id").as_string() ||
            source.at("original_installed_state_digest").as_string() != snapshot.at("reviewed_plan").at("installed_state_digest").as_string() ||
            source.at("ownership_manifest_digest").as_string() != snapshot.at("ownership_manifest").at("manifest_digest").as_string() ||
            source.at("applied_at").as_string() != snapshot.at("apply_request").at("applied_at").as_string())
            throw std::runtime_error("native maintenance installed publication lost its original pending effect");
        const auto expected = maintenance_installed_postimage(spec, history);
        if (state::serialize_installed_state(expected) != text)
            throw std::runtime_error("native maintenance installed bytes differ from the original reviewed postimage");
        auto bindings = derive_publisher_maintenance_postimage_bindings(snapshot, json::parse(text));
        auto owner = std::make_unique<Entry>(); // Allocate custody before the writer's native create.
        owner->directory = false; owner->created = true;
        installed_parent = &open_directory(installed_record_path.parent_path());
        prepared_record_path = path;
        installed_record_text = text;
        base::Sha256 hash; hash.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
        installed_record_sha256 = hash.finish();
        prepared_transaction_sha256 = tx.snapshot_sha256; prepared_history_sha256 = history.journal_digest;
        installed_postimage_bindings = std::move(bindings);
        installed_postimage_file = std::move(owner);
        installed_prepared = true;
        require_authority(spec);
    }
    bool metadata_created(const fs::path& path, const std::string& text, HANDLE file) {
        require_authority(spec);
        if (normalized(path).parent_path() != installed_record_path.parent_path()) return false;
        if (!installed_prepared || path != prepared_record_path || text != installed_record_text ||
            installed_postimage_file->handle.value != INVALID_HANDLE_VALUE)
            throw std::runtime_error("native maintenance installed creation differs from its prepared effect");
        auto observed = facts(file, false);
        installed_record_facts = observed;
        installed_record_facts.native_name = installed_parent->facts.native_name + L"\\" + installed_record_path.filename().wstring();
        installed_postimage_file->facts = std::move(observed);
        // Transfer only at the last nonthrowing step. The writer immediately
        // releases its local owner and then borrows this exact created handle.
        installed_postimage_file->handle.value = file;
        return true;
    }
    void metadata_before_issue(const fs::path& path, const std::string& text) {
        require_authority(spec);
        if (normalized(path).parent_path() != installed_record_path.parent_path()) return;
        if (path != prepared_record_path || text != installed_record_text || installed_issue_active || installed_confirmed)
            throw std::runtime_error("native maintenance installed publication cannot be retried");
        const auto tx = transaction::TransactionSession::inspect_recovery(spec);
        const auto history = transaction::MaintenanceEffectJournal::inspect(spec, tx.stream_source_digest);
        if (tx.snapshot_sha256 != prepared_transaction_sha256 || history.journal_digest != prepared_history_sha256 ||
            history.pending_kind != "write_installed")
            throw std::runtime_error("native maintenance original pending installed effect changed before publication");
        require_installed_bytes();
        require_authority(spec);
        installed_issue_active = true; // Last step before the writer's actual native call.
    }
    void metadata_confirm(const fs::path& path, const std::string& text, HANDLE file) {
        require_authority(spec);
        if (normalized(path).parent_path() != installed_record_path.parent_path()) return;
        if (!installed_issue_active || installed_confirmed || path != prepared_record_path || text != installed_record_text ||
            file != installed_postimage_file->handle.value ||
            !same(observe_publisher_file_handle(file), installed_record_facts))
            throw std::runtime_error("native maintenance installed publication is unconfirmed");
        require_installed_bytes();
        const auto listed = child(installed_parent->handle.value, installed_record_path.filename().wstring());
        if (!listed) throw std::runtime_error("native maintenance published installed child is absent");
        Held linked;
        linked.value = open_publisher_listed_child(installed_parent->handle.value, *listed);
        if (!same(facts(linked.value, false), installed_record_facts) ||
            !equal(observe_publisher_install_state_bindings(original_state.state_root(),
                original_context.record().at("install_id").as_string(), service.service_sid), installed_postimage_bindings))
            throw std::runtime_error("native maintenance installed revision lacks its exact native postimage");
        installed_confirmed = true; installed_issue_active = false; installed_postimage_file->complete = true;
        require_authority(spec);
    }
    void metadata_failed(const fs::path& path) noexcept {
        if (installed_prepared && path == prepared_record_path && installed_issue_active) {
            installed_uncertain = true; installed_issue_active = false;
        }
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
    void admit_original_payload() {
        const auto& snapshot = original_context.record().at("reviewed_snapshot");
        const auto root = fs::u8path(snapshot.at("installed_state").at("target_root").as_string());
        installed_root = &open_directory(root);
        original_root_identity = journal_identity(installed_root->handle.value);
        original_directories.emplace(fs::path{}, installed_root);
        if (spec.operation == "move") return; // Original root retained; staging owns the new closure.
        const auto& ownership = snapshot.at("ownership_manifest");
        const auto& planned_files = spec.operation == "repair" ?
            snapshot.at("reviewed_plan").at("replacement_files") : ownership.at("files");
        if (planned_files.as_array().size() > 100000u || ownership.at("directories").as_array().size() > 100000u)
            throw std::runtime_error("native maintenance original custody exceeds its finite closure bound");
        std::uint64_t logical_bytes = 0;
        for (const auto& file : planned_files.as_array()) {
            const auto relative = owned_relative(file.at("relative_path").as_string());
            auto& parent = open_directory(root / relative.parent_path());
            const auto listed = child(parent.handle.value, relative.filename().wstring());
            if (!listed) continue;
            if (listed->attributes & FILE_ATTRIBUTE_DIRECTORY)
                throw std::runtime_error("native maintenance original owned file changed type");
            auto entry = std::make_unique<Entry>();
            entry->parent = &parent; entry->name = relative.filename().wstring(); entry->directory = false;
            auto inserted = original_files.emplace(relative, std::move(entry));
            if (!inserted.second) throw std::runtime_error("native maintenance original owned file repeated");
            auto& held = *inserted.first->second;
            held.handle.value = open_publisher_listed_maintenance_file(parent.handle.value, *listed);
            held.facts = facts(held.handle.value, false);
            FILE_STANDARD_INFO standard{};
            if (!GetFileInformationByHandleEx(held.handle.value, FileStandardInfo, &standard, sizeof(standard)) ||
                standard.DeletePending || standard.Directory || standard.EndOfFile.QuadPart < 0 ||
                static_cast<std::uint64_t>(standard.EndOfFile.QuadPart) > (1ull << 32) ||
                static_cast<std::uint64_t>(standard.EndOfFile.QuadPart) > (1ull << 34) - logical_bytes)
                throw std::runtime_error("native maintenance original owned bytes exceed observation bounds");
            held.size = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart); logical_bytes += held.size;
            LARGE_INTEGER zero{};
            if (!SetFilePointerEx(held.handle.value, zero, nullptr, FILE_BEGIN))
                throw std::runtime_error("native maintenance original file position unavailable");
            base::Sha256 hash; std::array<unsigned char, 64u * 1024u> bytes{}; std::uint64_t consumed = 0;
            while (consumed < held.size) {
                DWORD count = 0;
                const DWORD wanted = static_cast<DWORD>(std::min<std::uint64_t>(bytes.size(), held.size - consumed));
                if (!ReadFile(held.handle.value, bytes.data(), wanted, &count, nullptr) || count != wanted)
                    throw std::runtime_error("native maintenance original owned file read changed");
                hash.update(bytes.data(), count); consumed += count;
            }
            held.sha256 = hash.finish(); held.stream_identity = journal_identity(held.handle.value);
            require_bytes(held);
        }
        // Own the original directories before the first journal, rather than
        // adopt a later same-path object. Missing original directories remain
        // absent observations; this fresh native profile does not create them.
        for (const auto& value : ownership.at("directories").as_array()) {
            const auto relative = owned_relative(value.at("relative_path").as_string());
            const auto path = root / relative;
            auto& parent = open_directory(path.parent_path());
            const auto listed = child(parent.handle.value, path.filename().wstring());
            if (!listed) continue;
            original_directories.emplace(relative, &open_directory(path));
        }
    }
    transaction::MaintenanceEffectInspection require_pending(const std::string& kind) const {
        require_authority(spec);
        const auto tx = transaction::TransactionSession::inspect_recovery(spec);
        const auto history = transaction::MaintenanceEffectJournal::inspect(spec, tx.stream_source_digest, true);
        const auto artifact = read_maintenance_reviewed_plan(spec);
        const auto next = inspect_maintenance_continuation(spec);
        const auto source = json::parse(history.source_context);
        const auto& snapshot = original_context.record().at("reviewed_snapshot");
        if (history.pending_kind != kind || !next.pending || next.next_kind != kind ||
            next.history_digest != history.journal_digest || !equal(next.next_details, history.pending_details) ||
            tx.stream_source_context != history.source_context ||
            !equal(artifact.at("reviewed_plan"), snapshot.at("reviewed_plan")) ||
            source.at("install_id").as_string() != snapshot.at("install_id").as_string() ||
            source.at("original_installed_transaction_id").as_string() != snapshot.at("installed_state").at("transaction_id").as_string() ||
            source.at("applied_at").as_string() != snapshot.at("apply_request").at("applied_at").as_string() ||
            normalized(fs::u8path(source.at("installed_root").at("root").as_string())) !=
                normalized(fs::u8path(snapshot.at("installed_state").at("target_root").as_string())) ||
            source.at("installed_root").at("native_identity").as_string() != original_root_identity)
            throw std::runtime_error("native maintenance payload lost its original reviewed next intent");
        require_authority(spec);
        return history;
    }
    Entry& target_directory(const fs::path& relative, bool create_backup = false) {
        if (!staging || !publication_confirmed) throw std::runtime_error("native maintenance published creation is unavailable");
        Entry* parent = staging; fs::path partial;
        for (const auto& component : relative) {
            if (!is_publisher_canonical_component(component.wstring()))
                throw std::runtime_error("native maintenance target directory is not canonical");
            partial /= component;
            const auto key = (relative_volume_path(spec.staging_parent / (".usk-stage-" + spec.transaction_id)) / partial).lexically_normal();
            const auto found = directories.find(key);
            if (found == directories.end()) {
                if (!create_backup || *partial.begin() != fs::path("backup"))
                    throw std::runtime_error("native maintenance target directory lacks original creation custody");
                parent = &create_directory(*parent, partial, component.wstring());
            } else parent = found->second.get();
            if (!parent->created) throw std::runtime_error("native maintenance target directory was not created by this owner");
            require_entry(*parent);
        }
        require_entry(*parent); return *parent;
    }
    static void require_file_details(const Entry& entry, const Value& details) {
        if (entry.stream_identity != details.at("native_identity").as_string() ||
            entry.size != details.at("size_bytes").as_unsigned() || entry.sha256 != details.at("sha256").as_string())
            throw std::runtime_error("native maintenance file differs from its original pending intent");
    }
    void rename_file(Entry& file, Entry& destination, const std::wstring& component) {
        require_bytes(file); require_entry(destination);
        auto postimage = file.facts;
        postimage.native_name = destination.facts.native_name + L"\\" + component;
        auto next_component = component;
        (void)rename_publisher_bound_file_no_replace(file.handle.value, file.parent->handle.value, file.name,
            destination.handle.value, component, file.facts, file.parent->facts, destination.facts, file.size, file.sha256);
        file.parent = &destination; file.name.swap(next_component); file.facts = std::move(postimage);
        require_bytes(file);
    }
    std::string remove_entry(Entry& entry, const Value& details) {
        require_entry(entry);
        if (entry.directory) {
            if (journal_identity(entry.handle.value) != details.at("native_identity").as_string())
                throw std::runtime_error("native maintenance directory lost its original identity");
            // Keep the observer when a bound directory is nonempty. The native
            // primitive independently returns retained without an issued call.
            if (!observe_publisher_directory_entries(entry.handle.value).empty()) {
                const auto result = remove_publisher_bound_empty_directory(entry.parent->handle.value, entry.name,
                    entry.facts, entry.parent->facts);
                if (result.native_call_attempted || result.absence_confirmed)
                    throw std::runtime_error("native maintenance nonempty directory unexpectedly changed");
                return "retained";
            }
        } else { require_file_details(entry, details); require_bytes(entry); }
        const auto expected = entry.facts;
        auto& parent = *entry.parent; require_entry(parent);
        // The primitive owns its affected mark/close handle. Release this
        // owner's redundant observer first, retaining full original facts,
        // creation provenance and independently held parent/generation custody.
        entry.handle.close_observer_once();
        const auto result = entry.directory ? remove_publisher_bound_empty_directory(parent.handle.value, entry.name, expected, parent.facts) :
            remove_publisher_bound_file(parent.handle.value, entry.name, expected, parent.facts, entry.size, entry.sha256);
        if (!result.native_call_attempted || !result.absence_confirmed)
            throw std::runtime_error("native maintenance removal was not confirmed; retained recovery required");
        return "applied";
    }
    std::string apply_payload(const transaction::TransactionSpec& supplied,
        const transaction::MaintenanceEffectInspection& inspected) {
        require_authority(supplied);
        const auto history = require_pending(inspected.pending_kind);
        if (history.journal_digest != inspected.journal_digest || history.source_context != inspected.source_context ||
            history.pending_sequence != inspected.pending_sequence || !equal(history.pending_details, inspected.pending_details) ||
            !publication_confirmed || !attempted_payload_histories.insert(history.journal_digest).second)
            throw std::runtime_error("native maintenance payload lacks its single original publication/intent");
        try {
            const auto& details = history.pending_details;
            const auto relative = fs::u8path(details.at("relative_path").as_string());
            std::string outcome = "applied";
            if (history.pending_kind == "backup_file") {
                auto& file = *original_files.at(relative);
                require_file_details(file, details);
                const auto backup = fs::path("backup") / relative;
                auto& parent = target_directory(backup.parent_path(), true);
                // Directory creation precedes rename but leaves the durable
                // original backup intent unresolved on any failure.
                (void)require_pending(history.pending_kind);
                rename_file(file, parent, backup.filename().wstring());
            } else if (history.pending_kind == "replace_file") {
                auto& file = *files.at(fs::path("payload") / relative);
                if (!file.created || !file.complete) throw std::runtime_error("native repair replacement lacks completed creation custody");
                require_file_details(file, details);
                auto& parent = open_directory(fs::u8path(original_state.installed_state().at("target_root").as_string()) / relative.parent_path());
                rename_file(file, parent, relative.filename().wstring());
            } else if (history.pending_kind == "remove_file") {
                const auto role = details.at("root_role").as_string();
                Entry* file = nullptr;
                if (role == "installed") file = original_files.at(relative).get();
                else if (role == "operation_target" && spec.operation == "repair" && *relative.begin() == fs::path("backup")) {
                    auto original = relative.lexically_relative("backup"); file = original_files.at(original).get();
                    if (file->parent != &target_directory(relative.parent_path()) || file->name != relative.filename().wstring())
                        throw std::runtime_error("native maintenance backup cleanup lost its original rename postimage");
                } else if (role == "operation_target" && spec.operation == "uninstall" && relative == fs::path("operation.marker"))
                    file = files.at(relative).get();
                else throw std::runtime_error("native maintenance removal is outside its original role");
                outcome = remove_entry(*file, details);
            } else if (history.pending_kind == "remove_directory") {
                const auto role = details.at("root_role").as_string();
                Entry* directory = role == "installed" ? original_directories.at(relative) :
                    role == "operation_target" ? &target_directory(relative) : nullptr;
                if (!directory) throw std::runtime_error("native maintenance directory removal has an unrelated role");
                outcome = remove_entry(*directory, details);
                if (outcome == "retained" && role != "installed")
                    throw std::runtime_error("native maintenance created cleanup directory is not empty");
            } else throw std::runtime_error("native maintenance payload kind is unsupported");
            require_authority(supplied);
            const auto after = transaction::MaintenanceEffectJournal::inspect(spec, history.source_digest);
            if (after.journal_digest != history.journal_digest)
                throw std::runtime_error("native maintenance intent changed during its effect");
            return outcome;
        } catch (...) { payload_failed = true; throw; }
    }
    void commit(const transaction::TransactionSpec& s, const fs::path& path, const std::string& id,
        const transaction::CommitClosureObservation& closure) {
        require_authority(s);
        (void)require_pending("publish_target");
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
        publication_confirmed = true;
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
    usk::platform::windows::detail::MetadataRecordPublicationHooks hooks;
    hooks.prepare = [this](const auto& p, const auto& text) { impl_->metadata_prepare(p, text); };
    hooks.created = [this](const auto& p, const auto& text, HANDLE file) { return impl_->metadata_created(p, text, file); };
    hooks.before_issue = [this](const auto& p, const auto& text) { impl_->metadata_before_issue(p, text); };
    hooks.confirm = [this](const auto& p, const auto& text, HANDLE file) { impl_->metadata_confirm(p, text, file); };
    hooks.failed = [this](const auto& p) { impl_->metadata_failed(p); };
    impl_->metadata->bind_native_maintenance_publication(std::move(hooks));
    scope_.reset(new transaction::detail::ScopedNativeMaintenanceTransaction(impl_->operations));
}
NativeMaintenanceContext::~NativeMaintenanceContext() {
    scope_.reset();
    impl_->metadata.reset();
    fence_.reset();
}
}
#endif
