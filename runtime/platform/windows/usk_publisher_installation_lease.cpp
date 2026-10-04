// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_installation_lease.h"
#if defined(_WIN32)
#include "usk_publisher_anchor_create.h"
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
    ~Handle() { CloseHandle(value_); }
    HANDLE get() const { return value_; }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
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
std::string read_held_text(HANDLE handle, const std::string& sid, std::size_t limit) {
    const auto before = observe_publisher_file_handle(handle);
    require_publisher_object_security_shape(before, sid);
    require_publisher_stream_shape(handle);
    LARGE_INTEGER size{};
    FILE_BASIC_INFO basic{};
    if (!GetFileSizeEx(handle, &size) || !GetFileInformationByHandleEx(handle, FileBasicInfo,
            &basic, sizeof(basic)) || size.QuadPart <= 0 || static_cast<std::uint64_t>(size.QuadPart) > limit)
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

std::string observe_publisher_install_state_revision(HANDLE state_root,
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
    return usk::json::sha256_canonical(Value(std::move(values)));
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

struct PublisherInstallOperationContext::Impl {
    HANDLE volume;
    std::wstring volume_root;
    const PublisherInstallOperationGuard& guard;
    std::string install_id, operation_id, service_sid;
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
        const std::string& operation)
        : volume(held_volume), volume_root(root), guard(held), install_id(install), operation_id(operation) {
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
        const auto text = read_text(records->get(), *entry, service_sid, 4u * 1024u * 1024u);
        original = usk::json::parse(text);
        const std::set<std::string> fields{"schema", "install_id", "operation", "operation_id",
            "volume_root_identity", "initial_state_revision", "reviewed_snapshot", "context_sha256"};
        if (original.as_object().size() != fields.size()) throw std::runtime_error("operation context fields differ");
        for (const auto& item : original.as_object())
            if (!fields.count(item.first)) throw std::runtime_error("operation context field unknown");
        auto unsealed = original;
        unsealed.as_object().erase("context_sha256");
        if (original.at("schema").as_string() != "usk.installation_operation_context.v1" ||
            original.at("install_id").as_string() != install_id ||
            original.at("operation").as_string() != "install_local" ||
            original.at("operation_id").as_string() != operation_id ||
            !equal(original.at("volume_root_identity"), volume_identity) ||
            original.at("context_sha256").as_string() != usk::json::sha256_canonical(unsealed) ||
            original.at("initial_state_revision").as_string() !=
                usk::json::sha256_canonical(Value(Value::Array{})) ||
            original.at("reviewed_snapshot").type() != Value::Type::object ||
            usk::json::canonical(original) + "\n" != text)
            throw std::runtime_error("operation context binding differs");
        bind_file(*entry);
        if (read_held_text(file->get(), service_sid, 4u * 1024u * 1024u) != text)
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
            const auto setup_name = std::filesystem::u8path(original.at("reviewed_snapshot").at("setup_root").as_string()).filename().wstring();
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
    void prepare(const Value& snapshot, const std::string& revision) {
        guard.require_owned(volume_root, install_id);
        if (revision != usk::json::sha256_canonical(Value(Value::Array{})))
            throw InstallStateRevisionStale();
        if (file) {
            fence();
            if (!equal(original.at("reviewed_snapshot"), snapshot) ||
                original.at("initial_state_revision").as_string() != revision) throw InstallLeaseConflict();
            return;
        }
        if (!equal(volume_identity, root_identity(volume, service_sid))) throw InstallLeaseStale();
        Value value(Value::Object{{"schema", Value("usk.installation_operation_context.v1")},
            {"install_id", Value(install_id)}, {"operation", Value("install_local")},
            {"operation_id", Value(operation_id)}, {"volume_root_identity", volume_identity},
            {"initial_state_revision", Value(revision)}, {"reviewed_snapshot", snapshot}});
        value.as_object().emplace("context_sha256", Value(usk::json::sha256_canonical(value)));
        const auto text = usk::json::canonical(value) + "\n";
        if (text.size() > 4u * 1024u * 1024u) throw std::runtime_error("operation context record budget exhausted");
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
        if (!entry || read_text(records->get(), *entry, service_sid, 4u * 1024u * 1024u) != text)
            throw std::runtime_error("operation context durable readback differs");
        original = std::move(value);
        bind_file(*entry);
        if (read_held_text(file->get(), service_sid, 4u * 1024u * 1024u) != text)
            throw std::runtime_error("operation context retained-handle readback differs");
        fence();
    }
};
PublisherInstallOperationContext::PublisherInstallOperationContext(HANDLE volume, const std::wstring& root,
    const std::wstring& service, const PublisherInstallOperationGuard& guard,
    const std::string& install_id, const std::string& operation_id)
    : impl_(std::make_unique<Impl>(volume, root, service, guard, install_id, operation_id)) {}
PublisherInstallOperationContext::~PublisherInstallOperationContext() = default;
bool PublisherInstallOperationContext::exists() const { return bool(impl_->file); }
void PublisherInstallOperationContext::prepare(const Value& snapshot, const std::string& revision) {
    impl_->prepare(snapshot, revision);
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
