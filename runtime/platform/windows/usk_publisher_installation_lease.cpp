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
    std::wstring bootstrap_name(const Value& reservation, const wchar_t* kind) const {
        return context_name.substr(0, context_name.size() - 5) + kind +
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
        if (tree.descendants.size() > 5) throw InstallLeaseStale();
        const std::vector<std::wstring> order{L"staging", L"destination", L"state", L"journal"};
        std::set<std::wstring> present;
        bool snapshot_present = false;
        for (const auto& entry : tree.descendants) {
            const bool directory_entry = (entry.object.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            require_publisher_stream_shape(entry.streams, directory_entry);
            if (directory_entry) {
                if (std::find(order.begin(), order.end(), entry.relative_path) == order.end() ||
                    !present.insert(entry.relative_path).second) throw InstallLeaseStale();
            } else {
                if (entry.relative_path != L"journal\\lab-reviewed-plan.json" || snapshot_present ||
                    entry.size > 4u * 1024u * 1024u) throw InstallLeaseStale();
                snapshot_present = true;
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
        bool missing = false;
        for (const auto& name : order) {
            if (!present.count(name)) missing = true;
            else if (missing) throw InstallLeaseStale();
        }
        if (snapshot_present && present.size() != order.size()) throw InstallLeaseStale();
        require_publisher_tree_phase_match(tree, observe_publisher_tree(publication));
        return tree;
    }
    bool bootstrap_resume_required() const {
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
