// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_maintenance_mutation.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_metadata.h"
#include "usk_publisher_rename_information.h"
#include "usk_publisher_volume_stream_observation.h"
#include "usk_sha256.h"
#if defined(_WIN32)
#include <winternl.h>
#include <array>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace usk::platform::windows {
namespace detail {
struct PublisherRemovalOwner final {
    PublisherRemovalOwner() = default;
    void open_once(HANDLE parent, const PublisherDirectoryEntry& listed, bool directory,
        const PublisherMaintenanceNames* maintenance_names) {
        if (value_ != INVALID_HANDLE_VALUE || disposition_attempted || close_attempted)
            throw std::runtime_error("maintenance removal owner already initialized or quarantined");
        value_ = directory ? open_publisher_listed_child(parent, listed, false, true, false, false, false, maintenance_names) :
            open_publisher_listed_maintenance_file(parent, listed);
    }
    ~PublisherRemovalOwner() {
        if (!disposition_attempted && !close_attempted && value_ && value_ != INVALID_HANDLE_VALUE)
            CloseHandle(value_);
    }
    PublisherRemovalOwner(const PublisherRemovalOwner&) = delete;
    PublisherRemovalOwner& operator=(const PublisherRemovalOwner&) = delete;
    HANDLE get() const {
        if (disposition_attempted || close_attempted)
            throw std::runtime_error("maintenance removal object unavailable after disposition or close attempt");
        return value_;
    }
    bool close_once() noexcept {
        if (close_attempted) return false;
        close_attempted = true;
        if (!CloseHandle(value_)) { close_error = GetLastError(); return false; }
        close_confirmed = true;
        value_ = INVALID_HANDLE_VALUE;
        return true;
    }
    bool disposition_attempted = false, close_attempted = false, close_confirmed = false;
    DWORD close_error = ERROR_SUCCESS;
private:
    HANDLE value_ = INVALID_HANDLE_VALUE;
};
}
PublisherRemovalUnconfirmed::PublisherRemovalUnconfirmed(const std::string& message,
    std::shared_ptr<detail::PublisherRemovalOwner> owner)
    : std::runtime_error(message), retained_owner_(std::move(owner)) {}
namespace {
class HeldHandle {
public:
    explicit HeldHandle(HANDLE value) : value_(value) {}
    ~HeldHandle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    HeldHandle(const HeldHandle&) = delete;
    HeldHandle& operator=(const HeldHandle&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};
bool same(const PublisherHandleObservation& left, const PublisherHandleObservation& right) {
    return usk::json::canonical(publisher_handle_observation_json(left)) ==
        usk::json::canonical(publisher_handle_observation_json(right));
}
std::wstring child_name(const PublisherHandleObservation& parent, const std::wstring& component) {
    if (parent.native_name.empty()) throw std::runtime_error("maintenance file parent native name unavailable");
    return parent.native_name + (parent.native_name.back() == L'\\' ? L"" : L"\\") + component;
}
std::optional<PublisherDirectoryEntry> exact_child(HANDLE parent, const std::wstring& component,
    const PublisherMaintenanceNames* maintenance_names = nullptr) {
    std::optional<PublisherDirectoryEntry> selected;
    for (const auto& entry : observe_publisher_directory_entries(parent, 64u * 1024u * 1024u, maintenance_names)) {
        if (CompareStringOrdinal(entry.name.c_str(), -1, component.c_str(), -1, TRUE) != CSTR_EQUAL) continue;
        if (entry.name != component || selected) throw std::runtime_error("maintenance file name is ambiguous");
        selected = entry;
    }
    return selected;
}
void require_absent(HANDLE parent, const std::wstring& component) {
    using CreateFn = NTSTATUS (NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
        PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    auto* create = module ? reinterpret_cast<CreateFn>(GetProcAddress(module, "NtCreateFile")) : nullptr;
    if (!create) throw std::runtime_error("maintenance native absence observation unavailable");
    UNICODE_STRING name{};
    name.Length = static_cast<USHORT>(component.size() * sizeof(WCHAR));
    name.MaximumLength = name.Length;
    name.Buffer = const_cast<PWSTR>(component.data());
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = parent;
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE;
    IO_STATUS_BLOCK io{};
    HANDLE opened = INVALID_HANDLE_VALUE;
    // FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT.
    // No directory-only option: a regular-file collision must also refuse.
    const auto status = create(&opened, FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        &attributes, &io, nullptr, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        1u, 0x00200000u | 0x00000020u, nullptr, 0);
    HeldHandle held(opened);
    if (status != static_cast<NTSTATUS>(0xC0000034u) ||
        (opened && opened != INVALID_HANDLE_VALUE))
        throw std::runtime_error("maintenance rename destination absence is not confirmed");
}
void require_parent(HANDLE parent, const PublisherHandleObservation& expected) {
    const auto current = observe_publisher_directory_handle(parent);
    observe_publisher_noninheritable_handle_flags(parent);
    require_publisher_stream_shape(parent);
    if (!same(current, expected) || current.case_sensitive || current.link_count != 1 ||
        (current.attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        throw std::runtime_error("maintenance rename parent changed");
}
void require_content(HANDLE file, const PublisherHandleObservation& expected,
    std::uint64_t expected_size, const std::string& expected_sha256) {
    const auto before = observe_publisher_file_handle(file);
    observe_publisher_noninheritable_handle_flags(file);
    require_publisher_stream_shape(file);
    FILE_BASIC_INFO initial{}, final{};
    FILE_STANDARD_INFO standard{};
    if (!same(before, expected) || before.link_count != 1 ||
        (before.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
        !GetFileInformationByHandleEx(file, FileBasicInfo, &initial, sizeof(initial)) ||
        !GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard)) ||
        standard.Directory || standard.DeletePending || standard.EndOfFile.QuadPart < 0 ||
        static_cast<std::uint64_t>(standard.EndOfFile.QuadPart) != expected_size)
        throw std::runtime_error("maintenance rename file preimage changed");
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
        throw std::runtime_error("maintenance rename file seek unavailable");
    usk::base::Sha256 digest;
    std::array<unsigned char, 64u * 1024u> buffer{};
    std::uint64_t consumed = 0;
    while (true) {
        DWORD read = 0;
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr))
            throw std::runtime_error("maintenance rename file read unavailable");
        if (!read) break;
        if (consumed > expected_size || read > expected_size - consumed)
            throw std::runtime_error("maintenance rename file exceeded original size");
        digest.update(buffer.data(), read);
        consumed += read;
    }
    FILE_STANDARD_INFO after{};
    if (consumed != expected_size || digest.finish() != expected_sha256 ||
        !GetFileInformationByHandleEx(file, FileBasicInfo, &final, sizeof(final)) ||
        !GetFileInformationByHandleEx(file, FileStandardInfo, &after, sizeof(after)) ||
        final.LastWriteTime.QuadPart != initial.LastWriteTime.QuadPart ||
        final.ChangeTime.QuadPart != initial.ChangeTime.QuadPart ||
        after.EndOfFile.QuadPart != standard.EndOfFile.QuadPart || after.DeletePending ||
        !same(observe_publisher_file_handle(file), before))
        throw std::runtime_error("maintenance rename file content or identity changed");
    require_publisher_stream_shape(file);
}
void require_same_volume(HANDLE left, HANDLE right) {
    const auto first = observe_local_ntfs_volume_handle(left);
    const auto second = observe_local_ntfs_volume_handle(right);
    if (first.file_id_volume_serial != second.file_id_volume_serial ||
        first.volume_information_serial != second.volume_information_serial ||
        first.filesystem_name != second.filesystem_name ||
        first.filesystem_flags != second.filesystem_flags ||
        first.maximum_component_length != second.maximum_component_length ||
        first.volume_label != second.volume_label || first.remote_protocol_error != second.remote_protocol_error)
        throw std::runtime_error("maintenance rename handles differ in admitted local volume");
}
} // namespace

PublisherBoundFileRenameObservation rename_publisher_bound_file_no_replace(
    HANDLE file, HANDLE source_parent, const std::wstring& source_component,
    HANDLE destination_parent, const std::wstring& destination_component,
    const PublisherHandleObservation& expected_file,
    const PublisherHandleObservation& expected_source_parent,
    const PublisherHandleObservation& expected_destination_parent,
    std::uint64_t expected_size, const std::string& expected_sha256) {
    if (!file || file == INVALID_HANDLE_VALUE || !source_parent || source_parent == INVALID_HANDLE_VALUE ||
        !destination_parent || destination_parent == INVALID_HANDLE_VALUE ||
        file == source_parent || file == destination_parent ||
        !is_publisher_canonical_component(source_component) ||
        !is_publisher_canonical_component(destination_component) ||
        expected_sha256.size() != 64 ||
        expected_sha256.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw std::runtime_error("maintenance file rename inputs invalid");
    require_active_publisher_effect_fence();
    require_parent(source_parent, expected_source_parent);
    require_parent(destination_parent, expected_destination_parent);
    require_same_volume(file, source_parent);
    require_same_volume(file, destination_parent);
    require_content(file, expected_file, expected_size, expected_sha256);
    if (expected_file.native_name != child_name(expected_source_parent, source_component) ||
        expected_file.file_id == expected_source_parent.file_id ||
        expected_file.file_id == expected_destination_parent.file_id ||
        (expected_source_parent.file_id == expected_destination_parent.file_id &&
            source_component == destination_component))
        throw std::runtime_error("maintenance file rename source is not bound to its parent");
    const auto listed = exact_child(source_parent, source_component);
    if (!listed) throw std::runtime_error("maintenance file rename original source is absent");
    HeldHandle independent(open_publisher_listed_maintenance_file(source_parent, *listed));
    require_content(independent.get(), expected_file, expected_size, expected_sha256);
    require_absent(destination_parent, destination_component);
    PublisherRenameInformation arguments(destination_parent, destination_component);
    const auto source_access = observe_publisher_handle_granted_access(file);
    const auto parent_access = observe_publisher_handle_granted_access(destination_parent);
    if (!(source_access & DELETE) || !(parent_access & FILE_ADD_FILE))
        throw std::runtime_error("maintenance file rename handles lack actual native mutation rights");
    const auto* fields = static_cast<const FILE_RENAME_INFO*>(arguments.data());
    if (fields->RootDirectory != destination_parent || fields->ReplaceIfExists ||
        fields->FileNameLength != destination_component.size() * sizeof(WCHAR))
        throw std::runtime_error("maintenance file rename native arguments differ");
    using SetFn = NTSTATUS (NTAPI *)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, int);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    auto* set = module ? reinterpret_cast<SetFn>(GetProcAddress(module, "NtSetInformationFile")) : nullptr;
    if (!set) throw std::runtime_error("maintenance file rename native call unavailable");
    LARGE_INTEGER frequency{}, started{}, ended{};
    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0)
        throw std::runtime_error("maintenance file rename clock unavailable");
    require_parent(source_parent, expected_source_parent);
    require_parent(destination_parent, expected_destination_parent);
    require_content(file, expected_file, expected_size, expected_sha256);
    require_content(independent.get(), expected_file, expected_size, expected_sha256);
    require_active_publisher_effect_fence();
    if (!QueryPerformanceCounter(&started))
        throw std::runtime_error("maintenance file rename start clock unavailable");
    IO_STATUS_BLOCK io{};
    const auto status = set(file, &io, arguments.data(), arguments.size(), 10); // FileRenameInformation
    if (status != 0 || io.Status != 0)
        throw PublisherRenameUnconfirmed("maintenance file native rename returned NTSTATUS " +
            std::to_string(static_cast<unsigned long>(status)) + "; IO " +
            std::to_string(static_cast<unsigned long>(io.Status)) + "; retained recovery required");
    try {
        if (!QueryPerformanceCounter(&ended) || ended.QuadPart < started.QuadPart)
            throw std::runtime_error("maintenance file rename completion clock unavailable");
        require_active_publisher_effect_fence();
        require_parent(source_parent, expected_source_parent);
        require_parent(destination_parent, expected_destination_parent);
        require_same_volume(file, source_parent);
        require_same_volume(file, destination_parent);
        auto postimage = expected_file;
        postimage.native_name = child_name(expected_destination_parent, destination_component);
        require_content(file, postimage, expected_size, expected_sha256);
        require_content(independent.get(), postimage, expected_size, expected_sha256);
        require_absent(source_parent, source_component);
        const auto visible = exact_child(destination_parent, destination_component);
        if (!visible) throw std::runtime_error("maintenance renamed file is not visible");
        HeldHandle reopened(open_publisher_listed_child(destination_parent, *visible));
        require_content(reopened.get(), postimage, expected_size, expected_sha256);
        require_active_publisher_effect_fence();
        return {expected_file.file_id, expected_sha256, expected_source_parent.file_id,
            expected_destination_parent.file_id, expected_size, expected_file.native_name,
            postimage.native_name, started.QuadPart, ended.QuadPart, frequency.QuadPart,
            static_cast<std::uint32_t>(status), static_cast<std::uint32_t>(io.Status),
            source_access, parent_access};
    } catch (const std::exception& failure) {
        throw PublisherRenameUnconfirmed(std::string("maintenance file rename returned success but ") +
            failure.what() + "; retained recovery required");
    }
}
namespace {
PublisherBoundRemovalObservation remove_bound_object(
    HANDLE parent, const std::wstring& component,
    const PublisherHandleObservation& expected,
    const PublisherHandleObservation& expected_parent,
    bool directory, std::uint64_t expected_size, const std::string& expected_sha256,
    const PublisherMaintenanceNames* maintenance_names = nullptr) {
    if (!parent || parent == INVALID_HANDLE_VALUE || !is_publisher_admitted_component(parent, component, maintenance_names) ||
        expected.native_name != child_name(expected_parent, component) ||
        expected.file_id == expected_parent.file_id ||
        (!directory && (expected_sha256.size() != 64 ||
            expected_sha256.find_first_not_of("0123456789abcdef") != std::string::npos)))
        throw std::runtime_error("maintenance native removal inputs invalid");
    require_active_publisher_effect_fence();
    require_parent(parent, expected_parent);
    const auto listed = exact_child(parent, component, maintenance_names);
    if (!listed) throw std::runtime_error("maintenance native removal original child absent");
    auto owner = std::make_shared<detail::PublisherRemovalOwner>();
    owner->open_once(parent, *listed, directory, maintenance_names);
    const auto require_object = [&] {
        if (directory) {
            const auto observed = observe_publisher_directory_handle(owner->get());
            observe_publisher_noninheritable_handle_flags(owner->get());
            require_publisher_stream_shape(owner->get());
            if (!same(observed, expected) || observed.case_sensitive || observed.link_count != 1 ||
                (observed.attributes & FILE_ATTRIBUTE_REPARSE_POINT))
                throw std::runtime_error("maintenance removal directory changed");
        } else require_content(owner->get(), expected, expected_size, expected_sha256);
        require_same_volume(owner->get(), parent);
        require_parent(parent, expected_parent);
    };
    require_object();
    const auto access = observe_publisher_handle_granted_access(owner->get());
    if (!(access & DELETE)) throw std::runtime_error("maintenance removal handle lacks actual DELETE");
    if (directory && !observe_publisher_directory_entries(owner->get()).empty()) {
        require_object();
        require_active_publisher_effect_fence();
        return {expected.file_id, expected_parent.file_id, component, false, false,
            0, 0, 0, 0, 0, access};
    }
    FILE_STANDARD_INFO before{};
    if (!GetFileInformationByHandleEx(owner->get(), FileStandardInfo, &before, sizeof(before)) ||
        before.DeletePending || (before.Directory != FALSE) != directory)
        throw std::runtime_error("maintenance removal initial disposition unavailable");
    using SetFn = NTSTATUS (NTAPI *)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, int);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    auto* set = module ? reinterpret_cast<SetFn>(GetProcAddress(module, "NtSetInformationFile")) : nullptr;
    if (!set) throw std::runtime_error("maintenance native disposition call unavailable");
    LARGE_INTEGER frequency{}, started{}, ended{};
    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0)
        throw std::runtime_error("maintenance removal clock unavailable");
    require_object();
    require_active_publisher_effect_fence();
    if (!QueryPerformanceCounter(&started))
        throw std::runtime_error("maintenance removal start clock unavailable");
    FILE_DISPOSITION_INFO disposition{TRUE};
    IO_STATUS_BLOCK io{};
    const auto affected = owner->get();
    owner->disposition_attempted = true;
    const auto status = set(affected, &io, &disposition,
        static_cast<ULONG>(sizeof(disposition)), 13); // FileDispositionInformation
    const bool clock_available = QueryPerformanceCounter(&ended) && ended.QuadPart >= started.QuadPart;
    // After disposition the only operation on the affected object is close.
    // One attempt clears ownership only on TRUE. FALSE is quarantined in the
    // typed failure, with no subsequent use or destructor retry before worker
    // disposal. No assumption about whether the numeric handle is still open.
    const bool closed = owner->close_once();
    if (status != 0 || io.Status != 0 || !closed)
        throw PublisherRemovalUnconfirmed("maintenance native removal returned NTSTATUS " +
            std::to_string(static_cast<unsigned long>(status)) + "; IO " +
            std::to_string(static_cast<unsigned long>(io.Status)) + "; close confirmed " +
            (closed ? "true" : "false") + "; close error " + std::to_string(owner->close_error) +
            "; retained recovery required", owner);
    try {
        if (!clock_available)
            throw std::runtime_error("maintenance removal completion clock unavailable");
        require_active_publisher_effect_fence();
        require_parent(parent, expected_parent);
        require_absent(parent, component);
        require_active_publisher_effect_fence();
        return {expected.file_id, expected_parent.file_id, component, true, true,
            started.QuadPart, ended.QuadPart, frequency.QuadPart,
            static_cast<std::uint32_t>(status), static_cast<std::uint32_t>(io.Status), access};
    } catch (const std::exception& failure) {
        throw PublisherRemovalUnconfirmed(std::string("maintenance removal returned success but ") +
            failure.what() + "; retained recovery required", owner);
    }
}
}

PublisherBoundRemovalObservation remove_publisher_bound_file(
    HANDLE parent, const std::wstring& component,
    const PublisherHandleObservation& expected_file,
    const PublisherHandleObservation& expected_parent,
    std::uint64_t expected_size, const std::string& expected_sha256) {
    return remove_bound_object(parent, component, expected_file, expected_parent,
        false, expected_size, expected_sha256);
}
PublisherBoundRemovalObservation remove_publisher_bound_empty_directory(
    HANDLE parent, const std::wstring& component,
    const PublisherHandleObservation& expected_directory,
    const PublisherHandleObservation& expected_parent, const PublisherMaintenanceNames* maintenance_names) {
    return remove_bound_object(parent, component, expected_directory, expected_parent,
        true, 0, {}, maintenance_names);
}
}
#endif
