// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_rename_information.h"
#include "usk_publisher_volume_stream_observation.h"

#if defined(_WIN32)
#include <winternl.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace usk::platform::windows {
namespace {
class OwnedHandle {
public:
    explicit OwnedHandle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
    ~OwnedHandle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};

bool same_aces(const std::vector<ObservedAce>& left,
    const std::vector<ObservedAce>& right) {
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (left[index].type != right[index].type ||
            left[index].flags != right[index].flags ||
            left[index].access_mask != right[index].access_mask ||
            left[index].sid != right[index].sid) return false;
    }
    return true;
}

bool same_object(const PublisherHandleObservation& left,
    const PublisherHandleObservation& right, bool compare_name) {
    return left.file_id == right.file_id &&
        (!compare_name || left.native_name == right.native_name) &&
        left.attributes == right.attributes &&
        left.reparse_tag == right.reparse_tag &&
        left.link_count == right.link_count &&
        left.case_sensitive == right.case_sensitive &&
        left.owner_sid == right.owner_sid &&
        left.dacl_protected == right.dacl_protected &&
        same_aces(left.dacl_aces, right.dacl_aces);
}

bool same_volume(const PublisherVolumeObservation& left,
    const PublisherVolumeObservation& right) {
    return left.volume_label == right.volume_label &&
        left.volume_information_serial == right.volume_information_serial &&
        left.file_id_volume_serial == right.file_id_volume_serial &&
        left.filesystem_name == right.filesystem_name &&
        left.maximum_component_length == right.maximum_component_length &&
        left.filesystem_flags == right.filesystem_flags &&
        left.remote_protocol_error == right.remote_protocol_error;
}

NTSTATUS open_relative_directory(HANDLE parent, const std::wstring& component,
    HANDLE& opened) {
    using NtCreateFileFn = NTSTATUS (NTAPI *)(PHANDLE, ACCESS_MASK,
        POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
        ULONG, ULONG, PVOID, ULONG);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto* nt_create = ntdll ? reinterpret_cast<NtCreateFileFn>(
        GetProcAddress(ntdll, "NtCreateFile")) : nullptr;
    if (!nt_create) throw std::runtime_error("publisher relative open is unavailable");
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
    opened = INVALID_HANDLE_VALUE;
    constexpr ULONG open_existing = 1; // FILE_OPEN
    constexpr ULONG no_follow = 0x00200000; // FILE_OPEN_REPARSE_POINT
    constexpr ULONG synchronous = 0x00000020; // FILE_SYNCHRONOUS_IO_NONALERT
    return nt_create(&opened, FILE_READ_ATTRIBUTES | READ_CONTROL |
        FILE_LIST_DIRECTORY | SYNCHRONIZE, &attributes, &io, nullptr,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE |
        FILE_SHARE_DELETE, open_existing,
        FILE_DIRECTORY_FILE | no_follow | synchronous, nullptr, 0);
}
} // namespace

PublisherBoundRenameObservation probe_publisher_bound_rename_no_replace(
    HANDLE staged_root, HANDLE destination_parent,
    const std::wstring& destination_component,
    const PublisherHandleObservation& expected_staged_root,
    const PublisherHandleObservation& expected_destination_parent,
    const std::function<void()>& after_absence_check) {
    if (!staged_root || staged_root == INVALID_HANDLE_VALUE ||
        !destination_parent || destination_parent == INVALID_HANDLE_VALUE ||
        staged_root == destination_parent ||
        !is_publisher_canonical_component(destination_component)) {
        throw std::runtime_error("publisher rename has invalid bound inputs");
    }
    const auto staged = observe_publisher_directory_handle(staged_root);
    const auto parent = observe_publisher_directory_handle(destination_parent);
    const auto staged_volume = observe_local_ntfs_volume_handle(staged_root);
    const auto parent_volume = observe_local_ntfs_volume_handle(destination_parent);
    if (!same_object(staged, expected_staged_root, true) ||
        !same_object(parent, expected_destination_parent, true) ||
        !same_volume(staged_volume, parent_volume) ||
        staged.file_id == parent.file_id || staged.case_sensitive ||
        parent.case_sensitive || staged.link_count != 1 || parent.link_count != 1 ||
        (staged.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (parent.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        throw std::runtime_error("publisher rename preflight identity or volume changed");
    }
    HANDLE present = INVALID_HANDLE_VALUE;
    const NTSTATUS absent = open_relative_directory(
        destination_parent, destination_component, present);
    OwnedHandle unexpected(present);
    constexpr NTSTATUS name_not_found = static_cast<NTSTATUS>(0xC0000034u);
    if (absent != name_not_found) {
        throw std::runtime_error("publisher rename cannot establish absent destination");
    }
    if (after_absence_check) after_absence_check();
    if (!same_object(observe_publisher_directory_handle(staged_root), staged, true) ||
        !same_object(observe_publisher_directory_handle(destination_parent), parent, true) ||
        !same_volume(observe_local_ntfs_volume_handle(staged_root), staged_volume) ||
        !same_volume(observe_local_ntfs_volume_handle(destination_parent), parent_volume)) {
        throw std::runtime_error("publisher rename bound handles changed before call");
    }
    PublisherRenameInformation information(destination_parent, destination_component);
    using NtSetInformationFileFn = NTSTATUS (NTAPI *)(
        HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, int);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto* nt_set = ntdll ? reinterpret_cast<NtSetInformationFileFn>(
        GetProcAddress(ntdll, "NtSetInformationFile")) : nullptr;
    if (!nt_set) throw std::runtime_error("publisher native rename is unavailable");
    IO_STATUS_BLOCK io{};
    const NTSTATUS status = nt_set(staged_root, &io, information.data(),
        information.size(), 10 /* FileRenameInformation */);
    if (status != 0 || io.Status != 0) {
        throw PublisherRenameUnconfirmed("publisher native rename returned NTSTATUS " +
            std::to_string(static_cast<unsigned long>(status)) +
            "; IO status " + std::to_string(static_cast<unsigned long>(io.Status)) +
            "; buffer bytes " + std::to_string(information.size()) +
            "; outcome requires retained recovery observation");
    }
    try {
        const auto moved = observe_publisher_directory_handle(staged_root);
        const auto parent_after = observe_publisher_directory_handle(destination_parent);
        const std::wstring visible_name = parent.native_name +
            (parent.native_name.back() == L'\\' ? L"" : L"\\") +
            destination_component;
        if (!same_object(moved, staged, false) ||
            moved.native_name != visible_name ||
            !same_object(parent_after, parent, true) ||
            !same_volume(observe_local_ntfs_volume_handle(staged_root), staged_volume) ||
            !same_volume(observe_local_ntfs_volume_handle(destination_parent), parent_volume)) {
            throw std::runtime_error("publisher post-rename handle identity changed");
        }
        HANDLE opened = INVALID_HANDLE_VALUE;
        const NTSTATUS reopened = open_relative_directory(
            destination_parent, destination_component, opened);
        OwnedHandle visible(opened);
        if (reopened != 0 || !visible.get() ||
            visible.get() == INVALID_HANDLE_VALUE ||
            !same_object(observe_publisher_directory_handle(visible.get()), moved, true)) {
            throw std::runtime_error("publisher visible child did not rebind to staged root");
        }
        return {staged.file_id, staged.native_name, moved.native_name};
    } catch (const std::exception& failure) {
        throw PublisherRenameUnconfirmed(std::string("publisher rename returned success but ") +
            failure.what() + "; retained recovery required");
    }
}
} // namespace usk::platform::windows
#endif
