// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_anchor_create.h"
#include "usk_publisher_directory_entries.h"

#if defined(_WIN32)
#include <winternl.h>

#include <algorithm>
#include <cwctype>
#include <stdexcept>
#include <string>
#include <vector>

namespace usk::platform::windows {
namespace {
bool valid_component(const std::wstring& name) {
    if (name.empty() || name.size() > 128 || name.back() == L'.') return false;
    for (const wchar_t ch : name) {
        if (!((ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z') ||
              (ch >= L'0' && ch <= L'9') || ch == L'_' || ch == L'-' || ch == L'.')) return false;
    }
    std::wstring stem = name.substr(0, name.find(L'.'));
    std::transform(stem.begin(), stem.end(), stem.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towupper(ch));
    });
    if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" ||
        (stem.size() == 4 && (stem.compare(0, 3, L"COM") == 0 ||
            stem.compare(0, 3, L"LPT") == 0) && stem[3] >= L'1' && stem[3] <= L'9')) {
        return false;
    }
    return true;
}
} // namespace

static HANDLE create_relative_with_descriptor(
    HANDLE parent, const std::wstring& name,
    const std::vector<unsigned char>& security_descriptor, bool directory) {
    if (!parent || parent == INVALID_HANDLE_VALUE ||
        !(directory ? valid_component(name) : is_publisher_canonical_component(name)) ||
        security_descriptor.empty() ||
        !IsValidSecurityDescriptor(const_cast<unsigned char*>(security_descriptor.data()))) {
        throw std::runtime_error("publisher anchor creation has invalid bound inputs");
    }
    using NtCreateFileFn = NTSTATUS (NTAPI *)(PHANDLE, ACCESS_MASK,
        POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
        ULONG, ULONG, PVOID, ULONG);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto* nt_create = ntdll ? reinterpret_cast<NtCreateFileFn>(
        GetProcAddress(ntdll, "NtCreateFile")) : nullptr;
    if (!nt_create) throw std::runtime_error("Windows relative creation entry point is unavailable");
    std::vector<unsigned char> descriptor = security_descriptor;
    UNICODE_STRING object_name{};
    object_name.Length = static_cast<USHORT>(name.size() * sizeof(WCHAR));
    object_name.MaximumLength = static_cast<USHORT>((name.size() + 1) * sizeof(WCHAR));
    object_name.Buffer = const_cast<PWSTR>(name.c_str());
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = parent;
    attributes.ObjectName = &object_name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    attributes.SecurityDescriptor = descriptor.data();
    IO_STATUS_BLOCK io{};
    HANDLE created = INVALID_HANDLE_VALUE;
    constexpr ULONG create_only = 2; // FILE_CREATE: existing names collide.
    const ACCESS_MASK access = directory
        ? FILE_READ_ATTRIBUTES | FILE_TRAVERSE | FILE_LIST_DIRECTORY |
            FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | DELETE |
            READ_CONTROL | SYNCHRONIZE
        : FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES |
            FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
    const ULONG options = (directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE) |
        FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT;
    const NTSTATUS outcome = nt_create(&created, access,
        &attributes, &io, nullptr,
        directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, create_only,
        options, nullptr, 0);
    constexpr ULONG created_new_object = 2; // FILE_CREATED in IO_STATUS_BLOCK.Information.
    if (outcome != 0 || !created || created == INVALID_HANDLE_VALUE ||
        io.Information != created_new_object) {
        if (created && created != INVALID_HANDLE_VALUE) CloseHandle(created);
        throw std::runtime_error("Windows parent-bound create-only object failed; NTSTATUS " +
            std::to_string(static_cast<unsigned long>(outcome)));
    }
    return created;
}

HANDLE create_directory_relative_with_descriptor(
    HANDLE parent, const std::wstring& name,
    const std::vector<unsigned char>& security_descriptor) {
    return create_relative_with_descriptor(parent, name, security_descriptor, true);
}

HANDLE create_file_relative_with_descriptor(
    HANDLE parent, const std::wstring& name,
    const std::vector<unsigned char>& security_descriptor) {
    return create_relative_with_descriptor(parent, name, security_descriptor, false);
}

} // namespace usk::platform::windows
#endif
