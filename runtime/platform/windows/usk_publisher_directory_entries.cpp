// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_directory_entries.h"

#if defined(_WIN32)
#include <winternl.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace usk::platform::windows {
namespace {
struct OrdinalCaseInsensitive {
    bool operator()(const std::wstring& left, const std::wstring& right) const {
        const int order = CompareStringOrdinal(left.data(), static_cast<int>(left.size()),
            right.data(), static_cast<int>(right.size()), TRUE);
        if (order == 0) {
            throw std::runtime_error("publisher directory name comparison failed");
        }
        return order == CSTR_LESS_THAN;
    }
};

std::wstring native_handle_name(HANDLE handle) {
    constexpr std::size_t buffer_bytes = 64 * 1024;
    std::vector<std::max_align_t> buffer(
        (buffer_bytes + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t));
    if (!GetFileInformationByHandleEx(handle, FileNameInfo, buffer.data(),
            static_cast<DWORD>(buffer_bytes))) {
        throw std::runtime_error("publisher child native name is unavailable");
    }
    const auto* info = reinterpret_cast<const FILE_NAME_INFO*>(buffer.data());
    if (info->FileNameLength % sizeof(WCHAR) != 0 ||
        info->FileNameLength > buffer_bytes - offsetof(FILE_NAME_INFO, FileName)) {
        throw std::runtime_error("publisher child native name is malformed");
    }
    return {info->FileName, info->FileNameLength / sizeof(WCHAR)};
}

bool valid_component(const std::wstring& name) {
    if (name.empty() || name.size() > 255 || name == L"." || name == L".." ||
        name.back() == L'.' || name.back() == L' ' ||
        !IsNormalizedString(NormalizationC, name.data(),
            static_cast<int>(name.size()))) return false;
    for (const wchar_t ch : name) {
        if (ch < 32 || ch == 127 || ch == L'\\' || ch == L'/' ||
            ch == L':' || ch == L'<' || ch == L'>' || ch == L'"' ||
            ch == L'|' || ch == L'?' || ch == L'*') return false;
    }
    const std::wstring stem = name.substr(0, name.find(L'.'));
    if (stem.empty() || stem.back() == L' ') return false;
    const auto equals = [&](const wchar_t* reserved) {
        return CompareStringOrdinal(stem.data(), static_cast<int>(stem.size()),
            reserved, -1, TRUE) == CSTR_EQUAL;
    };
    if (equals(L"CON") || equals(L"PRN") || equals(L"AUX") ||
        equals(L"NUL")) return false;
    for (const wchar_t* prefix : {L"COM", L"LPT"}) {
        if (stem.size() == 4 &&
            CompareStringOrdinal(stem.data(), 3, prefix, 3, TRUE) == CSTR_EQUAL &&
            ((stem[3] >= L'1' && stem[3] <= L'9') ||
                stem[3] == L'\u00b9' || stem[3] == L'\u00b2' ||
                stem[3] == L'\u00b3')) return false;
    }
    return true;
}
} // namespace

bool is_publisher_canonical_component(const std::wstring& name) {
    return valid_component(name);
}

std::vector<PublisherDirectoryEntry> observe_publisher_directory_entries(
    HANDLE directory, std::size_t byte_budget) {
    if (!directory || directory == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("publisher directory enumeration requires a handle");
    }
    if (byte_budget == 0 || byte_budget > 64 * 1024 * 1024) {
        throw std::runtime_error("publisher directory enumeration byte budget is invalid");
    }
    FILE_ATTRIBUTE_TAG_INFO type{};
    if (!GetFileInformationByHandleEx(directory, FileAttributeTagInfo,
            &type, sizeof(type)) ||
        (type.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        throw std::runtime_error("publisher directory enumeration requires a directory");
    }
    constexpr std::size_t buffer_bytes = 64 * 1024;
    constexpr std::size_t maximum_entries = 200000;
    std::vector<std::max_align_t> buffer(
        (buffer_bytes + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t));
    auto* data = reinterpret_cast<unsigned char*>(buffer.data());
    std::vector<PublisherDirectoryEntry> entries;
    std::set<std::wstring, OrdinalCaseInsensitive> names;
    std::size_t evidence_bytes = 0;
    bool restart = true;
    while (true) {
        std::memset(data, 0, buffer_bytes);
        const auto info_class = restart ? FileIdExtdDirectoryRestartInfo :
            FileIdExtdDirectoryInfo;
        restart = false;
        if (!GetFileInformationByHandleEx(directory, info_class, data,
                static_cast<DWORD>(buffer_bytes))) {
            const DWORD error = GetLastError();
            if (error == ERROR_NO_MORE_FILES) break;
            throw std::runtime_error("publisher directory enumeration failed; Win32 " +
                std::to_string(error));
        }
        std::size_t offset = 0;
        while (true) {
            if (buffer_bytes - offset < offsetof(FILE_ID_EXTD_DIR_INFO, FileName)) {
                throw std::runtime_error("publisher directory record is truncated");
            }
            const auto* info = reinterpret_cast<const FILE_ID_EXTD_DIR_INFO*>(
                data + offset);
            const std::size_t record_bytes = info->NextEntryOffset == 0 ?
                buffer_bytes - offset : info->NextEntryOffset;
            if (record_bytes < offsetof(FILE_ID_EXTD_DIR_INFO, FileName) ||
                record_bytes > buffer_bytes - offset ||
                info->FileNameLength == 0 ||
                info->FileNameLength % sizeof(WCHAR) != 0 ||
                info->FileNameLength > 255 * sizeof(WCHAR) ||
                info->FileNameLength >
                    record_bytes - offsetof(FILE_ID_EXTD_DIR_INFO, FileName) ||
                info->EndOfFile.QuadPart < 0) {
                throw std::runtime_error("publisher directory record is malformed");
            }
            std::wstring name(info->FileName,
                info->FileNameLength / sizeof(WCHAR));
            if (name != L"." && name != L"..") {
                if (!valid_component(name)) {
                    throw std::runtime_error("publisher directory name is outside the canonical profile");
                }
                if (names.find(name) != names.end()) {
                    throw std::runtime_error("publisher directory contains case-fold aliases");
                }
                const std::size_t entry_bytes =
                    2 * sizeof(PublisherDirectoryEntry) +
                    2 * name.size() * sizeof(WCHAR) + 128;
                if (entries.size() >= maximum_entries ||
                    entry_bytes > byte_budget - evidence_bytes) {
                    throw std::runtime_error("publisher directory enumeration exceeds its budget");
                }
                names.insert(name);
                evidence_bytes += entry_bytes;
                PublisherDirectoryEntry entry{};
                entry.name = std::move(name);
                std::copy(std::begin(info->FileId.Identifier),
                    std::end(info->FileId.Identifier), entry.file_id.begin());
                entry.attributes = info->FileAttributes;
                entry.reparse_tag =
                    (info->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ?
                    info->ReparsePointTag : 0;
                entry.listing_size = info->EndOfFile.QuadPart;
                entries.push_back(std::move(entry));
            }
            if (info->NextEntryOffset == 0) break;
            if (info->NextEntryOffset % 8 != 0 ||
                info->NextEntryOffset > buffer_bytes - offset) {
                throw std::runtime_error("publisher directory linkage is malformed");
            }
            offset += info->NextEntryOffset;
        }
    }
    return entries;
}

HANDLE open_publisher_listed_child(HANDLE parent,
    const PublisherDirectoryEntry& listed) {
    if (!parent || parent == INVALID_HANDLE_VALUE ||
        !valid_component(listed.name)) {
        throw std::runtime_error("publisher relative child open has invalid inputs");
    }
    using NtCreateFileFn = NTSTATUS (NTAPI *)(PHANDLE, ACCESS_MASK,
        POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
        ULONG, ULONG, PVOID, ULONG);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto* nt_create = ntdll ? reinterpret_cast<NtCreateFileFn>(
        GetProcAddress(ntdll, "NtCreateFile")) : nullptr;
    if (!nt_create) throw std::runtime_error("publisher relative open is unavailable");
    UNICODE_STRING object_name{};
    object_name.Length = static_cast<USHORT>(listed.name.size() * sizeof(WCHAR));
    object_name.MaximumLength = object_name.Length;
    object_name.Buffer = const_cast<PWSTR>(listed.name.data());
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = parent;
    attributes.ObjectName = &object_name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE;
    const bool directory = (listed.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    const ACCESS_MASK access = FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE |
        (directory ? (FILE_LIST_DIRECTORY | FILE_TRAVERSE) : FILE_READ_DATA);
    constexpr ULONG open_existing = 1; // FILE_OPEN
    constexpr ULONG no_follow = 0x00200000; // FILE_OPEN_REPARSE_POINT
    constexpr ULONG synchronous = 0x00000020; // FILE_SYNCHRONOUS_IO_NONALERT
    IO_STATUS_BLOCK io{};
    HANDLE child = INVALID_HANDLE_VALUE;
    const NTSTATUS outcome = nt_create(&child, access, &attributes, &io,
        nullptr, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        open_existing, no_follow | synchronous |
            (directory ? 0x00000001u : 0x00000040u), // DIRECTORY/NON_DIRECTORY_FILE
        nullptr, 0);
    if (outcome != 0 || !child || child == INVALID_HANDLE_VALUE) {
        if (child && child != INVALID_HANDLE_VALUE) CloseHandle(child);
        throw std::runtime_error("publisher parent-bound child open failed; NTSTATUS " +
            std::to_string(static_cast<unsigned long>(outcome)));
    }
    try {
        FILE_ID_INFO parent_id{};
        FILE_ID_INFO child_id{};
        FILE_ATTRIBUTE_TAG_INFO child_attributes{};
        FILE_STANDARD_INFO child_standard{};
        if (!GetFileInformationByHandleEx(parent, FileIdInfo,
                &parent_id, sizeof(parent_id)) ||
            !GetFileInformationByHandleEx(child, FileIdInfo,
                &child_id, sizeof(child_id)) ||
            !GetFileInformationByHandleEx(child, FileAttributeTagInfo,
                &child_attributes, sizeof(child_attributes)) ||
            !GetFileInformationByHandleEx(child, FileStandardInfo,
                &child_standard, sizeof(child_standard))) {
            throw std::runtime_error("publisher child handle lacks identity facts");
        }
        if (child_id.VolumeSerialNumber != parent_id.VolumeSerialNumber ||
            !std::equal(listed.file_id.begin(), listed.file_id.end(),
                std::begin(child_id.FileId.Identifier)) ||
            ((child_attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory ||
            (child_attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            (listed.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            child_standard.NumberOfLinks != 1) {
            throw std::runtime_error("publisher child listing and held identity diverged");
        }
        std::wstring expected = native_handle_name(parent);
        if (expected.empty() || expected.back() != L'\\') expected += L'\\';
        expected += listed.name;
        if (native_handle_name(child) != expected) {
            throw std::runtime_error("publisher child native name differs from its bound parent");
        }
        return child;
    } catch (...) {
        CloseHandle(child);
        throw;
    }
}

} // namespace usk::platform::windows
#endif
