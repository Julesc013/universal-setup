// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_handle_observation.h"

#if defined(_WIN32)
#include <aclapi.h>
#include <sddl.h>

#include <cstddef>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace usk::platform::windows {
namespace {
struct LocalFreeDeleter {
    void operator()(void* pointer) const { if (pointer) LocalFree(pointer); }
};
using LocalAllocation = std::unique_ptr<void, LocalFreeDeleter>;

std::string sid_text(PSID sid) {
    if (!sid || !IsValidSid(sid)) throw std::runtime_error("publisher observation has an invalid SID");
    LPWSTR raw = nullptr;
    if (!ConvertSidToStringSidW(sid, &raw)) {
        throw std::runtime_error("publisher observation cannot render a SID");
    }
    LocalAllocation owned(raw);
    std::string result;
    for (const wchar_t* cursor = raw; *cursor; ++cursor) {
        if (*cursor > 0x7f) throw std::runtime_error("publisher observation SID is not ASCII");
        result.push_back(static_cast<char>(*cursor));
    }
    return result;
}

std::string file_id_text(const FILE_ID_INFO& id) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(16 + 1 + sizeof(id.FileId.Identifier) * 2, '0');
    for (unsigned index = 0; index < 8; ++index) {
        const auto byte = static_cast<unsigned>((id.VolumeSerialNumber >> ((7u - index) * 8u)) & 0xffu);
        result[index * 2] = digits[byte >> 4];
        result[index * 2 + 1] = digits[byte & 15u];
    }
    result[16] = ':';
    for (std::size_t index = 0; index < sizeof(id.FileId.Identifier); ++index) {
        const auto byte = id.FileId.Identifier[index];
        result[17 + index * 2] = digits[byte >> 4];
        result[18 + index * 2] = digits[byte & 15u];
    }
    return result;
}

std::wstring handle_name(HANDLE handle) {
    std::vector<unsigned char> buffer(65536);
    if (!GetFileInformationByHandleEx(handle, FileNameInfo, buffer.data(),
            static_cast<DWORD>(buffer.size()))) {
        throw std::runtime_error("publisher observation cannot read the handle name");
    }
    const auto* info = reinterpret_cast<const FILE_NAME_INFO*>(buffer.data());
    if (info->FileNameLength % sizeof(WCHAR) != 0 ||
        info->FileNameLength > buffer.size() - offsetof(FILE_NAME_INFO, FileName)) {
        throw std::runtime_error("publisher observation has a malformed handle name");
    }
    return {info->FileName, info->FileNameLength / sizeof(WCHAR)};
}

std::vector<ObservedAce> observe_aces(PACL dacl) {
    if (!dacl || !IsValidAcl(dacl)) {
        throw std::runtime_error("publisher observation requires a valid non-null DACL");
    }
    std::vector<ObservedAce> entries;
    entries.reserve(dacl->AceCount);
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void* raw = nullptr;
        if (!GetAce(dacl, index, &raw) || !raw) {
            throw std::runtime_error("publisher observation cannot read a DACL ACE");
        }
        const auto* header = static_cast<const ACE_HEADER*>(raw);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE &&
            header->AceType != ACCESS_DENIED_ACE_TYPE) {
            throw std::runtime_error("publisher observation refuses an unsupported ACE type");
        }
        if (header->AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(DWORD)) {
            throw std::runtime_error("publisher observation has a truncated ACE");
        }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        auto* sid = reinterpret_cast<PSID>(const_cast<DWORD*>(&ace->SidStart));
        const auto sid_capacity = header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart);
        const auto* sid_bytes = reinterpret_cast<const unsigned char*>(sid);
        const auto subauthority_count = sid_bytes[1];
        const auto bounded_sid_size = 8u + 4u * subauthority_count;
        if (subauthority_count > SID_MAX_SUB_AUTHORITIES ||
            bounded_sid_size > sid_capacity || !IsValidSid(sid) ||
            GetLengthSid(sid) != bounded_sid_size) {
            throw std::runtime_error("publisher observation has a malformed ACE SID");
        }
        entries.push_back({header->AceType, header->AceFlags, ace->Mask, sid_text(sid)});
    }
    return entries;
}
} // namespace

PublisherHandleObservation observe_publisher_directory_handle(HANDLE handle) {
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("publisher observation requires an open handle");
    }
    FILE_ID_INFO id{};
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    FILE_STANDARD_INFO standard{};
    FILE_CASE_SENSITIVE_INFO case_info{};
    if (!GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id)) ||
        !GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        !GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)) ||
        !GetFileInformationByHandleEx(handle, FileCaseSensitiveInfo, &case_info, sizeof(case_info))) {
        throw std::runtime_error("publisher observation cannot read all directory identity facts");
    }
    if ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        throw std::runtime_error("publisher observation requires a directory handle");
    }
    const std::wstring name = handle_name(handle);
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
    const DWORD security_status = GetSecurityInfo(handle, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &raw_descriptor);
    LocalAllocation descriptor(raw_descriptor);
    if (security_status != ERROR_SUCCESS || !raw_descriptor) {
        throw std::runtime_error("publisher observation cannot read same-handle security facts");
    }
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(raw_descriptor, &control, &revision)) {
        throw std::runtime_error("publisher observation cannot read DACL control flags");
    }
    return {file_id_text(id), name, attributes.FileAttributes, attributes.ReparseTag,
        standard.NumberOfLinks, (case_info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR) != 0,
        sid_text(owner), (control & SE_DACL_PROTECTED) != 0, observe_aces(dacl)};
}

} // namespace usk::platform::windows
#endif
