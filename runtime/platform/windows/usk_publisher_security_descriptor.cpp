// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_security_descriptor.h"

#if defined(_WIN32)
#include <sddl.h>

#include <cstddef>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <vector>

namespace usk::platform::windows {
namespace {
struct LocalFreeDeleter {
    void operator()(void* pointer) const { if (pointer) LocalFree(pointer); }
};

bool is_service_sid(PSID sid) {
    if (!sid || !IsValidSid(sid) || *GetSidSubAuthorityCount(sid) != 6 ||
        *GetSidSubAuthority(sid, 0) != SECURITY_SERVICE_ID_BASE_RID) return false;
    const SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    return std::memcmp(GetSidIdentifierAuthority(sid), &nt_authority,
        sizeof(nt_authority)) == 0;
}
} // namespace

DWORD publisher_directory_access_mask() {
    return DELETE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_APPEND_DATA |
        FILE_DELETE_CHILD | FILE_EXECUTE | FILE_LIST_DIRECTORY |
        FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA | FILE_TRAVERSE |
        FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_EA |
        READ_CONTROL | SYNCHRONIZE | WRITE_DAC | WRITE_OWNER;
}

std::vector<unsigned char> make_publisher_directory_security_descriptor(
    const std::wstring& service_sid) {
    if (service_sid.empty()) throw std::runtime_error("publisher service SID is missing");
    PSID raw_service_sid = nullptr;
    if (!ConvertStringSidToSidW(service_sid.c_str(), &raw_service_sid)) {
        throw std::runtime_error("publisher service SID is malformed");
    }
    std::unique_ptr<void, LocalFreeDeleter> owned_service_sid(raw_service_sid);
    if (!is_service_sid(raw_service_sid)) {
        throw std::runtime_error("publisher security descriptor requires a service SID");
    }
    alignas(DWORD) unsigned char system_sid[SECURITY_MAX_SID_SIZE]{};
    DWORD system_size = sizeof(system_sid);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system_sid, &system_size)) {
        throw std::runtime_error("publisher SYSTEM SID construction failed");
    }
    const auto system_length = GetLengthSid(system_sid);
    const auto service_length = GetLengthSid(raw_service_sid);
    const std::size_t acl_size = sizeof(ACL) +
        2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) +
        system_length + service_length;
    if (acl_size > std::numeric_limits<DWORD>::max()) {
        throw std::runtime_error("publisher ACL length exceeds Windows limits");
    }
    std::vector<unsigned char> acl_bytes(acl_size);
    auto* acl = reinterpret_cast<PACL>(acl_bytes.data());
    if (!InitializeAcl(acl, static_cast<DWORD>(acl_size), ACL_REVISION) ||
        !AddAccessAllowedAceEx(acl, ACL_REVISION, 0,
            publisher_directory_access_mask(), system_sid) ||
        !AddAccessAllowedAceEx(acl, ACL_REVISION, 0,
            publisher_directory_access_mask(), raw_service_sid)) {
        throw std::runtime_error("publisher protected ACL construction failed");
    }
    SECURITY_DESCRIPTOR absolute{};
    if (!InitializeSecurityDescriptor(&absolute, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorOwner(&absolute, system_sid, FALSE) ||
        !SetSecurityDescriptorDacl(&absolute, TRUE, acl, FALSE) ||
        !SetSecurityDescriptorControl(&absolute, SE_DACL_PROTECTED,
            SE_DACL_PROTECTED)) {
        throw std::runtime_error("publisher protected descriptor construction failed");
    }
    DWORD relative_size = 0;
    if (MakeSelfRelativeSD(&absolute, nullptr, &relative_size) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || relative_size == 0) {
        throw std::runtime_error("publisher descriptor size query failed");
    }
    std::vector<unsigned char> relative(relative_size);
    if (!MakeSelfRelativeSD(&absolute, relative.data(), &relative_size) ||
        relative_size != relative.size() ||
        !IsValidSecurityDescriptor(relative.data())) {
        throw std::runtime_error("publisher self-relative descriptor is invalid");
    }
    return relative;
}

} // namespace usk::platform::windows
#endif
