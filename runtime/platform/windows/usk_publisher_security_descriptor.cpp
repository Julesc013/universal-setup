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

std::vector<unsigned char> read_publisher_owner_dacl_from_handle(HANDLE object) {
    if (!object || object == INVALID_HANDLE_VALUE)
        throw std::runtime_error("publisher stored security requires an open handle");
    constexpr auto requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    DWORD needed = 0;
    if (GetKernelObjectSecurity(object, requested, nullptr, 0, &needed) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        needed < SECURITY_DESCRIPTOR_MIN_LENGTH || needed > 65536)
        throw std::runtime_error("publisher stored security size is unavailable or exceeds its bound");
    std::vector<unsigned char> bytes(needed);
    DWORD returned = 0;
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    if (!GetKernelObjectSecurity(object, requested, bytes.data(), needed, &returned) ||
        returned != needed || !IsValidSecurityDescriptor(bytes.data()) ||
        GetSecurityDescriptorLength(bytes.data()) != needed ||
        !GetSecurityDescriptorControl(bytes.data(), &control, &revision) ||
        (control & SE_SELF_RELATIVE) == 0)
        throw std::runtime_error("publisher stored security is unavailable or changed during observation");
    return bytes;
}

DWORD publisher_directory_access_mask() {
    return DELETE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_APPEND_DATA |
        FILE_DELETE_CHILD | FILE_EXECUTE | FILE_LIST_DIRECTORY |
        FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA | FILE_TRAVERSE |
        FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_EA |
        READ_CONTROL | SYNCHRONIZE | WRITE_DAC | WRITE_OWNER;
}

DWORD publisher_consumer_read_access_mask() {
    return FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
}

static void require_account_sid(const std::string& sid, DWORD minimum_rid) {
    PSID raw = nullptr;
    if (sid.empty() || !ConvertStringSidToSidA(sid.c_str(), &raw)) {
        throw std::runtime_error("publisher consumer SID is malformed");
    }
    std::unique_ptr<void, LocalFreeDeleter> owned(raw);
    const SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (!IsValidSid(raw) || *GetSidSubAuthorityCount(raw) != 5 ||
        *GetSidSubAuthority(raw, 0) != SECURITY_NT_NON_UNIQUE ||
        *GetSidSubAuthority(raw, 4) < minimum_rid ||
        std::memcmp(GetSidIdentifierAuthority(raw), &nt, sizeof(nt)) != 0) {
        throw std::runtime_error("publisher account SID differs from its required account class");
    }
    LPSTR canonical = nullptr;
    if (!ConvertSidToStringSidA(raw, &canonical)) {
        throw std::runtime_error("publisher consumer SID cannot be rendered");
    }
    std::unique_ptr<void, LocalFreeDeleter> canonical_owned(canonical);
    if (sid != canonical) throw std::runtime_error("publisher consumer SID is not canonical");
}

void require_publisher_registered_account_sid(const std::string& sid) {
    require_account_sid(sid, 0);
}

void require_publisher_consumer_sid(const std::string& sid) {
    require_account_sid(sid, 1000);
}

static std::vector<unsigned char> make_descriptor(
    const std::wstring& service_sid, const std::string& consumer_sid) {
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
    PSID raw_consumer_sid = nullptr;
    if (!consumer_sid.empty()) {
        require_publisher_consumer_sid(consumer_sid);
        if (!ConvertStringSidToSidA(consumer_sid.c_str(), &raw_consumer_sid)) {
            throw std::runtime_error("publisher consumer SID conversion failed");
        }
    }
    std::unique_ptr<void, LocalFreeDeleter> owned_consumer_sid(raw_consumer_sid);
    const auto consumer_length = raw_consumer_sid ? GetLengthSid(raw_consumer_sid) : 0;
    const std::size_t acl_size = sizeof(ACL) +
        (raw_consumer_sid ? 3u : 2u) * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) +
        system_length + service_length + consumer_length;
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
    if (raw_consumer_sid && !AddAccessAllowedAceEx(acl, ACL_REVISION, 0,
            publisher_consumer_read_access_mask(), raw_consumer_sid)) {
        throw std::runtime_error("publisher consumer read ACE construction failed");
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

std::vector<unsigned char> make_publisher_directory_security_descriptor(
    const std::wstring& service_sid) {
    return make_descriptor(service_sid, {});
}

std::vector<unsigned char> make_publisher_consumer_security_descriptor(
    const std::wstring& service_sid, const std::string& consumer_sid) {
    require_publisher_consumer_sid(consumer_sid);
    return make_descriptor(service_sid, consumer_sid);
}

void set_publisher_boundary_security_from_handle(HANDLE boundary,
    const std::vector<unsigned char>& descriptor) {
    if (!boundary || boundary == INVALID_HANDLE_VALUE || descriptor.empty() || descriptor.size() > 65536)
        throw std::runtime_error("boundary security inputs are unavailable");
    FILE_ATTRIBUTE_TAG_INFO tag{};
    auto* raw = const_cast<unsigned char*>(descriptor.data());
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    PSID owner = nullptr;
    if (!GetFileInformationByHandleEx(boundary, FileAttributeTagInfo, &tag, sizeof(tag)) ||
        (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || tag.ReparseTag != 0 ||
        !IsValidSecurityDescriptor(raw) ||
        !GetSecurityDescriptorControl(raw, &control, &revision) ||
        (control & (SE_SELF_RELATIVE | SE_DACL_PROTECTED)) != (SE_SELF_RELATIVE | SE_DACL_PROTECTED) ||
        !GetSecurityDescriptorOwner(raw, &owner, &defaulted) || !owner ||
        !GetSecurityDescriptorDacl(raw, &present, &dacl, &defaulted) || !present || !dacl || !IsValidAcl(dacl))
        throw std::runtime_error("boundary security descriptor or held object differs");
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void* ace = nullptr;
        if (!GetAce(dacl, index, &ace) || !ace || static_cast<ACE_HEADER*>(ace)->AceFlags != 0)
            throw std::runtime_error("boundary descriptor cannot carry inheritable ACEs");
    }
    using NtSetSecurityObjectFn = LONG (NTAPI *)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto set_security = module ? reinterpret_cast<NtSetSecurityObjectFn>(
        GetProcAddress(module, "NtSetSecurityObject")) : nullptr;
    if (!set_security || set_security(boundary, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
        PROTECTED_DACL_SECURITY_INFORMATION, raw) != 0)
        throw std::runtime_error("held boundary native security update failed");
}

void protect_publisher_metadata_dacl_from_handle(HANDLE metadata,
    const std::vector<unsigned char>& original) {
    if (!metadata || metadata == INVALID_HANDLE_VALUE ||
        original.size() < SECURITY_DESCRIPTOR_MIN_LENGTH || original.size() > 65536)
        throw std::runtime_error("metadata protection inputs are unavailable");
    FILE_ATTRIBUTE_TAG_INFO tag{};
    auto protected_descriptor = original;
    auto* raw = protected_descriptor.data();
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
    PACL dacl = nullptr; BOOL present = FALSE, defaulted = FALSE;
    if (!GetFileInformationByHandleEx(metadata, FileAttributeTagInfo, &tag, sizeof(tag)) ||
        (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || tag.ReparseTag != 0 ||
        !IsValidSecurityDescriptor(raw) || GetSecurityDescriptorLength(raw) != original.size() ||
        !GetSecurityDescriptorControl(raw, &control, &revision) || (control & SE_SELF_RELATIVE) == 0 ||
        !GetSecurityDescriptorDacl(raw, &present, &dacl, &defaulted) || !present || !dacl || !IsValidAcl(dacl))
        throw std::runtime_error("metadata protection descriptor or object differs");
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void* ace = nullptr;
        if (!GetAce(dacl, index, &ace) || !ace ||
            static_cast<ACE_HEADER*>(ace)->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            (static_cast<ACE_HEADER*>(ace)->AceFlags & ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) != 0)
            throw std::runtime_error("metadata protection cannot change unsupported ACEs");
    }
    const auto read = [&] { return read_publisher_owner_dacl_from_handle(metadata); };
    if (read() != original)
        throw std::runtime_error("metadata protection prestate changed");
    if (!SetSecurityDescriptorControl(raw, SE_DACL_PROTECTED, SE_DACL_PROTECTED))
        throw std::runtime_error("metadata protected descriptor cannot be derived");
    using NtSetSecurityObjectFn = LONG (NTAPI *)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto set_security = module ? reinterpret_cast<NtSetSecurityObjectFn>(
        GetProcAddress(module, "NtSetSecurityObject")) : nullptr;
    // DACL only: no owner update, inheritance propagation, or grants added.
    if (!set_security || set_security(metadata,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, raw) != 0 ||
        read() != protected_descriptor)
        throw std::runtime_error("held metadata protection update or exact readback failed");
}

} // namespace usk::platform::windows
#endif
