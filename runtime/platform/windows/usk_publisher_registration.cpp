// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <aclapi.h>
#include <winioctl.h>

#include "usk_publisher_registration.h"
#include "usk_publisher_service_readback_internal.h"
#include "usk_publisher_execution_observation.h"
#include "usk_publisher_data_partition.h"
#include "usk_publisher_handle_observation.h"
#include "usk_publisher_tree_observation.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_volume_stream_observation.h"
#include "usk_publisher_volume_operation_guard.h"
#include "usk_publisher_device_acl.h"
#include "usk_publisher_request_channel.h"
#include "usk_publisher_consumer_access.h"
#include "usk_publisher_token_observation.h"
#include "usk_publisher_service_access.h"
#include "usk_stable_file.h"
#include "usk_record_io.h"
#include "usk_json.h"
#include "usk_sha256.h"
#include "usk_effect_dispatch.h"

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <fcntl.h>
#include <io.h>

namespace usk::platform::windows {
namespace {
class ServiceHandle {
public:
    explicit ServiceHandle(SC_HANDLE value) : value_(value) {}
    ~ServiceHandle() { if (value_) CloseServiceHandle(value_); }
    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;
    SC_HANDLE get() const noexcept { return value_; }
private:
    SC_HANDLE value_;
};

class FileHandle {
public:
    explicit FileHandle(HANDLE value) : value_(value) {}
    FileHandle(const wchar_t* path, DWORD access, DWORD sharing, DWORD flags) noexcept
        : value_(CreateFileW(path, access, sharing, nullptr, OPEN_EXISTING, flags, nullptr)) {}
    ~FileHandle() { if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
    HANDLE get() const noexcept { return value_; }
    HANDLE release() noexcept { const HANDLE value = value_; value_ = INVALID_HANDLE_VALUE; return value; }
    void close() noexcept { if (value_ != INVALID_HANDLE_VALUE) CloseHandle(release()); }
    void close_confirmed() {
        // Consume custody before the call: an unknown close is never retried
        // or used as proof that this controller released raw mutation access.
        const HANDLE closing = release();
        if (closing == INVALID_HANDLE_VALUE || !CloseHandle(closing))
            throw std::runtime_error("publisher raw device handle close unconfirmed; Win32 " +
                std::to_string(GetLastError()));
    }
private:
    HANDLE value_;
};

std::uint64_t observe_supported_discovery_windows_build() {
#if !defined(_M_X64) && !defined(__x86_64__)
    throw std::runtime_error("publisher discovery requires the x64 implementation");
#else
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    if (sizeof(void*) != 8 || system.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64)
        throw std::runtime_error("publisher discovery requires native x64 Windows");
    // Query the already-loaded OS module; no module-search or manifest-based
    // version fallback. Documented OSVERSIONINFOW/RtlGetVersion observation:
    // https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlgetversion
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto address = module ? GetProcAddress(module, "RtlGetVersion") : nullptr;
    using Query = LONG (WINAPI*)(OSVERSIONINFOW*);
    Query query = nullptr;
    static_assert(sizeof(query) == sizeof(address));
    std::memcpy(&query, &address, sizeof(query));
    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    if (!query || query(&version) != 0 || version.dwPlatformId != VER_PLATFORM_WIN32_NT ||
        version.dwMajorVersion != 10 || version.dwMinorVersion != 0 || version.dwBuildNumber < 17763)
        throw std::runtime_error("publisher discovery Windows build is unavailable or unsupported");
    return version.dwBuildNumber;
#endif
}

class ScopedControllerPrivilege {
public:
    explicit ScopedControllerPrivilege(const wchar_t* privilege = L"SeBackupPrivilege") {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &token_)) {
            throw std::runtime_error("publisher controller cannot inspect its process token");
        }
        LUID backup{};
        if (!LookupPrivilegeValueW(nullptr, privilege, &backup)) {
            CloseHandle(token_);
            token_ = nullptr;
            throw std::runtime_error("publisher controller backup privilege is unavailable");
        }
        TOKEN_PRIVILEGES enabled{};
        enabled.PrivilegeCount = 1;
        enabled.Privileges[0].Luid = backup;
        enabled.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        DWORD previous_size = sizeof(previous_);
        const BOOL adjusted = AdjustTokenPrivileges(token_, FALSE, &enabled,
            sizeof(previous_), &previous_, &previous_size);
        const DWORD error = GetLastError();
        if (!adjusted || error != ERROR_SUCCESS) {
            CloseHandle(token_);
            token_ = nullptr;
            throw std::runtime_error("publisher controller cannot enable scoped backup observation; Win32 " +
                std::to_string(error));
        }
    }
    ~ScopedControllerPrivilege() {
        if (token_) {
            AdjustTokenPrivileges(token_, FALSE, &previous_, 0, nullptr, nullptr);
            CloseHandle(token_);
        }
    }
    ScopedControllerPrivilege(const ScopedControllerPrivilege&) = delete;
    ScopedControllerPrivilege& operator=(const ScopedControllerPrivilege&) = delete;
private:
    HANDLE token_ = nullptr;
    TOKEN_PRIVILEGES previous_{};
};

class LocalDescriptor {
public:
    explicit LocalDescriptor(const wchar_t* sddl) {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,
                SDDL_REVISION_1, &value_, nullptr)) {
            throw std::runtime_error("service control lock descriptor construction failed");
        }
    }
    ~LocalDescriptor() { LocalFree(value_); }
    LocalDescriptor(const LocalDescriptor&) = delete;
    LocalDescriptor& operator=(const LocalDescriptor&) = delete;
    PSECURITY_DESCRIPTOR get() const noexcept { return value_; }
private:
    PSECURITY_DESCRIPTOR value_ = nullptr;
};

void require_control_lock_shape(HANDLE handle, bool directory) {
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) ||
        (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        ((tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory) {
        throw std::runtime_error("service control lock path is not an ordinary object");
    }
    PSID owner = nullptr;
    PACL dacl = nullptr;
    auto security = read_publisher_owner_dacl_from_handle(handle);
    auto* descriptor = security.data();
    BOOL present = FALSE, defaulted = FALSE;
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present)
        throw std::runtime_error("service control lock stored security observation failed");
    BYTE administrators[SECURITY_MAX_SID_SIZE]{};
    BYTE system[SECURITY_MAX_SID_SIZE]{};
    DWORD administrators_size = sizeof(administrators);
    DWORD system_size = sizeof(system);
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    ACL_SIZE_INFORMATION size{};
    const bool valid = CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr,
            administrators, &administrators_size) &&
        CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &system_size) &&
        owner && EqualSid(owner, administrators) && dacl &&
        GetSecurityDescriptorControl(descriptor, &control, &revision) &&
        (control & SE_DACL_PROTECTED) != 0 &&
        GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation) &&
        size.AceCount == 2;
    bool exact_aces = valid;
    bool saw_system = false;
    bool saw_administrators = false;
    for (DWORD index = 0; exact_aces && index < 2; ++index) {
        void* raw = nullptr;
        if (!GetAce(dacl, index, &raw)) { exact_aces = false; break; }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        const BYTE flags = directory ? OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE : 0;
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            ace->Header.AceFlags != flags || ace->Mask != FILE_ALL_ACCESS) {
            exact_aces = false;
            break;
        }
        PSID sid = const_cast<DWORD*>(&ace->SidStart);
        if (EqualSid(sid, system)) saw_system = true;
        else if (EqualSid(sid, administrators)) saw_administrators = true;
        else exact_aces = false;
    }
    if (!exact_aces || !saw_system || !saw_administrators) {
        throw std::runtime_error("service control lock owner or protected ACL differs");
    }
}

void read_protected_control_directory(const std::wstring& path) {
    FileHandle directory(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (directory.get() == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("service control lock directory cannot be opened");
    }
    require_control_lock_shape(directory.get(), true);
}

void create_protected_directory(const std::wstring& path, SECURITY_ATTRIBUTES& attributes) {
    if (!CreateDirectoryW(path.c_str(), &attributes) && GetLastError() != ERROR_ALREADY_EXISTS)
        throw std::runtime_error("service control lock directory creation failed");
    read_protected_control_directory(path);
}

class ServiceControlGuard {
public:
    explicit ServiceControlGuard(const std::wstring& service, bool read_existing = false,
        bool write_existing = false) {
        LocalDescriptor directory_descriptor(
            L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        SECURITY_ATTRIBUTES directory_attributes{sizeof(SECURITY_ATTRIBUTES),
            directory_descriptor.get(), FALSE};
        PWSTR raw_program_files = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFilesX64, 0, nullptr,
                &raw_program_files)) || !raw_program_files) {
            if (raw_program_files) CoTaskMemFree(raw_program_files);
            throw std::runtime_error("protected Program Files location unavailable");
        }
        const std::filesystem::path program_files(raw_program_files);
        CoTaskMemFree(raw_program_files);
        const DWORD program_files_attributes = GetFileAttributesW(program_files.c_str());
        if (!program_files.is_absolute() ||
            program_files_attributes == INVALID_FILE_ATTRIBUTES ||
            (program_files_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (program_files_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            throw std::runtime_error("protected Program Files root is not an ordinary directory");
        }
        const auto root = program_files / L"Universal Setup";
        const auto locks = root / L"PublisherControl";
        if (read_existing || write_existing) {
            read_protected_control_directory(root.wstring());
            read_protected_control_directory(locks.wstring());
        } else {
            create_protected_directory(root.wstring(), directory_attributes);
            create_protected_directory(locks.wstring(), directory_attributes);
        }

        LocalDescriptor file_descriptor(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)");
        SECURITY_ATTRIBUTES file_attributes{sizeof(SECURITY_ATTRIBUTES),
            file_descriptor.get(), FALSE};
        // The generated SCM name is the global identity; a volume-specific
        // lock would allow two registrations to race over one executable.
        const auto path = locks / (service + L".lock");
        // A restricted service holds the existing administrative lock read-only.
        // Zero sharing still excludes cooperating controllers; it neither creates
        // nor writes a private administrative object.
        const DWORD access = read_existing ? READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE :
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL;
        FileHandle file(CreateFileW(path.c_str(), access,
            0, (read_existing || write_existing) ? nullptr : &file_attributes,
            (read_existing || write_existing) ? OPEN_EXISTING : OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL |
            FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (file.get() == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("publisher service control is active or its lock is unavailable");
        }
        require_control_lock_shape(file.get(), false);
        handle_ = file.release();
    }
    ~ServiceControlGuard() {
        if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
    }
    ServiceControlGuard(const ServiceControlGuard&) = delete;
    ServiceControlGuard& operator=(const ServiceControlGuard&) = delete;
private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

bool generated_name(const std::wstring& name) {
    constexpr wchar_t prefix[] = L"USK_PUB_";
    if (name.size() != 40 || name.compare(0, 8, prefix) != 0) return false;
    for (std::size_t index = 8; index < name.size(); ++index) {
        const wchar_t ch = name[index];
        if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) return false;
    }
    return true;
}

bool lower_sha256(const std::wstring& value) {
    if (value.size() != 64) return false;
    for (const wchar_t ch : value) {
        if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) return false;
    }
    return true;
}

void require_canonical_sid(const std::wstring& value) {
    PSID parsed = nullptr;
    if (!ConvertStringSidToSidW(value.c_str(), &parsed))
        throw std::runtime_error("caller SID is invalid");
    LPWSTR canonical = nullptr;
    const bool okay = ConvertSidToStringSidW(parsed, &canonical) &&
        value == canonical;
    if (canonical) LocalFree(canonical);
    LocalFree(parsed);
    if (!okay) throw std::runtime_error("caller SID is not canonical");
}

void require_current_caller_sid(const std::wstring& expected) {
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
        throw std::runtime_error("current caller token unavailable");
    }
    FileHandle token(raw_token);
    DWORD needed = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &needed);
    if (!needed || needed > 64u * 1024u) {
        throw std::runtime_error("current caller identity size is invalid");
    }
    std::vector<BYTE> bytes(needed);
    if (!GetTokenInformation(token.get(), TokenUser, bytes.data(), needed, &needed)) {
        throw std::runtime_error("current caller identity unavailable");
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(bytes.data());
    LPWSTR rendered = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &rendered) || !rendered) {
        throw std::runtime_error("current caller SID unavailable");
    }
    const bool matching = expected == rendered;
    LocalFree(rendered);
    if (!matching) {
        throw std::runtime_error("reviewed apply caller differs from this process identity");
    }
}

std::vector<BYTE> retained_service_sid(const std::wstring& value) {
    require_canonical_sid(value);
    PSID parsed = nullptr;
    if (!ConvertStringSidToSidW(value.c_str(), &parsed))
        throw std::runtime_error("retained service SID is unavailable");
    const DWORD length = GetLengthSid(parsed);
    if (length > SECURITY_MAX_SID_SIZE) {
        LocalFree(parsed);
        throw std::runtime_error("retained service SID has an invalid length");
    }
    std::vector<BYTE> result(length);
    const bool valid = *GetSidSubAuthorityCount(parsed) == 6 &&
        *GetSidSubAuthority(parsed, 0) == SECURITY_SERVICE_ID_BASE_RID &&
        CopySid(length, result.data(), parsed);
    LocalFree(parsed);
    if (!valid) throw std::runtime_error("retained service SID is not a service identity");
    return result;
}

void require_file(const std::wstring& value) {
    const std::filesystem::path path(value);
    if (!path.is_absolute() || path.lexically_normal() != path ||
        value.find(L'"') != std::wstring::npos || value.size() > 2048) {
        throw std::runtime_error("service input path is not absolute and normalized");
    }
    const DWORD attributes = GetFileAttributesW(value.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        throw std::runtime_error("service input is not an ordinary file");
    }
}

std::filesystem::path publisher_binary_path(const std::wstring& name) {
    PWSTR raw = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFilesX64, 0, nullptr, &raw)) || !raw) {
        if (raw) CoTaskMemFree(raw);
        throw std::runtime_error("protected Program Files location unavailable");
    }
    const std::filesystem::path root(raw);
    CoTaskMemFree(raw);
    return root / L"Universal Setup" / L"Publisher" / (name + L".exe");
}

std::vector<BYTE> publisher_service_sid(const std::wstring& name, bool require_registered = true) {
    const auto expected = derive_ascii_publisher_service_sid(name);
    if (!require_registered) return expected;
    const std::wstring account = L"NT SERVICE\\" + name;
    std::vector<BYTE> sid(SECURITY_MAX_SID_SIZE);
    std::array<wchar_t, 256> domain{};
    DWORD sid_size = static_cast<DWORD>(sid.size());
    DWORD domain_size = static_cast<DWORD>(domain.size());
    SID_NAME_USE use{};
    if (!LookupAccountNameW(nullptr, account.c_str(), sid.data(), &sid_size,
            domain.data(), &domain_size, &use) || !IsValidSid(sid.data()) ||
        *GetSidSubAuthorityCount(sid.data()) != 6 ||
        *GetSidSubAuthority(sid.data(), 0) != SECURITY_SERVICE_ID_BASE_RID ||
        !EqualSid(sid.data(), const_cast<unsigned char*>(expected.data()))) {
        throw std::runtime_error("publisher service SID is unavailable");
    }
    sid.resize(sid_size);
    return sid;
}

void require_protected_binary_handle(const std::wstring& name,
    const std::wstring& binary, HANDLE file, bool service_grant,
    const std::vector<BYTE>* expected_service_sid = nullptr) {
    const auto expected = publisher_binary_path(name);
    if (CompareStringOrdinal(binary.c_str(), -1, expected.c_str(), -1, TRUE) !=
            CSTR_EQUAL) {
        throw std::runtime_error("publisher executable is outside the protected installation directory");
    }
    const auto publisher = expected.parent_path();
    const auto root = publisher.parent_path();
    for (const auto& directory : {root, publisher}) {
        FileHandle handle(CreateFileW(directory.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (handle.get() == INVALID_HANDLE_VALUE)
            throw std::runtime_error("protected publisher directory is unavailable");
        require_control_lock_shape(handle.get(), true);
    }
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (!file || file == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandleEx(file, FileAttributeTagInfo,
            &tag, sizeof(tag)) ||
        (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
        throw std::runtime_error("protected publisher executable is not an ordinary file");
    if (!service_grant) {
        require_control_lock_shape(file, false);
        return;
    }
    auto service_sid = expected_service_sid ? *expected_service_sid :
        publisher_service_sid(name);
    PSID owner = nullptr;
    PACL dacl = nullptr;
    auto security = read_publisher_owner_dacl_from_handle(file);
    auto* descriptor = security.data();
    BOOL present = FALSE, defaulted = FALSE;
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present || !dacl)
        throw std::runtime_error("protected publisher executable stored security is unavailable");
    BYTE administrators[SECURITY_MAX_SID_SIZE]{};
    BYTE system[SECURITY_MAX_SID_SIZE]{};
    DWORD administrators_size = sizeof(administrators);
    DWORD system_size = sizeof(system);
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    ACL_SIZE_INFORMATION size{};
    const bool valid = CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr,
            administrators, &administrators_size) &&
        CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &system_size) &&
        owner && EqualSid(owner, administrators) &&
        GetSecurityDescriptorControl(descriptor, &control, &revision) &&
        (control & SE_DACL_PROTECTED) != 0 &&
        GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation) &&
        size.AceCount == 3;
    bool exact = valid;
    bool saw_system = false, saw_administrators = false, saw_service = false;
    for (DWORD index = 0; exact && index < 3; ++index) {
        void* raw = nullptr;
        if (!GetAce(dacl, index, &raw)) { exact = false; break; }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            ace->Header.AceFlags != 0) { exact = false; break; }
        PSID sid = const_cast<DWORD*>(&ace->SidStart);
        if (ace->Mask == FILE_ALL_ACCESS && EqualSid(sid, system)) saw_system = true;
        else if (ace->Mask == FILE_ALL_ACCESS && EqualSid(sid, administrators))
            saw_administrators = true;
        else if (ace->Mask == (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) &&
            EqualSid(sid, service_sid.data())) saw_service = true;
        else exact = false;
    }
    if (!exact || !saw_system || !saw_administrators || !saw_service)
        throw std::runtime_error("protected publisher executable ACL differs");
}

void require_protected_binary(const std::wstring& name,
    const std::wstring& binary, bool service_grant = true) {
    require_file(binary);
    FileHandle handle(CreateFileW(binary.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (handle.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("protected publisher executable is unavailable");
    require_protected_binary_handle(name, binary, handle.get(), service_grant);
}

void grant_service_binary_read(const std::wstring& name,
    const std::wstring& binary) {
    const auto sid = publisher_service_sid(name);
    FileHandle handle(CreateFileW(binary.c_str(), READ_CONTROL | WRITE_DAC,
        0, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (handle.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("protected publisher executable cannot be secured");
    PACL previous = nullptr;
    auto security = read_publisher_owner_dacl_from_handle(handle.get());
    BOOL present = FALSE, defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(security.data(), &present, &previous, &defaulted) ||
        !present || !previous)
        throw std::runtime_error("protected publisher executable stored DACL is unavailable");
    EXPLICIT_ACCESS_W entry{};
    entry.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    entry.grfAccessMode = GRANT_ACCESS;
    entry.grfInheritance = NO_INHERITANCE;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
    entry.Trustee.ptstrName = reinterpret_cast<LPWSTR>(const_cast<BYTE*>(sid.data()));
    PACL updated = nullptr;
    const DWORD composed = SetEntriesInAclW(1, &entry, previous, &updated);
    if (composed != ERROR_SUCCESS || !updated)
        throw std::runtime_error("publisher service executable grant could not be composed");
    const DWORD applied = SetSecurityInfo(handle.get(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, updated, nullptr);
    LocalFree(updated);
    if (applied != ERROR_SUCCESS)
        throw std::runtime_error("publisher service executable read grant failed");
    handle.close();
    require_protected_binary(name, binary);
}

struct InstalledBinary {
    std::wstring path;
    bool created_here = false;
};

InstalledBinary install_protected_binary(const std::wstring& name,
    const std::wstring& source, const std::wstring& expected_sha256,
    bool resume_owned_registration = false) {
    require_file(source);
    if (!lower_sha256(expected_sha256))
        throw std::runtime_error("publisher executable digest is invalid");
    std::string expected_digest;
    expected_digest.reserve(expected_sha256.size());
    for (const wchar_t character : expected_sha256)
        expected_digest.push_back(static_cast<char>(character));
    const auto target = publisher_binary_path(name);
    LocalDescriptor directory_descriptor(L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    SECURITY_ATTRIBUTES directory_attributes{sizeof(SECURITY_ATTRIBUTES),
        directory_descriptor.get(), FALSE};
    create_protected_directory(target.parent_path().wstring(), directory_attributes);
    const auto pending = target.wstring() + L".pending";
    const DWORD pending_attributes = GetFileAttributesW(pending.c_str());
    if (pending_attributes != INVALID_FILE_ATTRIBUTES) {
        FileHandle orphan(CreateFileW(pending.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
            0, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (orphan.get() == INVALID_HANDLE_VALUE)
            throw std::runtime_error("orphan publisher copy is active or inaccessible");
        require_control_lock_shape(orphan.get(), false);
        orphan.close();
        if (!DeleteFileW(pending.c_str()))
            throw std::runtime_error("orphan publisher copy could not be removed");
    } else if (GetLastError() != ERROR_FILE_NOT_FOUND) {
        throw std::runtime_error("orphan publisher copy absence is uncertain");
    }
    const DWORD target_attributes = GetFileAttributesW(target.c_str());
    if (target_attributes != INVALID_FILE_ATTRIBUTES) {
        try {
            require_protected_binary(name, target.wstring(), false);
        } catch (const std::exception&) {
            if (!resume_owned_registration) throw;
            require_protected_binary(name, target.wstring(), true);
        }
        if (usk::base::sha256_hex_file(target) != expected_digest)
            throw std::runtime_error("orphan publisher executable digest differs");
        return {target.wstring(), false};
    }
    if (GetLastError() != ERROR_FILE_NOT_FOUND)
        throw std::runtime_error("protected publisher executable absence is uncertain");
    LocalDescriptor file_descriptor(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)");
    SECURITY_ATTRIBUTES file_attributes{sizeof(SECURITY_ATTRIBUTES),
        file_descriptor.get(), FALSE};
    FileHandle input(CreateFileW(source.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (input.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("publisher executable source cannot be opened");
    FILE_ATTRIBUTE_TAG_INFO source_tag{};
    LARGE_INTEGER source_size{};
    if (!GetFileInformationByHandleEx(input.get(), FileAttributeTagInfo,
            &source_tag, sizeof(source_tag)) ||
        (source_tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !GetFileSizeEx(input.get(), &source_size) || source_size.QuadPart <= 0 ||
        source_size.QuadPart > 256ll * 1024 * 1024) {
        throw std::runtime_error("publisher executable source has an invalid shape or size");
    }
    FileHandle output(CreateFileW(pending.c_str(), GENERIC_WRITE | READ_CONTROL |
        FILE_READ_ATTRIBUTES, 0, &file_attributes, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (output.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("protected publisher executable already exists or cannot be created");
    bool promoted = false;
    try {
        usk::base::Sha256 hash;
        std::array<unsigned char, 64 * 1024> buffer{};
        LONGLONG copied = 0;
        for (;;) {
            DWORD read = 0;
            if (!ReadFile(input.get(), buffer.data(), static_cast<DWORD>(buffer.size()),
                    &read, nullptr))
                throw std::runtime_error("publisher executable source read failed");
            if (read == 0) break;
            copied += read;
            if (copied > source_size.QuadPart)
                throw std::runtime_error("publisher executable source grew while copying");
            hash.update(buffer.data(), read);
            DWORD written = 0;
            if (!WriteFile(output.get(), buffer.data(), read, &written, nullptr) ||
                written != read)
                throw std::runtime_error("protected publisher executable write failed");
        }
        if (copied != source_size.QuadPart ||
            hash.finish() != expected_digest ||
            !FlushFileBuffers(output.get())) {
            throw std::runtime_error("protected publisher executable digest, length or flush differs");
        }
        output.close();
        FileHandle staged(CreateFileW(pending.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (staged.get() == INVALID_HANDLE_VALUE)
            throw std::runtime_error("protected publisher copy readback is unavailable");
        require_control_lock_shape(staged.get(), false);
        staged.close();
        if (!MoveFileExW(pending.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH))
            throw std::runtime_error("protected publisher executable no-replace promotion failed");
        promoted = true;
        require_protected_binary(name, target.wstring(), false);
    } catch (...) {
        output.close();
        const auto cleanup = promoted ? target.c_str() : pending.c_str();
        if (!DeleteFileW(cleanup))
            throw std::runtime_error("publisher executable installation failed and its owned file could not be removed");
        throw;
    }
    return {target.wstring(), true};
}

void require_volume(const std::wstring& value) {
    (void)usk::platform::windows::publisher_volume_operation_guard_name(value);
}

std::string owner_dacl_sddl(const std::vector<BYTE>& bytes);
usk::json::Value device_owner_dacl_policy(const std::vector<BYTE>& bytes);
std::vector<BYTE> device_security_from_sddl(const std::string& text);
std::vector<BYTE> intended_device_security(const std::vector<BYTE>& original,
    const std::vector<BYTE>& service_sid, bool read_only_original = false);
usk::json::Value registration_volume_identity(const std::wstring& volume, bool controller_backup);
usk::json::Value dedicated_target_disk_identity(const std::wstring& volume);
usk::json::Value target_empty_namespace(HANDLE root, bool require_metadata_protected);

// Bounded read-only diagnostics, never an admission verdict. When collected
// after refusal they describe a fresh observation, not the earlier failing
// descriptor. Keep the original strict failure as the primary reason.
usk::json::Value device_acl_diagnostic(HANDLE handle) {
    using usk::json::Value;
    try {
        const auto bytes = usk::platform::windows::read_publisher_owner_dacl_from_handle(handle);
        SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
        if (!GetSecurityDescriptorControl(const_cast<BYTE*>(bytes.data()), &control, &revision))
            throw std::runtime_error("device security control unavailable; Win32 " + std::to_string(GetLastError()));
        const auto sddl = owner_dacl_sddl(bytes);
        return Value(Value::Object{{"status", Value(sddl.size() <= 16384u ? "observed" : "oversized")},
            {"security_control", Value(static_cast<std::uint64_t>(control))},
            {"dacl_protected", Value((control & SE_DACL_PROTECTED) != 0)},
            {"owner_dacl", sddl.size() <= 16384u ? Value(sddl) : Value()},
            {"owner_dacl_bytes", Value(static_cast<std::uint64_t>(sddl.size()))}});
    } catch (const std::exception&) {
        return Value(Value::Object{{"status", Value("unavailable")}});
    }
}

// Locking NTFS dismounts it. The remounted volume device can lose the
// per-service ACE installed by the dedicated-volume provisioner. The known
// Windows Authenticated Users modify grant must first be reduced to read and
// execute. This routine is reached only after exact protected-root admission
// and a successful exclusive volume lock. Unknown outside mutation refuses.
void require_volume_device_service_access(HANDLE volume,
    const std::vector<BYTE>& service_sid, bool allow_locked_default = false) {
    if (!volume || volume == INVALID_HANDLE_VALUE)
        throw std::runtime_error("publisher device handle is unavailable for ACL admission");
    const auto inspect = [&](PSID owner, PACL dacl) {
        return usk::platform::windows::require_publisher_device_acl_shape(
            owner, dacl, const_cast<BYTE*>(service_sid.data()));
    };
    PSID before_owner = nullptr;
    PACL before = nullptr;
    PSECURITY_DESCRIPTOR before_descriptor = nullptr;
    const DWORD read_error = GetSecurityInfo(volume, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &before_owner, nullptr, &before, nullptr,
        &before_descriptor);
    if (read_error != ERROR_SUCCESS)
        throw std::runtime_error("publisher volume device DACL is unavailable; Win32 " +
            std::to_string(read_error));
    bool already_granted = false;
    bool already_protected = false;
    std::vector<BYTE> restricted_default;
    try {
        SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
        if (!GetSecurityDescriptorControl(before_descriptor, &control, &revision))
            throw std::runtime_error("publisher volume device security control is unavailable");
        already_protected = (control & SE_DACL_PROTECTED) != 0;
        try { already_granted = inspect(before_owner, before); }
        catch (const std::exception&) {
            if (!allow_locked_default) throw;
            restricted_default = usk::platform::windows::restrict_publisher_default_device_acl(
                before_owner, before, const_cast<BYTE*>(service_sid.data()));
            before = reinterpret_cast<PACL>(restricted_default.data());
            already_granted = inspect(before_owner, before);
        }
    }
    catch (...) { LocalFree(before_descriptor); throw; }
    if (!already_granted || !restricted_default.empty() || !already_protected) {
        EXPLICIT_ACCESS_W grant{};
        grant.grfAccessPermissions = FILE_ALL_ACCESS;
        grant.grfAccessMode = GRANT_ACCESS;
        grant.grfInheritance = NO_INHERITANCE;
        grant.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        grant.Trustee.TrusteeType = TRUSTEE_IS_USER;
        grant.Trustee.ptstrName = reinterpret_cast<LPWSTR>(
            const_cast<BYTE*>(service_sid.data()));
        PACL updated = before;
        if (!already_granted) {
            updated = nullptr;
            const DWORD compose_error = SetEntriesInAclW(1, &grant, before, &updated);
            if (compose_error != ERROR_SUCCESS || !updated) {
                LocalFree(before_descriptor);
                throw std::runtime_error("publisher volume device service ACE cannot be composed");
            }
        }
        const DWORD set_error = SetSecurityInfo(volume, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, updated, nullptr);
        if (!already_granted) LocalFree(updated);
        if (set_error != ERROR_SUCCESS) {
            LocalFree(before_descriptor);
            throw std::runtime_error("publisher volume device service ACE cannot be installed; Win32 " +
                std::to_string(set_error));
        }
    }
    LocalFree(before_descriptor);
    PSID after_owner = nullptr;
    PACL after = nullptr;
    PSECURITY_DESCRIPTOR after_descriptor = nullptr;
    const DWORD confirm_error = GetSecurityInfo(volume, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &after_owner, nullptr, &after, nullptr,
        &after_descriptor);
    if (confirm_error != ERROR_SUCCESS)
        throw std::runtime_error("publisher volume device service ACE cannot be read back");
    try {
        if (!inspect(after_owner, after))
            throw std::runtime_error("publisher volume device service ACE was not retained");
        SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
        if (!GetSecurityDescriptorControl(after_descriptor, &control, &revision) ||
            (control & SE_DACL_PROTECTED) == 0)
            throw std::runtime_error("publisher volume device DACL protection was not retained");
    } catch (...) { LocalFree(after_descriptor); throw; }
    LocalFree(after_descriptor);
}

// Run in the elevated controller just before SCM start. The restricted
// service cannot open a volume for direct DASD access. A protected root ACL
// alone cannot revoke a handle opened during volume provisioning; Windows'
// successful FSCTL_LOCK_VOLUME guarantees there are no open files on this
// dedicated volume. First check its exact service-owned NTFS root, and close
// that observation handle before requesting the lock.
void require_exclusive_volume_admission(const std::wstring& name,
    const std::wstring& root, FileHandle* retained_mounted_device = nullptr,
    const usk::json::Value* retained_intended_policy = nullptr,
    const usk::json::Value* unpublished_device_transition = nullptr,
    const usk::json::Value* unpublished_admission_identity = nullptr) {
    if ((retained_mounted_device != nullptr) != (retained_intended_policy != nullptr))
        throw std::runtime_error("mounted device admission custody/policy association differs");
    if ((unpublished_device_transition == nullptr) != (unpublished_admission_identity == nullptr) ||
        (unpublished_device_transition && !retained_mounted_device))
        throw std::runtime_error("mounted bootstrap identity/transition association differs");
    require_volume(root);
    auto sid = publisher_service_sid(name);
    LPWSTR rendered = nullptr;
    if (!ConvertSidToStringSidW(sid.data(), &rendered) || !rendered) {
        throw std::runtime_error("publisher service SID cannot be rendered for volume admission");
    }
    const std::wstring service_sid(rendered);
    LocalFree(rendered);
    std::string service_sid_ascii;
    service_sid_ascii.reserve(service_sid.size());
    for (const wchar_t ch : service_sid) {
        if (ch > 0x7f) throw std::runtime_error("publisher service SID is not ASCII");
        service_sid_ascii.push_back(static_cast<char>(ch));
    }
    std::string root_file_id;
    ULONGLONG root_volume_serial = 0;
    const auto observe_root = [&] {
        ScopedControllerPrivilege backup_observation;
        auto held_root = std::make_unique<FileHandle>(root.c_str(),
            FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        if (held_root->get() == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("cannot open protected volume root for admission; Win32 " +
                std::to_string(GetLastError()));
        }
        const auto volume_facts =
            usk::platform::windows::observe_local_ntfs_volume_handle(held_root->get());
        const auto root_facts =
            usk::platform::windows::observe_publisher_directory_handle(held_root->get());
        usk::platform::windows::require_publisher_object_security_shape(
            root_facts, service_sid_ascii);
        if (root_file_id.empty()) {
            root_file_id = root_facts.file_id;
            root_volume_serial = volume_facts.file_id_volume_serial;
        } else if (root_facts.file_id != root_file_id ||
            volume_facts.file_id_volume_serial != root_volume_serial) {
            throw std::runtime_error("publisher volume root changed across exclusive admission");
        }
        return held_root;
    };
    observe_root();
    const std::wstring device = root.substr(0, root.size() - 1);
    FileHandle volume(!retained_mounted_device ? CreateFileW(device.c_str(),
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr) : INVALID_HANDLE_VALUE);
    // The unpublished v3 caller owns the exact mounted transition file object.
    // Borrow it through lock/remount rather than closing that native reference
    // and hardening a different direct-volume file object after dismount.
    const HANDLE locking_volume = retained_mounted_device ? retained_mounted_device->get() : volume.get();
    if (locking_volume == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("cannot open dedicated publisher volume for exclusive admission; Win32 " +
            std::to_string(GetLastError()));
    }
    DWORD returned = 0;
    if (!DeviceIoControl(locking_volume, FSCTL_LOCK_VOLUME, nullptr, 0,
            nullptr, 0, &returned, nullptr)) {
        throw std::runtime_error("publisher volume has a pre-opened file or cannot be locked; Win32 " +
            std::to_string(GetLastError()));
    }
    // The locked volume is accessible only through this locking file object.
    // Inspect and repair its device ACL before any other process can acquire a
    // newly granted raw-volume handle after unlock.
    try {
        require_volume_device_service_access(locking_volume, sid, true);
    } catch (const std::exception& error) {
        throw std::runtime_error(
            std::string("locked publisher volume device ACL admission: ") + error.what());
    }
    const auto locked_admitted_device = device_acl_diagnostic(locking_volume);
    if (!DeviceIoControl(locking_volume, FSCTL_UNLOCK_VOLUME, nullptr, 0,
            nullptr, 0, &returned, nullptr)) {
        throw std::runtime_error("publisher volume could not be unlocked after exclusive admission; Win32 " +
            std::to_string(GetLastError()));
    }
    // Retain the hardened locking file object across remount and the fresh
    // device-security check before releasing that native reference. Unlock has
    // already completed; the new mount must independently pass the strict
    // profile. A restored outside-mutation grant still refuses admission.
    auto remounted_root = observe_root(); // Pin the exact remounted root read-only.
    FileHandle remounted(CreateFileW(device.c_str(), READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, 0, nullptr));
    if (remounted.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("remounted publisher device cannot be observed; Win32 " +
            std::to_string(GetLastError()));
    const auto require_strict_device = [&](HANDLE handle) {
        // This strict predicate never repairs a failed policy. Unpublished
        // safe-original completion below has separate, narrower effect gates.
        const auto bytes = read_publisher_owner_dacl_from_handle(handle);
        auto* descriptor = const_cast<BYTE*>(bytes.data());
        PSID owner = nullptr; PACL dacl = nullptr;
        BOOL owner_defaulted = FALSE, present = FALSE, dacl_defaulted = FALSE;
        SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
        if (!GetSecurityDescriptorOwner(descriptor, &owner, &owner_defaulted) ||
            !GetSecurityDescriptorDacl(descriptor, &present, &dacl, &dacl_defaulted) ||
            !present || !dacl || !GetSecurityDescriptorControl(descriptor, &control, &revision) ||
            (control & SE_DACL_PROTECTED) == 0 ||
            !require_publisher_device_acl_shape(owner, dacl, const_cast<BYTE*>(sid.data())))
            throw std::runtime_error("remounted publisher device lacks its protected service policy");
        if (retained_intended_policy &&
            usk::json::canonical(device_owner_dacl_policy(bytes)) !=
                usk::json::canonical(*retained_intended_policy))
            throw std::runtime_error("mounted device differs from retained intended policy");
    };
    std::unique_ptr<FileHandle> remounted_acl_writer;
    try {
        if (unpublished_device_transition) {
            const auto expected = usk::json::canonical(*retained_intended_policy);
            if (usk::json::canonical(device_owner_dacl_policy(
                    read_publisher_owner_dacl_from_handle(remounted.get()))) != expected) {
                const auto& original_text = unpublished_device_transition->at("original_owner_dacl").as_string();
                const auto original = device_security_from_sddl(original_text);
                // This pure derivation refuses outside mutation BEFORE any
                // known-default reduction can run. E4's AU modify still refuses.
                const auto intended = intended_device_security(original, sid, true);
                if (usk::json::canonical(device_owner_dacl_policy(intended)) != expected)
                    throw std::runtime_error("safe mounted bootstrap postimage differs from retained intent");
                const auto require_original = [&](HANDLE handle) {
                    const auto bytes = read_publisher_owner_dacl_from_handle(handle);
                    if (owner_dacl_sddl(bytes) != original_text)
                        throw std::runtime_error("remounted device differs from exact safe original intent");
                    (void)intended_device_security(bytes, sid, true);
                };
                const auto require_bootstrap_identity = [&] {
                    ScopedControllerPrivilege backup_observation;
                    if (usk::json::canonical(registration_volume_identity(root, true)) !=
                            usk::json::canonical(unpublished_admission_identity->at("volume_identity")) ||
                        usk::json::canonical(dedicated_target_disk_identity(root)) !=
                            usk::json::canonical(unpublished_admission_identity->at("disk_identity")) ||
                        usk::json::canonical(target_empty_namespace(remounted_root->get(), true)) !=
                            usk::json::canonical(unpublished_admission_identity->at("metadata")))
                        throw std::runtime_error("safe mounted bootstrap identity or namespace differs");
                    observe_root();
                };
                require_original(locking_volume);
                require_original(remounted.get());
                require_bootstrap_identity();
                remounted_acl_writer = std::make_unique<FileHandle>(device.c_str(),
                    READ_CONTROL | WRITE_DAC,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
                if (remounted_acl_writer->get() == INVALID_HANDLE_VALUE)
                    throw std::runtime_error("safe mounted bootstrap ACL writer is unavailable");
                require_bootstrap_identity();
                require_original(remounted_acl_writer->get());
                require_original(remounted.get());
                PACL dacl = nullptr; BOOL present = FALSE, defaulted = FALSE;
                if (!GetSecurityDescriptorDacl(const_cast<BYTE*>(intended.data()),
                        &present, &dacl, &defaulted) || !present || !dacl)
                    throw std::runtime_error("safe mounted bootstrap intended DACL is unavailable");
                const DWORD error = SetSecurityInfo(remounted_acl_writer->get(), SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, dacl, nullptr);
                if (error != ERROR_SUCCESS)
                    throw std::runtime_error("safe mounted bootstrap outcome is uncertain; Win32 " +
                        std::to_string(error));
                require_strict_device(remounted_acl_writer->get());
                require_bootstrap_identity();
            }
        }
        require_strict_device(locking_volume);
        require_strict_device(remounted.get());
    } catch (const std::exception& error) {
        const auto diagnostic = usk::json::Value(usk::json::Value::Object{
            {"schema", usk::json::Value("usk.publisher_device_remount_diagnostic.v1")},
            {"locked_admitted_device", locked_admitted_device},
            {"fresh_observations_after_refusal", usk::json::Value(usk::json::Value::Object{
                {"original_locking_handle", device_acl_diagnostic(locking_volume)},
                {"remounted_device_handle", device_acl_diagnostic(remounted.get())}})}});
        throw std::runtime_error(
            std::string("remounted publisher volume device ACL admission: ") + error.what() +
            "; diagnostic " + usk::json::canonical(diagnostic));
    }
    // Keep a read-only mounted root while releasing the actual raw writer.
    // No controller WRITE_DAC/direct-write handle survives successful admission.
    if (remounted_acl_writer) remounted_acl_writer->close_confirmed();
    if (retained_mounted_device) retained_mounted_device->close_confirmed();
    else volume.close_confirmed();
    FileHandle released_device(CreateFileW(device.c_str(), READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, 0, nullptr));
    if (released_device.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("publisher device post-release observation unavailable; Win32 " +
            std::to_string(GetLastError()));
    require_strict_device(released_device.get());
    const auto root_after_release = observe_root();
}

std::wstring command_prefix(const std::wstring& service,
    const std::wstring& binary, const std::wstring& volume) {
    return L"\"" + binary + L"\" --service " + service +
        L" --no-receipt " + volume;
}

std::wstring command_suffix(const std::wstring& caller, const std::wstring& mode) {
    if (mode == L"--grant-client-read") {
        return L" --authorized-client-sid " + caller + L" --grant-client-read";
    }
    return (mode.empty() ? L"" : L" " + mode) +
        std::wstring(L" --authorized-client-sid ") + caller;
}

std::vector<std::wstring> command_arguments(const std::wstring& command) {
    int count = 0;
    LPWSTR* raw = CommandLineToArgvW(command.c_str(), &count);
    if (!raw || count < 0 || count > 16) {
        if (raw) LocalFree(raw);
        throw std::runtime_error("registered service command is malformed");
    }
    std::vector<std::wstring> result;
    for (int index = 0; index < count; ++index) result.emplace_back(raw[index]);
    LocalFree(raw);
    return result;
}

struct ServiceConfiguration {
    std::wstring binary_path;
    std::wstring account;
    std::wstring display_name;
    DWORD type = 0;
    DWORD start = 0;
    DWORD sid_type = 0;
};

bool same_configuration(const ServiceConfiguration& first, const ServiceConfiguration& second) {
    return first.binary_path == second.binary_path && first.account == second.account &&
        first.display_name == second.display_name && first.type == second.type &&
        first.start == second.start && first.sid_type == second.sid_type;
}

ServiceConfiguration query_configuration(SC_HANDLE service) {
    DWORD needed = 0;
    (void)QueryServiceConfigW(service, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > 16384)
        throw std::runtime_error("service configuration size is unavailable");
    std::vector<BYTE> bytes(needed);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(bytes.data());
    if (!QueryServiceConfigW(service, config, needed, &needed) ||
        !config->lpBinaryPathName || !config->lpServiceStartName || !config->lpDisplayName)
        throw std::runtime_error("service configuration is unavailable");
    SERVICE_SID_INFO sid{};
    if (!QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO,
            reinterpret_cast<BYTE*>(&sid), sizeof(sid), &needed))
        throw std::runtime_error("service SID configuration is unavailable");
    return {config->lpBinaryPathName, config->lpServiceStartName, config->lpDisplayName,
        config->dwServiceType, config->dwStartType, sid.dwServiceSidType};
}

void require_profile(const ServiceConfiguration& config) {
    if (config.type != SERVICE_WIN32_OWN_PROCESS ||
        config.start != SERVICE_DEMAND_START ||
        CompareStringOrdinal(config.account.c_str(), -1,
            L"LocalSystem", -1, TRUE) != CSTR_EQUAL ||
        config.sid_type != SERVICE_SID_TYPE_RESTRICTED) {
        throw std::runtime_error("service is not the restricted own-process profile");
    }
}

void require_existing_command(const std::wstring& command,
    const std::wstring& service, const std::wstring& binary,
    const std::wstring& volume, const std::wstring& caller,
    const std::wstring& mode) {
    const auto args = command_arguments(command);
    if (args.size() < 8 || args[0] != binary || args[1] != L"--service" ||
        args[2] != service || args[3] != L"--no-receipt" || args[4] != volume) {
        throw std::runtime_error("existing service identity or volume differs");
    }
    std::size_t index = 5;
    if (args[index] == L"--reviewed-plan-envelope") {
        if (args.size() < index + 5 || !lower_sha256(args[index + 2]))
            throw std::runtime_error("existing reviewed source binding is malformed");
        index += 3;
    } else if (args[index] == L"--recover-reviewed") {
        ++index;
    } else if (args[index] == L"--verify-installed") {
        ++index;
    } else {
        throw std::runtime_error("existing service mode differs");
    }
    if (mode == L"--admit-client-observer" || mode == L"--service-admitted-client") {
        if (index >= args.size() || args[index++] != mode)
            throw std::runtime_error("existing caller access mode differs");
    }
    const bool grant = mode == L"--grant-client-read";
    if (args.size() != index + 2 + static_cast<std::size_t>(grant) ||
        args[index] != L"--authorized-client-sid" || args[index + 1] != caller ||
        (grant && args[index + 2] != mode)) {
        throw std::runtime_error("existing authorized caller differs");
    }
}

void require_stopped(SC_HANDLE service) {
    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<BYTE*>(&status), sizeof(status), &needed) ||
        status.dwCurrentState != SERVICE_STOPPED) {
        throw std::runtime_error("service must be stopped before reconfiguration");
    }
}

std::string utf8(const std::wstring& value) {
    if (value.empty()) return {};
    if (value.size() > 16384) throw std::runtime_error("publisher registration text exceeds bound");
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (count <= 0) throw std::runtime_error("publisher registration text is invalid");
    std::string result(static_cast<std::size_t>(count), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), count, nullptr, nullptr) != count)
        throw std::runtime_error("publisher registration text conversion failed");
    return result;
}

usk::json::Value registration_volume_identity(const std::wstring& volume, bool controller_backup = true) {
    require_volume(volume);
    std::unique_ptr<ScopedControllerPrivilege> backup;
    if (controller_backup) backup = std::make_unique<ScopedControllerPrivilege>();
    FileHandle root(CreateFileW(volume.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (root.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("registered publisher volume identity is unavailable");
    const auto observed = observe_publisher_directory_handle(root.get());
    const auto facts = observe_local_ntfs_volume_handle(root.get());
    return usk::json::Value(usk::json::Value::Object{
        {"volume_root", usk::json::Value(utf8(volume))},
        {"root_file_id", usk::json::Value(observed.file_id)},
        {"volume_serial", usk::json::Value(std::to_string(facts.file_id_volume_serial))}
    });
}

std::filesystem::path registration_binding_path(const std::wstring& name) {
    return publisher_binary_path(name).parent_path() / (name + L".binding.json");
}

void write_protected_bytes(const std::filesystem::path& path,
    const std::string& bytes, std::size_t maximum_bytes) {
    if (bytes.empty() || bytes.size() > maximum_bytes)
        throw std::runtime_error("protected controller file exceeds bound");
    LocalDescriptor descriptor(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor.get(), FALSE};
    GUID nonce{};
    wchar_t nonce_text[40]{};
    if (FAILED(CoCreateGuid(&nonce)) || !StringFromGUID2(nonce, nonce_text, static_cast<int>(std::size(nonce_text))))
        throw std::runtime_error("protected record temporary identity is unavailable");
    const auto pending = path.wstring() + L".pending-" + nonce_text;
    FileHandle file(CreateFileW(pending.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
        0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (file.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("registration binding already exists or cannot be created");
    try {
        require_control_lock_shape(file.get(), false);
        DWORD written = 0;
        if (!WriteFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) ||
            written != bytes.size() || !FlushFileBuffers(file.get()))
            throw std::runtime_error("registration binding could not be made durable");
        file.close();
        // Same-volume, no-replace promotion publishes only a complete flushed
        // record. A process crash leaves an unpublished protected temporary,
        // never a truncated authoritative final record.
        if (!MoveFileExW(pending.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH))
            throw std::runtime_error("protected record no-replace promotion failed");
    } catch (...) {
        // Only the file created by this invocation may be removed. Existing
        // names were refused by CREATE_NEW and are never adopted or replaced.
        file.close();
        if (!DeleteFileW(pending.c_str()))
            throw std::runtime_error("failed registration binding must be retained for recovery");
        throw;
    }
}

void write_protected_document(const std::filesystem::path& path, const usk::json::Value& value) {
    write_protected_bytes(path, usk::json::canonical(value) + "\n", 16384);
}

usk::json::Value registration_binding(const std::wstring& name,
    const std::wstring& command, const std::wstring& digest,
    const usk::json::Value& volume_identity) {
    auto sid = publisher_service_sid(name, false);
    LPWSTR rendered = nullptr;
    if (!ConvertSidToStringSidW(sid.data(), &rendered) || !rendered)
        throw std::runtime_error("registered service SID cannot be retained");
    const auto service_sid = utf8(rendered);
    LocalFree(rendered);
    return usk::json::Value(usk::json::Value::Object{
        {"schema", usk::json::Value("usk.publisher_registration_binding.v1")},
        {"service_name", usk::json::Value(utf8(name))},
        {"service_sid", usk::json::Value(service_sid)},
        {"command", usk::json::Value(utf8(command))},
        {"binary_sha256", usk::json::Value(utf8(digest))},
        {"volume_identity", volume_identity}
    });
}

usk::json::Value read_protected_document(const std::filesystem::path& path) {
    FileHandle file(CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (file.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("publisher registration binding is unavailable");
    require_control_lock_shape(file.get(), false);
    require_publisher_stream_shape(file.get());
    const auto observation = observe_publisher_file_handle(file.get());
    if (observation.link_count != 1)
        throw std::runtime_error("publisher registration binding has another link");
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.get(), &size) || size.QuadPart <= 0 || size.QuadPart > 16384)
        throw std::runtime_error("publisher registration binding exceeds bound");
    std::string bytes(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    if (!ReadFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) ||
        read != bytes.size()) throw std::runtime_error("publisher registration binding is truncated");
    usk::json::ParseLimits limits;
    limits.max_bytes = 16384;
    limits.max_string_bytes = 8192;
    const auto value = usk::json::parse(bytes, limits);
    return value;
}

bool protected_document_exists(const std::filesystem::path& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) return true;
    const DWORD error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
        throw std::runtime_error("protected registration record absence is uncertain");
    return false;
}

void require_mutable_legacy_registration(const std::wstring& name) {
    const auto parent = registration_binding_path(name).parent_path();
    if (protected_document_exists(parent / (name + L".target-intent.json")) ||
        protected_document_exists(parent / (name + L".target-admitted.json")))
        throw std::runtime_error("admitted public registration dispatches operations without SCM reconfiguration");
}

usk::json::Value read_registration_binding(const std::wstring& name,
    const std::wstring& command, const std::wstring& volume, bool controller_backup = true) {
    const auto value = read_protected_document(registration_binding_path(name));
    if (value.as_object().size() != 6 ||
        value.at("schema").as_string() != "usk.publisher_registration_binding.v1" ||
        value.at("service_name").as_string() != utf8(name) ||
        value.at("command").as_string() != utf8(command) ||
        usk::json::canonical(value.at("volume_identity")) !=
            usk::json::canonical(registration_volume_identity(volume, controller_backup)))
        throw std::runtime_error("publisher registration binding differs from live configuration");
    auto sid = publisher_service_sid(name);
    LPWSTR rendered = nullptr;
    if (!ConvertSidToStringSidW(sid.data(), &rendered) || !rendered)
        throw std::runtime_error("publisher service SID is unavailable");
    const auto observed_sid = utf8(rendered);
    LocalFree(rendered);
    if (value.at("service_sid").as_string() != observed_sid)
        throw std::runtime_error("publisher retained service SID differs");
    return value;
}

std::string guid_text(const GUID& value) {
    wchar_t text[40]{};
    if (!StringFromGUID2(value, text, static_cast<int>(std::size(text))))
        throw std::runtime_error("target disk identity is unavailable");
    return utf8(text);
}

usk::json::Value dedicated_target_disk_identity(const std::wstring& volume) {
    FileHandle device(CreateFileW(volume.substr(0, volume.size() - 1).c_str(),
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
    if (device.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("target volume device is unavailable");
    VOLUME_DISK_EXTENTS extents{};
    DWORD returned = 0;
    if (!DeviceIoControl(device.get(), IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        nullptr, 0, &extents, sizeof(extents), &returned, nullptr) ||
        returned < sizeof(extents) || extents.NumberOfDiskExtents != 1 ||
        extents.Extents[0].StartingOffset.QuadPart < 0 || extents.Extents[0].ExtentLength.QuadPart <= 0)
        throw std::runtime_error("target volume is not one identified disk extent");
    const auto& extent = extents.Extents[0];
    const auto disk_path = L"\\\\.\\PhysicalDrive" + std::to_wstring(extent.DiskNumber);
    FileHandle disk(CreateFileW(disk_path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
    if (disk.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("target physical disk identity is unavailable");
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    std::array<BYTE, 4096> storage{};
    if (!DeviceIoControl(disk.get(), IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
        storage.data(), static_cast<DWORD>(storage.size()), &returned, nullptr) ||
        returned < sizeof(STORAGE_DEVICE_DESCRIPTOR))
        throw std::runtime_error("target disk locality is unavailable");
    const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(storage.data());
    if (descriptor->RemovableMedia || descriptor->BusType == BusTypeUsb ||
        descriptor->BusType == BusTypeUnknown || descriptor->BusType == BusTypeiScsi)
        throw std::runtime_error("target disk is removable, remote or unclassified");
    // Compare actual OS locations, never environment variables or drive labels.
    wchar_t windows[32768]{}, mount[32768]{}, system_volume[64]{};
    if (!GetWindowsDirectoryW(windows, static_cast<UINT>(std::size(windows))) ||
        !GetVolumePathNameW(windows, mount, static_cast<DWORD>(std::size(mount))) ||
        !GetVolumeNameForVolumeMountPointW(mount, system_volume, static_cast<DWORD>(std::size(system_volume))) ||
        CompareStringOrdinal(system_volume, -1, volume.c_str(), -1, TRUE) == CSTR_EQUAL)
        throw std::runtime_error("target volume is system storage or cannot be classified");
    std::vector<std::max_align_t> layout_bytes(65536 / sizeof(std::max_align_t));
    if (!DeviceIoControl(disk.get(), IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nullptr, 0,
        layout_bytes.data(), 65536, &returned, nullptr) || returned < offsetof(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry))
        throw std::runtime_error("target disk layout is unavailable");
    const auto* layout = reinterpret_cast<const DRIVE_LAYOUT_INFORMATION_EX*>(layout_bytes.data());
    if (layout->PartitionCount > 128 || offsetof(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry) +
        layout->PartitionCount * sizeof(PARTITION_INFORMATION_EX) > returned)
        throw std::runtime_error("target disk layout exceeds its bound");
    const auto* selected = &require_publisher_data_partition(layout->PartitionStyle,
        layout->PartitionEntry, layout->PartitionCount, extent);
    const auto disk_id = layout->PartitionStyle == PARTITION_STYLE_GPT ?
        guid_text(layout->Gpt.DiskId) : std::to_string(layout->Mbr.Signature);
    return usk::json::Value(usk::json::Value::Object{
        {"disk_id", usk::json::Value(disk_id)},
        {"partition_number", usk::json::Value(std::to_string(selected->PartitionNumber))},
        {"partition_id", usk::json::Value(selected->PartitionStyle == PARTITION_STYLE_GPT ?
            guid_text(selected->Gpt.PartitionId) : std::string("mbr"))},
        {"offset", usk::json::Value(std::to_string(extent.StartingOffset.QuadPart))},
        {"length", usk::json::Value(std::to_string(extent.ExtentLength.QuadPart))},
        {"bus_type", usk::json::Value(std::to_string(descriptor->BusType))}
    });
}

std::string owner_dacl_sddl(const std::vector<BYTE>& bytes) {
    auto* descriptor = const_cast<BYTE*>(bytes.data());
    LPWSTR rendered = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &rendered, nullptr) || !rendered) {
        throw std::runtime_error("target pre-state security cannot be retained");
    }
    const auto result = utf8(rendered);
    LocalFree(rendered);
    return result;
}

std::string owner_dacl_sddl(HANDLE object) {
    return owner_dacl_sddl(read_publisher_owner_dacl_from_handle(object));
}

// Owner, ordered ACEs and inheritance protection are the intended policy.
// AUTO_INHERITED bookkeeping can differ after SetSecurityInfo; it supplies
// no additional grant and is not substituted for these actual policy fields.
usk::json::Value device_owner_dacl_policy(const std::vector<BYTE>& bytes) {
    using usk::json::Value;
    if (bytes.empty() || bytes.size() > 16384u || !IsValidSecurityDescriptor(const_cast<BYTE*>(bytes.data())))
        throw std::runtime_error("mounted device security is unavailable or exceeds its bound");
    auto* descriptor = const_cast<BYTE*>(bytes.data());
    PSID owner = nullptr; PACL dacl = nullptr;
    BOOL defaulted = FALSE, present = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) || !owner || !IsValidSid(owner) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present || !dacl ||
        !IsValidAcl(dacl) || dacl->AceCount > 65u ||
        !GetSecurityDescriptorControl(descriptor, &control, &revision))
        throw std::runtime_error("mounted device owner or DACL cannot be retained");
    const auto sid_text = [](PSID sid) {
        LPWSTR rendered = nullptr;
        if (!sid || !IsValidSid(sid) || !ConvertSidToStringSidW(sid, &rendered) || !rendered)
            throw std::runtime_error("mounted device principal is unavailable");
        const auto text = utf8(rendered);
        LocalFree(rendered);
        return text;
    };
    Value::Array aces;
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void* entry = nullptr;
        if (!GetAce(dacl, index, &entry) || !entry)
            throw std::runtime_error("mounted device ACE is unavailable");
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(entry);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceSize < sizeof(ACCESS_ALLOWED_ACE))
            throw std::runtime_error("mounted device ACE is unsupported");
        const auto* sid = reinterpret_cast<const SID*>(&ace->SidStart);
        if (sid->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES ||
            offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8u + 4u * sid->SubAuthorityCount > ace->Header.AceSize)
            throw std::runtime_error("mounted device ACE principal is truncated");
        aces.emplace_back(Value::Object{{"type", Value(static_cast<std::uint64_t>(ace->Header.AceType))},
            {"flags", Value(static_cast<std::uint64_t>(ace->Header.AceFlags))},
            {"mask", Value(static_cast<std::uint64_t>(ace->Mask))},
            {"sid", Value(sid_text(const_cast<SID*>(sid)))}});
    }
    return Value(Value::Object{{"owner", Value(sid_text(owner))},
        {"dacl_protected", Value((control & SE_DACL_PROTECTED) != 0)}, {"aces", Value(std::move(aces))}});
}

std::vector<BYTE> device_security_from_sddl(const std::string& text) {
    if (text.empty() || text.size() > 8192u)
        throw std::runtime_error("mounted original security exceeds its text bound");
    PSECURITY_DESCRIPTOR raw = nullptr;
    const std::wstring wide(text.begin(), text.end());
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.c_str(), SDDL_REVISION_1, &raw, nullptr))
        throw std::runtime_error("mounted original security cannot be decoded");
    std::unique_ptr<void, decltype(&LocalFree)> owned(raw, &LocalFree);
    const auto length = GetSecurityDescriptorLength(raw);
    if (length == 0 || length > 16384u)
        throw std::runtime_error("mounted original security exceeds its byte bound");
    const auto* first = static_cast<const BYTE*>(raw);
    return std::vector<BYTE>(first, first + length);
}

std::vector<BYTE> intended_device_security(const std::vector<BYTE>& original,
    const std::vector<BYTE>& service_sid, bool read_only_original) {
    (void)device_owner_dacl_policy(original);
    auto* descriptor = const_cast<BYTE*>(original.data());
    PSID owner = nullptr; PACL dacl = nullptr; BOOL defaulted = FALSE, present = FALSE;
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present)
        throw std::runtime_error("mounted device prestate cannot be decoded");
    if (read_only_original)
        return usk::platform::windows::publisher_read_only_device_admission_postimage(owner, dacl,
            const_cast<BYTE*>(service_sid.data()));
    return usk::platform::windows::publisher_device_admission_postimage(owner, dacl,
        const_cast<BYTE*>(service_sid.data()));
}

usk::json::Value capture_mounted_device_transition(const std::wstring& volume,
    const std::vector<BYTE>& service_sid) {
    FileHandle device(CreateFileW(volume.substr(0, volume.size() - 1).c_str(), READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
    if (device.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("mounted device prestate is unavailable");
    const auto original = read_publisher_owner_dacl_from_handle(device.get());
    const auto original_sddl = owner_dacl_sddl(original);
    if (original_sddl.size() > 8192u) throw std::runtime_error("mounted device prestate exceeds its text bound");
    const auto intended = intended_device_security(original, service_sid);
    return usk::json::Value(usk::json::Value::Object{
        {"original_owner_dacl", usk::json::Value(original_sddl)},
        {"intended_policy", device_owner_dacl_policy(intended)}});
}

// Only the unpublished target's protected v3 intent supplies this bootstrap
// prestate. Generic admission/recovery keeps the strict remount check.
std::unique_ptr<FileHandle> apply_mounted_device_transition(const std::wstring& volume, const std::vector<BYTE>& service_sid,
    const usk::json::Value& transition, bool permit_original_effect) {
    if (transition.as_object().size() != 2 || !transition.contains("original_owner_dacl") || !transition.contains("intended_policy"))
        throw std::runtime_error("mounted device transition has invalid fields");
    const auto& original_text = transition.at("original_owner_dacl").as_string();
    if (original_text.empty() || original_text.size() > 8192u)
        throw std::runtime_error("mounted device transition prestate is unavailable or exceeds its bound");
    const std::wstring original_wide(original_text.begin(), original_text.end());
    LocalDescriptor original(original_wide.c_str());
    const auto length = GetSecurityDescriptorLength(original.get());
    const auto* first = static_cast<const BYTE*>(original.get());
    const auto intended = intended_device_security(std::vector<BYTE>(first, first + length), service_sid);
    const auto expected = usk::json::canonical(device_owner_dacl_policy(intended));
    if (usk::json::canonical(transition.at("intended_policy")) != expected)
        throw std::runtime_error("mounted device intended policy differs from its original prestate");
    // make_unique allocates custody before this constructor opens the handle.
    auto device = std::make_unique<FileHandle>(volume.substr(0, volume.size() - 1).c_str(),
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
    if (device->get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("mounted device bootstrap security handle is unavailable");
    const auto current = read_publisher_owner_dacl_from_handle(device->get());
    if (usk::json::canonical(device_owner_dacl_policy(current)) == expected) return device;
    if (!permit_original_effect)
        throw std::runtime_error("admitted target cannot repeat its mounted device bootstrap effect");
    if (owner_dacl_sddl(current) != original_text)
        throw std::runtime_error("mounted device differs from retained original and intended security");
    PACL dacl = nullptr; BOOL present = FALSE, defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(const_cast<BYTE*>(intended.data()), &present, &dacl, &defaulted) || !present || !dacl)
        throw std::runtime_error("mounted device intended DACL is unavailable");
    const DWORD error = SetSecurityInfo(device->get(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
    if (error != ERROR_SUCCESS)
        throw std::runtime_error("mounted device bootstrap security outcome is uncertain; Win32 " + std::to_string(error));
    if (usk::json::canonical(device_owner_dacl_policy(read_publisher_owner_dacl_from_handle(device->get()))) != expected)
        throw std::runtime_error("mounted device bootstrap security poststate differs; retained");
    // Keep this exact mounted file object through the final lock and strict
    // remount checks. This metadata effect alone does not revoke open handles.
    return device;
}

bool native_metadata_security_matches(const std::vector<BYTE>& bytes,
    const PublisherHandleObservation& observation, bool require_protected = true) {
    auto* descriptor = const_cast<BYTE*>(bytes.data());
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
    PSID owner = nullptr; PACL dacl = nullptr; BOOL defaulted = FALSE, present = FALSE;
    if (!GetSecurityDescriptorControl(descriptor, &control, &revision) ||
        (control & SE_SELF_RELATIVE) == 0 || (require_protected && (control & SE_DACL_PROTECTED) == 0) ||
        !GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) || !owner || !IsValidSid(owner) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present ||
        !dacl || !IsValidAcl(dacl) || dacl->AceCount != observation.dacl_aces.size()) return false;
    const auto sid_text = [](PSID sid) {
        LPWSTR rendered = nullptr;
        if (!ConvertSidToStringSidW(sid, &rendered) || !rendered)
            throw std::runtime_error("stored metadata SID is unavailable");
        const auto result = utf8(rendered); LocalFree(rendered); return result;
    };
    if (sid_text(owner) != observation.owner_sid) return false;
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void* raw = nullptr;
        if (!GetAce(dacl, index, &raw) || !raw) return false;
        const auto* header = static_cast<const ACE_HEADER*>(raw);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            header->AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8) return false;
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        const auto sid = const_cast<DWORD*>(&ace->SidStart);
        const auto* sid_bytes = reinterpret_cast<const BYTE*>(sid);
        const auto sid_room = header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart);
        if (sid_bytes[1] > SID_MAX_SUB_AUTHORITIES || 8u + 4u * sid_bytes[1] > sid_room ||
            !IsValidSid(sid) || GetLengthSid(sid) > sid_room)
            return false;
        const auto& observed = observation.dacl_aces[index];
        if (header->AceType != observed.type || header->AceFlags != observed.flags ||
            ace->Mask != observed.access_mask || sid_text(sid) != observed.sid) return false;
    }
    return true;
}

usk::json::Value target_empty_namespace(HANDLE root, bool require_metadata_protected = true) {
    // The root itself can carry streams independently of its directory entries.
    // Every pre-effect, post-lock and retirement namespace check includes it.
    require_publisher_stream_shape(root);
    using usk::json::Value;
    Value::Array metadata;
    const auto entries = observe_publisher_directory_entries(root, 65536);
    for (const auto& entry : entries) {
        // NTFS/Windows may initialize this reserved OS metadata directory.
        // It is never adopted as payload. The initial trusted prestate may
        // need an intent-backed protection-only transition; all completed
        // admission and retirement observations still require protection.
        if (entry.name != L"System Volume Information" ||
            (entry.attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || entry.reparse_tag != 0)
            throw std::runtime_error("target volume contains preexisting user or publication state");
        FileHandle held(open_publisher_listed_child(root, entry, false, false, false, false, true));
        const auto tree = observe_publisher_tree(held.get(), true);
        const auto native_security = read_publisher_owner_dacl_from_handle(held.get());
        SECURITY_DESCRIPTOR_CONTROL metadata_control{}; DWORD metadata_revision = 0;
        if (!GetSecurityDescriptorControl(const_cast<BYTE*>(native_security.data()),
            &metadata_control, &metadata_revision))
            throw std::runtime_error("target metadata stored control is unavailable");
        if ((metadata_control & SE_DACL_PROTECTED) == 0 &&
            std::any_of(tree.root.dacl_aces.begin(), tree.root.dacl_aces.end(), [](const auto& ace) {
                return (ace.flags & ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) != 0;
            }))
            throw std::runtime_error("target metadata protection transition has unsupported parent ACE flags");
        const auto trusted = [](const PublisherHandleObservation& object) {
            if (object.owner_sid != "S-1-5-18" && object.owner_sid != "S-1-5-32-544") return false;
            if (object.dacl_aces.empty() || object.case_sensitive || object.reparse_tag != 0 ||
                object.link_count != 1) return false;
            for (const auto& ace : object.dacl_aces)
                if (ace.type != ACCESS_ALLOWED_ACE_TYPE ||
                    (ace.sid != "S-1-5-18" && ace.sid != "S-1-5-32-544")) return false;
            return true;
        };
        // Protection can be absent only in the bounded original prestate.
        // Always bind the raw owner/ordered ACEs to the separate observation.
        if (!native_metadata_security_matches(native_security, tree.root, require_metadata_protected) ||
            !trusted(tree.root) || tree.descendants.size() > 3) {
            const auto security = owner_dacl_sddl(native_security);
            throw std::runtime_error("target OS metadata security or bounds differ; owner=" +
                tree.root.owner_sid + "; protected=" + (tree.root.dacl_protected ? "true" : "false") +
                "; descendants=" + std::to_string(tree.descendants.size()) +
                "; stored_security=" + (security.size() <= 2048 ? security : std::string("exceeds diagnostic bound")));
        }
        metadata.emplace_back(Value::Object{
            {"path", Value(utf8(entry.name))}, {"file_id", Value(tree.root.file_id)},
            {"security", Value(owner_dacl_sddl(native_security))},
            {"attributes", Value(static_cast<std::uint64_t>(tree.root.attributes))}
        });
        const auto children = observe_publisher_directory_entries(held.get(), 65536);
        for (const auto& child : tree.descendants) {
            if ((child.relative_path != L"IndexerVolumeGuid" && child.relative_path != L"WPSettings.dat" &&
                 child.relative_path != L"tracking.log") || child.size > 1024u * 1024u ||
                child.object.link_count != 1 || !trusted(child.object) ||
                (child.object.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                throw std::runtime_error("target OS metadata has unclassified content");
            require_publisher_stream_shape(child.streams, false);
            const auto listed = std::find_if(children.begin(), children.end(), [&](const auto& candidate) {
                return candidate.name == child.relative_path;
            });
            if (listed == children.end()) throw std::runtime_error("target metadata child disappeared");
            FileHandle child_handle(open_publisher_listed_child(held.get(), *listed,
                false, false, false, false, true));
            const auto child_observation = observe_publisher_file_handle(child_handle.get());
            const auto child_security = read_publisher_owner_dacl_from_handle(child_handle.get());
            if (child_observation.file_id != child.object.file_id || !trusted(child_observation) ||
                !native_metadata_security_matches(child_security, child_observation, false))
                throw std::runtime_error("target metadata child security or identity changed");
            metadata.emplace_back(Value::Object{
                {"path", Value(utf8(entry.name + L"\\" + child.relative_path))},
                {"file_id", Value(child.object.file_id)}, {"sha256", Value(child.sha256)},
                {"size", Value(std::to_string(child.size))},
                {"security", Value(owner_dacl_sddl(child_security))},
                {"attributes", Value(static_cast<std::uint64_t>(child.object.attributes))}
            });
        }
    }
    return Value(std::move(metadata));
}

usk::json::Value protected_metadata_snapshot(const usk::json::Value& original) {
    auto result = original;
    for (auto& object : result.as_array()) {
        if (object.at("path").as_string() != "System Volume Information") continue;
        const auto text = object.at("security").as_string();
        const std::wstring wide_text(text.begin(), text.end());
        LocalDescriptor descriptor(wide_text.c_str());
        const auto length = GetSecurityDescriptorLength(descriptor.get());
        const auto* first = static_cast<const BYTE*>(descriptor.get());
        std::vector<BYTE> bytes(first, first + length);
        if (!SetSecurityDescriptorControl(bytes.data(), SE_DACL_PROTECTED, SE_DACL_PROTECTED))
            throw std::runtime_error("target metadata protected poststate cannot be derived");
        object.as_object()["security"] = usk::json::Value(owner_dacl_sddl(bytes));
    }
    return result;
}

void require_metadata_transition_state(const usk::json::Value& current,
    const usk::json::Value& original, const usk::json::Value& expected) {
    const auto actual = usk::json::canonical(current);
    if (actual != usk::json::canonical(original) && actual != usk::json::canonical(expected))
        throw std::runtime_error("target metadata differs from retained original and intended protected state");
}

void protect_target_metadata(HANDLE root, const usk::json::Value& original,
    const usk::json::Value& expected) {
    const auto current = target_empty_namespace(root, false);
    require_metadata_transition_state(current, original, expected);
    if (usk::json::canonical(current) == usk::json::canonical(expected)) return;
    const auto entries = observe_publisher_directory_entries(root, 65536);
    if (entries.size() != 1) throw std::runtime_error("target metadata namespace changed before protection");
    FileHandle held(open_publisher_metadata_dacl_child(root, entries.front()));
    const auto observation = observe_publisher_directory_handle(held.get());
    const auto security = read_publisher_owner_dacl_from_handle(held.get());
    const auto& retained = original.as_array().front();
    if (retained.at("path").as_string() != "System Volume Information" ||
        observation.file_id != retained.at("file_id").as_string() ||
        owner_dacl_sddl(security) != retained.at("security").as_string() ||
        usk::json::canonical(target_empty_namespace(root, false)) != usk::json::canonical(original))
        throw std::runtime_error("held metadata differs before protection");
    protect_publisher_metadata_dacl_from_handle(held.get(), security);
    if (usk::json::canonical(target_empty_namespace(root)) != usk::json::canonical(expected))
        throw std::runtime_error("protected metadata differs from retained intended state");
}

void prove_initial_exclusive_access(const std::wstring& volume) {
    FileHandle device(CreateFileW(volume.substr(0, volume.size() - 1).c_str(),
        GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr));
    DWORD returned = 0;
    if (device.get() == INVALID_HANDLE_VALUE || !DeviceIoControl(device.get(), FSCTL_LOCK_VOLUME,
        nullptr, 0, nullptr, 0, &returned, nullptr))
        throw std::runtime_error("target volume has open handles or cannot be exclusively admitted");
    if (!DeviceIoControl(device.get(), FSCTL_UNLOCK_VOLUME, nullptr, 0,
        nullptr, 0, &returned, nullptr))
        throw std::runtime_error("initial target volume unlock is unavailable");
}

void require_unpublished_public_retirement(const std::wstring& name,
    const std::wstring& volume, const std::string& service_sid) {
    const auto parent = registration_binding_path(name).parent_path();
    const bool intent = protected_document_exists(parent / (name + L".target-intent.json"));
    const bool admitted = protected_document_exists(parent / (name + L".target-admitted.json"));
    if (!intent && !admitted) return; // Existing laboratory registrations.
    if (!intent || !admitted)
        throw std::runtime_error("target admission is incomplete; retain publisher recovery authority");
    const auto binding = read_protected_document(registration_binding_path(name));
    const auto admission = read_protected_document(parent / (name + L".target-admitted.json"));
    if (binding.as_object().size() != 6 ||
        binding.at("schema").as_string() != "usk.publisher_registration_binding.v1" ||
        binding.at("service_name").as_string() != utf8(name) ||
        binding.at("service_sid").as_string() != service_sid ||
        usk::json::canonical(binding.at("volume_identity")) !=
            usk::json::canonical(registration_volume_identity(volume)) ||
        admission.as_object().size() != 2 ||
        admission.at("schema").as_string() != "usk.publisher_target_admitted.v1" ||
        admission.at("identity").at("registration_sha256").as_string() !=
            usk::json::sha256_canonical(binding) ||
        usk::json::canonical(admission.at("identity").at("volume_identity")) !=
            usk::json::canonical(binding.at("volume_identity")) ||
        usk::json::canonical(admission.at("identity").at("disk_identity")) !=
            usk::json::canonical(dedicated_target_disk_identity(volume)))
        throw std::runtime_error("public retirement boundary differs; retain publisher authority");
    ScopedControllerPrivilege backup;
    FileHandle root(CreateFileW(volume.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (root.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("public retirement target is unavailable; retain publisher authority");
    require_publisher_object_security_shape(observe_publisher_directory_handle(root.get()), service_sid);
    try {
        // Any publication, staging, journal or installed-state namespace still
        // needs this authority. Only the admitted but unpublished empty target
        // can retire here; installed retirement belongs to the owned uninstall.
        if (usk::json::canonical(target_empty_namespace(root.get())) !=
            usk::json::canonical(admission.at("identity").at("metadata")))
            throw std::runtime_error("retained protected metadata differs before retirement");
    } catch (const std::exception&) {
        throw std::runtime_error("public install or recovery authority is still needed; complete owned uninstall before retirement");
    }
}

void provision_registered_target(const std::wstring& name) {
    ServiceControlGuard control(name);
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    ServiceHandle service(manager.get() ? OpenServiceW(manager.get(), name.c_str(),
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS) : nullptr);
    if (!service.get()) throw std::runtime_error("registered target is unavailable");
    require_stopped(service.get());
    const auto configuration = query_configuration(service.get());
    require_profile(configuration);
    const auto args = command_arguments(configuration.binary_path);
    if (args.size() < 10 || args[5] != L"--reviewed-plan-envelope")
        throw std::runtime_error("target provisioning needs its original reviewed registration");
    require_protected_binary(name, args[0]);
    const auto binding = read_registration_binding(name, configuration.binary_path, args[4]);
    const auto volume = args[4];
    const auto intent_path = registration_binding_path(name).parent_path() / (name + L".target-intent.json");
    const auto admitted_path = registration_binding_path(name).parent_path() / (name + L".target-admitted.json");
    using usk::json::Value;
    bool intent_retained = protected_document_exists(intent_path);
    try {
        const auto disk = dedicated_target_disk_identity(volume);
        prove_initial_exclusive_access(volume);
        Value original_metadata, expected_metadata, retained, device_transition;
        const auto service_sid = publisher_service_sid(name);
        std::string original_security;
        if (intent_retained) {
            retained = read_protected_document(intent_path);
            const bool has_device_transition = publisher_target_intent_has_device_transition(retained);
            original_metadata = retained.at("original_metadata");
            expected_metadata = protected_metadata_snapshot(original_metadata);
            original_security = retained.at("original_owner_dacl").as_string();
            if (has_device_transition) device_transition = retained.at("mounted_device_transition");
        }
        {
            ScopedControllerPrivilege backup;
            FileHandle root(CreateFileW(volume.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (root.get() == INVALID_HANDLE_VALUE) throw std::runtime_error("target root pre-state is unavailable");
            const auto current_metadata = target_empty_namespace(root.get(), false);
            if (intent_retained) require_metadata_transition_state(current_metadata, original_metadata, expected_metadata);
            else {
                original_metadata = current_metadata;
                expected_metadata = protected_metadata_snapshot(original_metadata);
                original_security = owner_dacl_sddl(root.get());
            }
        }
        const Value identity(Value::Object{
            {"registration_sha256", Value(usk::json::sha256_canonical(binding))},
            {"volume_identity", binding.at("volume_identity")},
            {"disk_identity", disk}, {"metadata", expected_metadata}
        });
        if (intent_retained) {
            if (usk::json::canonical(retained.at("identity")) != usk::json::canonical(identity))
                throw std::runtime_error("retained target admission identity or intended metadata differs");
        } else {
            device_transition = capture_mounted_device_transition(volume, service_sid);
            write_protected_document(intent_path, Value(Value::Object{
                {"schema", Value("usk.publisher_target_intent.v3")}, {"identity", identity},
                {"original_metadata", original_metadata},
                {"original_owner_dacl", Value(original_security)},
                {"mounted_device_transition", device_transition}
            }));
        }
        intent_retained = true;
        {
            ScopedControllerPrivilege restore(L"SeRestorePrivilege");
            ScopedControllerPrivilege backup;
            FileHandle root(CreateFileW(volume.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES |
                READ_CONTROL | WRITE_OWNER | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (root.get() == INVALID_HANDLE_VALUE) throw std::runtime_error("target root security access is unavailable");
            if (usk::json::canonical(registration_volume_identity(volume)) !=
                    usk::json::canonical(binding.at("volume_identity")))
                throw std::runtime_error("target namespace changed before provisioning");
            require_metadata_transition_state(target_empty_namespace(root.get(), false), original_metadata, expected_metadata);
            const auto observed = observe_publisher_directory_handle(root.get());
            bool already_protected = false;
            try { require_publisher_object_security_shape(observed, binding.at("service_sid").as_string());
                already_protected = true; } catch (const std::exception&) {}
            if (!already_protected && owner_dacl_sddl(root.get()) != original_security)
                throw std::runtime_error("target security differs from original admission intent");
            protect_target_metadata(root.get(), original_metadata, expected_metadata);
            if (!already_protected) {
                const auto sid = binding.at("service_sid").as_string();
                const auto descriptor = make_publisher_directory_security_descriptor(std::wstring(sid.begin(), sid.end()));
                set_publisher_boundary_security_from_handle(root.get(), descriptor);
            }
            require_publisher_object_security_shape(observe_publisher_directory_handle(root.get()),
                binding.at("service_sid").as_string());
        }
        std::unique_ptr<FileHandle> mounted_device;
        bool unpublished_device_bootstrap = false;
        if (device_transition.type() != Value::Type::null_value) {
            // Reentry/new mutation is bound to the same protected unpublished
            // namespace, registration and disk before the device-only effect.
            if (usk::json::canonical(registration_volume_identity(volume)) !=
                    usk::json::canonical(binding.at("volume_identity")) ||
                usk::json::canonical(dedicated_target_disk_identity(volume)) != usk::json::canonical(disk))
                throw std::runtime_error("mounted device bootstrap identity is unavailable");
            unpublished_device_bootstrap = !protected_document_exists(admitted_path);
            mounted_device = apply_mounted_device_transition(volume, service_sid, device_transition,
                unpublished_device_bootstrap);
        }
        // This second successful lock proves no conflicting file handles
        // remain after root hardening; it never revokes an open handle. It also verifies
        // the remounted root and restricted-service raw-device access.
        require_exclusive_volume_admission(name, volume,
            mounted_device.get(), mounted_device ? &device_transition.at("intended_policy") : nullptr,
            unpublished_device_bootstrap ? &device_transition : nullptr,
            unpublished_device_bootstrap ? &identity : nullptr);
        {
            ScopedControllerPrivilege backup;
            FileHandle root(CreateFileW(volume.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (root.get() == INVALID_HANDLE_VALUE ||
                usk::json::canonical(target_empty_namespace(root.get())) != usk::json::canonical(expected_metadata) ||
                usk::json::canonical(registration_volume_identity(volume)) != usk::json::canonical(binding.at("volume_identity")) ||
                usk::json::canonical(dedicated_target_disk_identity(volume)) != usk::json::canonical(disk))
                throw std::runtime_error("target identity or metadata changed across provisioning");
        }
        const Value admitted(Value::Object{
            {"schema", Value("usk.publisher_target_admitted.v1")}, {"identity", identity}
        });
        if (GetFileAttributesW(admitted_path.c_str()) != INVALID_FILE_ATTRIBUTES) {
            if (usk::json::canonical(read_protected_document(admitted_path)) != usk::json::canonical(admitted))
                throw std::runtime_error("retained target admission differs");
        } else if (GetLastError() == ERROR_FILE_NOT_FOUND) write_protected_document(admitted_path, admitted);
        else throw std::runtime_error("target admission absence is uncertain");
    } catch (const std::exception& error) {
        if (intent_retained) throw PublisherRequestOutcomeUnknown(
            std::string("target admission incomplete; protected intent retained: ") + error.what());
        throw;
    }
}

// Initial enrollment already records both successful provisioning locks.
// Owned safe-original v3 starts observe that completed hardware boundary;
// they do not dismount it again or acquire ACL mutation authority.
struct RegisteredTargetStartObservation {
    std::wstring volume;
    usk::json::Value binding;
    usk::json::Value identity;
    usk::json::Value intended_policy;
    std::string service_sid;
    std::unique_ptr<FileHandle> root;
    std::unique_ptr<FileHandle> device;
    std::array<std::unique_ptr<FileHandle>, 3> records;

    void verify(const std::wstring& name, const std::wstring& command) const {
        if (usk::json::canonical(read_registration_binding(name, command, volume)) !=
                usk::json::canonical(binding))
            throw std::runtime_error("registered start binding changed");
        require_publisher_stream_shape(root->get());
        const auto root_facts = observe_publisher_directory_handle(root->get());
        const auto volume_facts = observe_local_ntfs_volume_handle(root->get());
        require_publisher_object_security_shape(root_facts, service_sid);
        const auto& expected_volume = identity.at("volume_identity");
        if (root_facts.file_id != expected_volume.at("root_file_id").as_string() ||
            std::to_string(volume_facts.file_id_volume_serial) != expected_volume.at("volume_serial").as_string() ||
            usk::json::canonical(registration_volume_identity(volume)) !=
                usk::json::canonical(expected_volume) ||
            usk::json::canonical(dedicated_target_disk_identity(volume)) !=
                usk::json::canonical(identity.at("disk_identity")) ||
            usk::json::canonical(device_owner_dacl_policy(
                read_publisher_owner_dacl_from_handle(device->get()))) !=
                usk::json::canonical(intended_policy))
            throw std::runtime_error("registered start native boundary or intended device policy differs");
    }
};

std::unique_ptr<RegisteredTargetStartObservation> observe_registered_target_for_start(
    const std::wstring& name, const std::wstring& command, const std::wstring& volume) {
    const auto parent = registration_binding_path(name).parent_path();
    const auto intent_path = parent / (name + L".target-intent.json");
    const auto admitted_path = parent / (name + L".target-admitted.json");
    if (!protected_document_exists(intent_path)) {
        if (protected_document_exists(admitted_path))
            throw std::runtime_error("registered start admission has no original intent");
        return {}; // Existing generic registrations retain exclusive admission.
    }
    auto observation = std::make_unique<RegisteredTargetStartObservation>();
    const std::array<std::filesystem::path, 3> paths{
        registration_binding_path(name), intent_path, admitted_path};
    // Keep the original protected records closed to writes/replacement through
    // SCM start. Parsing still uses the existing bounded no-link/stream checks.
    for (std::size_t index = 0; index < paths.size(); ++index) {
        if (index == 2 && !protected_document_exists(admitted_path)) break;
        observation->records[index] = std::make_unique<FileHandle>(paths[index].c_str(),
            GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
            FILE_FLAG_OPEN_REPARSE_POINT);
        if (observation->records[index]->get() == INVALID_HANDLE_VALUE)
            throw std::runtime_error("registered start protected record custody unavailable");
        require_control_lock_shape(observation->records[index]->get(), false);
        require_publisher_stream_shape(observation->records[index]->get());
        if (observe_publisher_file_handle(observation->records[index]->get()).link_count != 1)
            throw std::runtime_error("registered start protected record has another link");
    }
    const auto intent = read_protected_document(intent_path);
    if (!publisher_target_intent_has_device_transition(intent)) return {}; // V2 unchanged.
    if (!observation->records[2])
        throw std::runtime_error("registered start target enrollment is incomplete");
    const auto admitted = read_protected_document(admitted_path);
    observation->binding = read_registration_binding(name, command, volume);
    observation->identity = intent.at("identity");
    if (observation->identity.as_object().size() != 4 ||
        admitted.as_object().size() != 2 ||
        admitted.at("schema").as_string() != "usk.publisher_target_admitted.v1" ||
        usk::json::canonical(admitted.at("identity")) != usk::json::canonical(observation->identity) ||
        observation->identity.at("registration_sha256").as_string() !=
            usk::json::sha256_canonical(observation->binding) ||
        usk::json::canonical(observation->identity.at("volume_identity")) !=
            usk::json::canonical(observation->binding.at("volume_identity")) ||
        usk::json::canonical(observation->identity.at("metadata")) !=
            usk::json::canonical(protected_metadata_snapshot(intent.at("original_metadata"))))
        throw std::runtime_error("registered start protected admission identity differs");
    const auto sid = publisher_service_sid(name);
    const auto& transition = intent.at("mounted_device_transition");
    const auto original = device_security_from_sddl(transition.at("original_owner_dacl").as_string());
    observation->intended_policy = transition.at("intended_policy");
    if (usk::json::canonical(device_owner_dacl_policy(intended_device_security(original, sid))) !=
            usk::json::canonical(observation->intended_policy))
        throw std::runtime_error("registered start intended policy differs from original derivation");
    try {
        (void)intended_device_security(original, sid, true);
    } catch (const std::runtime_error&) {
        return {}; // Recognized default-AU originals keep their existing lock path.
    }
    observation->volume = volume;
    observation->service_sid = observation->binding.at("service_sid").as_string();
    ScopedControllerPrivilege backup;
    observation->root = std::make_unique<FileHandle>(volume.c_str(),
        FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | READ_CONTROL | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    observation->device = std::make_unique<FileHandle>(volume.substr(0, volume.size() - 1).c_str(),
        READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
    if (observation->root->get() == INVALID_HANDLE_VALUE ||
        observation->device->get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("registered start read-only native custody unavailable");
    observation->verify(name, command);
    return observation;
}

void register_service(const std::wstring& name, const std::wstring& binary,
    const std::wstring& volume, const std::wstring& envelope,
    const std::wstring& digest, const std::wstring& caller,
    const std::wstring& binary_digest,
    const std::wstring& mode) {
    if (mode == L"--service-admitted-client") require_publisher_consumer_sid(utf8(caller));
    require_file(envelope);
    if (!lower_sha256(digest) || !lower_sha256(binary_digest))
        throw std::runtime_error("registration digest is invalid");
    // Reject mismatched package bytes before retaining any creation identity.
    // The pinned sources remain stable throughout copying and SCM admission.
    usk::base::StableFile source{std::filesystem::path(binary)};
    usk::base::StableFile reviewed{std::filesystem::path(envelope)};
    if (!source.identity().size_bytes || source.identity().size_bytes > 256u * 1024u * 1024u ||
        source.sha256_hex() != utf8(binary_digest) ||
        !reviewed.identity().size_bytes || reviewed.identity().size_bytes > 1024u * 1024u ||
        reviewed.sha256_hex() != utf8(digest))
        throw std::runtime_error("publisher packaged source digest or size differs");
    source.verify_unchanged();
    reviewed.verify_unchanged();
    ServiceControlGuard control(name);
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr,
        SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT));
    if (!manager.get()) throw std::runtime_error("service manager creation access unavailable");
    const auto volume_identity = registration_volume_identity(volume);
    const auto target = publisher_binary_path(name);
    const auto binding_path = registration_binding_path(name);
    const auto intent_path = target.parent_path() / (name + L".registration-intent.json");
    if (protected_document_exists(target.parent_path() / (name + L".retired.json")))
        throw std::runtime_error("publisher registration is retired; its name cannot be reused");
    const std::wstring command = command_prefix(name, target.wstring(), volume) +
        L" --reviewed-plan-envelope \"" + envelope + L"\" " + digest +
        command_suffix(caller, mode);
    const auto expected = registration_binding(name, command, binary_digest, volume_identity);
    const bool resuming = protected_document_exists(intent_path);
    const DWORD registration_access = SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS |
        (mode == L"--service-admitted-client" ? READ_CONTROL | WRITE_DAC : 0u);
    std::unique_ptr<ServiceHandle> service = std::make_unique<ServiceHandle>(
        OpenServiceW(manager.get(), name.c_str(),
            registration_access));
    if (!service->get() && GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST)
        throw std::runtime_error("publisher service presence is uncertain");
    usk::json::Value intent;
    if (resuming) {
        intent = read_protected_document(intent_path);
        if (intent.as_object().size() != 3 ||
            intent.at("schema").as_string() != "usk.publisher_registration_intent.v1" ||
            usk::json::canonical(intent.at("binding")) != usk::json::canonical(expected))
            throw std::runtime_error("retained registration intent differs from requested identity");
    } else {
        if (service->get() || protected_document_exists(binding_path) ||
            protected_document_exists(target) ||
            protected_document_exists(target.wstring() + L".pending"))
            throw std::runtime_error("publisher registration name or executable already exists without owned intent");
        GUID nonce{};
        if (FAILED(CoCreateGuid(&nonce)))
            throw std::runtime_error("registration creation identity is unavailable");
        intent = usk::json::Value(usk::json::Value::Object{
            {"schema", usk::json::Value("usk.publisher_registration_intent.v1")},
            {"creation_id", usk::json::Value(guid_text(nonce))},
            {"binding", expected}
        });
        LocalDescriptor directory_descriptor(L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), directory_descriptor.get(), FALSE};
        create_protected_directory(target.parent_path().wstring(), attributes);
        // This is durable before executable installation or SCM creation.
        // CreateService writes the corresponding unpredictable display tag in
        // the same operation as the owned name and command, so interruption
        // never requires adopting an unmarked preexisting service.
        write_protected_document(intent_path, intent);
    }
    const auto creation_id = intent.at("creation_id").as_string();
    const std::wstring wide_id(creation_id.begin(), creation_id.end());
    GUID parsed_id{};
    if (creation_id.size() != 38 || FAILED(CLSIDFromString(wide_id.c_str(), &parsed_id)) ||
        guid_text(parsed_id) != creation_id)
        throw std::runtime_error("retained registration creation identity is malformed");
    const std::wstring display_name = L"Universal Setup publisher " + wide_id;
    try {
        if (service->get()) {
            const auto before = query_configuration(service->get());
            if (before.binary_path != command || before.display_name != display_name ||
                before.type != SERVICE_WIN32_OWN_PROCESS || before.start != SERVICE_DEMAND_START ||
                CompareStringOrdinal(before.account.c_str(), -1, L"LocalSystem", -1, TRUE) != CSTR_EQUAL ||
                (before.sid_type != SERVICE_SID_TYPE_NONE && before.sid_type != SERVICE_SID_TYPE_RESTRICTED))
                throw std::runtime_error("existing service is not the retained creation identity");
            require_stopped(service->get());
        } else if (protected_document_exists(binding_path)) {
            throw std::runtime_error("completed registration service is absent; retain ownership for explicit recovery");
        }
        const auto installed = install_protected_binary(name, binary, binary_digest, resuming);
        source.verify_unchanged();
        reviewed.verify_unchanged();
        if (!service->get()) {
            service = std::make_unique<ServiceHandle>(CreateServiceW(manager.get(), name.c_str(),
                display_name.c_str(), registration_access,
                SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                command.c_str(), nullptr, nullptr, nullptr, L"LocalSystem", nullptr));
            if (!service->get())
                throw std::runtime_error("owned publisher service could not be created; intent retained");
        }
        SERVICE_SID_INFO sid{SERVICE_SID_TYPE_RESTRICTED};
        if (!ChangeServiceConfig2W(service->get(), SERVICE_CONFIG_SERVICE_SID_INFO, &sid))
            throw std::runtime_error("restricted service SID configuration failed");
        if (mode == L"--service-admitted-client")
            grant_publisher_service_client_start(service->get(), utf8(caller));
        try {
            require_protected_binary(name, installed.path);
        } catch (const std::exception&) {
            require_protected_binary(name, installed.path, false);
            grant_service_binary_read(name, installed.path);
        }
        const auto observed = query_configuration(service->get());
        require_profile(observed);
        require_stopped(service->get());
        if (observed.binary_path != command || observed.display_name != display_name)
            throw std::runtime_error("registered service command differs from reviewed input");
        if (protected_document_exists(binding_path)) {
            if (usk::json::canonical(read_registration_binding(name, command, volume)) !=
                    usk::json::canonical(expected))
                throw std::runtime_error("completed registration binding differs; retained");
        } else write_protected_document(binding_path, expected);
    } catch (const std::exception& error) {
        // Once intent is durable, keep the owned executable and stopped SCM
        // entry for an exact same-identity retry. Never delete a previous or
        // uncertain registration while reporting an initial refusal.
        throw PublisherRequestOutcomeUnknown(
            std::string("publisher registration incomplete; protected creation intent retained: ") + error.what());
    }
}

void request_start(const std::wstring& name, const std::wstring& binary,
    const std::wstring& volume, const std::wstring& caller,
    const std::wstring& mode, const std::wstring* exact_command);

std::string read_reviewed_apply(const std::wstring& envelope_path,
    const std::wstring& envelope_sha256, const std::wstring& apply_path, bool maintenance = false) {
    if (!lower_sha256(envelope_sha256)) {
        throw std::runtime_error("reviewed envelope digest is invalid");
    }
    std::string expected_digest;
    expected_digest.reserve(envelope_sha256.size());
    for (const wchar_t ch : envelope_sha256) {
        expected_digest.push_back(static_cast<char>(ch));
    }
    usk::base::StableFile envelope{std::filesystem::path(envelope_path)};
    if (!envelope.identity().size_bytes ||
        envelope.identity().size_bytes > 1024u * 1024u ||
        envelope.sha256_hex() != expected_digest) {
        throw std::runtime_error("reviewed envelope identity differs before registration");
    }
    const auto envelope_bytes = envelope.read(0,
        static_cast<std::size_t>(envelope.identity().size_bytes));
    envelope.verify_unchanged();
    usk::base::StableFile apply{std::filesystem::path(apply_path)};
    if (!apply.identity().size_bytes || apply.identity().size_bytes > 1024u * 1024u) {
        throw std::runtime_error("reviewed apply exceeds transport bound");
    }
    const auto apply_bytes = apply.read(0,
        static_cast<std::size_t>(apply.identity().size_bytes));
    apply.verify_unchanged();
    usk::json::ParseLimits limits;
    limits.max_bytes = 1024u * 1024u;
    limits.max_string_bytes = 512u * 1024u;
    const auto reviewed = usk::json::parse(
        std::string(envelope_bytes.begin(), envelope_bytes.end()), limits);
    const auto request = usk::json::parse(
        std::string(apply_bytes.begin(), apply_bytes.end()), limits);
    const bool maintenance_envelope = maintenance && reviewed.at("schema").as_string() ==
        "usk.publisher.maintenance_reviewed_plan_envelope.v1";
    const auto request_schema = request.at("schema").as_string();
    if ((!maintenance_envelope && reviewed.at("schema").as_string() !=
            "usk.publisher.lab_reviewed_plan_envelope.v2") ||
        reviewed.at("activation").as_string() != "operator_acceptance_candidate" ||
        (maintenance_envelope ? (request_schema != "usk.repair_apply_request.v1" &&
            request_schema != "usk.move_apply_request.v1" && request_schema != "usk.uninstall_apply_request.v1") :
            request_schema != "usk.install_local_apply_request.v1") ||
        request.at("confirmation").as_string() != "APPLY" ||
        usk::json::canonical(reviewed.at("apply_request")) !=
            usk::json::canonical(request)) {
        throw std::runtime_error("apply request differs from reviewed envelope");
    }
    return usk::json::canonical(request);
}

std::filesystem::path reviewed_operation_path(const std::wstring& name,
    const std::string& request_sha256, bool envelope) {
    const std::wstring digest(request_sha256.begin(), request_sha256.end());
    if (!lower_sha256(digest)) throw std::runtime_error("reviewed operation identity is invalid");
    return registration_binding_path(name).parent_path() /
        (name + L".operation-" + digest + (envelope ? L".envelope.json" : L".approval.json"));
}

std::unique_ptr<FileHandle> hold_protected_reviewed_file(const std::filesystem::path& path,
    std::uint64_t maximum_bytes) {
    auto file = std::make_unique<FileHandle>(CreateFileW(path.c_str(),
        GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (file->get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("protected reviewed operation is unavailable");
    require_control_lock_shape(file->get(), false);
    require_publisher_stream_shape(file->get());
    const auto observed = observe_publisher_file_handle(file->get());
    LARGE_INTEGER size{};
    if (observed.link_count != 1 || !GetFileSizeEx(file->get(), &size) ||
        size.QuadPart <= 0 || static_cast<std::uint64_t>(size.QuadPart) > maximum_bytes)
        throw std::runtime_error("protected reviewed operation shape or size differs");
    return file;
}

usk::json::Value parse_reviewed_operation_envelope(const std::string& bytes,
    const std::string& request) {
    usk::json::ParseLimits limits;
    limits.max_bytes = 1024u * 1024u;
    limits.max_string_bytes = 512u * 1024u;
    const auto envelope = usk::json::parse(bytes, limits);
    const auto schema = envelope.at("schema").as_string();
    const auto& apply = envelope.at("apply_request");
    const auto request_schema = apply.at("schema").as_string();
    std::string operation;
    if (schema == "usk.publisher.maintenance_reviewed_plan_envelope.v1") {
        if (request_schema == "usk.repair_apply_request.v1") operation = "repair";
        else if (request_schema == "usk.move_apply_request.v1") operation = "move";
        else if (request_schema == "usk.uninstall_apply_request.v1") operation = "uninstall";
        else throw std::runtime_error("reviewed maintenance operation schema is unavailable");
        if (apply.as_object().size() != 7u ||
            envelope.at("plan_request").at("schema").as_string() != "usk." + operation + "_plan_request.v1" ||
            !usk::record_io::valid_identifier(apply.at("transaction_id").as_string()) ||
            !usk::record_io::valid_identifier(envelope.at("plan_request").at("install_id").as_string()) ||
            apply.at("applied_at").as_string().empty())
            throw std::runtime_error("reviewed maintenance identity differs");
    }
    if (envelope.as_object().size() != 7 ||
        (operation.empty() && schema != "usk.publisher.lab_reviewed_plan_envelope.v2") ||
        envelope.at("activation").as_string() != "operator_acceptance_candidate" ||
        (operation.empty() && request_schema != "usk.install_local_apply_request.v1") ||
        envelope.at("apply_request").at("confirmation").as_string() != "APPLY" ||
        usk::json::canonical(envelope.at("apply_request")) != request ||
        usk::json::canonical(envelope.at("apply_request").at("plan_request")) !=
            usk::json::canonical(envelope.at("plan_request")) ||
        envelope.at("apply_request").at("reviewed_plan_digest").as_string() !=
            envelope.at("reviewed_plan_digest").as_string() ||
        envelope.at("apply_request").at("reviewed_plan_id").as_string() !=
            envelope.at("plan_request").at(operation.empty() ? "request_id" : "plan_id").as_string())
        throw std::runtime_error("protected reviewed envelope differs from exact approved request");
    // All seven envelope fields are mandatory; an unknown replacement field
    // cannot hide behind the cardinality check. Native mapping follows later.
    (void)envelope.at("state_root").as_string();
    (void)envelope.at("acceptance_root").as_string();
    return envelope;
}

usk::json::Value enroll_reviewed_operation(const std::wstring& name, const std::wstring& envelope_path,
    const std::wstring& envelope_digest, const std::wstring& apply_path) {
    // The administrative write access to the existing native controller lock
    // is required before any store effect. An ordinary client cannot enroll.
    ServiceControlGuard control(name, false, true);
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    ServiceHandle service(manager.get() ? OpenServiceW(manager.get(), name.c_str(),
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL) : nullptr);
    if (!service.get()) throw std::runtime_error("reviewed operation registration unavailable");
    require_stopped(service.get());
    const auto before = query_configuration(service.get());
    require_profile(before);
    const auto args = command_arguments(before.binary_path);
    if (args.size() < 10 || args[5] != L"--reviewed-plan-envelope" ||
        args[args.size() - 3] != L"--service-admitted-client")
        throw std::runtime_error("reviewed operation needs an owned admitted registration");
    const auto caller = args.back();
    require_existing_command(before.binary_path, name, args[0], args[4], caller,
        L"--service-admitted-client");
    require_protected_binary(name, args[0]);
    const auto binding = read_registration_binding(name, before.binary_path, args[4]);
    const auto admitted = read_protected_document(registration_binding_path(name).parent_path() /
        (name + L".target-admitted.json"));
    const auto& target = admitted.at("identity");
    if (admitted.as_object().size() != 2 ||
        admitted.at("schema").as_string() != "usk.publisher_target_admitted.v1" ||
        target.at("registration_sha256").as_string() != usk::json::sha256_canonical(binding) ||
        usk::json::canonical(target.at("volume_identity")) != usk::json::canonical(binding.at("volume_identity")) ||
        usk::json::canonical(target.at("disk_identity")) != usk::json::canonical(dedicated_target_disk_identity(args[4])))
        throw std::runtime_error("reviewed operation target admission differs");
    const auto request = read_reviewed_apply(envelope_path, envelope_digest, apply_path, true);
    usk::base::StableFile source{std::filesystem::path(envelope_path)};
    if (!source.identity().size_bytes || source.identity().size_bytes > 1024u * 1024u ||
        source.sha256_hex() != utf8(envelope_digest))
        throw std::runtime_error("reviewed envelope changed before enrollment");
    const auto raw = source.read(0, static_cast<std::size_t>(source.identity().size_bytes));
    const std::string bytes(raw.begin(), raw.end());
    (void)parse_reviewed_operation_envelope(bytes, request);
    const auto request_sha = usk::json::sha256_canonical(usk::json::parse(request));
    const auto blob_path = reviewed_operation_path(name, request_sha, true);
    const auto approval_path = reviewed_operation_path(name, request_sha, false);
    using usk::json::Value;
    const Value approval(Value::Object{
        {"schema", Value("usk.publisher_reviewed_operation_approval.v1")},
        {"registration_sha256", Value(usk::json::sha256_canonical(binding))},
        {"target_admitted_sha256", Value(usk::json::sha256_canonical(admitted))},
        {"caller_sid", Value(utf8(caller))}, {"request_sha256", Value(request_sha)},
        {"envelope_sha256", Value(utf8(envelope_digest))},
        {"envelope_size_bytes", Value(source.identity().size_bytes)}});
    // Existing final objects are never overwritten. An exact stopped retry
    // may complete a protected blob whose approval publication was interrupted.
    bool store_effects_may_exist = false;
    try {
    if (!protected_document_exists(blob_path)) {
        store_effects_may_exist = true;
        write_protected_bytes(blob_path, bytes, 1024u * 1024u);
    }
    const auto held_blob = hold_protected_reviewed_file(blob_path, 1024u * 1024u);
    usk::base::StableFile blob(blob_path);
    if (blob.identity().size_bytes != source.identity().size_bytes ||
        blob.sha256_hex() != utf8(envelope_digest))
        throw std::runtime_error("retained reviewed envelope differs; never replace it");
    source.verify_unchanged();
    blob.verify_unchanged();
    const auto after = query_configuration(service.get());
    require_profile(after);
    require_stopped(service.get());
    if (before.binary_path != after.binary_path || before.display_name != after.display_name ||
        usk::json::canonical(read_registration_binding(name, after.binary_path, args[4])) !=
            usk::json::canonical(binding))
        throw std::runtime_error("reviewed operation registration changed during enrollment");
    if (protected_document_exists(approval_path)) {
        if (usk::json::canonical(read_protected_document(approval_path)) != usk::json::canonical(approval))
            throw std::runtime_error("retained reviewed operation approval differs");
    } else {
        store_effects_may_exist = true;
        write_protected_document(approval_path, approval);
    }
    const auto actual = read_protected_document(approval_path);
    if (usk::json::canonical(actual) != usk::json::canonical(approval))
        throw std::runtime_error("reviewed operation durable approval readback differs");
    return actual;
    } catch (const std::exception& error) {
        if (store_effects_may_exist)
            throw PublisherRequestOutcomeUnknown(std::string("reviewed operation store effects may exist: ") + error.what());
        throw;
    }
}

int report_registered_response(const std::wstring& name, const std::string& request) {
    std::string response;
    std::string status;
    try {
        response = usk::platform::windows::submit_publisher_request(name, request, 120000);
        usk::json::ParseLimits limits;
        limits.max_bytes = 4u * 1024u * 1024u;
        limits.max_string_bytes = 2u * 1024u * 1024u;
        const auto parsed = usk::json::parse(response, limits);
        if (parsed.at("schema").as_string() !=
                "usk.publisher_lab_service_observation.v1") {
            throw std::runtime_error("unexpected publisher response schema");
        }
        status = parsed.at("status").as_string();
        if (status != "pass" && status != "failed" && status != "recovery_required") {
            throw std::runtime_error("unexpected publisher response status");
        }
    } catch (const std::exception& error) {
        throw usk::platform::windows::PublisherRequestOutcomeUnknown(error.what());
    }
    if (_setmode(_fileno(stdout), _O_BINARY) == -1) {
        throw usk::platform::windows::PublisherRequestOutcomeUnknown(
            "binary output unavailable");
    }
    std::cout << response;
    std::cout.flush();
    if (!std::cout) {
        throw usk::platform::windows::PublisherRequestOutcomeUnknown(
            "publisher response output failed");
    }
    return status == "pass" ? 0 : 3;
}

int apply_registered(const std::wstring& name, const std::wstring& installed_binary,
    const std::wstring& volume, const std::wstring& envelope,
    const std::wstring& envelope_digest, const std::wstring& caller,
    const std::wstring& binary_digest, const std::wstring& apply_file,
    const std::wstring& mode) {
    require_current_caller_sid(caller);
    require_file(apply_file);
    const std::string request = read_reviewed_apply(envelope, envelope_digest, apply_file);
    if (!lower_sha256(binary_digest)) {
        throw std::runtime_error("installed publisher digest is invalid");
    }
    require_protected_binary(name, installed_binary);
    usk::base::StableFile binary{std::filesystem::path(installed_binary)};
    std::string expected_binary_digest;
    expected_binary_digest.reserve(binary_digest.size());
    for (const wchar_t ch : binary_digest) {
        expected_binary_digest.push_back(static_cast<char>(ch));
    }
    if (binary.sha256_hex() != expected_binary_digest) {
        throw std::runtime_error("installed publisher digest differs");
    }
    binary.verify_unchanged();
    const std::wstring expected_command = command_prefix(name, installed_binary, volume) +
        L" --reviewed-plan-envelope \"" + envelope + L"\" " + envelope_digest +
        command_suffix(caller, mode);
    request_start(name, installed_binary, volume, caller, mode, &expected_command);
    return report_registered_response(name, request);
}

void configure_recovery(const std::wstring& name, const std::wstring& binary,
    const std::wstring& volume, const std::wstring& caller,
    const std::wstring& mode) {
    require_protected_binary(name, binary);
    ServiceControlGuard control(name);
    require_mutable_legacy_registration(name);
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.get()) throw std::runtime_error("service manager connection unavailable");
    ServiceHandle service(OpenServiceW(manager.get(), name.c_str(),
        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
    if (!service.get()) throw std::runtime_error("registered publisher service unavailable");
    require_stopped(service.get());
    const auto before = query_configuration(service.get());
    require_profile(before);
    require_existing_command(before.binary_path, name, binary, volume, caller, mode);
    const std::wstring command = command_prefix(name, binary, volume) +
        L" --recover-reviewed" + command_suffix(caller, mode);
    if (!ChangeServiceConfigW(service.get(), SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE, command.c_str(), nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr)) {
        throw std::runtime_error("registered recovery configuration failed");
    }
    const auto after = query_configuration(service.get());
    require_profile(after);
    if (after.binary_path != command)
        throw std::runtime_error("registered recovery command readback differs");
}

void configure_verify(const std::wstring& name, const std::wstring& binary,
    const std::wstring& volume, const std::wstring& caller,
    const std::wstring& mode) {
    require_protected_binary(name, binary);
    ServiceControlGuard control(name);
    require_mutable_legacy_registration(name);
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.get()) throw std::runtime_error("service manager connection unavailable");
    ServiceHandle service(OpenServiceW(manager.get(), name.c_str(),
        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
    if (!service.get()) throw std::runtime_error("registered publisher service unavailable");
    require_stopped(service.get());
    const auto before = query_configuration(service.get());
    require_profile(before);
    require_existing_command(before.binary_path, name, binary, volume, caller, mode);
    const std::wstring command = command_prefix(name, binary, volume) +
        L" --verify-installed" + command_suffix(caller, mode);
    if (!ChangeServiceConfigW(service.get(), SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE, command.c_str(), nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr)) {
        throw std::runtime_error("registered verify configuration failed");
    }
    const auto after = query_configuration(service.get());
    require_profile(after);
    if (after.binary_path != command)
        throw std::runtime_error("registered verify command readback differs");
}

void request_start(const std::wstring& name, const std::wstring& binary,
    const std::wstring& volume, const std::wstring& caller,
    const std::wstring& mode, const std::wstring* exact_command) {
    require_protected_binary(name, binary);
    ServiceControlGuard control(name);
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.get()) throw std::runtime_error("service manager connection unavailable");
    ServiceHandle service(OpenServiceW(manager.get(), name.c_str(),
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START));
    if (!service.get()) throw std::runtime_error("registered publisher service unavailable");
    require_stopped(service.get());
    const auto config = query_configuration(service.get());
    require_profile(config);
    require_existing_command(config.binary_path, name, binary, volume, caller, mode);
    if (exact_command && config.binary_path != *exact_command) {
        throw std::runtime_error("registered reviewed source or caller differs");
    }
    std::unique_ptr<RegisteredTargetStartObservation> start_observation;
    if (command_arguments(config.binary_path)[5] != L"--verify-installed") {
        start_observation = observe_registered_target_for_start(name, config.binary_path, volume);
        if (!start_observation) require_exclusive_volume_admission(name, volume);
    }
    if (!StartServiceW(service.get(), 0, nullptr)) {
        const DWORD error = GetLastError();
        if (exact_command) {
            // SCM may have spawned the worker before returning a timeout.
            // The reviewed caller must recover this same registration rather
            // than interpreting an unconfirmed start as no publication effect.
            throw usk::platform::windows::PublisherRequestOutcomeUnknown(
                "reviewed publisher start outcome is uncertain; Win32 " +
                std::to_string(error));
        }
        throw std::runtime_error("matching publisher service could not start; Win32 " +
            std::to_string(error));
    }
    if (start_observation) {
        const auto after = query_configuration(service.get());
        require_profile(after);
        if (after.binary_path != config.binary_path)
            throw std::runtime_error("registered start configuration changed");
        start_observation->verify(name, after.binary_path);
    }
}

int run_registered_operation(const std::wstring& name, const std::wstring& binary_path,
    const std::wstring& volume, const std::wstring& caller,
    const std::wstring& binary_digest, const std::wstring& request_path,
    const std::wstring& access_mode, bool recovery) {
    require_current_caller_sid(caller);
    require_file(request_path);
    if (!lower_sha256(binary_digest)) {
        throw std::runtime_error("installed publisher digest is invalid");
    }
    usk::base::StableFile request_file{std::filesystem::path(request_path)};
    if (!request_file.identity().size_bytes ||
        request_file.identity().size_bytes > 1024u * 1024u) {
        throw std::runtime_error("registered request exceeds transport bound");
    }
    const auto request_bytes = request_file.read(0,
        static_cast<std::size_t>(request_file.identity().size_bytes));
    request_file.verify_unchanged();
    usk::json::ParseLimits limits;
    limits.max_bytes = 1024u * 1024u;
    limits.max_string_bytes = 512u * 1024u;
    const auto parsed = usk::json::parse(
        std::string(request_bytes.begin(), request_bytes.end()), limits);
    const std::string expected_schema = recovery ?
        "usk.publisher_recovery_request.v1" :
        "usk.publisher_installed_verify_request.v1";
    if (parsed.at("schema").as_string() != expected_schema) {
        throw std::runtime_error("registered request mode differs");
    }
    const std::string request = usk::json::canonical(parsed);
    require_protected_binary(name, binary_path);
    usk::base::StableFile binary{std::filesystem::path(binary_path)};
    std::string expected_digest;
    expected_digest.reserve(binary_digest.size());
    for (const wchar_t ch : binary_digest) {
        expected_digest.push_back(static_cast<char>(ch));
    }
    if (binary.sha256_hex() != expected_digest) {
        throw std::runtime_error("installed publisher digest differs");
    }
    binary.verify_unchanged();
    {
        // Reconfiguration and start share the same controller lock. No other
        // cooperating controller can swap the mode between these steps.
        ServiceControlGuard control(name);
        require_mutable_legacy_registration(name);
        ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!manager.get()) {
            throw std::runtime_error("service manager connection unavailable");
        }
        ServiceHandle service(OpenServiceW(manager.get(), name.c_str(),
            SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS |
                SERVICE_START));
        if (!service.get()) {
            throw std::runtime_error("registered publisher service unavailable");
        }
        require_stopped(service.get());
        const auto before = query_configuration(service.get());
        require_profile(before);
        require_existing_command(before.binary_path, name, binary_path,
            volume, caller, access_mode);
        const std::wstring command = command_prefix(name, binary_path, volume) +
            (recovery ? L" --recover-reviewed" : L" --verify-installed") +
            command_suffix(caller, access_mode);
        if (!ChangeServiceConfigW(service.get(), SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE, command.c_str(), nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr)) {
            throw std::runtime_error("registered operation configuration failed");
        }
        const auto after = query_configuration(service.get());
        require_profile(after);
        if (after.binary_path != command) {
            throw std::runtime_error("registered operation command readback differs");
        }
        if (recovery) {
            require_exclusive_volume_admission(name, volume);
        }
        if (!StartServiceW(service.get(), 0, nullptr)) {
            throw usk::platform::windows::PublisherRequestOutcomeUnknown(
                "registered operation start outcome is uncertain; Win32 " +
                std::to_string(GetLastError()));
        }
    }
    return report_registered_response(name, request);
}

void request_unregister(const std::wstring& name, const std::wstring& binary,
    const std::wstring& volume, const std::wstring& caller,
    const std::wstring& mode) {
    require_protected_binary(name, binary);
    ServiceControlGuard control(name);
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.get()) throw std::runtime_error("service manager connection unavailable");
    ServiceHandle service(OpenServiceW(manager.get(), name.c_str(),
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | DELETE));
    if (!service.get()) throw std::runtime_error("registered publisher service unavailable");
    require_stopped(service.get());
    const auto config = query_configuration(service.get());
    require_profile(config);
    require_existing_command(config.binary_path, name, binary, volume, caller, mode);
    const auto expected_sid = publisher_service_sid(name);
    LPWSTR rendered_sid = nullptr;
    if (!ConvertSidToStringSidW(const_cast<unsigned char*>(expected_sid.data()), &rendered_sid))
        throw std::runtime_error("publisher retirement SID is unavailable");
    const auto service_sid = utf8(rendered_sid);
    LocalFree(rendered_sid);
    require_unpublished_public_retirement(name, volume, service_sid);
    require_stopped(service.get());
    if (!DeleteService(service.get()))
        throw std::runtime_error("matching publisher service deletion request failed");
}

void retire_protected_binary(const std::wstring& name,
    const std::wstring& binary, const std::wstring& expected_sha256,
    const std::wstring& service_sid_text) {
    if (!lower_sha256(expected_sha256))
        throw std::runtime_error("retired publisher executable digest is invalid");
    // The SCM name and protected binary share the same control lock. A pending
    // deletion is retained until SCM confirms absence; registration cannot race
    // the final file disposition through this product control path.
    const auto service_sid = retained_service_sid(service_sid_text);
    ServiceControlGuard control(name);
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.get()) throw std::runtime_error("service manager connection unavailable");
    ServiceHandle service(OpenServiceW(manager.get(), name.c_str(), SERVICE_QUERY_CONFIG));
    if (service.get() || GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST)
        throw std::runtime_error("publisher service remains present or its absence is uncertain");
    const auto records = registration_binding_path(name).parent_path();
    if (protected_document_exists(records / (name + L".target-intent.json")) ||
        protected_document_exists(records / (name + L".target-admitted.json"))) {
        const auto binding = read_protected_document(registration_binding_path(name));
        const auto root_text = binding.at("volume_identity").at("volume_root").as_string();
        const std::wstring retained_volume(root_text.begin(), root_text.end());
        require_volume(retained_volume);
        if (binding.at("binary_sha256").as_string() != utf8(expected_sha256) ||
            !EqualSid(const_cast<BYTE*>(service_sid.data()), derive_ascii_publisher_service_sid(name).data()))
            throw std::runtime_error("retired publisher identity differs from protected registration");
        require_unpublished_public_retirement(name, retained_volume, utf8(service_sid_text));
    }
    FileHandle file(CreateFileW(binary.c_str(), DELETE | GENERIC_READ | READ_CONTROL |
        FILE_READ_ATTRIBUTES, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (file.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("protected publisher executable is active or unavailable");
    require_protected_binary_handle(name, binary, file.get(), true, &service_sid);
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.get(), &size) || size.QuadPart <= 0 ||
        size.QuadPart > 256ll * 1024 * 1024)
        throw std::runtime_error("protected publisher executable size differs");
    usk::base::Sha256 hash;
    std::array<unsigned char, 64 * 1024> buffer{};
    LONGLONG read_total = 0;
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()),
                &read, nullptr))
            throw std::runtime_error("protected publisher executable read failed");
        if (read == 0) break;
        read_total += read;
        if (read_total > size.QuadPart)
            throw std::runtime_error("protected publisher executable grew during retirement");
        hash.update(buffer.data(), read);
    }
    std::string expected;
    expected.reserve(expected_sha256.size());
    for (const wchar_t character : expected_sha256)
        expected.push_back(static_cast<char>(character));
    if (read_total != size.QuadPart || hash.finish() != expected)
        throw std::runtime_error("protected publisher executable digest differs; retained");
    FILE_DISPOSITION_INFO disposition{};
    disposition.DeleteFile = TRUE;
    if (!SetFileInformationByHandle(file.get(), FileDispositionInfo,
            &disposition, sizeof(disposition)))
        throw std::runtime_error("protected publisher executable could not be retired");
    file.close();
    if (GetFileAttributesW(binary.c_str()) != INVALID_FILE_ATTRIBUTES ||
        GetLastError() != ERROR_FILE_NOT_FOUND)
        throw std::runtime_error("retired publisher executable absence is unconfirmed");
}

} // namespace

usk::json::Value parse_publisher_reviewed_operation_envelope(
    const std::string& bytes, const std::string& canonical_request) {
    return parse_reviewed_operation_envelope(bytes, canonical_request);
}
usk::json::Value parse_publisher_maintenance_recovery_request(const std::string& bytes) {
    usk::json::ParseLimits limits;
    limits.max_bytes = 2048;
    limits.max_string_bytes = 256;
    const auto request = usk::json::parse(bytes, limits);
    const auto& operation = request.at("operation").as_string();
    if (request.as_object().size() != 4 ||
        request.at("schema").as_string() != "usk.publisher_maintenance_recovery_request.v1" ||
        (operation != "repair" && operation != "move" && operation != "uninstall"))
        throw std::runtime_error("maintenance recovery requires a closed original operation selector");
    for (const auto field : {"install_id", "transaction_id"}) {
        const auto& id = request.at(field).as_string();
        if (id.empty() || id.size() > 128 || id.find_first_not_of(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != std::string::npos)
            throw std::runtime_error("maintenance recovery original identity differs");
    }
    return request;
}

struct RegisteredPublisherAdmission::State {
    std::unique_ptr<ServiceControlGuard> control;
    std::shared_ptr<ServiceHandle> service;
    std::unique_ptr<PublisherServiceReadbackScope> service_readback;
    ServiceConfiguration configuration;
    std::unique_ptr<usk::base::StableFile> binary;
    usk::json::Value service_access;
    usk::json::Value admission_evidence;
    std::unique_ptr<FileHandle> selected_approval_file, selected_envelope_file;
    std::unique_ptr<usk::base::StableFile> selected_envelope_source;
    usk::json::Value selected_approval, selected_envelope;
    std::filesystem::path selected_approval_path;
    std::wstring name;
};

RegisteredPublisherAdmission::RegisteredPublisherAdmission(const std::wstring& name,
    const std::wstring& volume, const std::wstring& caller) : state_(std::make_unique<State>()) {
    PublisherServiceReadbackScope::require_available();
    // Actual SCM/current-token corroboration precedes every filesystem effect,
    // including controller-guard creation. Caller text does not grant authority.
    const auto observed = observe_current_restricted_publisher_service(name);
    if (!generated_name(name)) throw std::runtime_error("registered publisher name differs");
    require_volume(volume);
    require_canonical_sid(caller);
    require_publisher_consumer_sid(utf8(caller));
    state_->control = std::make_unique<ServiceControlGuard>(name, true);
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.get()) throw std::runtime_error("registered publisher SCM unavailable");
    state_->service = std::make_shared<ServiceHandle>(OpenServiceW(manager.get(), name.c_str(),
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL));
    if (!state_->service->get()) throw std::runtime_error("registered publisher service unavailable");
    const auto before = query_configuration(state_->service->get());
    state_->service_access = observe_publisher_service_access(state_->service->get(), utf8(caller));
    require_profile(before);
    const auto args = command_arguments(before.binary_path);
    if (args.size() < 8 || args[4] != volume)
        throw std::runtime_error("registered publisher target differs from running worker");
    require_existing_command(before.binary_path, name, args[0], volume, caller, L"--service-admitted-client");
    wchar_t current_image[32768]{};
    const auto length = GetModuleFileNameW(nullptr, current_image, static_cast<DWORD>(std::size(current_image)));
    if (!length || length >= std::size(current_image) ||
        CompareStringOrdinal(current_image, -1, args[0].c_str(), -1, TRUE) != CSTR_EQUAL)
        throw std::runtime_error("registered publisher image differs from its actual process");
    require_protected_binary(name, args[0]);
    const auto binding = read_registration_binding(name, before.binary_path, volume, false);
    const auto admitted = read_protected_document(registration_binding_path(name).parent_path() /
        (name + L".target-admitted.json"));
    const auto& target = admitted.at("identity");
    if (observed.service_sid != binding.at("service_sid").as_string() || admitted.as_object().size() != 2 ||
        admitted.at("schema").as_string() != "usk.publisher_target_admitted.v1" ||
        target.at("registration_sha256").as_string() != usk::json::sha256_canonical(binding) ||
        usk::json::canonical(target.at("volume_identity")) != usk::json::canonical(binding.at("volume_identity")) ||
        usk::json::canonical(target.at("disk_identity")) != usk::json::canonical(dedicated_target_disk_identity(volume)))
        throw std::runtime_error("registered publisher target admission differs from retained authority");
    state_->binary = std::make_unique<usk::base::StableFile>(std::filesystem::path(args[0]));
    if (state_->binary->sha256_hex() != binding.at("binary_sha256").as_string())
        throw std::runtime_error("registered publisher executable differs from retained package digest");
    state_->binary->verify_unchanged();
    const auto after = query_configuration(state_->service->get());
    require_profile(after);
    const auto current = observe_current_restricted_publisher_service(name);
    if (!same_configuration(after, before) ||
        usk::json::canonical(observe_publisher_service_access(state_->service->get(), utf8(caller))) !=
            usk::json::canonical(state_->service_access) ||
        current.process_id != observed.process_id || current.service_sid != observed.service_sid)
        throw std::runtime_error("registered publisher configuration changed during admission");
    using usk::json::Value;
    const auto& image = state_->binary->identity();
    state_->name = name;
    state_->admission_evidence = Value(Value::Object{
        {"schema", Value("usk.publisher_registered_admission_observation.v1")},
        {"scope", Value("held_registered_service_image_and_controller_target_admission")},
        {"service_name", Value(utf8(name))}, {"service_sid", Value(observed.service_sid)},
        {"process_id", Value(static_cast<std::uint64_t>(observed.process_id))},
        {"configured_caller_sid", Value(utf8(caller))},
        {"publisher_image", Value(Value::Object{
            {"path", Value(utf8(args[0]))}, {"volume_id", Value(image.volume_id)},
            {"file_id", Value(image.file_id)}, {"size_bytes", Value(image.size_bytes)},
            {"sha256", binding.at("binary_sha256")}})},
        {"registration_sha256", Value(usk::json::sha256_canonical(binding))},
        {"target_admitted_sha256", Value(usk::json::sha256_canonical(admitted))},
        {"target_identity", target}});
    state_->configuration = before;
    // Establish the original native readback lifetime before any selected
    // operation freezes worker security. All named readbacks on this exact
    // execution thread now query this same held object and fresh token facts.
    state_->service_readback.reset(new PublisherServiceReadbackScope(
        state_->service->get(), state_->service, current));
}
RegisteredPublisherAdmission::~RegisteredPublisherAdmission() = default;

usk::json::Value RegisteredPublisherAdmission::evidence() const {
    state_->service_readback->require_current();
    const auto before = query_configuration(state_->service->get());
    require_profile(before);
    if (!same_configuration(before, state_->configuration))
        throw std::runtime_error("registered publisher original configuration changed");
    state_->binary->verify_unchanged();
    const auto current = observe_current_restricted_publisher_service(state_->name);
    if (current.process_id != state_->admission_evidence.at("process_id").as_unsigned() ||
        current.service_sid != state_->admission_evidence.at("service_sid").as_string() ||
        usk::json::canonical(observe_publisher_service_access(state_->service->get(),
            state_->admission_evidence.at("configured_caller_sid").as_string())) !=
                usk::json::canonical(state_->service_access))
        throw std::runtime_error("registered publisher admission observation lost its held binding");
    const auto after = query_configuration(state_->service->get());
    require_profile(after);
    if (!same_configuration(after, before) || !same_configuration(after, state_->configuration))
        throw std::runtime_error("registered publisher original configuration changed during readback");
    state_->service_readback->require_current();
    state_->binary->verify_unchanged();
    if (state_->selected_envelope_source) {
        require_control_lock_shape(state_->selected_approval_file->get(), false);
        require_control_lock_shape(state_->selected_envelope_file->get(), false);
        require_publisher_stream_shape(state_->selected_approval_file->get());
        require_publisher_stream_shape(state_->selected_envelope_file->get());
        if (usk::json::canonical(read_protected_document(state_->selected_approval_path)) !=
                usk::json::canonical(state_->selected_approval))
            throw std::runtime_error("held reviewed operation approval changed");
        state_->selected_envelope_source->verify_unchanged();
    }
    return state_->admission_evidence;
}

bool RegisteredPublisherAdmission::select_reviewed_operation(const std::string& request,
    const PublisherRequestChannel& channel, std::wstring& envelope_path,
    std::string& envelope_sha256) const {
    if (state_->selected_envelope_source)
        throw std::runtime_error("one-request registration already selected its operation");
    const auto admission = evidence();
    const auto parsed = usk::json::parse(request);
    const auto canonical = usk::json::canonical(parsed);
    const auto request_sha = usk::json::sha256_canonical(parsed);
    const auto approval_path = reviewed_operation_path(state_->name, request_sha, false);
    if (!protected_document_exists(approval_path)) return false;
    auto held_approval = hold_protected_reviewed_file(approval_path, 16384);
    const auto approval = read_protected_document(approval_path);
    const auto client = channel.observe_authenticated_object_access(held_approval->get()).at("client");
    if (approval.as_object().size() != 7 ||
        approval.at("schema").as_string() != "usk.publisher_reviewed_operation_approval.v1" ||
        approval.at("registration_sha256").as_string() != admission.at("registration_sha256").as_string() ||
        approval.at("target_admitted_sha256").as_string() != admission.at("target_admitted_sha256").as_string() ||
        approval.at("caller_sid").as_string() != admission.at("configured_caller_sid").as_string() ||
        client.at("user_sid").as_string() != approval.at("caller_sid").as_string() ||
        approval.at("request_sha256").as_string() != request_sha)
        throw std::runtime_error("protected reviewed operation approval binding differs");
    const auto blob_path = reviewed_operation_path(state_->name, request_sha, true);
    auto held_blob = hold_protected_reviewed_file(blob_path, 1024u * 1024u);
    auto source = std::make_unique<usk::base::StableFile>(blob_path);
    if (source->identity().size_bytes != approval.at("envelope_size_bytes").as_unsigned() ||
        source->sha256_hex() != approval.at("envelope_sha256").as_string())
        throw std::runtime_error("approved reviewed envelope native bytes differ");
    const auto bytes = source->read(0, static_cast<std::size_t>(source->identity().size_bytes));
    const auto envelope = parse_reviewed_operation_envelope(std::string(bytes.begin(), bytes.end()), canonical);
    source->verify_unchanged();
    state_->selected_approval_file = std::move(held_approval);
    state_->selected_envelope_file = std::move(held_blob);
    state_->selected_envelope_source = std::move(source);
    state_->selected_approval_path = approval_path;
    state_->selected_approval = approval;
    state_->selected_envelope = envelope;
    (void)evidence();
    envelope_path = blob_path.wstring();
    envelope_sha256 = approval.at("envelope_sha256").as_string();
    return true;
}

bool RegisteredPublisherAdmission::has_selected_reviewed_operation() const noexcept {
    return state_->selected_envelope_source != nullptr;
}

usk::json::Value RegisteredPublisherAdmission::selected_reviewed_envelope() const {
    if (!has_selected_reviewed_operation())
        throw std::runtime_error("no protected reviewed operation was selected");
    (void)evidence();
    return state_->selected_envelope;
}

usk::json::Value RegisteredPublisherAdmission::selected_reviewed_operation_observation() const {
    if (!has_selected_reviewed_operation())
        throw std::runtime_error("no native reviewed operation is held");
    (void)evidence();
    using usk::json::Value;
    return Value(Value::Object{
        {"schema", Value("usk.publisher_selected_reviewed_operation_observation.v1")},
        {"scope", Value("authenticated_exact_request_and_held_protected_enrollment_files")},
        {"approval", state_->selected_approval},
        {"approval_sha256", Value(usk::json::sha256_canonical(state_->selected_approval))},
        {"approval_file", publisher_handle_observation_json(observe_publisher_file_handle(state_->selected_approval_file->get()))},
        {"envelope_sha256", Value(state_->selected_envelope_source->sha256_hex())},
        {"envelope_file", publisher_handle_observation_json(observe_publisher_file_handle(state_->selected_envelope_file->get()))}});
}

usk::json::Value RegisteredPublisherAdmission::capability_observation(const std::string& request_id, bool scoped_profile) const {
    using usk::json::Value;
    const auto admitted = evidence();
    const auto observed = observe_current_restricted_publisher_service(state_->name);
    if (observed.process_id != admitted.at("process_id").as_unsigned() ||
        observed.service_sid != admitted.at("service_sid").as_string())
        throw std::runtime_error("service capability worker changed during observation");
    const auto& target = admitted.at("target_identity");
    const auto& volume = target.at("volume_identity");
    // These are retained controller-admission bindings, with the current disk
    // identity checked by admission. They do not assert fresh boundary ACLs.
    auto result = Value(Value::Object{
        {"schema", Value("usk.publisher_capability.v2")}, {"request_id", Value(request_id)},
        {"provider_id", Value("windows_nt_x64_local_ntfs_service_sid_noreplace_v1")},
        {"implementation", Value("partial")}, {"realization", Value("restricted_service")},
        {"availability", Value(false)}, {"required_privilege", Value("none_for_registered_caller")},
        {"permission", Value("registered_caller_observed")},
        {"authority", Value("not_granted_by_discovery")}, {"qualification", Value("incomplete")},
        {"qualification_scope", Value("service_admitted_target_observation")},
        {"binding_provenance", Value("retained_controller_admission_and_current_disk_identity")},
        {"support", Value("unsupported")}, {"recovery_ceiling", Value("candidate_source_free_restart")},
        {"power_loss_qualified", Value(false)}, {"revalidation_required_before_effects", Value(true)},
        {"execution_lease_held", Value(false)},
        {"service_state", Value(static_cast<std::uint64_t>(observed.service_state))},
        {"effects", Value(Value::Array{Value("service_start_may_occur"),
            Value("controller_guard_held_during_observation")})},
        {"platform", Value(Value::Object{{"os_family", Value("Windows NT")},
            {"native_arch", Value("x64")}, {"process_arch", Value("x64")},
            {"windows_build", Value(observe_supported_discovery_windows_build())},
            {"minimum_windows_build", Value(std::uint64_t{17763})}})},
        {"binding", Value(Value::Object{{"service_name", admitted.at("service_name")},
            {"service_sid", admitted.at("service_sid")},
            {"caller_sid", admitted.at("configured_caller_sid")},
            {"process_id", admitted.at("process_id")},
            {"binary_sha256", admitted.at("publisher_image").at("sha256")},
            {"registration_sha256", admitted.at("registration_sha256")},
            {"target_admitted_sha256", admitted.at("target_admitted_sha256")},
            {"volume_guid_root", volume.at("volume_root")},
            {"root_file_id", volume.at("root_file_id")},
            {"volume_serial", volume.at("volume_serial")}})}});
    if (scoped_profile) {
        // Qualified source-path bounds, not a grant from a query or a claim
        // about historical records. All operation checks still precede effects.
        const auto actual = observe_publisher_execution_platform();
        const bool qualified = publisher_registered_execution_platform_qualified(actual);
        auto& fields = result.as_object();
        fields.at("schema") = Value("usk.publisher_capability.v3");
        fields.at("availability") = Value(qualified);
        fields.at("qualification") = Value(qualified ? "qualified_for_scope" : "incomplete");
        fields.at("support") = Value(qualified ? "supported_for_scope" : "unsupported");
        fields.at("qualification_scope") = Value("registered_public_apply_v9_process_restart_replay_verify");
        fields.at("recovery_ceiling") = Value("source_free_process_restart_v9");
        fields.at("platform").as_object().emplace("sdk_version", actual.at("sdk_version"));
        fields.emplace("qualification_bounds", Value(Value::Object{
            {"phase_schema", Value("usk.publisher.lab_phase_evidence.v9")},
            {"execution_schema", Value("usk.publisher_execution_observation.v6")},
            {"sdk_version", Value("10.0.26100.0")},
            {"qualified_windows_build", Value(std::uint64_t{20348})}}));
    }
    return result;
}

std::string submit_registered_publisher_request(const std::wstring& name,
    const std::string& request, const PublisherRequestOptions& options) {
    // Legacy privileged admission holds the controller guard here. The new
    // registered mode holds it in the actual service while the ordinary client
    // validates SCM's stored policy and binds the live pipe/PID/image.
    std::string schema;
    std::string inspection_id;
    bool service_observation = false;
    std::uint64_t windows_build = 0;
    try {
        if (!generated_name(name) || request.empty() || request.size() > 1024u * 1024u)
            throw std::runtime_error("publisher request identity or size differs");
        usk::json::ParseLimits limits;
        limits.max_bytes = 1024u * 1024u;
        limits.max_string_bytes = 512u * 1024u;
        const auto submitted = usk::json::parse(request, limits);
        schema = submitted.at("schema").as_string();
        if (schema == "usk.publisher_capability_request.v1" ||
            schema == "usk.publisher_capability_request.v2" ||
            schema == "usk.publisher_capability_request.v3") {
            service_observation = schema != "usk.publisher_capability_request.v1";
            inspection_id = submitted.at("request_id").as_string();
            if (submitted.as_object().size() != 2 || inspection_id.empty() || inspection_id.size() > 128 ||
                inspection_id.find_first_not_of(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != std::string::npos)
                throw std::runtime_error("publisher inspection request differs");
            windows_build = observe_supported_discovery_windows_build();
        } else if (schema != "usk.install_local_apply_request.v1" &&
            schema != "usk.repair_apply_request.v1" && schema != "usk.move_apply_request.v1" &&
            schema != "usk.uninstall_apply_request.v1" &&
            schema != "usk.publisher_recovery_request.v1" &&
            schema != "usk.publisher_maintenance_recovery_request.v1" &&
            schema != "usk.publisher_installed_verify_request.v1")
            throw std::runtime_error("publisher request schema is unavailable");
        if (schema == "usk.publisher_maintenance_recovery_request.v1")
            (void)parse_publisher_maintenance_recovery_request(request);
        if (options.conflict_wait_milliseconds > publisher_request_max_conflict_wait_milliseconds)
            throw std::invalid_argument("publisher contention wait exceeds bound");
        if (options.cancel_event) {
            const DWORD cancelled = WaitForSingleObject(options.cancel_event, 0);
            if (cancelled == WAIT_OBJECT_0)
                throw usk::base::EffectRequestNotDispatched(
                    usk::base::EffectRequestNotDispatched::Reason::operation_cancelled,
                    publisher_request_inspection_reference(name));
            if (cancelled != WAIT_TIMEOUT) throw std::runtime_error("publisher cancellation event unavailable");
        }
    } catch (const usk::base::EffectRequestNotDispatched&) {
        throw;
    } catch (const std::exception&) {
        throw usk::base::EffectRequestNotDispatched();
    }

    std::unique_ptr<ServiceControlGuard> control;
    std::unique_ptr<ServiceHandle> service;
    std::unique_ptr<usk::base::StableFile> binary;
    std::unique_ptr<RegisteredTargetStartObservation> start_observation;
    std::wstring admitted_image;
    try {
        ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!manager.get()) throw std::runtime_error("SCM connection is unavailable");
        service = std::make_unique<ServiceHandle>(OpenServiceW(manager.get(), name.c_str(),
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL |
                (inspection_id.empty() || service_observation ? SERVICE_START : 0)));
        if (!service->get()) throw std::runtime_error("publisher registration is unavailable");
        const auto before = query_configuration(service->get());
        require_profile(before);
        const auto args = command_arguments(before.binary_path);
        if (args.size() < 8) throw std::runtime_error("publisher registration is malformed");
        const bool grant = args.back() == L"--grant-client-read";
        const auto caller_index = args.size() - (grant ? 2u : 1u);
        const auto caller = args[caller_index];
        const bool observer = args.size() >= 3 &&
            args[args.size() - 3] == L"--admit-client-observer";
        const std::wstring mode = grant ? L"--grant-client-read" :
            observer ? L"--admit-client-observer" : L"";
        require_canonical_sid(caller);
        require_current_caller_sid(caller);
        require_volume(args[4]);
        const bool service_admitted = args.size() >= 3 && args[args.size() - 3] == L"--service-admitted-client";
        if (service_admitted) {
            require_publisher_consumer_sid(utf8(caller));
            const auto service_access = observe_publisher_service_access(service->get(), utf8(caller));
            // The administrator-owned SCM command selects this service-side
            // admission path. The actual worker checks its private records and
            // disk identity under its controller guard before opening the pipe.
            // The client binds the live pipe/PID/image before sending any bytes.
            require_existing_command(before.binary_path, name, args[0], args[4], caller, L"--service-admitted-client");
            if (CompareStringOrdinal(args[0].c_str(), -1, publisher_binary_path(name).c_str(), -1, TRUE) != CSTR_EQUAL)
                throw std::runtime_error("registered publisher image is outside the protected installation");
            if (!inspection_id.empty() && !service_observation) {
                // V1 discovery requires five genuine private/raw-disk bindings.
                // Recognize this mode and refuse after caller/SCM validation,
                // without a guard, service start or fabricated digest.
                throw std::runtime_error("standard publisher discovery evidence is unavailable");
            }
            SERVICE_STATUS_PROCESS status{};
            DWORD needed = 0;
            if (!QueryServiceStatusEx(service->get(), SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&status), sizeof(status), &needed))
                throw std::runtime_error("registered publisher process status unavailable");
            if (status.dwCurrentState == SERVICE_STOPPED) {
                if (!StartServiceW(service->get(), 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
                    throw std::runtime_error("registered publisher could not be started");
            } else if (status.dwCurrentState != SERVICE_RUNNING && status.dwCurrentState != SERVICE_START_PENDING)
                throw std::runtime_error("registered publisher is unavailable while stopping");
            const auto after = query_configuration(service->get());
            require_profile(after);
            if (after.binary_path != before.binary_path || after.display_name != before.display_name ||
                usk::json::canonical(observe_publisher_service_access(service->get(), utf8(caller))) !=
                    usk::json::canonical(service_access))
                throw std::runtime_error("registered publisher configuration changed before dispatch");
            admitted_image = args[0];
        } else {
        if (service_observation)
            throw std::runtime_error("service-mediated observation requires registered service admission");
        require_existing_command(before.binary_path, name, args[0], args[4], caller, mode);
        require_protected_binary(name, args[0]);
        const auto binding = read_registration_binding(name, before.binary_path, args[4]);
        const auto admitted_path = registration_binding_path(name).parent_path() /
            (name + L".target-admitted.json");
        const auto admitted = read_protected_document(admitted_path);
        const auto& target = admitted.at("identity");
        if (admitted.as_object().size() != 2 ||
            admitted.at("schema").as_string() != "usk.publisher_target_admitted.v1" ||
            target.at("registration_sha256").as_string() != usk::json::sha256_canonical(binding) ||
            usk::json::canonical(target.at("volume_identity")) != usk::json::canonical(binding.at("volume_identity")) ||
            usk::json::canonical(target.at("disk_identity")) !=
                usk::json::canonical(dedicated_target_disk_identity(args[4])))
            throw std::runtime_error("publisher target admission differs from retained registration");
        binary = std::make_unique<usk::base::StableFile>(std::filesystem::path(args[0]));
        if (binary->sha256_hex() != binding.at("binary_sha256").as_string())
            throw std::runtime_error("publisher executable differs from retained package digest");
        binary->verify_unchanged();
        admitted_image = args[0];
        // The ordinary client reuses the reviewed registration. Recovery and
        // verification never open the original envelope or payload sources.
        if (args[5] != L"--reviewed-plan-envelope" &&
            !((args[5] == L"--recover-reviewed" &&
                (schema == "usk.publisher_recovery_request.v1" || !inspection_id.empty())) ||
              (args[5] == L"--verify-installed" &&
                (schema == "usk.publisher_installed_verify_request.v1" || !inspection_id.empty()))))
            throw std::runtime_error("registered publisher mode differs from request");
        if (!inspection_id.empty()) {
            // The independently matched registered caller can be a built-in
            // account. Discovery does not grant the ordinary consumer-read ACE.
            require_publisher_registered_account_sid(utf8(caller));
            // Discovery uses query handles only. It neither creates controller
            // locks nor starts/reconfigures a service, admits a target or grants
            // execution authority. This observation is not a held execution lease.
            ScopedControllerPrivilege backup;
            FileHandle root(CreateFileW(args[4].c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            FileHandle device(CreateFileW(args[4].substr(0, args[4].size() - 1).c_str(), READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
            if (root.get() == INVALID_HANDLE_VALUE || device.get() == INVALID_HANDLE_VALUE)
                throw std::runtime_error("publisher discovery boundary is unavailable");
            const auto root_security = read_publisher_owner_dacl_from_handle(root.get());
            const auto root_facts = observe_publisher_directory_handle(root.get());
            require_publisher_object_security_shape(root_facts, binding.at("service_sid").as_string());
            if (read_publisher_owner_dacl_from_handle(root.get()) != root_security)
                throw std::runtime_error("publisher root security changed across shape observation");
            if (root_facts.file_id != binding.at("volume_identity").at("root_file_id").as_string())
                throw std::runtime_error("publisher discovery held root identity differs");
            const auto device_security = read_publisher_owner_dacl_from_handle(device.get());
            PSID device_owner = nullptr;
            PACL device_dacl = nullptr;
            BOOL present = FALSE, defaulted = FALSE;
            auto service_sid = publisher_service_sid(name);
            auto* descriptor = const_cast<unsigned char*>(device_security.data());
            if (!GetSecurityDescriptorOwner(descriptor, &device_owner, &defaulted) ||
                !GetSecurityDescriptorDacl(descriptor, &present, &device_dacl, &defaulted) || !present ||
                !require_publisher_device_acl_shape(device_owner, device_dacl, service_sid.data()))
                throw std::runtime_error("publisher discovery device security differs");
            const auto security_digest = [](const std::vector<unsigned char>& bytes) {
                usk::base::Sha256 hash;
                hash.update(bytes.data(), bytes.size());
                return hash.finish();
            };
            const auto boundary_digest = usk::json::sha256_canonical(usk::json::Value(usk::json::Value::Object{
                {"root_file_id", usk::json::Value(root_facts.file_id)},
                {"root_security_sha256", usk::json::Value(security_digest(root_security))},
                {"device_security_sha256", usk::json::Value(security_digest(device_security))}}));
            const auto after = query_configuration(service->get());
            require_profile(after);
            if (after.binary_path != before.binary_path ||
                usk::json::canonical(read_registration_binding(name, after.binary_path, args[4])) !=
                    usk::json::canonical(binding) ||
                usk::json::canonical(read_protected_document(admitted_path)) != usk::json::canonical(admitted) ||
                usk::json::canonical(dedicated_target_disk_identity(args[4])) !=
                    usk::json::canonical(target.at("disk_identity")))
                throw std::runtime_error("publisher observation changed during discovery");
            binary->verify_unchanged();
            if (read_publisher_owner_dacl_from_handle(root.get()) != root_security ||
                read_publisher_owner_dacl_from_handle(device.get()) != device_security ||
                observe_publisher_directory_handle(root.get()).file_id != root_facts.file_id)
                throw std::runtime_error("publisher boundary changed during discovery");
            SERVICE_STATUS_PROCESS status{};
            DWORD needed = 0;
            if (!QueryServiceStatusEx(service->get(), SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&status), sizeof(status), &needed) ||
                status.dwServiceType != SERVICE_WIN32_OWN_PROCESS ||
                status.dwCurrentState < SERVICE_STOPPED || status.dwCurrentState > SERVICE_PAUSED)
                throw std::runtime_error("publisher observation status is unavailable");
            using usk::json::Value;
            return usk::json::canonical(Value(Value::Object{
                {"schema", Value("usk.publisher_capability.v1")},
                {"request_id", Value(inspection_id)},
                {"provider_id", Value("windows_nt_x64_local_ntfs_service_sid_noreplace_v1")},
                {"implementation", Value("partial")},
                {"realization", Value("restricted_service")},
                {"availability", Value(false)},
                {"required_privilege", Value("SeBackupPrivilege_and_disk_read")},
                {"permission", Value("registered_caller_observed")},
                {"authority", Value("not_granted_by_discovery")},
                {"qualification", Value("incomplete")},
                {"qualification_scope", Value("registered_target_observation")},
                {"support", Value("unsupported")},
                {"recovery_ceiling", Value("candidate_source_free_restart")},
                {"power_loss_qualified", Value(false)},
                {"revalidation_required_before_effects", Value(true)},
                {"execution_lease_held", Value(false)},
                {"service_state", Value(static_cast<std::uint64_t>(status.dwCurrentState))},
                {"effects", Value(Value::Array{})},
                {"platform", Value(Value::Object{
                    {"os_family", Value("Windows NT")}, {"native_arch", Value("x64")},
                    {"process_arch", Value("x64")}, {"windows_build", Value(windows_build)},
                    {"minimum_windows_build", Value(std::uint64_t{17763})}})},
                {"binding", Value(Value::Object{
                    {"service_name", Value(utf8(name))},
                    {"service_sid", binding.at("service_sid")},
                    {"caller_sid", Value(utf8(caller))},
                    {"binary_sha256", binding.at("binary_sha256")},
                    {"registration_sha256", Value(usk::json::sha256_canonical(binding))},
                    {"target_sha256", Value(usk::json::sha256_canonical(target))},
                    {"boundary_sha256", Value(boundary_digest)},
                    {"volume_guid_root", Value(utf8(args[4]))}})}}));
        }
        control = std::make_unique<ServiceControlGuard>(name);
        const auto locked_configuration = query_configuration(service->get());
        require_profile(locked_configuration);
        if (locked_configuration.binary_path != before.binary_path)
            throw std::runtime_error("publisher registration changed before controller lock");
        SERVICE_STATUS_PROCESS status{};
        DWORD needed = 0;
        if (!QueryServiceStatusEx(service->get(), SC_STATUS_PROCESS_INFO,
            reinterpret_cast<BYTE*>(&status), sizeof(status), &needed))
            throw std::runtime_error("publisher process status is unavailable");
        if (status.dwCurrentState == SERVICE_STOPPED) {
            if (schema != "usk.publisher_installed_verify_request.v1") {
                start_observation = observe_registered_target_for_start(name, before.binary_path, args[4]);
                if (!start_observation) require_exclusive_volume_admission(name, args[4]);
            }
            const auto after_admission = query_configuration(service->get());
            require_profile(after_admission);
            if (after_admission.binary_path != before.binary_path)
                throw std::runtime_error("publisher registration changed during admission");
            if (!StartServiceW(service->get(), 0, nullptr))
                throw std::runtime_error("publisher could not be started");
            if (start_observation) {
                const auto after_start = query_configuration(service->get());
                require_profile(after_start);
                if (after_start.binary_path != before.binary_path)
                    throw std::runtime_error("publisher registration changed across start");
                start_observation->verify(name, after_start.binary_path);
            }
        } else if (status.dwCurrentState != SERVICE_RUNNING &&
                   status.dwCurrentState != SERVICE_START_PENDING) {
            throw std::runtime_error("publisher is unavailable while stopping");
        }
        }
    } catch (const std::exception&) {
        // The authenticated service does not execute until it receives a
        // request. SCM startup by itself cannot authorize a publication.
        throw usk::base::EffectRequestNotDispatched();
    }
    // The concrete transport owns the exact first-write boundary. Its typed
    // non-dispatch result cannot turn a lost post-write reply into a refusal.
    try {
        return submit_publisher_request(name, request, 120000, admitted_image, options);
    } catch (const usk::base::EffectRequestNotDispatched&) {
        throw;
    } catch (const PublisherRequestOutcomeUnknown&) {
        throw;
    } catch (const std::exception&) {
        // The concrete transport wraps every exception after an attempted
        // write as outcome-unknown. Only its remaining pre-write exceptions
        // reach this admission refusal; raw candidate behavior is unchanged.
        throw usk::base::EffectRequestNotDispatched();
    }
}

int publisher_service_control_main(int argc, wchar_t** argv) {
    if (argc >= 2 && std::wstring(argv[1]) == L"--enroll-reviewed-operation") {
        if (argc != 6 || !generated_name(argv[2])) return 2;
        try {
            const auto approval = enroll_reviewed_operation(argv[2], argv[3], argv[4], argv[5]);
            using usk::json::Value;
            std::cout << usk::json::canonical(Value(Value::Object{
                {"schema", Value("usk.publisher_service_control.v1")},
                {"status", Value("reviewed_operation_enrolled")},
                {"service", Value(utf8(argv[2]))}, {"approval", approval}})) << '\n';
            std::cout.flush();
            if (!std::cout) throw PublisherRequestOutcomeUnknown("reviewed operation approval output unavailable");
            return 0;
        } catch (const PublisherRequestOutcomeUnknown& error) {
            std::cerr << "usk_publisher_service_control: " << error.what() << '\n';
            return 5;
        } catch (const std::exception& error) {
            std::cerr << "usk_publisher_service_control: " << error.what() << '\n';
            return 3;
        }
    }
    if (argc >= 2 && std::wstring(argv[1]) == L"--provision-target") {
        if (argc != 4 || !generated_name(argv[2]) ||
            std::wstring(argv[3]) != L"--confirm-empty-volume") return 2;
        try {
            provision_registered_target(argv[2]);
            std::wcout << L"{\"schema\":\"usk.publisher_service_control.v1\","
                L"\"status\":\"target_admitted\",\"service\":\"" << argv[2] << L"\"}\n";
            return 0;
        } catch (const PublisherRequestOutcomeUnknown& error) {
            std::cerr << "usk_publisher_service_control: " << error.what() << '\n';
            return 5;
        } catch (const std::exception& error) {
            std::cerr << "usk_publisher_service_control: " << error.what() << '\n';
            return 3;
        }
    }
    const bool registration = argc >= 2 && std::wstring(argv[1]) == L"--register";
    const bool apply = argc >= 2 && std::wstring(argv[1]) == L"--apply-registered";
    const bool run_recovery = argc >= 2 && std::wstring(argv[1]) == L"--recover-registered";
    const bool run_verify = argc >= 2 && std::wstring(argv[1]) == L"--verify-registered";
    const bool recovery = argc >= 2 && std::wstring(argv[1]) == L"--recover";
    const bool verify = argc >= 2 && std::wstring(argv[1]) == L"--verify";
    const bool start = argc >= 2 && std::wstring(argv[1]) == L"--start";
    const bool unregister = argc >= 2 && std::wstring(argv[1]) == L"--unregister";
    const bool retire = argc >= 2 && std::wstring(argv[1]) == L"--retire-binary";
    if ((!registration || (argc != 9 && argc != 10)) &&
        (!apply || (argc != 10 && argc != 11)) &&
        (!run_recovery || (argc != 8 && argc != 9)) &&
        (!run_verify || (argc != 8 && argc != 9)) &&
        (!recovery || (argc != 6 && argc != 7)) &&
        (!verify || (argc != 6 && argc != 7)) &&
        (!start || (argc != 6 && argc != 7)) &&
        (!unregister || (argc != 6 && argc != 7)) &&
        (!retire || argc != 6)) {
        std::wcerr << L"usage: usk_publisher_service_control (--register NAME SOURCE_BINARY VOLUME ENVELOPE SHA256 CALLER_SID BINARY_SHA256 | --apply-registered NAME INSTALLED_BINARY VOLUME ENVELOPE SHA256 CALLER_SID BINARY_SHA256 APPLY_FILE | --recover-registered NAME INSTALLED_BINARY VOLUME CALLER_SID BINARY_SHA256 REQUEST_FILE | --verify-registered NAME INSTALLED_BINARY VOLUME CALLER_SID BINARY_SHA256 REQUEST_FILE | --recover NAME INSTALLED_BINARY VOLUME CALLER_SID | --verify NAME INSTALLED_BINARY VOLUME CALLER_SID | --start NAME INSTALLED_BINARY VOLUME CALLER_SID | --unregister NAME INSTALLED_BINARY VOLUME CALLER_SID) [--admit-client-observer|--grant-client-read] | --retire-binary NAME INSTALLED_BINARY BINARY_SHA256 SERVICE_SID | --enroll-reviewed-operation NAME ENVELOPE SHA256 APPLY_FILE\n";
        return 2;
    }
    try {
        const std::wstring name(argv[2]);
        const std::wstring binary(argv[3]);
        const std::wstring volume(retire ? L"" : argv[4]);
        const std::wstring caller(retire ? L"" : argv[(registration || apply) ? 7 : 5]);
        const bool has_mode = !retire && argc ==
            (apply ? 11 : registration ? 10 : (run_recovery || run_verify) ? 9 : 7);
        const std::wstring mode = has_mode ? argv[argc - 1] : L"";
        if (!generated_name(name) ||
            (has_mode && mode != L"--admit-client-observer" &&
                mode != L"--grant-client-read" && mode != L"--service-admitted-client") ||
            (mode == L"--service-admitted-client" && !registration && !unregister)) {
            throw std::runtime_error("service name or caller access mode is invalid");
        }
        if (!retire) {
            require_volume(volume);
            require_canonical_sid(caller);
        }
        if (retire) {
            retire_protected_binary(name, binary, argv[4], argv[5]);
        } else if (apply) {
            return apply_registered(name, binary, volume, argv[5], argv[6],
                caller, argv[8], argv[9], mode);
        } else if (run_recovery || run_verify) {
            return run_registered_operation(name, binary, volume, caller,
                argv[6], argv[7], mode, run_recovery);
        } else if (registration) {
            register_service(name, binary, volume, argv[5], argv[6], caller,
                argv[8], mode);
        } else if (recovery) {
            configure_recovery(name, binary, volume, caller, mode);
        } else if (verify) {
            configure_verify(name, binary, volume, caller, mode);
        } else if (start) {
            request_start(name, binary, volume, caller, mode, nullptr);
        } else {
            request_unregister(name, binary, volume, caller, mode);
        }
        std::wcout << L"{\"schema\":\"usk.publisher_service_control.v1\",\"status\":\""
            << (retire ? L"binary_retired" : registration ? L"registered" : recovery ? L"recovery_configured" : verify ? L"verify_configured" : start ? L"start_requested" : L"removal_requested")
            << L"\",\"service\":\"" << name << L"\"}\n";
        return 0;
    } catch (const usk::platform::windows::PublisherRequestOutcomeUnknown& error) {
        std::cerr << "usk_publisher_service_control: outcome unknown; " << error.what() << '\n';
        return 5;
    } catch (const std::exception& error) {
        std::cerr << "usk_publisher_service_control: " << error.what() << '\n';
        return 3;
    }
}
} // namespace usk::platform::windows
#endif
