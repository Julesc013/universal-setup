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

#include "usk_publisher_handle_observation.h"
#include "usk_publisher_tree_observation.h"
#include "usk_publisher_volume_stream_observation.h"
#include "usk_publisher_volume_operation_guard.h"
#include "usk_publisher_device_acl.h"
#include "usk_publisher_request_channel.h"
#include "usk_stable_file.h"
#include "usk_json.h"
#include "usk_sha256.h"

#include <array>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <fcntl.h>
#include <io.h>

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
    ~FileHandle() { if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
    HANDLE get() const noexcept { return value_; }
    HANDLE release() noexcept { const HANDLE value = value_; value_ = INVALID_HANDLE_VALUE; return value; }
    void close() noexcept { if (value_ != INVALID_HANDLE_VALUE) CloseHandle(release()); }
private:
    HANDLE value_;
};

class ScopedBackupPrivilege {
public:
    ScopedBackupPrivilege() {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &token_)) {
            throw std::runtime_error("publisher controller cannot inspect its process token");
        }
        LUID backup{};
        if (!LookupPrivilegeValueW(nullptr, L"SeBackupPrivilege", &backup)) {
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
    ~ScopedBackupPrivilege() {
        if (token_) {
            AdjustTokenPrivileges(token_, FALSE, &previous_, 0, nullptr, nullptr);
            CloseHandle(token_);
        }
    }
    ScopedBackupPrivilege(const ScopedBackupPrivilege&) = delete;
    ScopedBackupPrivilege& operator=(const ScopedBackupPrivilege&) = delete;
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
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD result = GetSecurityInfo(handle, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &descriptor);
    if (result != ERROR_SUCCESS) {
        throw std::runtime_error("service control lock security observation failed");
    }
    const auto free_descriptor = [&] { LocalFree(descriptor); };
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
    free_descriptor();
    if (!exact_aces || !saw_system || !saw_administrators) {
        throw std::runtime_error("service control lock owner or protected ACL differs");
    }
}

void create_protected_directory(const std::wstring& path, SECURITY_ATTRIBUTES& attributes) {
    if (!CreateDirectoryW(path.c_str(), &attributes) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        throw std::runtime_error("service control lock directory creation failed");
    }
    FileHandle directory(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (directory.get() == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("service control lock directory cannot be opened");
    }
    require_control_lock_shape(directory.get(), true);
}

class ServiceControlGuard {
public:
    explicit ServiceControlGuard(const std::wstring& service) {
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
        create_protected_directory(root.wstring(), directory_attributes);
        create_protected_directory(locks.wstring(), directory_attributes);

        LocalDescriptor file_descriptor(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)");
        SECURITY_ATTRIBUTES file_attributes{sizeof(SECURITY_ATTRIBUTES),
            file_descriptor.get(), FALSE};
        // The generated SCM name is the global identity; a volume-specific
        // lock would allow two registrations to race over one executable.
        const auto path = locks / (service + L".lock");
        FileHandle file(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            0, &file_attributes, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL |
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

std::vector<BYTE> publisher_service_sid(const std::wstring& name) {
    const std::wstring account = L"NT SERVICE\\" + name;
    std::vector<BYTE> sid(SECURITY_MAX_SID_SIZE);
    std::array<wchar_t, 256> domain{};
    DWORD sid_size = static_cast<DWORD>(sid.size());
    DWORD domain_size = static_cast<DWORD>(domain.size());
    SID_NAME_USE use{};
    if (!LookupAccountNameW(nullptr, account.c_str(), sid.data(), &sid_size,
            domain.data(), &domain_size, &use) || !IsValidSid(sid.data()) ||
        *GetSidSubAuthorityCount(sid.data()) != 6 ||
        *GetSidSubAuthority(sid.data(), 0) != SECURITY_SERVICE_ID_BASE_RID) {
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
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD error = GetSecurityInfo(file, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &descriptor);
    if (error != ERROR_SUCCESS || !descriptor || !dacl) {
        if (descriptor) LocalFree(descriptor);
        throw std::runtime_error("protected publisher executable security is unavailable");
    }
    const auto release = [&] { LocalFree(descriptor); };
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
    release();
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
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD observed = GetSecurityInfo(handle.get(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, &previous, nullptr,
        &descriptor);
    if (observed != ERROR_SUCCESS || !descriptor || !previous) {
        if (descriptor) LocalFree(descriptor);
        throw std::runtime_error("protected publisher executable DACL is unavailable");
    }
    EXPLICIT_ACCESS_W entry{};
    entry.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    entry.grfAccessMode = GRANT_ACCESS;
    entry.grfInheritance = NO_INHERITANCE;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
    entry.Trustee.ptstrName = reinterpret_cast<LPWSTR>(const_cast<BYTE*>(sid.data()));
    PACL updated = nullptr;
    const DWORD composed = SetEntriesInAclW(1, &entry, previous, &updated);
    LocalFree(descriptor);
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
    const std::wstring& source, const std::wstring& expected_sha256) {
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
        require_protected_binary(name, target.wstring(), false);
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

// Locking NTFS dismounts it. The remounted volume device can lose the
// per-service ACE installed by the dedicated-volume provisioner. Reinstate
// only that exact service SID after the lock and before starting SCM.
void require_volume_device_service_access(HANDLE volume,
    const std::vector<BYTE>& service_sid) {
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
    try { already_granted = inspect(before_owner, before); }
    catch (...) { LocalFree(before_descriptor); throw; }
    if (!already_granted) {
        EXPLICIT_ACCESS_W grant{};
        grant.grfAccessPermissions = FILE_ALL_ACCESS;
        grant.grfAccessMode = GRANT_ACCESS;
        grant.grfInheritance = NO_INHERITANCE;
        grant.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        grant.Trustee.TrusteeType = TRUSTEE_IS_USER;
        grant.Trustee.ptstrName = reinterpret_cast<LPWSTR>(
            const_cast<BYTE*>(service_sid.data()));
        PACL updated = nullptr;
        const DWORD compose_error = SetEntriesInAclW(1, &grant, before, &updated);
        if (compose_error != ERROR_SUCCESS || !updated) {
            LocalFree(before_descriptor);
            throw std::runtime_error("publisher volume device service ACE cannot be composed");
        }
        const DWORD set_error = SetSecurityInfo(volume, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, updated, nullptr);
        LocalFree(updated);
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
    const std::wstring& root) {
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
        ScopedBackupPrivilege backup_observation;
        FileHandle held_root(CreateFileW(root.c_str(),
            FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr));
        if (held_root.get() == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("cannot open protected volume root for admission; Win32 " +
                std::to_string(GetLastError()));
        }
        const auto volume_facts =
            usk::platform::windows::observe_local_ntfs_volume_handle(held_root.get());
        const auto root_facts =
            usk::platform::windows::observe_publisher_directory_handle(held_root.get());
        usk::platform::windows::require_publisher_object_security_shape(
            root_facts, service_sid_ascii);
        if (root_file_id.empty()) {
            root_file_id = root_facts.file_id;
            root_volume_serial = volume_facts.file_id_volume_serial;
        } else if (root_facts.file_id != root_file_id ||
            volume_facts.file_id_volume_serial != root_volume_serial) {
            throw std::runtime_error("publisher volume root changed across exclusive admission");
        }
    };
    observe_root();
    const std::wstring device = root.substr(0, root.size() - 1);
    FileHandle volume(CreateFileW(device.c_str(),
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
    if (volume.get() == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("cannot open dedicated publisher volume for exclusive admission; Win32 " +
            std::to_string(GetLastError()));
    }
    DWORD returned = 0;
    if (!DeviceIoControl(volume.get(), FSCTL_LOCK_VOLUME, nullptr, 0,
            nullptr, 0, &returned, nullptr)) {
        throw std::runtime_error("publisher volume has a pre-opened file or cannot be locked; Win32 " +
            std::to_string(GetLastError()));
    }
    // The locked volume is accessible only through this locking file object.
    // Inspect and repair its device ACL before any other process can acquire a
    // newly granted raw-volume handle after unlock.
    require_volume_device_service_access(volume.get(), sid);
    if (!DeviceIoControl(volume.get(), FSCTL_UNLOCK_VOLUME, nullptr, 0,
            nullptr, 0, &returned, nullptr)) {
        throw std::runtime_error("publisher volume could not be unlocked after exclusive admission; Win32 " +
            std::to_string(GetLastError()));
    }
    volume.close();
    observe_root(); // Remount through the same GUID and recheck the exact root.
    FileHandle remounted(CreateFileW(device.c_str(), READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, 0, nullptr));
    if (remounted.get() == INVALID_HANDLE_VALUE)
        throw std::runtime_error("remounted publisher device cannot be secured; Win32 " +
            std::to_string(GetLastError()));
    require_volume_device_service_access(remounted.get(), sid);
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
    DWORD type = 0;
    DWORD start = 0;
    DWORD sid_type = 0;
};

ServiceConfiguration query_configuration(SC_HANDLE service) {
    DWORD needed = 0;
    (void)QueryServiceConfigW(service, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > 16384)
        throw std::runtime_error("service configuration size is unavailable");
    std::vector<BYTE> bytes(needed);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(bytes.data());
    if (!QueryServiceConfigW(service, config, needed, &needed) ||
        !config->lpBinaryPathName || !config->lpServiceStartName)
        throw std::runtime_error("service configuration is unavailable");
    SERVICE_SID_INFO sid{};
    if (!QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO,
            reinterpret_cast<BYTE*>(&sid), sizeof(sid), &needed))
        throw std::runtime_error("service SID configuration is unavailable");
    return {config->lpBinaryPathName, config->lpServiceStartName,
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
    if (mode == L"--admit-client-observer") {
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

void register_service(const std::wstring& name, const std::wstring& binary,
    const std::wstring& volume, const std::wstring& envelope,
    const std::wstring& digest, const std::wstring& caller,
    const std::wstring& binary_digest,
    const std::wstring& mode) {
    require_file(envelope);
    if (!lower_sha256(digest)) throw std::runtime_error("envelope digest is invalid");
    ServiceControlGuard control(name);
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr,
        SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT));
    if (!manager.get()) throw std::runtime_error("service manager creation access unavailable");
    ServiceHandle existing(OpenServiceW(manager.get(), name.c_str(), SERVICE_QUERY_CONFIG));
    if (existing.get() || GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST)
        throw std::runtime_error("publisher service name is already present or uncertain");
    const auto installed = install_protected_binary(name, binary, binary_digest);
    const std::wstring command = command_prefix(name, installed.path, volume) +
        L" --reviewed-plan-envelope \"" + envelope + L"\" " + digest +
        command_suffix(caller, mode);
    ServiceHandle service(CreateServiceW(manager.get(), name.c_str(), name.c_str(),
        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | DELETE,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        command.c_str(), nullptr, nullptr, nullptr, L"LocalSystem", nullptr));
    if (!service.get()) {
        ServiceHandle concurrent(OpenServiceW(manager.get(), name.c_str(),
            SERVICE_QUERY_CONFIG));
        const bool absent = !concurrent.get() &&
            GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST;
        if (absent && installed.created_here &&
            !DeleteFileW(installed.path.c_str()))
            throw std::runtime_error("service creation failed and installed executable could not be removed");
        throw std::runtime_error("new publisher service could not be created");
    }
    try {
        SERVICE_SID_INFO sid{SERVICE_SID_TYPE_RESTRICTED};
        if (!ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_SERVICE_SID_INFO, &sid))
            throw std::runtime_error("restricted service SID configuration failed");
        grant_service_binary_read(name, installed.path);
        const auto observed = query_configuration(service.get());
        require_profile(observed);
        if (observed.binary_path != command)
            throw std::runtime_error("registered service command differs from reviewed input");
    } catch (...) {
        if (!DeleteService(service.get())) {
            const DWORD deletion_error = GetLastError();
            throw std::runtime_error("registration failed and created service deletion failed (Win32 error " +
                std::to_string(deletion_error) + ")");
        }
        if (!DeleteFileW(installed.path.c_str()))
            throw std::runtime_error("registration failed and installed executable deletion failed");
        throw;
    }
}

void request_start(const std::wstring& name, const std::wstring& binary,
    const std::wstring& volume, const std::wstring& caller,
    const std::wstring& mode, const std::wstring* exact_command);

std::string read_reviewed_apply(const std::wstring& envelope_path,
    const std::wstring& envelope_sha256, const std::wstring& apply_path) {
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
    if (reviewed.at("schema").as_string() !=
            "usk.publisher.lab_reviewed_plan_envelope.v2" ||
        reviewed.at("activation").as_string() != "operator_acceptance_candidate" ||
        request.at("schema").as_string() != "usk.install_local_apply_request.v1" ||
        request.at("confirmation").as_string() != "APPLY" ||
        usk::json::canonical(reviewed.at("apply_request")) !=
            usk::json::canonical(request)) {
        throw std::runtime_error("apply request differs from reviewed envelope");
    }
    return usk::json::canonical(request);
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

void configure_recovery(const std::wstring& name, const std::wstring& binary,
    const std::wstring& volume, const std::wstring& caller,
    const std::wstring& mode) {
    require_protected_binary(name, binary);
    ServiceControlGuard control(name);
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
    if (command_arguments(config.binary_path)[5] != L"--verify-installed")
        require_exclusive_volume_admission(name, volume);
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

int wmain(int argc, wchar_t** argv) {
    const bool registration = argc >= 2 && std::wstring(argv[1]) == L"--register";
    const bool apply = argc >= 2 && std::wstring(argv[1]) == L"--apply-registered";
    const bool recovery = argc >= 2 && std::wstring(argv[1]) == L"--recover";
    const bool verify = argc >= 2 && std::wstring(argv[1]) == L"--verify";
    const bool start = argc >= 2 && std::wstring(argv[1]) == L"--start";
    const bool unregister = argc >= 2 && std::wstring(argv[1]) == L"--unregister";
    const bool retire = argc >= 2 && std::wstring(argv[1]) == L"--retire-binary";
    if ((!registration || (argc != 9 && argc != 10)) &&
        (!apply || (argc != 10 && argc != 11)) &&
        (!recovery || (argc != 6 && argc != 7)) &&
        (!verify || (argc != 6 && argc != 7)) &&
        (!start || (argc != 6 && argc != 7)) &&
        (!unregister || (argc != 6 && argc != 7)) &&
        (!retire || argc != 6)) {
        std::wcerr << L"usage: usk_publisher_service_control (--register NAME SOURCE_BINARY VOLUME ENVELOPE SHA256 CALLER_SID BINARY_SHA256 | --apply-registered NAME INSTALLED_BINARY VOLUME ENVELOPE SHA256 CALLER_SID BINARY_SHA256 APPLY_FILE | --recover NAME INSTALLED_BINARY VOLUME CALLER_SID | --verify NAME INSTALLED_BINARY VOLUME CALLER_SID | --start NAME INSTALLED_BINARY VOLUME CALLER_SID | --unregister NAME INSTALLED_BINARY VOLUME CALLER_SID) [--admit-client-observer|--grant-client-read] | --retire-binary NAME INSTALLED_BINARY BINARY_SHA256 SERVICE_SID\n";
        return 2;
    }
    try {
        const std::wstring name(argv[2]);
        const std::wstring binary(argv[3]);
        const std::wstring volume(retire ? L"" : argv[4]);
        const std::wstring caller(retire ? L"" : argv[(registration || apply) ? 7 : 5]);
        const bool has_mode = !retire && argc == (apply ? 11 : registration ? 10 : 7);
        const std::wstring mode = has_mode ? argv[argc - 1] : L"";
        if (!generated_name(name) ||
            (has_mode && mode != L"--admit-client-observer" &&
                mode != L"--grant-client-read")) {
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
    } catch (const usk::platform::windows::PublisherRequestOutcomeUnknown&) {
        std::cerr << "usk_publisher_service_control: outcome unknown; recover the registered service\n";
        return 5;
    } catch (const std::exception& error) {
        std::cerr << "usk_publisher_service_control: " << error.what() << '\n';
        return 3;
    }
}
#endif
