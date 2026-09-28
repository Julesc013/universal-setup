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

#include "usk_publisher_volume_operation_guard.h"

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

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
private:
    HANDLE value_;
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
    ServiceControlGuard(const std::wstring& volume, const std::wstring& service) {
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
        // The volume syntax and generated service name were checked by wmain.
        const auto guid = volume.substr(std::wstring(L"\\\\?\\Volume{").size(), 36u);
        const auto path = locks / (guid + L"." + service + L".lock");
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

void require_volume(const std::wstring& value) {
    (void)usk::platform::windows::publisher_volume_operation_guard_name(value);
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
    const std::wstring& mode) {
    require_file(binary);
    require_file(envelope);
    if (!lower_sha256(digest)) throw std::runtime_error("envelope digest is invalid");
    ServiceControlGuard control(volume, name);
    const std::wstring command = command_prefix(name, binary, volume) +
        L" --reviewed-plan-envelope \"" + envelope + L"\" " + digest +
        command_suffix(caller, mode);
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
    if (!manager.get()) throw std::runtime_error("service manager creation access unavailable");
    ServiceHandle service(CreateServiceW(manager.get(), name.c_str(), name.c_str(),
        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | DELETE,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        command.c_str(), nullptr, nullptr, nullptr, L"LocalSystem", nullptr));
    if (!service.get()) throw std::runtime_error("new publisher service could not be created");
    try {
        SERVICE_SID_INFO sid{SERVICE_SID_TYPE_RESTRICTED};
        if (!ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_SERVICE_SID_INFO, &sid))
            throw std::runtime_error("restricted service SID configuration failed");
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
        throw;
    }
}

void configure_recovery(const std::wstring& name, const std::wstring& binary,
    const std::wstring& volume, const std::wstring& caller,
    const std::wstring& mode) {
    require_file(binary);
    ServiceControlGuard control(volume, name);
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
    require_file(binary);
    ServiceControlGuard control(volume, name);
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
    const std::wstring& mode) {
    require_file(binary);
    ServiceControlGuard control(volume, name);
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.get()) throw std::runtime_error("service manager connection unavailable");
    ServiceHandle service(OpenServiceW(manager.get(), name.c_str(),
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START));
    if (!service.get()) throw std::runtime_error("registered publisher service unavailable");
    require_stopped(service.get());
    const auto config = query_configuration(service.get());
    require_profile(config);
    require_existing_command(config.binary_path, name, binary, volume, caller, mode);
    if (!StartServiceW(service.get(), 0, nullptr))
        throw std::runtime_error("matching publisher service could not start");
}

void request_unregister(const std::wstring& name, const std::wstring& binary,
    const std::wstring& volume, const std::wstring& caller,
    const std::wstring& mode) {
    require_file(binary);
    ServiceControlGuard control(volume, name);
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

} // namespace

int wmain(int argc, wchar_t** argv) {
    const bool registration = argc >= 2 && std::wstring(argv[1]) == L"--register";
    const bool recovery = argc >= 2 && std::wstring(argv[1]) == L"--recover";
    const bool verify = argc >= 2 && std::wstring(argv[1]) == L"--verify";
    const bool start = argc >= 2 && std::wstring(argv[1]) == L"--start";
    const bool unregister = argc >= 2 && std::wstring(argv[1]) == L"--unregister";
    if ((!registration || (argc != 8 && argc != 9)) &&
        (!recovery || (argc != 6 && argc != 7)) &&
        (!verify || (argc != 6 && argc != 7)) &&
        (!start || (argc != 6 && argc != 7)) &&
        (!unregister || (argc != 6 && argc != 7))) {
        std::wcerr << L"usage: usk_publisher_service_control (--register NAME BINARY VOLUME ENVELOPE SHA256 CALLER_SID | --recover NAME BINARY VOLUME CALLER_SID | --verify NAME BINARY VOLUME CALLER_SID | --start NAME BINARY VOLUME CALLER_SID | --unregister NAME BINARY VOLUME CALLER_SID) [--admit-client-observer|--grant-client-read]\n";
        return 2;
    }
    try {
        const std::wstring name(argv[2]);
        const std::wstring binary(argv[3]);
        const std::wstring volume(argv[4]);
        const std::wstring caller(argv[registration ? 7 : 5]);
        const bool has_mode = argc == (registration ? 9 : 7);
        const std::wstring mode = has_mode ? argv[argc - 1] : L"";
        if (!generated_name(name) ||
            (has_mode && mode != L"--admit-client-observer" &&
                mode != L"--grant-client-read")) {
            throw std::runtime_error("service name or caller access mode is invalid");
        }
        require_volume(volume);
        require_canonical_sid(caller);
        if (registration) {
            register_service(name, binary, volume, argv[5], argv[6], caller, mode);
        } else if (recovery) {
            configure_recovery(name, binary, volume, caller, mode);
        } else if (verify) {
            configure_verify(name, binary, volume, caller, mode);
        } else if (start) {
            request_start(name, binary, volume, caller, mode);
        } else {
            request_unregister(name, binary, volume, caller, mode);
        }
        std::wcout << L"{\"schema\":\"usk.publisher_service_control.v1\",\"status\":\""
            << (registration ? L"registered" : recovery ? L"recovery_configured" : verify ? L"verify_configured" : start ? L"start_requested" : L"removal_requested")
            << L"\",\"service\":\"" << name << L"\"}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "usk_publisher_service_control: " << error.what() << '\n';
        return 3;
    }
}
#endif
