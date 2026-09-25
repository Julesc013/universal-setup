// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

// Disposable-lab provisioning only. The caller independently binds this GUID
// volume to a newly created VHD before invoking this executable.
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <initguid.h>
#include <virtdisk.h>
#include <winioctl.h>

#include <array>
#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
class Handle {
public:
    explicit Handle(HANDLE value) : value_(value) {
        if (value_ == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("volume device open failed: " +
                std::to_string(GetLastError()));
        }
    }
    ~Handle() { CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};

class LocalPointer {
public:
    explicit LocalPointer(void* value = nullptr) : value_(value) {}
    ~LocalPointer() { if (value_) LocalFree(value_); }
    LocalPointer(const LocalPointer&) = delete;
    LocalPointer& operator=(const LocalPointer&) = delete;
    void* get() const { return value_; }
    void reset(void* value) { if (value_) LocalFree(value_); value_ = value; }
private:
    void* value_;
};

std::string ascii(const wchar_t* text) {
    std::string result;
    for (; *text; ++text) {
        if (*text < 32 || *text > 126) throw std::runtime_error("non-ASCII security identity");
        result.push_back(static_cast<char>(*text));
    }
    return result;
}

bool guid_root(const std::wstring& value) {
    if (value.size() != 49 || value.compare(0, 11, L"\\\\?\\Volume{") != 0 ||
        value.substr(47) != L"}\\") return false;
    for (std::size_t index = 11; index < 47; ++index) {
        const wchar_t ch = value[index];
        if (index == 19 || index == 24 || index == 29 || index == 34) {
            if (ch != L'-') return false;
        } else if (!((ch >= L'0' && ch <= L'9') ||
                (ch >= L'a' && ch <= L'f') || (ch >= L'A' && ch <= L'F'))) {
            return false;
        }
    }
    return true;
}

bool owned_vhd_path(const std::wstring& value) {
    std::array<wchar_t, 32768> root{};
    const DWORD length = GetEnvironmentVariableW(L"RUNNER_TEMP", root.data(),
        static_cast<DWORD>(root.size()));
    if (length == 0 || length >= root.size()) return false;
    std::wstring prefix(root.data(), length);
    while (!prefix.empty() && (prefix.back() == L'\\' || prefix.back() == L'/')) {
        prefix.pop_back();
    }
    prefix += L"\\usk-wu006-";
    const std::wstring suffix = L"\\publisher.vhdx";
    if (value.size() != prefix.size() + 32 + suffix.size() ||
        value.compare(0, prefix.size(), prefix) != 0 ||
        value.compare(prefix.size() + 32, suffix.size(), suffix) != 0) return false;
    for (std::size_t index = prefix.size(); index < prefix.size() + 32; ++index) {
        const wchar_t ch = value[index];
        if (!((ch >= L'0' && ch <= L'9') ||
                (ch >= L'a' && ch <= L'f') || (ch >= L'A' && ch <= L'F'))) return false;
    }
    return true;
}

bool generated_suffix(const std::wstring& value, const std::wstring& prefix,
    const std::wstring& suffix) {
    if (value.size() != prefix.size() + 32 + suffix.size() ||
        value.compare(0, prefix.size(), prefix) != 0 ||
        value.compare(prefix.size() + 32, suffix.size(), suffix) != 0) return false;
    for (std::size_t index = prefix.size(); index < prefix.size() + 32; ++index) {
        const wchar_t ch = value[index];
        if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) {
            return false;
        }
    }
    return true;
}

bool guest_vm_guid(const std::wstring& value) {
    if (value.size() != 36) return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        const wchar_t ch = value[index];
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (ch != L'-') return false;
        } else if (!((ch >= L'0' && ch <= L'9') ||
                (ch >= L'a' && ch <= L'f') ||
                (ch >= L'A' && ch <= L'F'))) {
            return false;
        }
    }
    return true;
}

bool admitted_campaign_vm(const std::wstring& expected_id) {
    if (!guest_vm_guid(expected_id)) return false;
    std::array<wchar_t, 64> observed{};
    DWORD bytes = static_cast<DWORD>(observed.size() * sizeof(wchar_t));
    const LONG result = RegGetValueW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        L"VirtualMachineId", RRF_RT_REG_SZ, nullptr, observed.data(), &bytes);
    return result == ERROR_SUCCESS &&
        guest_vm_guid(std::wstring(observed.data())) &&
        CompareStringOrdinal(expected_id.c_str(), -1, observed.data(), -1,
            TRUE) == CSTR_EQUAL;
}

DWORD attached_vhd_disk_number(HANDLE disk) {
    std::array<wchar_t, 128> physical{};
    ULONG bytes = static_cast<ULONG>(physical.size() * sizeof(wchar_t));
    const DWORD path_error = GetVirtualDiskPhysicalPath(disk, &bytes,
        physical.data());
    if (path_error != ERROR_SUCCESS) {
        throw std::runtime_error("owned VHD physical path unavailable: " +
            std::to_string(path_error));
    }
    const std::wstring prefix = L"\\\\.\\PhysicalDrive";
    const std::wstring actual(physical.data());
    if (actual.compare(0, prefix.size(), prefix) != 0) {
        throw std::runtime_error("owned VHD physical path has unexpected shape");
    }
    const wchar_t* number = actual.c_str() + prefix.size();
    wchar_t* end = nullptr;
    const unsigned long parsed = std::wcstoul(number, &end, 10);
    if (end == number || *end != L'\0') {
        throw std::runtime_error("owned VHD physical path has no disk number");
    }
    return static_cast<DWORD>(parsed);
}

std::string dacl_sddl(HANDLE volume, PACL* dacl, LocalPointer& descriptor) {
    PSECURITY_DESCRIPTOR raw = nullptr;
    const DWORD error = GetSecurityInfo(volume, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr, &raw);
    if (error != ERROR_SUCCESS || raw == nullptr || *dacl == nullptr) {
        throw std::runtime_error("volume device DACL unavailable: " + std::to_string(error));
    }
    descriptor.reset(raw);
    LPWSTR rendered = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(raw, SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION, &rendered, nullptr)) {
        throw std::runtime_error("volume device DACL rendering failed");
    }
    LocalPointer text(rendered);
    return ascii(rendered);
}

std::string quote(const std::string& value) {
    std::string result = "\"";
    for (char ch : value) {
        if (ch == '\\' || ch == '"') result.push_back('\\');
        result.push_back(ch);
    }
    return result + '"';
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc < 2) {
            throw std::runtime_error("disposable lab admission mode is required");
        }
        const bool hosted = argc == 6 &&
            std::wstring(argv[1]) == L"--owned-vhd-volume";
        const bool campaign_vm = argc == 7 &&
            std::wstring(argv[1]) == L"--owned-vm-vhd-volume";
        if (!hosted && !campaign_vm) {
            throw std::runtime_error("expected a supported disposable-lab admission mode");
        }
        if (hosted) {
            wchar_t actions[8]{};
            wchar_t environment[32]{};
            if (GetEnvironmentVariableW(L"GITHUB_ACTIONS", actions, 8) == 0 ||
                std::wstring(actions) != L"true" ||
                GetEnvironmentVariableW(L"RUNNER_ENVIRONMENT", environment, 32) == 0 ||
                std::wstring(environment) != L"github-hosted") {
                throw std::runtime_error("device ACL provisioning requires a hosted disposable runner");
            }
        } else if (!admitted_campaign_vm(argv[6])) {
            throw std::runtime_error("current Hyper-V guest ID does not match the campaign VM");
        }
        const std::wstring root(argv[2]);
        if (!guid_root(root)) throw std::runtime_error("invalid volume GUID root");
        const std::wstring service_name(argv[3]);
        const std::wstring prefix = hosted ? L"USK_WU006_" : L"USK_VM_";
        if (!generated_suffix(service_name, prefix, L"")) {
            throw std::runtime_error("invalid campaign service name");
        }
        const std::wstring vhd(argv[5]);
        const bool owned_path = hosted ? owned_vhd_path(vhd) :
            generated_suffix(vhd, L"C:\\USK-Lab\\publisher-test-", L".vhdx");
        if (!owned_path) {
            throw std::runtime_error("backing file is outside the admitted disposable lab");
        }
        VIRTUAL_STORAGE_TYPE type{};
        type.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
        type.VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT;
        HANDLE raw_vhd = nullptr;
        const DWORD open_error = OpenVirtualDisk(&type, vhd.c_str(),
            VIRTUAL_DISK_ACCESS_GET_INFO | VIRTUAL_DISK_ACCESS_DETACH,
            OPEN_VIRTUAL_DISK_FLAG_NONE,
            nullptr, &raw_vhd);
        if (open_error != ERROR_SUCCESS || !raw_vhd ||
            raw_vhd == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("owned VHD cannot be opened: " +
                std::to_string(open_error));
        }
        Handle vhd_handle(raw_vhd);
        const DWORD vhd_disk_number = attached_vhd_disk_number(vhd_handle.get());
        const std::wstring device = root.substr(0, root.size() - 1);
        Handle volume(CreateFileW(device.c_str(), READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, 0, nullptr));
        wchar_t* disk_end = nullptr;
        const unsigned long expected_disk = std::wcstoul(argv[4], &disk_end, 10);
        if (disk_end == argv[4] || *disk_end != L'\0') {
            throw std::runtime_error("invalid owned VHD disk number");
        }
        VOLUME_DISK_EXTENTS extents{};
        DWORD returned = 0;
        if (!DeviceIoControl(volume.get(), IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                nullptr, 0, &extents, sizeof(extents), &returned, nullptr) ||
            extents.NumberOfDiskExtents != 1 ||
            extents.Extents[0].DiskNumber != expected_disk ||
            extents.Extents[0].DiskNumber != vhd_disk_number) {
            throw std::runtime_error("volume device does not resolve to the exact owned VHD disk");
        }
        PACL old_dacl = nullptr;
        LocalPointer old_descriptor;
        const std::string before = dacl_sddl(volume.get(), &old_dacl, old_descriptor);

        // The dedicated service SID is the only new principal. Keep all
        // existing volume-device ACEs and never install a null DACL.
        const std::wstring account = L"NT SERVICE\\" + service_name;
        std::array<unsigned char, SECURITY_MAX_SID_SIZE> sid_buffer{};
        std::array<wchar_t, 256> domain{};
        DWORD sid_bytes = static_cast<DWORD>(sid_buffer.size());
        DWORD domain_chars = static_cast<DWORD>(domain.size());
        SID_NAME_USE use{};
        if (!LookupAccountNameW(nullptr, account.c_str(), sid_buffer.data(),
                &sid_bytes, domain.data(), &domain_chars, &use)) {
            throw std::runtime_error("campaign service SID cannot be resolved from SCM identity");
        }
        PSID sid = sid_buffer.data();
        if (!IsValidSid(sid) || *GetSidSubAuthorityCount(sid) != 6 ||
            *GetSidSubAuthority(sid, 0) != SECURITY_SERVICE_ID_BASE_RID) {
            throw std::runtime_error("resolved identity is not a dedicated service SID");
        }
        LPWSTR sid_text = nullptr;
        if (!ConvertSidToStringSidW(sid, &sid_text)) {
            throw std::runtime_error("dedicated service SID cannot be rendered");
        }
        LocalPointer owned_sid_text(sid_text);
        EXPLICIT_ACCESS_W entry{};
        entry.grfAccessPermissions = FILE_ALL_ACCESS;
        entry.grfAccessMode = GRANT_ACCESS;
        entry.grfInheritance = NO_INHERITANCE;
        entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
        entry.Trustee.ptstrName = static_cast<LPWSTR>(sid);
        PACL updated = nullptr;
        const DWORD acl_error = SetEntriesInAclW(1, &entry, old_dacl, &updated);
        if (acl_error != ERROR_SUCCESS || updated == nullptr) {
            throw std::runtime_error("device DACL composition failed: " +
                std::to_string(acl_error));
        }
        LocalPointer owned_acl(updated);
        const DWORD set_error = SetSecurityInfo(volume.get(), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, updated, nullptr);
        if (set_error != ERROR_SUCCESS) {
            throw std::runtime_error("owned VHD device DACL update failed: " +
                std::to_string(set_error));
        }
        PACL confirmed_dacl = nullptr;
        LocalPointer confirmed_descriptor;
        const std::string after = dacl_sddl(volume.get(), &confirmed_dacl,
            confirmed_descriptor);
        if (after.find(ascii(sid_text)) == std::string::npos) {
            throw std::runtime_error("dedicated service ACE was not observed after update");
        }
        std::cout << "{\"admission\":" << quote(hosted ? "hosted_runner" : "campaign_vm") <<
            ",\"before_dacl\":" << quote(before) <<
            ",\"after_dacl\":" << quote(after) <<
            ",\"service_sid\":" << quote(ascii(sid_text)) <<
            ",\"vhd_disk_number\":" << vhd_disk_number << "}\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 2;
    }
}
