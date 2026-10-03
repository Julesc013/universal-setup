// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_security_descriptor.h"

#include <sddl.h>
#include <aclapi.h>
#include <windows.h>

#include <iostream>
#include <filesystem>
#include <cstring>
#include <stdexcept>
#include <string>

using usk::platform::windows::make_publisher_directory_security_descriptor;
using usk::platform::windows::publisher_directory_access_mask;

namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

bool refused(const std::wstring& sid) {
    try { (void)make_publisher_directory_security_descriptor(sid); }
    catch (const std::exception&) { return true; }
    return false;
}

std::string reported_security_text(HANDLE object) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    check(GetSecurityInfo(object, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        nullptr, nullptr, nullptr, nullptr, &descriptor) == ERROR_SUCCESS && descriptor,
        "test reported security query failed");
    LPSTR rendered = nullptr;
    check(ConvertSecurityDescriptorToStringSecurityDescriptorA(descriptor, SDDL_REVISION_1,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &rendered, nullptr) != FALSE,
        "test reported security rendering failed");
    const std::string result(rendered);
    LocalFree(rendered); LocalFree(descriptor);
    return result;
}

std::vector<unsigned char> security_bytes(HANDLE object) {
    // Query the stored kernel descriptor. GetSecurityInfo's legacy
    // INHERITED_ACE projection may depend on the current parent's ACEs.
    DWORD needed = 0;
    (void)GetKernelObjectSecurity(object, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        nullptr, 0, &needed);
    check(needed > 0 && needed <= 65536, "test stored security size unavailable");
    std::vector<unsigned char> bytes(needed);
    auto* descriptor = bytes.data();
    check(GetKernelObjectSecurity(object, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        descriptor, needed, &needed) != FALSE, "test stored security read failed");
    bytes.resize(needed);
    return bytes;
}

std::string security_text(HANDLE object) {
    const auto bytes = security_bytes(object);
    auto* descriptor = const_cast<unsigned char*>(bytes.data());
    LPSTR text = nullptr;
    check(ConvertSecurityDescriptorToStringSecurityDescriptorA(descriptor, SDDL_REVISION_1,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &text, nullptr) != FALSE,
        "test security rendering failed");
    const std::string result(text);
    LocalFree(text);
    return result;
}

void boundary_preserves_unexpected_child() {
    HANDLE token = nullptr;
    check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != FALSE, "test caller token unavailable");
    DWORD needed = 0;
    (void)GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    std::vector<unsigned char> token_bytes(needed);
    check(GetTokenInformation(token, TokenUser, token_bytes.data(), needed, &needed) != FALSE, "test caller SID unavailable");
    CloseHandle(token);
    LPWSTR sid = nullptr;
    check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(token_bytes.data())->User.Sid, &sid) != FALSE,
        "test caller SID rendering failed");
    const std::wstring caller(sid); LocalFree(sid);
    const auto root = std::filesystem::temp_directory_path() /
        (L"usk-boundary-security-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    const auto child_path = root / L"unexpected-marker.bin";
    const auto initial = L"O:" + caller + L"D:PAI(A;OICI;FA;;;" + caller + L")(A;OICI;FA;;;SY)(A;OICI;FR;;;BU)";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(initial.c_str(), SDDL_REVISION_1,
        &descriptor, nullptr) != FALSE, "test initial descriptor unavailable");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    check(CreateDirectoryW(root.c_str(), &attributes) != FALSE, "test boundary directory creation failed");
    LocalFree(descriptor);
    HANDLE child = CreateFileW(child_path.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    check(child != INVALID_HANDLE_VALUE, "test unexpected child creation failed");
    const std::string marker = "USK-PRE";
    DWORD written = 0;
    check(WriteFile(child, marker.data(), static_cast<DWORD>(marker.size()), &written, nullptr) != FALSE &&
        written == marker.size(), "test marker write failed");
    const auto before = security_bytes(child);
    // Model the OS metadata directory's protected SYSTEM-only inheritable
    // DACL. Keep the fixture caller as owner and retain the granted handle;
    // this is an owned temporary directory, not workstation OS metadata.
    const auto metadata_path = root / L"os-metadata";
    check(CreateDirectoryW(metadata_path.c_str(), nullptr) != FALSE, "test metadata directory creation failed");
    HANDLE metadata = CreateFileW(metadata_path.c_str(), READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    check(metadata != INVALID_HANDLE_VALUE, "test metadata handle unavailable");
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)", SDDL_REVISION_1,
        &descriptor, nullptr) != FALSE, "test metadata descriptor unavailable");
    PACL metadata_dacl = nullptr; BOOL metadata_present = FALSE, metadata_defaulted = FALSE;
    check(GetSecurityDescriptorDacl(descriptor, &metadata_present, &metadata_dacl, &metadata_defaulted) != FALSE &&
        metadata_present && SetSecurityInfo(metadata, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, metadata_dacl, nullptr) == ERROR_SUCCESS,
        "test protected metadata DACL setup failed");
    LocalFree(descriptor);
    const auto metadata_before = security_bytes(metadata);
    const auto metadata_reported_before = reported_security_text(metadata);
    FILE_ID_INFO before_id{};
    check(GetFileInformationByHandleEx(child, FileIdInfo, &before_id, sizeof(before_id)) != FALSE,
        "test child identity unavailable");
    HANDLE held = CreateFileW(root.c_str(), READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    check(held != INVALID_HANDLE_VALUE, "test boundary handle unavailable");
    const auto final = L"O:" + caller + L"D:P(A;;FA;;;" + caller + L")(A;;FA;;;SY)";
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(final.c_str(), SDDL_REVISION_1,
        &descriptor, nullptr) != FALSE, "test final descriptor unavailable");
    const auto length = GetSecurityDescriptorLength(descriptor);
    const auto* first = static_cast<unsigned char*>(descriptor);
    const std::vector<unsigned char> bytes(first, first + length);
    LocalFree(descriptor);
    usk::platform::windows::set_publisher_boundary_security_from_handle(held, bytes);
    check(security_bytes(child) == before, "boundary security update changed stored unexpected child descriptor");
    check(security_bytes(metadata) == metadata_before,
        "boundary update changed stored protected metadata descriptor");
    std::cout << "metadata_security_before=" << metadata_reported_before << '\n'
        << "metadata_security_after=" << reported_security_text(metadata) << '\n'
        << "metadata_stored_descriptor_unchanged=true\n";
    HANDLE reopened = CreateFileW(child_path.c_str(), GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    check(reopened != INVALID_HANDLE_VALUE, "test child reentry failed");
    FILE_ID_INFO reopened_id{};
    check(GetFileInformationByHandleEx(reopened, FileIdInfo, &reopened_id, sizeof(reopened_id)) != FALSE &&
        reopened_id.VolumeSerialNumber == before_id.VolumeSerialNumber &&
        std::memcmp(reopened_id.FileId.Identifier, before_id.FileId.Identifier, sizeof(before_id.FileId.Identifier)) == 0 &&
        security_bytes(reopened) == before, "boundary update changed persisted child identity or descriptor");
    char persisted[7]{}; DWORD persisted_read = 0;
    check(ReadFile(reopened, persisted, sizeof(persisted), &persisted_read, nullptr) != FALSE &&
        persisted_read == marker.size() && std::string(persisted, persisted_read) == marker,
        "boundary update changed independently reopened child bytes");
    CloseHandle(reopened);
    check(security_text(held).find("D:P") != std::string::npos &&
        security_text(held).find(";OICI;") == std::string::npos,
        "boundary security update did not remove inheritable parent grants");
    check(SetFilePointer(child, 0, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER, "test marker rewind failed");
    char observed[7]{}; DWORD read = 0;
    check(ReadFile(child, observed, sizeof(observed), &read, nullptr) != FALSE && read == marker.size() &&
        std::string(observed, read) == marker, "boundary security update changed unexpected child bytes");
    // Positive control: Win32 inheritance propagation on the same owned
    // fixture must be detected by the stored-descriptor comparison.
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(initial.c_str(), SDDL_REVISION_1,
        &descriptor, nullptr) != FALSE, "test control descriptor unavailable");
    PACL initial_dacl = nullptr; BOOL present = FALSE, defaulted = FALSE;
    check(GetSecurityDescriptorDacl(descriptor, &present, &initial_dacl, &defaulted) != FALSE && present,
        "test control DACL unavailable");
    check(SetSecurityInfo(held, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, initial_dacl, nullptr) == ERROR_SUCCESS, "test positive-control setup failed");
    LocalFree(descriptor);
    const auto control_before = security_bytes(child);
    PACL final_dacl = nullptr;
    check(GetSecurityDescriptorDacl(const_cast<unsigned char*>(bytes.data()), &present, &final_dacl, &defaulted) != FALSE && present,
        "test final control DACL unavailable");
    check(SetSecurityInfo(held, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, final_dacl, nullptr) == ERROR_SUCCESS && security_bytes(child) != control_before,
        "stored-descriptor harness did not detect propagating parent security change");
    // Restore access to this owned empty fixture through the retained granted
    // handle before cleanup; the SYSTEM-only DACL intentionally lacks DELETE.
    check(SetSecurityInfo(metadata, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, final_dacl, nullptr) == ERROR_SUCCESS,
        "test owned metadata cleanup ACL restoration failed");
    CloseHandle(metadata); CloseHandle(held); CloseHandle(child);
    check(DeleteFileW(child_path.c_str()) != FALSE && RemoveDirectoryW(metadata_path.c_str()) != FALSE &&
        RemoveDirectoryW(root.c_str()) != FALSE,
        "test boundary cleanup failed");
}
} // namespace

int main() {
    try {
        boundary_preserves_unexpected_child();
        const std::wstring service_sid =
            L"S-1-5-80-3180180915-1861177297-4117424284-3321057921-2519428456";
        const auto bytes = make_publisher_directory_security_descriptor(service_sid);
        auto* descriptor = const_cast<unsigned char*>(bytes.data());
        check(IsValidSecurityDescriptor(descriptor) != FALSE,
            "self-relative security descriptor is invalid");
        SECURITY_DESCRIPTOR_CONTROL control{};
        DWORD revision = 0;
        check(GetSecurityDescriptorControl(descriptor, &control, &revision) != FALSE &&
            (control & SE_DACL_PROTECTED) != 0,
            "publisher DACL is not protected");
        PSID owner = nullptr;
        BOOL owner_defaulted = FALSE;
        check(GetSecurityDescriptorOwner(descriptor, &owner, &owner_defaulted) != FALSE &&
            owner && IsWellKnownSid(owner, WinLocalSystemSid) != FALSE,
            "publisher descriptor owner is not SYSTEM");
        BOOL present = FALSE;
        BOOL dacl_defaulted = FALSE;
        PACL dacl = nullptr;
        check(GetSecurityDescriptorDacl(descriptor, &present, &dacl,
            &dacl_defaulted) != FALSE && present && dacl && dacl->AceCount == 2,
            "publisher DACL does not contain exactly two ACEs");
        PSID expected_service = nullptr;
        check(ConvertStringSidToSidW(service_sid.c_str(), &expected_service) != FALSE,
            "test service SID conversion failed");
        for (DWORD index = 0; index < 2; ++index) {
            void* raw = nullptr;
            check(GetAce(dacl, index, &raw) != FALSE && raw,
                "publisher ACE cannot be read");
            const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
            check(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
                ace->Header.AceFlags == 0 &&
                ace->Mask == publisher_directory_access_mask(),
                "publisher ACE type, flags, or rights diverge from the profile");
            PSID sid = const_cast<DWORD*>(&ace->SidStart);
            check(index == 0 ? IsWellKnownSid(sid, WinLocalSystemSid) != FALSE :
                EqualSid(sid, expected_service) != FALSE,
                "publisher DACL SID order or identity is wrong");
        }
        LocalFree(expected_service);
        using namespace usk::platform::windows;
        const std::string consumer_sid = "S-1-5-21-1-2-3-1001";
        const auto readable = make_publisher_consumer_security_descriptor(service_sid, consumer_sid);
        check(GetSecurityDescriptorDacl(const_cast<unsigned char*>(readable.data()),
            &present, &dacl, &dacl_defaulted) != FALSE && present && dacl && dacl->AceCount == 3,
            "consumer descriptor does not contain three explicit ACEs");
        void* reader_raw = nullptr;
        check(GetAce(dacl, 2, &reader_raw) != FALSE, "consumer ACE is unavailable");
        const auto* reader = static_cast<const ACCESS_ALLOWED_ACE*>(reader_raw);
        check(reader->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && reader->Header.AceFlags == 0 &&
            reader->Mask == (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) &&
            (reader->Mask & (DELETE | FILE_DELETE_CHILD | FILE_WRITE_DATA | FILE_APPEND_DATA |
                FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER)) == 0,
            "consumer ACE admits mutation or inheritance");
        for (const auto& invalid : {"S-1-5-18", "S-1-1-0", "S-1-5-32-545",
                "S-1-5-21-1-2-3-500", "S-1-5-21-1-2-3-513", "S-1-5-80-1-2-3-4-5", "invalid", ""}) {
            bool denied = false;
            try { (void)make_publisher_consumer_security_descriptor(service_sid, invalid); }
            catch (const std::exception&) { denied = true; }
            check(denied, "privileged/group/malformed consumer SID was accepted");
        }
        check(refused(L"S-1-5-21-1-2-3-1001") &&
            refused(L"S-1-5-80-1") && refused(L"invalid") && refused(L""),
            "non-service or malformed SID was accepted");
        std::cout << "Windows publisher protected descriptor construction PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
