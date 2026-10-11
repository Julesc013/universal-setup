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

struct OwnedBoundaryFixture {
    std::filesystem::path root, metadata_path, marker_path, metadata_child_path;
    HANDLE child = INVALID_HANDLE_VALUE, metadata = INVALID_HANDLE_VALUE;
    HANDLE metadata_child = INVALID_HANDLE_VALUE, boundary = INVALID_HANDLE_VALUE;
    std::vector<unsigned char> cleanup_descriptor;
    bool complete = false;
    bool cleanup() noexcept {
        bool ok = true;
        PACL acl = nullptr; BOOL present = FALSE, defaulted = FALSE;
        if (!cleanup_descriptor.empty() && GetSecurityDescriptorDacl(cleanup_descriptor.data(),
            &present, &acl, &defaulted) && present) {
            for (auto handle : {metadata, boundary}) {
                if (handle != INVALID_HANDLE_VALUE && SetSecurityInfo(handle, SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, acl, nullptr) != ERROR_SUCCESS) ok = false;
            }
        }
        for (auto* handle : {&metadata_child, &metadata, &boundary, &child}) {
            if (*handle != INVALID_HANDLE_VALUE) { CloseHandle(*handle); *handle = INVALID_HANDLE_VALUE; }
        }
        for (const auto& file : {metadata_child_path, marker_path}) {
            if (!file.empty() && !DeleteFileW(file.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) ok = false;
        }
        for (const auto& directory : {metadata_path, root}) {
            if (!directory.empty() && !RemoveDirectoryW(directory.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) ok = false;
        }
        complete = true;
        return ok;
    }
    ~OwnedBoundaryFixture() {
        if (!complete && !cleanup()) std::cerr << "owned native fixture cleanup incomplete\n";
    }
};

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
    OwnedBoundaryFixture fixture;
    const auto cleanup_text = L"D:P(A;;FA;;;" + caller + L")(A;;FA;;;SY)";
    PSECURITY_DESCRIPTOR cleanup = nullptr;
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(cleanup_text.c_str(), SDDL_REVISION_1,
        &cleanup, nullptr) != FALSE, "test cleanup descriptor unavailable");
    const auto* cleanup_first = static_cast<unsigned char*>(cleanup);
    fixture.cleanup_descriptor.assign(cleanup_first, cleanup_first + GetSecurityDescriptorLength(cleanup));
    LocalFree(cleanup);
    const auto initial = L"O:" + caller + L"D:PAI(A;OICI;FA;;;" + caller + L")(A;OICI;FA;;;SY)(A;OICI;FR;;;BU)";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(initial.c_str(), SDDL_REVISION_1,
        &descriptor, nullptr) != FALSE, "test initial descriptor unavailable");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    check(CreateDirectoryW(root.c_str(), &attributes) != FALSE, "test boundary directory creation failed");
    fixture.root = root;
    LocalFree(descriptor);
    HANDLE child = CreateFileW(child_path.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    check(child != INVALID_HANDLE_VALUE, "test unexpected child creation failed");
    fixture.child = child; fixture.marker_path = child_path;
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
    fixture.metadata_path = metadata_path;
    const auto metadata_child_path = metadata_path / L"IndexerVolumeGuid";
    const auto metadata_child_security = L"O:" + caller + L"D:P(A;;FA;;;" + caller + L")(A;;FR;;;SY)";
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(metadata_child_security.c_str(), SDDL_REVISION_1,
        &descriptor, nullptr) != FALSE, "test metadata child descriptor unavailable");
    SECURITY_ATTRIBUTES metadata_child_attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    HANDLE metadata_child = CreateFileW(metadata_child_path.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &metadata_child_attributes, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    LocalFree(descriptor);
    check(metadata_child != INVALID_HANDLE_VALUE, "test metadata child creation failed");
    fixture.metadata_child = metadata_child; fixture.metadata_child_path = metadata_child_path;
    const std::string metadata_marker = "OSM";
    check(WriteFile(metadata_child, metadata_marker.data(), static_cast<DWORD>(metadata_marker.size()),
        &written, nullptr) != FALSE && written == metadata_marker.size(), "test metadata marker write failed");
    FILE_ID_INFO metadata_child_id{};
    check(GetFileInformationByHandleEx(metadata_child, FileIdInfo, &metadata_child_id, sizeof(metadata_child_id)) != FALSE,
        "test metadata child identity unavailable");
    HANDLE metadata = CreateFileW(metadata_path.c_str(), READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    check(metadata != INVALID_HANDLE_VALUE, "test metadata handle unavailable");
    fixture.metadata = metadata;
    check(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)", SDDL_REVISION_1,
        &descriptor, nullptr) != FALSE, "test metadata descriptor unavailable");
    PACL metadata_dacl = nullptr; BOOL metadata_present = FALSE, metadata_defaulted = FALSE;
    check(GetSecurityDescriptorDacl(descriptor, &metadata_present, &metadata_dacl, &metadata_defaulted) != FALSE &&
        metadata_present && SetSecurityInfo(metadata, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, metadata_dacl, nullptr) == ERROR_SUCCESS,
        "test protected metadata DACL setup failed");
    LocalFree(descriptor);
    // Model an actual unprotected stored descriptor through the low-level
    // primitive, without Win32 inheritance propagation into this owned child.
    auto unprotected_metadata = security_bytes(metadata);
    check(SetSecurityDescriptorControl(unprotected_metadata.data(), SE_DACL_PROTECTED, 0) != FALSE,
        "test metadata unprotected descriptor unavailable");
    using NtSetSecurityObjectFn = LONG (NTAPI *)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
    const auto native_set = reinterpret_cast<NtSetSecurityObjectFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetSecurityObject"));
    const auto setup_status = native_set ? native_set(metadata,
        DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, unprotected_metadata.data()) : -1;
    std::cout << "metadata_unprotected_setup_status=" << setup_status
        << "; stored=" << security_text(metadata) << '\n';
    unprotected_metadata = security_bytes(metadata);
    SECURITY_DESCRIPTOR_CONTROL unprotected_control{}; DWORD unprotected_revision = 0;
    check(setup_status == 0 && GetSecurityDescriptorControl(unprotected_metadata.data(),
        &unprotected_control, &unprotected_revision) && (unprotected_control & SE_DACL_PROTECTED) == 0,
        "test actual metadata unprotected prestate differs");
    // An unprotected descendant is essential: a propagation-capable parent
    // setter would skip a protected child and hide the regression.
    auto metadata_child_unprotected = security_bytes(metadata_child);
    check(SetSecurityDescriptorControl(metadata_child_unprotected.data(), SE_DACL_PROTECTED, 0) != FALSE &&
        native_set(metadata_child, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            metadata_child_unprotected.data()) == 0, "test unprotected metadata child setup failed");
    const auto metadata_child_before = security_bytes(metadata_child);
    check(GetSecurityDescriptorControl(const_cast<unsigned char*>(metadata_child_before.data()),
        &unprotected_control, &unprotected_revision) && (unprotected_control & SE_DACL_PROTECTED) == 0,
        "test metadata child is still protected");
    auto expected_metadata = unprotected_metadata;
    check(SetSecurityDescriptorControl(expected_metadata.data(), SE_DACL_PROTECTED, SE_DACL_PROTECTED) != FALSE,
        "test metadata expected protected descriptor unavailable");
    usk::platform::windows::protect_publisher_metadata_dacl_from_handle(metadata, unprotected_metadata);
    check(security_bytes(metadata) == expected_metadata && security_bytes(metadata_child) == metadata_child_before,
        "metadata protection changed owner, ACEs or a descendant descriptor");
    FILE_ID_INFO metadata_child_after{};
    check(GetFileInformationByHandleEx(metadata_child, FileIdInfo, &metadata_child_after, sizeof(metadata_child_after)) != FALSE &&
        std::memcmp(&metadata_child_id, &metadata_child_after, sizeof(metadata_child_id)) == 0,
        "metadata protection changed descendant identity");
    check(SetFilePointer(metadata_child, 0, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER,
        "test metadata marker rewind failed");
    char metadata_read[3]{}; DWORD metadata_read_size = 0;
    check(ReadFile(metadata_child, metadata_read, sizeof(metadata_read), &metadata_read_size, nullptr) != FALSE &&
        metadata_read_size == metadata_marker.size() && std::string(metadata_read, metadata_read_size) == metadata_marker,
        "metadata protection changed descendant bytes");
    bool stale_refused = false;
    try { usk::platform::windows::protect_publisher_metadata_dacl_from_handle(metadata, unprotected_metadata); }
    catch (const std::exception&) { stale_refused = true; }
    check(stale_refused && security_bytes(metadata) == expected_metadata,
        "metadata protection adopted an altered retry prestate");
    usk::platform::windows::protect_publisher_metadata_dacl_from_handle(metadata, expected_metadata);
    check(security_bytes(metadata) == expected_metadata && security_bytes(metadata_child) == metadata_child_before,
        "metadata protected poststate reentry changed stored security");
    const auto metadata_before = security_bytes(metadata);
    const auto metadata_reported_before = reported_security_text(metadata);
    FILE_ID_INFO before_id{};
    check(GetFileInformationByHandleEx(child, FileIdInfo, &before_id, sizeof(before_id)) != FALSE,
        "test child identity unavailable");
    HANDLE held = CreateFileW(root.c_str(), READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    check(held != INVALID_HANDLE_VALUE, "test boundary handle unavailable");
    fixture.boundary = held;
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
    check(fixture.cleanup(), "test boundary cleanup failed");
}
} // namespace

int main() {
    try {
        using usk::platform::windows::require_publisher_registered_account_sid;
        using usk::platform::windows::require_publisher_consumer_sid;
        for (const auto& account : {"S-1-5-21-1-2-3-500", "S-1-5-21-1-2-3-1001"})
            require_publisher_registered_account_sid(account);
        for (const auto& invalid : {"S-1-5-18", "S-1-5-32-544", "S-1-5-80-1-2-3-4-5",
                "S-1-5-21-1-2-3", "S-1-5-21-1-2-3-4294967296", "S-1-5-21-01-2-3-500"}) {
            bool denied = false;
            try { require_publisher_registered_account_sid(invalid); }
            catch (const std::exception&) { denied = true; }
            check(denied, "non-account or noncanonical discovery SID was accepted");
        }
        bool built_in_consumer_denied = false;
        try { require_publisher_consumer_sid("S-1-5-21-1-2-3-500"); }
        catch (const std::exception&) { built_in_consumer_denied = true; }
        check(built_in_consumer_denied, "discovery validation broadened consumer-read admission");
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
