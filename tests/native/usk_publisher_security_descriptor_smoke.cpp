// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_security_descriptor.h"

#include <sddl.h>
#include <windows.h>

#include <iostream>
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
} // namespace

int main() {
    try {
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
