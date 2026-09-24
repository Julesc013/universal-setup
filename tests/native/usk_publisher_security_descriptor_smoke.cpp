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
