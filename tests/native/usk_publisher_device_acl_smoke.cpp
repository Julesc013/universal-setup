// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_device_acl.h"

#if defined(_WIN32)
#include <sddl.h>
#include <cstring>
#include <stdexcept>
#include <string>

namespace {

constexpr wchar_t service_sid[] = L"S-1-5-80-100-200-300-400-500";

bool inspect(const std::wstring& sddl, bool restrict_default = false) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PSID service = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),
            SDDL_REVISION_1, &descriptor, nullptr) ||
        !ConvertStringSidToSidW(service_sid, &service)) {
        if (descriptor) LocalFree(descriptor);
        throw std::runtime_error("device ACL test fixture cannot be parsed");
    }
    PSID owner = nullptr;
    BOOL owner_defaulted = FALSE;
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &owner_defaulted)) {
        LocalFree(service);
        LocalFree(descriptor);
        throw std::runtime_error("device ACL test fixture has no owner");
    }
    PACL dacl = nullptr;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) ||
        !present) {
        LocalFree(service);
        LocalFree(descriptor);
        throw std::runtime_error("device ACL test fixture has no DACL");
    }
    try {
        std::vector<BYTE> restricted;
        if (restrict_default) {
            const auto* first = reinterpret_cast<const BYTE*>(dacl);
            const std::vector<BYTE> original(first, first + dacl->AclSize);
            restricted = usk::platform::windows::restrict_publisher_default_device_acl(owner, dacl, service);
            if (std::memcmp(original.data(), dacl, original.size()) != 0)
                throw std::runtime_error("device ACL transformation changed original bytes");
            dacl = reinterpret_cast<PACL>(restricted.data());
        }
        const bool result = usk::platform::windows::require_publisher_device_acl_shape(
            owner, dacl, service);
        LocalFree(service);
        LocalFree(descriptor);
        return result;
    } catch (...) {
        LocalFree(service);
        LocalFree(descriptor);
        throw;
    }
}

bool refuses(const std::wstring& sddl, bool restrict_default = false) {
    try { (void)inspect(sddl, restrict_default); }
    catch (const std::runtime_error&) { return true; }
    return false;
}

} // namespace

int main() {
    const std::wstring baseline =
        L"O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)";
    const std::wstring service = L"(A;;FA;;;" + std::wstring(service_sid) + L")";
    if (inspect(baseline) || !inspect(baseline + service)) return 1;
    const std::wstring default_modify = L"(A;;0x1301bf;;;AU)";
    if (!refuses(baseline + default_modify + service) ||
        !inspect(baseline + default_modify + service, true) ||
        !inspect(baseline + L"(A;OICI;0x1301bf;;;AU)" + service, true) ||
        inspect(baseline + default_modify, true) ||
        !refuses(baseline + default_modify + default_modify + service, true) ||
        !refuses(baseline + L"(A;ID;0x1301bf;;;AU)" + service, true) ||
        !refuses(baseline + L"(A;;FA;;;AU)" + service, true) ||
        !refuses(baseline + default_modify + L"(A;;0x2;;;BU)" + service, true) ||
        !refuses(L"O:BUD:(A;;FA;;;SY)(A;;FA;;;BA)" + default_modify + service, true)) return 3;
    if (!refuses(baseline + L"(A;;0x2;;;BU)" + service) ||
        !refuses(baseline + L"(A;;FA;;;WD)" + service) ||
        !refuses(baseline + L"(D;;0x2;;;BU)" + service) ||
        !refuses(baseline + service + service) ||
        !refuses(baseline + L"(A;;FR;;;" + std::wstring(service_sid) + L")") ||
        !refuses(L"O:BUD:(A;;FA;;;SY)(A;;FA;;;BA)" + service)) {
        return 2;
    }
    return 0;
}
#endif
