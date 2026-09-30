// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_device_acl.h"

#if defined(_WIN32)
#include <array>
#include <cstddef>
#include <sddl.h>
#include <stdexcept>
#include <string>

namespace usk::platform::windows {

namespace {

std::array<BYTE, SECURITY_MAX_SID_SIZE> well_known_sid(WELL_KNOWN_SID_TYPE type) {
    std::array<BYTE, SECURITY_MAX_SID_SIZE> sid{};
    DWORD length = static_cast<DWORD>(sid.size());
    if (!CreateWellKnownSid(type, nullptr, sid.data(), &length) ||
        !IsValidSid(sid.data())) {
        throw std::runtime_error("publisher device trusted SID is unavailable");
    }
    return sid;
}

PSID checked_ace_sid(const ACCESS_ALLOWED_ACE* ace) {
    constexpr std::size_t offset = offsetof(ACCESS_ALLOWED_ACE, SidStart);
    if (ace->Header.AceSize < offset + 8u) {
        throw std::runtime_error("publisher device ACE SID is truncated");
    }
    auto* sid = reinterpret_cast<SID*>(const_cast<DWORD*>(&ace->SidStart));
    if (sid->Revision != SID_REVISION ||
        sid->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES ||
        offset + 8u + 4u * sid->SubAuthorityCount > ace->Header.AceSize ||
        !IsValidSid(sid)) {
        throw std::runtime_error("publisher device ACE SID is malformed");
    }
    return sid;
}

std::string diagnostic_sid(PSID sid) {
    LPSTR rendered = nullptr;
    if (!ConvertSidToStringSidA(sid, &rendered) || !rendered) {
        return "<unavailable>";
    }
    const std::string value(rendered);
    LocalFree(rendered);
    return value;
}

} // namespace

bool require_publisher_device_acl_shape(PSID owner, PACL dacl, PSID service_sid) {
    if (!owner || !IsValidSid(owner) || !dacl || !IsValidAcl(dacl) ||
        !service_sid || !IsValidSid(service_sid)) {
        throw std::runtime_error("publisher device owner, DACL or service SID is unavailable");
    }
    const auto system = well_known_sid(WinLocalSystemSid);
    const auto administrators = well_known_sid(WinBuiltinAdministratorsSid);
    if (!EqualSid(owner, const_cast<BYTE*>(system.data())) &&
        !EqualSid(owner, const_cast<BYTE*>(administrators.data()))) {
        throw std::runtime_error("publisher device owner is outside trusted principals");
    }
    constexpr ACCESS_MASK mutating = DELETE | WRITE_DAC | WRITE_OWNER |
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | GENERIC_WRITE | GENERIC_ALL;
    unsigned service_aces = 0;
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void* entry = nullptr;
        if (!GetAce(dacl, index, &entry) || !entry) {
            throw std::runtime_error("publisher device ACE is unreadable");
        }
        const auto* header = static_cast<const ACE_HEADER*>(entry);
        // Unknown allow/callback/object ACEs cannot be safely reduced to the
        // simple service/device-rights profile. Deny ACEs are also refused so
        // the service grant cannot be shadowed by an unmodelled rule.
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) {
            throw std::runtime_error("publisher device DACL has an unmodelled ACE");
        }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(entry);
        PSID sid = checked_ace_sid(ace);
        if (EqualSid(sid, service_sid)) {
            if (header->AceFlags != 0 || ace->Mask != FILE_ALL_ACCESS || ++service_aces > 1) {
                throw std::runtime_error("publisher device service ACE differs or repeats");
            }
        } else if (!EqualSid(sid, const_cast<BYTE*>(system.data())) &&
            !EqualSid(sid, const_cast<BYTE*>(administrators.data())) &&
            (ace->Mask & mutating) != 0) {
            throw std::runtime_error(
                "publisher device grants raw-volume mutation outside trusted principals: SID " +
                diagnostic_sid(sid) + ", mask " + std::to_string(ace->Mask));
        }
    }
    return service_aces == 1;
}

} // namespace usk::platform::windows
#endif
