// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_device_acl.h"

#if defined(_WIN32)
#include <array>
#include <aclapi.h>
#include <cstddef>
#include <sddl.h>
#include <set>
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

std::vector<BYTE> restrict_publisher_default_device_acl(PSID owner, PACL dacl, PSID service_sid) {
    if (!dacl || !IsValidAcl(dacl) || dacl->AclSize < sizeof(ACL))
        throw std::runtime_error("publisher default device DACL is unavailable");
    const auto authenticated_users = well_known_sid(WinAuthenticatedUserSid);
    const auto* first = reinterpret_cast<const BYTE*>(dacl);
    std::vector<BYTE> bytes(first, first + dacl->AclSize);
    auto* restricted = reinterpret_cast<PACL>(bytes.data());
    unsigned defaults = 0;
    for (DWORD index = 0; index < restricted->AceCount; ++index) {
        void* entry = nullptr;
        if (!GetAce(restricted, index, &entry) || !entry)
            throw std::runtime_error("publisher default device ACE is unreadable");
        auto* header = static_cast<ACE_HEADER*>(entry);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceSize < sizeof(ACCESS_ALLOWED_ACE))
            throw std::runtime_error("publisher default device ACE is unmodelled");
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(entry);
        if (!EqualSid(checked_ace_sid(ace), const_cast<BYTE*>(authenticated_users.data()))) continue;
        constexpr ACCESS_MASK windows_modify = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
        if (ace->Mask != windows_modify ||
            (header->AceFlags != 0 && header->AceFlags != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) || ++defaults != 1)
            throw std::runtime_error("publisher default Authenticated Users grant differs or repeats");
        ace->Mask = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    }
    if (defaults != 1)
        throw std::runtime_error("publisher device lacks the known default modify grant");
    (void)require_publisher_device_acl_shape(owner, restricted, service_sid);
    return bytes;
}

std::vector<BYTE> publisher_device_admission_postimage(PSID owner, PACL dacl, PSID service_sid) {
    if (!dacl || !IsValidAcl(dacl) || dacl->AceCount > 64u || dacl->AclSize > 16384u)
        throw std::runtime_error("publisher device admission DACL is unavailable or exceeds its bound");
    std::vector<BYTE> reduced;
    bool granted = false;
    try { granted = require_publisher_device_acl_shape(owner, dacl, service_sid); }
    catch (const std::exception&) {
        reduced = restrict_publisher_default_device_acl(owner, dacl, service_sid);
        dacl = reinterpret_cast<PACL>(reduced.data());
        granted = require_publisher_device_acl_shape(owner, dacl, service_sid);
    }
    PACL composed = dacl;
    if (!granted) {
        EXPLICIT_ACCESS_W grant{};
        grant.grfAccessPermissions = FILE_ALL_ACCESS;
        grant.grfAccessMode = GRANT_ACCESS;
        grant.grfInheritance = NO_INHERITANCE;
        grant.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        grant.Trustee.TrusteeType = TRUSTEE_IS_USER;
        grant.Trustee.ptstrName = reinterpret_cast<LPWSTR>(service_sid);
        const DWORD error = SetEntriesInAclW(1, &grant, dacl, &composed);
        if (error != ERROR_SUCCESS || !composed)
            throw std::runtime_error("publisher device admission grant cannot be composed");
    }
    try {
        if (!require_publisher_device_acl_shape(owner, composed, service_sid))
            throw std::runtime_error("publisher device admission postimage lacks its exact service grant");
        SECURITY_DESCRIPTOR descriptor{};
        if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
            !SetSecurityDescriptorOwner(&descriptor, owner, FALSE) ||
            !SetSecurityDescriptorDacl(&descriptor, TRUE, composed, FALSE) ||
            !SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED))
            throw std::runtime_error("publisher device admission postimage cannot be initialized");
        DWORD needed = 0;
        MakeSelfRelativeSD(&descriptor, nullptr, &needed);
        if (needed == 0 || needed > 16384u)
            throw std::runtime_error("publisher device admission postimage exceeds its bound");
        std::vector<BYTE> result(needed);
        if (!MakeSelfRelativeSD(&descriptor, result.data(), &needed))
            throw std::runtime_error("publisher device admission postimage cannot be retained");
        if (!granted) LocalFree(composed);
        return result;
    } catch (...) {
        if (!granted) LocalFree(composed);
        throw;
    }
}

std::vector<BYTE> publisher_read_only_device_admission_postimage(PSID owner, PACL dacl, PSID service_sid) {
    // Validate the retained prestate before any default-right reduction.
    (void)require_publisher_device_acl_shape(owner, dacl, service_sid);
    return publisher_device_admission_postimage(owner, dacl, service_sid);
}

bool publisher_target_intent_has_device_transition(const json::Value& intent) {
    const auto keys = [](const json::Value& value, const std::set<std::string>& expected) {
        std::set<std::string> actual;
        for (const auto& item : value.as_object()) actual.insert(item.first);
        if (actual != expected) throw std::runtime_error("target admission intent fields are invalid");
    };
    const auto& schema = intent.at("schema").as_string();
    std::set<std::string> expected{"schema", "identity", "original_metadata", "original_owner_dacl"};
    if (schema == "usk.publisher_target_intent.v2") {
        keys(intent, expected);
        return false;
    }
    if (schema != "usk.publisher_target_intent.v3")
        throw std::runtime_error("target admission intent version is unsupported");
    expected.insert("mounted_device_transition");
    keys(intent, expected);
    const auto& transition = intent.at("mounted_device_transition");
    keys(transition, {"original_owner_dacl", "intended_policy"});
    const auto& original = transition.at("original_owner_dacl").as_string();
    if (original.empty() || original.size() > 8192u)
        throw std::runtime_error("target admission mounted prestate is unavailable or exceeds its bound");
    const auto& policy = transition.at("intended_policy");
    keys(policy, {"owner", "dacl_protected", "aces"});
    if ((policy.at("owner").as_string() != "S-1-5-18" && policy.at("owner").as_string() != "S-1-5-32-544") ||
        !policy.at("dacl_protected").as_boolean() || policy.at("aces").as_array().empty() ||
        policy.at("aces").as_array().size() > 65u)
        throw std::runtime_error("target admission intended mounted policy is invalid");
    for (const auto& ace : policy.at("aces").as_array()) {
        keys(ace, {"type", "flags", "mask", "sid"});
        if (ace.at("type").as_unsigned() != ACCESS_ALLOWED_ACE_TYPE || ace.at("flags").as_unsigned() > 255u ||
            ace.at("mask").as_unsigned() > 0xffffffffu || ace.at("sid").as_string().empty() || ace.at("sid").as_string().size() > 256u)
            throw std::runtime_error("target admission intended mounted ACE is invalid");
    }
    return true;
}

} // namespace usk::platform::windows
#endif
