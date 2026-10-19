// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_service_access_query_internal.h"
#if defined(_WIN32)
#include <sddl.h>
#include <cstring>
#include <stdexcept>
namespace usk::platform::windows {
namespace detail::service_access_query {
void require(bool okay, const char* message) { if (!okay) throw std::runtime_error(message); }
std::string sid_text(PSID sid) {
    require(sid && IsValidSid(sid), "publisher service SID unavailable");
    LPSTR text = nullptr;
    require(ConvertSidToStringSidA(sid, &text) != FALSE, "publisher service SID conversion failed");
    LocalAllocation held{reinterpret_cast<HLOCAL>(text)};
    return text;
}
bool canonical_sid(const std::string& text) {
    if (text.empty() || text.size() > 184) return false;
    PSID sid = nullptr;
    if (!ConvertStringSidToSidA(text.c_str(), &sid)) return false;
    LocalAllocation held{reinterpret_cast<HLOCAL>(sid)};
    return IsValidSid(sid) && *GetSidSubAuthorityCount(sid) > 0 && sid_text(sid) == text;
}
bool privileged(const std::string& sid) { return sid == "S-1-5-18" || sid == "S-1-5-32-544"; }
std::vector<unsigned char> descriptor(SC_HANDLE service) {
    constexpr auto information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    DWORD size = 0;
    require(!QueryServiceObjectSecurity(service, information, nullptr, 0, &size) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER && size >= SECURITY_DESCRIPTOR_MIN_LENGTH &&
        size <= 1024 * 1024, "publisher service security size unavailable");
    std::vector<unsigned char> bytes(size);
    require(QueryServiceObjectSecurity(service, information, bytes.data(), size, &size) &&
        size <= bytes.size(), "publisher service security readback unavailable");
    bytes.resize(size);
    require(IsValidSecurityDescriptor(bytes.data()) && GetSecurityDescriptorLength(bytes.data()) <= bytes.size(),
        "publisher service security descriptor invalid");
    return bytes;
}
Value decode(std::vector<unsigned char>& bytes, const std::string& client) {
    PSID owner = nullptr;
    PACL dacl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    require(GetSecurityDescriptorOwner(bytes.data(), &owner, &defaulted) && owner &&
        GetSecurityDescriptorDacl(bytes.data(), &present, &dacl, &defaulted) && present && dacl &&
        IsValidAcl(dacl) && dacl->AceCount <= 4096 &&
        GetSecurityDescriptorControl(bytes.data(), &control, &revision) &&
        revision == SECURITY_DESCRIPTOR_REVISION && (control & SE_SELF_RELATIVE),
        "publisher service owner/DACL unavailable");
    Value::Array aces;
    for (DWORD index = 0; index != dacl->AceCount; ++index) {
        void* raw = nullptr;
        require(GetAce(dacl, index, &raw) && raw, "publisher service ACE unavailable");
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        require((ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceType == ACCESS_DENIED_ACE_TYPE) &&
            ace->Header.AceFlags == 0 && ace->Header.AceSize >= offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8,
            "publisher service ACE type/flags/size unsupported");
        const auto* sid = reinterpret_cast<const unsigned char*>(&ace->SidStart);
        require(sid[0] == SID_REVISION && sid[1] > 0 && sid[1] <= SID_MAX_SUB_AUTHORITIES &&
            offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8 + 4 * sid[1] == ace->Header.AceSize,
            "publisher service ACE SID exceeds record");
        aces.emplace_back(Value::Object{{"type", Value(static_cast<std::uint64_t>(ace->Header.AceType))},
            {"flags", Value(static_cast<std::uint64_t>(ace->Header.AceFlags))},
            {"access_mask", Value(static_cast<std::uint64_t>(ace->Mask))},
            {"sid", Value(sid_text(const_cast<DWORD*>(&ace->SidStart)))}});
    }
    return Value(Value::Object{{"schema", Value("usk.publisher_service_access.v1")},
        {"scope", Value("stored_service_owner_dacl")}, {"authorized_client_sid", Value(client)},
        {"owner_sid", Value(sid_text(owner))}, {"dacl_present", Value(true)},
        {"dacl_protected", Value((control & SE_DACL_PROTECTED) != 0)}, {"dacl_aces", Value(std::move(aces))}});
}}
using usk::json::Value;
using detail::service_access_query::require;
using detail::service_access_query::LocalAllocation;
using detail::service_access_query::sid_text;
using detail::service_access_query::canonical_sid;
using detail::service_access_query::privileged;
using detail::service_access_query::descriptor;
using detail::service_access_query::decode;
using detail::service_access_query::query_rights;
using detail::service_access_query::client_rights;
void require_publisher_service_access(const Value& value, const std::string& client) {
    require(value.as_object().size() == 7 && value.at("schema").as_string() == "usk.publisher_service_access.v1" &&
        value.at("scope").as_string() == "stored_service_owner_dacl" && canonical_sid(client) &&
        !privileged(client) && value.at("authorized_client_sid").as_string() == client &&
        value.at("dacl_present").as_boolean() && privileged(value.at("owner_sid").as_string()),
        "publisher service access is not the closed bound administrative policy");
    (void)value.at("dacl_protected").as_boolean();
    const auto& aces = value.at("dacl_aces").as_array();
    require(aces.size() <= 4096, "publisher service ACE count exceeds bound");
    for (const auto& ace : aces) {
        const auto type = ace.at("type").as_unsigned();
        const auto mask = ace.at("access_mask").as_unsigned();
        const auto& sid = ace.at("sid").as_string();
        const auto allowed = query_rights | (sid == client ? SERVICE_START : 0u);
        require(ace.as_object().size() == 4 && canonical_sid(sid) && ace.at("flags").as_unsigned() == 0 &&
            (type == ACCESS_ALLOWED_ACE_TYPE || type == ACCESS_DENIED_ACE_TYPE) && mask <= 0xffffffffu &&
            (type == ACCESS_DENIED_ACE_TYPE || privileged(sid) || (mask & ~allowed) == 0),
            "publisher service access grants outside configuration, execution or security mutation");
    }
}
Value observe_publisher_service_access(SC_HANDLE service, const std::string& client) {
    auto bytes = descriptor(service);
    auto facts = decode(bytes, client);
    require_publisher_service_access(facts, client);
    return facts;
}
}
#endif
