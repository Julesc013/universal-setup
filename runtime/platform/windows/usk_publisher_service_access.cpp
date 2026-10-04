// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_service_access.h"
#if defined(_WIN32)
#include <sddl.h>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <vector>
namespace usk::platform::windows {
namespace {
using usk::json::Value;
constexpr std::uint64_t query_rights = READ_CONTROL | SERVICE_QUERY_CONFIG |
    SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_INTERROGATE |
    SERVICE_USER_DEFINED_CONTROL;
constexpr DWORD client_rights = READ_CONTROL | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START;
void require(bool okay, const char* message) { if (!okay) throw std::runtime_error(message); }
struct LocalAllocation {
    HLOCAL value = nullptr;
    ~LocalAllocation() { if (value) LocalFree(value); }
};
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
}
}
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
void grant_publisher_service_client_start(SC_HANDLE service, const std::string& client) {
    auto bytes = descriptor(service);
    auto expected = decode(bytes, client);
    require_publisher_service_access(expected, client);
    auto& aces = expected.as_object().at("dacl_aces").as_array();
    for (const auto& ace : aces) {
        if (ace.at("type").as_unsigned() == ACCESS_ALLOWED_ACE_TYPE &&
            ace.at("flags").as_unsigned() == 0 && ace.at("sid").as_string() == client &&
            ace.at("access_mask").as_unsigned() == client_rights) return;
    }
    PSID sid = nullptr;
    require(ConvertStringSidToSidA(client.c_str(), &sid) != FALSE, "publisher client SID unavailable");
    LocalAllocation held{reinterpret_cast<HLOCAL>(sid)};
    PACL old = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    require(GetSecurityDescriptorDacl(bytes.data(), &present, &old, &defaulted) && present && old,
        "publisher service DACL unavailable before update");
    ACL_SIZE_INFORMATION size{};
    require(GetAclInformation(old, &size, sizeof(size), AclSizeInformation) && size.AceCount < 4096,
        "publisher service DACL update exceeds bound");
    const auto added = static_cast<DWORD>(offsetof(ACCESS_ALLOWED_ACE, SidStart)) + GetLengthSid(sid);
    const auto total = size.AclBytesInUse + added;
    require(total <= 65535, "publisher service DACL update size exceeds bound");
    std::vector<unsigned char> storage(total);
    auto* next = reinterpret_cast<PACL>(storage.data());
    require(InitializeAcl(next, total, ACL_REVISION) != FALSE, "publisher service DACL construction failed");
    for (DWORD index = 0; index != size.AceCount; ++index) {
        void* raw = nullptr;
        require(GetAce(old, index, &raw) && AddAce(next, ACL_REVISION, MAXDWORD, raw,
            static_cast<ACE_HEADER*>(raw)->AceSize), "publisher service original ACE retention failed");
    }
    require(AddAccessAllowedAceEx(next, ACL_REVISION, 0, client_rights, sid) != FALSE,
        "publisher service client grant construction failed");
    SECURITY_DESCRIPTOR update{};
    require(InitializeSecurityDescriptor(&update, SECURITY_DESCRIPTOR_REVISION) &&
        SetSecurityDescriptorDacl(&update, TRUE, next, FALSE), "publisher service descriptor construction failed");
    require(SetServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, &update) != FALSE,
        "publisher service client grant failed");
    aces.emplace_back(Value::Object{{"type", Value(std::uint64_t{ACCESS_ALLOWED_ACE_TYPE})},
        {"flags", Value(std::uint64_t{0})}, {"access_mask", Value(static_cast<std::uint64_t>(client_rights))},
        {"sid", Value(client)}});
    require(usk::json::canonical(observe_publisher_service_access(service, client)) == usk::json::canonical(expected),
        "publisher service client grant readback differs; registration remains incomplete");
}
}
#endif
