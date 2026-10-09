// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_process_boundary.h"

#if defined(_WIN32)
#include <aclapi.h>
#include <sddl.h>
#include <cstddef>
#include <set>
#include <stdexcept>

namespace usk::platform::windows {
namespace {
using usk::json::Value;
constexpr std::uint32_t query_rights = SYNCHRONIZE | READ_CONTROL |
    PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;

void require(bool condition, const char* diagnostic) {
    if (!condition) throw std::runtime_error(diagnostic);
}

struct LocalAllocation {
    HLOCAL value = nullptr;
    ~LocalAllocation() { if (value) LocalFree(value); }
};

std::string sid_text(PSID sid) {
    require(sid && IsValidSid(sid), "publisher process boundary SID is invalid");
    LPSTR text = nullptr;
    require(ConvertSidToStringSidA(sid, &text) != FALSE,
        "publisher process boundary SID text unavailable");
    LocalAllocation allocation{reinterpret_cast<HLOCAL>(text)};
    return text;
}

bool canonical_sid(const std::string& text) {
    if (text.empty() || text.size() > 184) return false;
    PSID raw = nullptr;
    if (!ConvertStringSidToSidA(text.c_str(), &raw)) return false;
    LocalAllocation allocation{reinterpret_cast<HLOCAL>(raw)};
    return IsValidSid(raw) && sid_text(raw) == text;
}

bool canonical_logon_sid(const std::string& text) {
    if (!canonical_sid(text) || text.compare(0, 8, "S-1-5-5-") != 0) return false;
    PSID raw = nullptr;
    if (!ConvertStringSidToSidA(text.c_str(), &raw)) return false;
    LocalAllocation allocation{reinterpret_cast<HLOCAL>(raw)};
    return *GetSidSubAuthorityCount(raw) == 3 && *GetSidSubAuthority(raw, 0) == SECURITY_LOGON_IDS_RID;
}
} // namespace

Value observe_current_publisher_process_boundary() {
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR raw = nullptr;
    const auto status = GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
        nullptr, &dacl, nullptr, &raw);
    LocalAllocation allocation{reinterpret_cast<HLOCAL>(raw)};
    require(status == ERROR_SUCCESS && raw && IsValidSecurityDescriptor(raw) &&
        owner && dacl && IsValidAcl(dacl) && dacl->AceCount <= 4096,
        "publisher process boundary owner/DACL unavailable");
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    require(GetSecurityDescriptorControl(raw, &control, &revision) &&
        (control & SE_DACL_PRESENT) && revision == SECURITY_DESCRIPTOR_REVISION,
        "publisher process boundary descriptor control unavailable");
    Value::Array aces;
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void* entry = nullptr;
        require(GetAce(dacl, index, &entry) && entry,
            "publisher process boundary ACE unavailable");
        const auto* header = static_cast<const ACE_HEADER*>(entry);
        require((header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_DENIED_ACE_TYPE) &&
            header->AceSize >= offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8,
            "publisher process boundary ACE type/size unsupported");
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(entry);
        PSID sid = const_cast<DWORD*>(&ace->SidStart);
        const auto* sid_bytes = static_cast<const unsigned char*>(sid);
        require(sid_bytes[0] == SID_REVISION && sid_bytes[1] <= SID_MAX_SUB_AUTHORITIES &&
            offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8 + 4 * sid_bytes[1] == header->AceSize &&
            IsValidSid(sid) && GetLengthSid(sid) + offsetof(ACCESS_ALLOWED_ACE, SidStart) == header->AceSize,
            "publisher process boundary ACE SID/length differs");
        aces.emplace_back(Value::Object{
            {"type", Value(static_cast<std::uint64_t>(header->AceType))},
            {"flags", Value(static_cast<std::uint64_t>(header->AceFlags))},
            {"access_mask", Value(static_cast<std::uint64_t>(ace->Mask))},
            {"sid", Value(sid_text(sid))}});
    }
    Value::Object fields;
    fields.emplace("schema", Value("usk.publisher_process_boundary.v1"));
    fields.emplace("scope", Value("stored_current_process_owner_dacl"));
    fields.emplace("process_id", Value(static_cast<std::uint64_t>(GetCurrentProcessId())));
    fields.emplace("owner_sid", Value(sid_text(owner)));
    fields.emplace("dacl_present", Value(true));
    fields.emplace("dacl_protected", Value((control & SE_DACL_PROTECTED) != 0));
    fields.emplace("dacl_aces", Value(std::move(aces)));
    return Value(std::move(fields));
}

void require_publisher_process_boundary(const Value& value, std::uint32_t process_id,
    const std::string& service_sid, const std::vector<ObservedTokenGroup>& process_groups) {
    require(value.as_object().size() == 7 &&
        value.at("schema").as_string() == "usk.publisher_process_boundary.v1" &&
        value.at("scope").as_string() == "stored_current_process_owner_dacl" &&
        process_id != 0 && value.at("process_id").as_unsigned() == process_id &&
        value.at("dacl_present").as_boolean() && canonical_sid(service_sid) && process_groups.size() <= 4096,
        "publisher process boundary is not the closed bound schema");
    (void)value.at("dacl_protected").as_boolean();
    std::set<std::string> trusted{"S-1-5-18", "S-1-5-32-544", service_sid};
    std::size_t logon_groups = 0;
    for (const auto& group : process_groups) {
        require(canonical_sid(group.sid), "publisher process boundary token group SID differs");
        if ((group.attributes & SE_GROUP_LOGON_ID) != SE_GROUP_LOGON_ID) continue;
        require(++logon_groups == 1 && canonical_logon_sid(group.sid) &&
            (group.attributes & SE_GROUP_ENABLED) && !(group.attributes & SE_GROUP_USE_FOR_DENY_ONLY),
            "publisher process boundary logon identity differs");
        trusted.insert(group.sid);
    }
    const auto& owner = value.at("owner_sid").as_string();
    require(canonical_sid(owner) && trusted.count(owner) == 1,
        "publisher process boundary owner can grant untrusted process mutation");
    const auto& aces = value.at("dacl_aces").as_array();
    require(aces.size() <= 4096, "publisher process boundary ACE count exceeds bound");
    for (const auto& ace : aces) {
        const auto& sid = ace.at("sid").as_string();
        const auto type = ace.at("type").as_unsigned();
        const auto mask = ace.at("access_mask").as_unsigned();
        require(ace.as_object().size() == 4 && canonical_sid(sid) &&
            (type == ACCESS_ALLOWED_ACE_TYPE || type == ACCESS_DENIED_ACE_TYPE) &&
            ace.at("flags").as_unsigned() == 0 && mask <= 0xffffffffu &&
            (type == ACCESS_DENIED_ACE_TYPE || trusted.count(sid) || (mask & ~query_rights) == 0),
            "publisher process boundary grants an outside capability or has unsupported ACE facts");
    }
}
} // namespace usk::platform::windows
#endif
