// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_service_access_query_internal.h"
#if defined(_WIN32)
#include <sddl.h>
#include <cstddef>
#include <cstring>
#include <stdexcept>
namespace usk::platform::windows {
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
