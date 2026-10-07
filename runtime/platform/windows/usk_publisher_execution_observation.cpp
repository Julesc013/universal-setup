// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_execution_observation.h"
#include "usk_publisher_handle_observation.h"
#include "usk_publisher_process_boundary.h"
#include "usk_publisher_worker_security.h"
#include "usk_publisher_request_channel.h"
#include "usk_publisher_effect_broker_internal.h"

#if defined(_WIN32)
#include <algorithm>
#include <array>
#include <cstring>
#include <set>
#include <stdexcept>
#include <sddl.h>

#ifndef USK_PUBLISHER_BUILD_SDK_VERSION
#define USK_PUBLISHER_BUILD_SDK_VERSION ""
#endif

namespace usk::platform::windows {
namespace {
using usk::json::Value;
const std::array<const char*, 7> roles{{"volume_root", "publication_root", "staging_anchor",
    "destination_parent", "state_anchor", "journal_anchor", "payload_root"}};

void require(bool condition, const char* diagnostic) {
    if (!condition) throw std::runtime_error(diagnostic);
}

bool hex(const std::string& value, std::size_t size) {
    return value.size() == size && std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

std::string hex64(std::uint64_t value) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(16, '0');
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[15 - index] = digits[value & 15u];
        value >>= 4;
    }
    return result;
}

std::string ascii_service_name(const std::wstring& value) {
    require(!value.empty() && value.size() <= 256 &&
        std::all_of(value.begin(), value.end(), [](wchar_t ch) { return ch >= 32 && ch < 127; }),
        "publisher execution service name is outside the ASCII profile");
    std::string result;
    for (const wchar_t ch : value) result.push_back(static_cast<char>(ch));
    return result;
}

bool canonical_sid(const std::string& value) {
    if (value.empty() || value.size() > 184) return false;
    PSID raw = nullptr;
    if (!ConvertStringSidToSidA(value.c_str(), &raw)) return false;
    LPSTR text = nullptr;
    const bool valid = IsValidSid(raw) && ConvertSidToStringSidA(raw, &text);
    const bool canonical = valid && value == text;
    if (text) LocalFree(text);
    LocalFree(raw);
    return canonical;
}

bool sdk_version(const std::string& value) {
    if (value.size() < 12 || value.size() > 20 || value.compare(0, 5, "10.0.") != 0 ||
        value.compare(value.size() - 2, 2, ".0") != 0) return false;
    const auto build = value.substr(5, value.size() - 7);
    if (build.empty() || build.front() == '0') return false;
    std::uint64_t number = 0;
    for (const char ch : build) {
        if (ch < '0' || ch > '9') return false;
        number = number * 10 + static_cast<unsigned>(ch - '0');
        if (number > 0xffffffffu) return false;
    }
    return number >= 17763;
}

void require_platform(const Value& value) {
    require(value.as_object().size() == 8 && value.at("os_family").as_string() == "Windows NT" &&
        value.at("native_arch").as_string() == "x64" && value.at("process_arch").as_string() == "x64" &&
        value.at("major_version").as_unsigned() == 10 && value.at("minor_version").as_unsigned() == 0 &&
        value.at("windows_build").as_unsigned() >= 17763 &&
        value.at("windows_build").as_unsigned() <= 0xffffffffu &&
        value.at("minimum_windows_build").as_unsigned() == 17763 &&
        sdk_version(value.at("sdk_version").as_string()),
        "publisher execution platform is outside the bound Windows x64 SDK profile");
}

Value groups_json(const std::vector<ObservedTokenGroup>& groups) {
    Value::Array result;
    for (const auto& group : groups) result.emplace_back(Value::Object{
        {"sid", Value(group.sid)}, {"attributes", Value(static_cast<std::uint64_t>(group.attributes))}});
    return Value(std::move(result));
}

std::vector<ObservedTokenGroup> parse_groups(const Value& value) {
    require(value.as_array().size() <= 4096, "publisher execution token group bound exceeded");
    std::vector<ObservedTokenGroup> groups;
    std::set<std::string> seen;
    for (const auto& group : value.as_array()) {
        const auto sid = group.at("sid").as_string();
        const auto attributes = group.at("attributes").as_unsigned();
        require(group.as_object().size() == 2 && canonical_sid(sid) &&
            seen.insert(sid).second && attributes <= 0xffffffffu,
            "publisher execution token group is malformed or duplicated");
        groups.push_back({sid, static_cast<std::uint32_t>(attributes)});
    }
    return groups;
}

Value service_json(const PublisherServiceObservation& service) {
    return Value(Value::Object{
        {"service_name", Value(ascii_service_name(service.service_name))},
        {"service_sid", Value(service.service_sid)},
        {"service_sid_type", Value(static_cast<std::uint64_t>(service.service_sid_type))},
        {"service_type", Value(static_cast<std::uint64_t>(service.service_type))},
        {"service_state", Value(static_cast<std::uint64_t>(service.service_state))},
        {"process_id", Value(static_cast<std::uint64_t>(service.process_id))},
        {"process_user_sid", Value(service.token.process_user_sid)},
        {"thread_impersonating", Value(service.token.current_thread_impersonating)},
        {"process_groups", groups_json(service.token.process_groups)},
        {"process_restricted_sids", groups_json(service.token.process_restricted_sids)},
        {"token_id", Value(hex64(service.token.identity.token_id))},
        {"authentication_id", Value(hex64(service.token.identity.authentication_id))},
        {"modified_id", Value(hex64(service.token.identity.modified_id))},
        {"token_type", Value(static_cast<std::uint64_t>(service.token.identity.token_type))}});
}

const std::array<std::pair<const char*, DWORD>, 9> access_rights{{
    {"write_or_add_file", FILE_WRITE_DATA}, {"append_or_add_directory", FILE_APPEND_DATA},
    {"write_ea", FILE_WRITE_EA}, {"delete_child", FILE_DELETE_CHILD},
    {"write_attributes", FILE_WRITE_ATTRIBUTES}, {"delete", DELETE},
    {"write_dac", WRITE_DAC}, {"write_owner", WRITE_OWNER}, {"maximum_allowed", MAXIMUM_ALLOWED}}};
constexpr DWORD mutation_rights = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
    FILE_DELETE_CHILD | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER;

void require_authenticated_client(const Value& client) {
    require(client.as_object().size() == 12 &&
        client.at("schema").as_string() == "usk.publisher_authenticated_client_observation.v1" &&
        client.at("scope").as_string() == "held_authenticated_identification_token" &&
        client.at("captured_process_id").as_unsigned() > 0 &&
        client.at("captured_process_id").as_unsigned() <= 0xffffffffu &&
        canonical_sid(client.at("user_sid").as_string()) &&
        client.at("token_type").as_unsigned() == TokenImpersonation &&
        client.at("impersonation_level").as_unsigned() >= SecurityIdentification &&
        client.at("impersonation_level").as_unsigned() <= SecurityDelegation,
        "publisher authenticated client is outside the closed identification-token scope");
    for (const auto* key : {"token_id", "authentication_id", "modified_id"})
        require(client.at(key).as_unsigned() != 0, "publisher authenticated token identity is absent");
    for (const auto* key : {"groups", "restricted_sids"}) {
        require(client.at(key).as_array().size() <= 1024, "publisher authenticated group bound exceeded");
        (void)parse_groups(client.at(key));
    }
    const auto& privileges = client.at("privileges").as_array();
    require(privileges.size() <= 256, "publisher authenticated privilege bound exceeded");
    std::set<std::uint64_t> seen;
    for (const auto& privilege : privileges)
        require(privilege.as_object().size() == 2 && privilege.at("luid").as_unsigned() != 0 &&
            seen.insert(privilege.at("luid").as_unsigned()).second &&
            privilege.at("attributes").as_unsigned() <= 0xffffffffu,
            "publisher authenticated privilege is malformed or duplicated");
}

// Validate offsets before any Win32 SID routine can dereference retained bytes.
// Only owner/group and ordered ACE facts are compared with the stored object;
// GetSecurityInfo control flags are kept in their own representation.
void require_access_descriptor(const Value& access, const Value& object) {
    const auto& encoded = access.at("descriptor_hex").as_string();
    require(encoded.size() >= 40 && encoded.size() <= 131072 && encoded.size() % 2 == 0 &&
        hex(encoded, encoded.size()), "publisher authenticated descriptor encoding is invalid");
    std::vector<unsigned char> bytes(encoded.size() / 2);
    const auto nibble = [](char ch) { return static_cast<unsigned>(ch <= '9' ? ch - '0' : ch - 'a' + 10); };
    for (std::size_t index = 0; index < bytes.size(); ++index)
        bytes[index] = static_cast<unsigned char>((nibble(encoded[2 * index]) << 4u) | nibble(encoded[2 * index + 1]));
    const auto u16 = [&](std::size_t offset) {
        require(offset <= bytes.size() - 2, "publisher authenticated descriptor word is truncated");
        return static_cast<std::uint32_t>(bytes[offset]) | (static_cast<std::uint32_t>(bytes[offset + 1]) << 8u);
    };
    const auto u32 = [&](std::size_t offset) {
        require(offset <= bytes.size() - 4, "publisher authenticated descriptor dword is truncated");
        return u16(offset) | (u16(offset + 2) << 16u);
    };
    const auto sid = [&](std::size_t offset, std::size_t end) {
        require(end <= bytes.size() && offset >= 20 && offset % 4 == 0 && offset <= end &&
            end - offset >= 8 && bytes[offset] == SID_REVISION && bytes[offset + 1] <= SID_MAX_SUB_AUTHORITIES &&
            8u + 4u * bytes[offset + 1] <= end - offset,
            "publisher authenticated descriptor SID is outside its byte bounds");
        auto raw = bytes.data() + offset;
        LPSTR text = nullptr;
        require(IsValidSid(raw) && ConvertSidToStringSidA(raw, &text), "publisher authenticated descriptor SID is invalid");
        const std::string result(text);
        LocalFree(text);
        return result;
    };
    require(bytes[0] == SECURITY_DESCRIPTOR_REVISION && bytes[1] == 0 &&
        (u16(2) & (SE_SELF_RELATIVE | SE_DACL_PRESENT)) == (SE_SELF_RELATIVE | SE_DACL_PRESENT) &&
        u32(12) == 0 && sid(u32(4), bytes.size()) == object.at("owner_sid").as_string() &&
        sid(u32(8), bytes.size()) == access.at("observed_group_sid").as_string(),
        "publisher authenticated descriptor header, owner or group differs");
    const auto acl = static_cast<std::size_t>(u32(16));
    require(acl >= 20 && acl % 4 == 0 && acl <= bytes.size() - 8 &&
        (bytes[acl] == ACL_REVISION || bytes[acl] == ACL_REVISION_DS) && bytes[acl + 1] == 0 && u16(acl + 6) == 0,
        "publisher authenticated descriptor ACL header is invalid");
    const auto size = static_cast<std::size_t>(u16(acl + 2));
    const auto& aces = object.at("dacl_aces").as_array();
    require(size >= 8 && size % 4 == 0 && size <= bytes.size() - acl && u16(acl + 4) == aces.size(),
        "publisher authenticated descriptor ACL closure differs");
    std::size_t offset = acl + 8;
    for (const auto& expected : aces) {
        require(offset <= acl + size && acl + size - offset >= 16,
            "publisher authenticated descriptor ACE is truncated");
        const auto ace_size = static_cast<std::size_t>(u16(offset + 2));
        require(ace_size >= 16 && ace_size % 4 == 0 && ace_size <= acl + size - offset &&
            bytes[offset] == ACCESS_ALLOWED_ACE_TYPE && bytes[offset] == expected.at("type").as_unsigned() &&
            bytes[offset + 1] == expected.at("flags").as_unsigned() &&
            u32(offset + 4) == expected.at("access_mask").as_unsigned() &&
            sid(offset + 8, offset + ace_size) == expected.at("sid").as_string(),
            "publisher authenticated descriptor ordered ACE differs from stored object");
        offset += ace_size;
    }
    require(offset == acl + size, "publisher authenticated descriptor ACL has unaccounted bytes");
}
} // namespace

void require_publisher_authenticated_object_access(const Value& access, const Value& client, const Value& object) {
    require_authenticated_client(client);
    require(access.as_object().size() == 8 &&
        access.at("schema").as_string() == "usk.publisher_authenticated_object_access.v1" &&
        access.at("scope").as_string() == "fresh_held_authenticated_token_and_file_descriptor" &&
        access.at("client_sha256").as_string() == usk::json::sha256_canonical(client) &&
        access.at("native_object_sha256").as_string() == usk::json::sha256_canonical(object) &&
        access.at("descriptor_api").as_string() == "GetSecurityInfo:SE_FILE_OBJECT:OWNER_GROUP_DACL" &&
        canonical_sid(access.at("observed_group_sid").as_string()),
        "publisher authenticated access binding or API scope differs");
    require_access_descriptor(access, object);
    const auto& checks = access.at("checks");
    require(checks.as_object().size() == access_rights.size(), "publisher authenticated access request closure differs");
    for (const auto& [name, requested] : access_rights) {
        const auto& check = checks.at(name);
        const auto granted = check.at("granted").as_unsigned();
        const auto allowed = check.at("allowed").as_boolean();
        require(check.as_object().size() == 3 && check.at("requested").as_unsigned() == requested &&
            (granted & ~static_cast<std::uint64_t>(FILE_ALL_ACCESS)) == 0 && allowed == (granted != 0) &&
            (requested == MAXIMUM_ALLOWED || granted == (allowed ? requested : 0u)),
            "publisher authenticated AccessCheck request or result is malformed");
    }
}

void require_publisher_execution_platform(const Value& value) { require_platform(value); }

void require_publisher_authenticated_descendant_access(const Value& value,
    const Value& client, const Value& tree) {
    require(value.as_object().size() == 4 &&
        value.at("schema").as_string() == "usk.publisher_authenticated_descendant_access.v1" &&
        value.at("scope").as_string() == "fresh_held_descriptors_for_bound_tree_no_content_rehash" &&
        value.at("client_sha256").as_string() == usk::json::sha256_canonical(client),
        "publisher authenticated descendant scope/client binding differs");
    const auto& rows = value.at("objects").as_array();
    const auto& descendants = tree.at("descendants").as_array();
    require(rows.size() == descendants.size() && rows.size() <= 200000,
        "publisher authenticated descendant closure coverage differs");
    for (std::size_t index = 0; index < rows.size(); ++index) {
        const auto& row = rows[index];
        const auto& descendant = descendants[index];
        require(row.as_object().size() == 2 &&
            row.at("relative_path").as_string() == descendant.at("relative_path").as_string(),
            "publisher authenticated descendant path/order binding differs");
        const auto& access = row.at("authenticated_access");
        require_publisher_authenticated_object_access(access, client, descendant.at("object"));
        for (const auto& [name, requested] : access_rights) {
            const auto& check = access.at("checks").at(name);
            require(requested == MAXIMUM_ALLOWED ? (check.at("granted").as_unsigned() & mutation_rights) == 0 :
                !check.at("allowed").as_boolean() && check.at("granted").as_unsigned() == 0,
                "publisher authenticated caller retains mutation access to a protected descendant");
        }
    }
}

Value observe_publisher_execution_platform() {
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto address = module ? GetProcAddress(module, "RtlGetVersion") : nullptr;
    using Query = LONG (WINAPI*)(OSVERSIONINFOW*);
    Query query = nullptr;
    static_assert(sizeof(query) == sizeof(address));
    std::memcpy(&query, &address, sizeof(query));
    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    require(query && query(&version) == 0 && version.dwPlatformId == VER_PLATFORM_WIN32_NT,
        "publisher execution cannot observe its runtime Windows version");
#if defined(_M_X64) || defined(__x86_64__)
    const char* process_arch = "x64";
#elif defined(_M_IX86) || defined(__i386__)
    const char* process_arch = "x86";
#else
    const char* process_arch = "unsupported";
#endif
    return Value(Value::Object{
        {"os_family", Value("Windows NT")},
        {"native_arch", Value(system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "unsupported")},
        {"process_arch", Value(process_arch)},
        {"major_version", Value(static_cast<std::uint64_t>(version.dwMajorVersion))},
        {"minor_version", Value(static_cast<std::uint64_t>(version.dwMinorVersion))},
        {"windows_build", Value(static_cast<std::uint64_t>(version.dwBuildNumber))},
        {"minimum_windows_build", Value(std::uint64_t{17763})},
        {"sdk_version", Value(USK_PUBLISHER_BUILD_SDK_VERSION)}});
}

bool publisher_registered_execution_platform_qualified(const Value& value) {
    try {
        require_platform(value);
        return value.at("windows_build").as_unsigned() == 20348 &&
            value.at("sdk_version").as_string() == "10.0.26100.0";
    } catch (const std::exception&) {
        return false;
    }
}

namespace {
Value observe_execution_phase(const std::wstring& service_name, const std::string& phase,
    const std::vector<PublisherPhaseHandle>& handles, const PublisherRequestChannel* authenticated_request,
    PublisherEffectWorkerReadback* effect_readback, PublisherEffectWorkerNativeSecurity* effect_security) {
    require(handles.size() == roles.size(), "publisher execution requires the seven distinct held roles");
    const bool effect = effect_readback != nullptr;
    require(effect == (effect_security != nullptr) && !(effect && authenticated_request),
        "publisher execution requires one concrete native observation route");
    PublisherServiceObservation before{};
    Value broker_before(Value::Object{}), child_before(Value::Object{});
    Value process_before, security_before;
    if (effect) {
        broker_before = effect_readback->service_admission();
        child_before = effect_security->observe_current();
        const auto context = publisher_effect_worker_record_context(broker_before);
        require(broker_before.at("service").at("service_name").as_string() == ascii_service_name(service_name) &&
            child_before.at("worker").at("process_id").as_unsigned() == GetCurrentProcessId() &&
            context.process_id == GetCurrentProcessId() &&
            child_before.at("worker").at("service_sid").as_string() == context.service_sid &&
            usk::json::canonical(child_before.at("worker").at("primary_token")) ==
                usk::json::canonical(broker_before.at("effect_primary_token")),
            "publisher execution child native security and original broker differ");
        process_before = child_before.at("process_boundary");
        security_before = child_before.at("worker_security");
    } else {
        before = observe_current_restricted_publisher_service(service_name);
        process_before = observe_current_publisher_process_boundary();
        require_publisher_process_boundary(process_before, before.process_id, before.service_sid, before.token.process_groups);
        security_before = observe_current_publisher_worker_security();
        require_publisher_worker_security(security_before, before);
    }
    const auto platform = observe_publisher_execution_platform();
    require_platform(platform);
    Value::Array observations;
    Value authenticated_client(Value::Object{});
    std::vector<std::pair<std::string, std::string>> bindings;
    for (std::size_t index = 0; index < handles.size(); ++index) {
        const auto& item = handles[index];
        require(item.role == roles[index], "publisher execution handle roles are not ordered");
        const auto flags = observe_publisher_noninheritable_handle_flags(item.handle);
        const auto granted_access = observe_publisher_handle_granted_access(item.handle);
        const auto object = observe_publisher_directory_handle(item.handle);
        require(flags == 0 && observe_publisher_noninheritable_handle_flags(item.handle) == flags &&
            observe_publisher_handle_granted_access(item.handle) == granted_access &&
            object.file_id == item.expected_file_id,
            "publisher execution held handle flags or object identity changed");
        Value observation(Value::Object{{"role", Value(item.role)}, {"file_id", Value(object.file_id)},
            {"handle_flags", Value(static_cast<std::uint64_t>(flags))},
            {"granted_access", Value(static_cast<std::uint64_t>(granted_access))},
            {"granted_access_api", Value("NtQueryObject:ObjectBasicInformation")},
            {"object_observation", publisher_handle_observation_json(object)}});
        if (authenticated_request || effect) {
            auto access = effect ? effect_readback->authenticated_object_access(item.handle) :
                authenticated_request->observe_authenticated_object_access(item.handle);
            if (index == 0) authenticated_client = access.at("client");
            require(usk::json::canonical(access.at("client")) == usk::json::canonical(authenticated_client) &&
                usk::json::canonical(access.at("native_object")) ==
                    usk::json::canonical(observation.at("object_observation")),
                "publisher phase authenticated client or same-handle access facts changed");
            access.as_object().erase("client");
            access.as_object().erase("native_object");
            access.as_object().emplace("client_sha256", Value(usk::json::sha256_canonical(authenticated_client)));
            access.as_object().emplace("native_object_sha256", Value(usk::json::sha256_canonical(observation.at("object_observation"))));
            observation.as_object().emplace("authenticated_access", std::move(access));
        }
        observations.emplace_back(std::move(observation));
        bindings.emplace_back(item.role, item.expected_file_id);
    }
    PublisherServiceObservation after{};
    Value broker_after(Value::Object{}), child_after(Value::Object{});
    Value process_after, security_after;
    std::string sid;
    if (effect) {
        child_after = effect_security->observe_current();
        broker_after = effect_readback->service_admission();
        for (const auto* field : {"schema", "authority", "scope", "worker", "process_boundary"})
            require(usk::json::canonical(child_before.at(field)) == usk::json::canonical(child_after.at(field)),
                "publisher execution original native child changed during observation");
        require(
            usk::json::canonical(publisher_effect_broker_immutable_record(broker_before)) ==
                usk::json::canonical(publisher_effect_broker_immutable_record(broker_after)),
            "publisher execution original native child/broker changed during observation");
        process_after = child_after.at("process_boundary");
        security_after = child_after.at("worker_security");
        sid = broker_after.at("service").at("service_sid").as_string();
    } else {
        after = observe_current_restricted_publisher_service(service_name);
        process_after = observe_current_publisher_process_boundary();
        require_publisher_process_boundary(process_after, after.process_id, after.service_sid, after.token.process_groups);
        security_after = observe_current_publisher_worker_security();
        require_publisher_worker_security(security_after, after);
        require(usk::json::canonical(service_json(before)) == usk::json::canonical(service_json(after)),
            "publisher execution native service changed during observation");
        sid = after.service_sid;
    }
    require(
        usk::json::canonical(process_before) == usk::json::canonical(process_after) &&
        usk::json::canonical(platform) == usk::json::canonical(observe_publisher_execution_platform()),
        "publisher execution service, process token or platform changed during observation");
    require_publisher_worker_security_continuity(security_before, security_after);
    Value result(Value::Object{{"schema", Value(effect ? "usk.publisher_execution_observation.v8" :
            authenticated_request ? "usk.publisher_execution_observation.v6" :
            "usk.publisher_execution_observation.v5")},
        {"scope", Value(effect ? "supplied_held_child_handles_authenticated_broker_access_and_native_retirement_partition" :
            authenticated_request ? "supplied_held_service_handles_authenticated_access_and_worker_security" :
            "supplied_held_service_handles_security_access_and_worker_security")}, {"phase", Value(phase)},
        {"platform", platform}, {"service", effect ? broker_after.at("service") : service_json(after)}, {"handles", Value(std::move(observations))},
        {"process_boundary", process_after}, {"worker_security", security_after}});
    if (authenticated_request || effect) result.as_object().emplace("authenticated_client", authenticated_client);
    if (effect) {
        auto worker = child_after.at("worker");
        worker.as_object().emplace("process_birth", broker_after.at("custody").at("peer_process_birth"));
        result.as_object().emplace("effect_worker", std::move(worker));
        result.as_object().emplace("broker_readback", broker_after);
    }
    require_publisher_execution_phase(result, service_name, sid, phase, bindings);
    return result;
}
}
Value observe_publisher_execution_phase(const std::wstring& service_name, const std::string& phase,
    const std::vector<PublisherPhaseHandle>& handles, const PublisherRequestChannel* authenticated_request) {
    return observe_execution_phase(service_name, phase, handles, authenticated_request, nullptr, nullptr);
}
Value observe_publisher_effect_execution_phase(const std::wstring& service_name, const std::string& phase,
    const std::vector<PublisherPhaseHandle>& handles, PublisherEffectWorkerReadback& readback,
    PublisherEffectWorkerNativeSecurity& security) {
    return observe_execution_phase(service_name, phase, handles, nullptr, &readback, &security);
}

void require_publisher_execution_phase(const Value& value, const std::wstring& service_name,
    const std::string& service_sid, const std::string& phase,
    const std::vector<std::pair<std::string, std::string>>& object_bindings) {
    const bool retirement_bound = value.at("schema").as_string() == "usk.publisher_execution_observation.v8";
    const bool effect_bound = retirement_bound || value.at("schema").as_string() == "usk.publisher_execution_observation.v7";
    const bool authenticated_bound = effect_bound || value.at("schema").as_string() == "usk.publisher_execution_observation.v6";
    const bool metadata_bound = authenticated_bound || value.at("schema").as_string() == "usk.publisher_execution_observation.v5";
    const bool rights_bound = metadata_bound || value.at("schema").as_string() == "usk.publisher_execution_observation.v4";
    const bool worker_bound = rights_bound || value.at("schema").as_string() == "usk.publisher_execution_observation.v3";
    const bool process_bound = worker_bound || value.at("schema").as_string() == "usk.publisher_execution_observation.v2";
    require(value.as_object().size() == (effect_bound ? 11u : authenticated_bound ? 9u : worker_bound ? 8u : process_bound ? 7u : 6u) &&
        (process_bound || value.at("schema").as_string() == "usk.publisher_execution_observation.v1") &&
        value.at("scope").as_string() == (retirement_bound ? "supplied_held_child_handles_authenticated_broker_access_and_native_retirement_partition" :
            effect_bound ? "supplied_held_child_handles_authenticated_broker_access_and_pinned_worker_security" :
            authenticated_bound ? "supplied_held_service_handles_authenticated_access_and_worker_security" :
            metadata_bound ? "supplied_held_service_handles_security_access_and_worker_security" :
            rights_bound ? "supplied_held_service_handles_granted_access_and_worker_security" :
            worker_bound ? "supplied_held_service_handles_and_worker_security" :
            process_bound ? "supplied_held_service_handles_and_process_owner_dacl" : "supplied_held_service_handles") &&
        value.at("phase").as_string() == phase &&
        (phase == "protected_empty" || phase == "sealed" || phase == "publish_prepared" ||
            phase == "before_rename" || phase == "visible_bound"),
        "publisher execution observation is not the closed phase schema");
    require_platform(value.at("platform"));
    const auto& service = value.at("service");
    if (effect_bound) {
        const auto& broker = value.at("broker_readback");
        const auto context = publisher_effect_worker_record_context(broker);
        const auto& worker = value.at("effect_worker");
        require(usk::json::canonical(service) == usk::json::canonical(broker.at("service")) &&
            service.at("service_name").as_string() == ascii_service_name(service_name) &&
            service.at("service_sid").as_string() == service_sid && worker.as_object().size() == 4 &&
            worker.at("service_sid").as_string() == service_sid && worker.at("process_id").as_unsigned() == context.process_id &&
            worker.at("process_birth").as_string() == broker.at("custody").at("peer_process_birth").as_string() &&
            usk::json::canonical(worker.at("primary_token")) == usk::json::canonical(broker.at("effect_primary_token")) &&
            usk::json::canonical(value.at("authenticated_client")) == usk::json::canonical(broker.at("authenticated_client")) &&
            !object_bindings.empty() && broker.at("volume_root").at("file_id").as_string() == object_bindings.front().second,
            "publisher retained actual child/SCM broker/caller/target binding differs");
        require_publisher_process_boundary(value.at("process_boundary"), context.process_id, service_sid, context.token.process_groups);
        require(value.at("worker_security").at("schema").as_string() ==
            (retirement_bound ? "usk.publisher_worker_security.v2" : "usk.publisher_worker_security.v1"),
            "publisher child execution reinterpreted its worker-security family");
        require_publisher_worker_security(value.at("worker_security"), context);
    } else {
    const auto pid = service.at("process_id").as_unsigned();
    PublisherTokenObservation token{service.at("process_user_sid").as_string(),
        parse_groups(service.at("process_groups")), parse_groups(service.at("process_restricted_sids")),
        service.at("thread_impersonating").as_boolean()};
    require(service.as_object().size() == 14 && service.at("service_name").as_string() == ascii_service_name(service_name) &&
        service.at("service_sid").as_string() == service_sid &&
        service.at("service_sid_type").as_unsigned() == SERVICE_SID_TYPE_RESTRICTED &&
        service.at("service_type").as_unsigned() == SERVICE_WIN32_OWN_PROCESS &&
        service.at("service_state").as_unsigned() == SERVICE_RUNNING && pid > 0 && pid <= 0xffffffffu &&
        service.at("token_type").as_unsigned() == TokenPrimary &&
        has_restricted_publisher_token_facts(token, service_sid), "publisher execution retained service identity is invalid");
    if (process_bound) require_publisher_process_boundary(value.at("process_boundary"),
        static_cast<std::uint32_t>(pid), service_sid, token.process_groups);
    for (const auto* key : {"token_id", "authentication_id", "modified_id"}) {
        const auto& id = service.at(key).as_string();
        require(hex(id, 16) && id != "0000000000000000", "publisher execution retained token identity is invalid");
    }
    if (worker_bound) {
        token.identity = {std::stoull(service.at("token_id").as_string(), nullptr, 16),
            std::stoull(service.at("authentication_id").as_string(), nullptr, 16),
            std::stoull(service.at("modified_id").as_string(), nullptr, 16), TokenPrimary};
        const PublisherServiceObservation observed{service_name, service_sid, SERVICE_SID_TYPE_RESTRICTED,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING, static_cast<std::uint32_t>(pid), token};
        require(value.at("worker_security").at("schema").as_string() == "usk.publisher_worker_security.v1",
            "publisher legacy execution reinterpreted retirement provenance");
        require_publisher_worker_security(value.at("worker_security"), observed);
    }
    }
    const auto& handles = value.at("handles").as_array();
    require(handles.size() == roles.size() && object_bindings.size() == roles.size(),
        "publisher execution retained handle-role closure is incomplete");
    std::set<std::string> identities;
    std::string volume;
    if (authenticated_bound) require_authenticated_client(value.at("authenticated_client"));
    for (std::size_t index = 0; index < roles.size(); ++index) {
        const auto& object = handles[index];
        const auto& id = object.at("file_id").as_string();
        require(object.as_object().size() == (authenticated_bound ? 7u : metadata_bound ? 6u : rights_bound ? 5u : 3u) && object.at("role").as_string() == roles[index] &&
            object_bindings[index].first == roles[index] && id == object_bindings[index].second &&
            object.at("handle_flags").as_unsigned() == 0 && id.size() == 49 && id[16] == ':' &&
            hex(id.substr(0, 16), 16) && hex(id.substr(17), 32) && identities.insert(id).second,
            "publisher execution retained handle flags, role or file binding is invalid");
        if (rights_bound) {
            const auto access = object.at("granted_access").as_unsigned();
            constexpr DWORD observation_rights = READ_CONTROL | FILE_READ_ATTRIBUTES;
            require(access <= 0xffffffffu && (access & observation_rights) == observation_rights &&
                object.at("granted_access_api").as_string() == "NtQueryObject:ObjectBasicInformation",
                "publisher execution held-handle access observation is invalid");
        }
        if (metadata_bound) {
            const auto& observed = object.at("object_observation");
            require(observed.as_object().size() == 9 && observed.at("file_id").as_string() == id &&
                observed.at("owner_sid").as_string() == "S-1-5-18" && observed.at("dacl_protected").as_boolean() &&
                observed.at("attributes").as_unsigned() <= 0xffffffffu &&
                (observed.at("attributes").as_unsigned() & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                (observed.at("attributes").as_unsigned() & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
                observed.at("reparse_tag").as_unsigned() == 0 && observed.at("link_count").as_unsigned() == 1 &&
                !observed.at("case_sensitive").as_boolean() && !observed.at("native_name").as_string().empty() &&
                observed.at("dacl_aces").as_array().size() == 2,
                "publisher execution retained same-handle security facts differ");
            const auto& aces = observed.at("dacl_aces").as_array();
            for (std::size_t ace_index = 0; ace_index < aces.size(); ++ace_index) {
                const auto& ace = aces[ace_index];
                require(ace.as_object().size() == 4 && ace.at("type").as_unsigned() == ACCESS_ALLOWED_ACE_TYPE &&
                    ace.at("flags").as_unsigned() == 0 && ace.at("access_mask").as_unsigned() == FILE_ALL_ACCESS &&
                    ace.at("sid").as_string() == (ace_index == 0 ? "S-1-5-18" : service_sid),
                    "publisher execution same-handle protected ACE facts differ");
            }
        }
        if (authenticated_bound) {
            const auto& access = object.at("authenticated_access");
            require_publisher_authenticated_object_access(access, value.at("authenticated_client"), object.at("object_observation"));
            for (const auto& [name, requested] : access_rights) {
                const auto& check = access.at("checks").at(name);
                require(requested == MAXIMUM_ALLOWED ? (check.at("granted").as_unsigned() & mutation_rights) == 0 :
                    !check.at("allowed").as_boolean() && check.at("granted").as_unsigned() == 0,
                    "publisher authenticated caller retains mutation access to a protected phase role");
            }
        }
        if (index == 0) volume = id.substr(0, 16);
        require(id.substr(0, 16) == volume, "publisher execution retained handles span volumes");
    }
}

void require_publisher_execution_worker_match(const Value& earlier, const Value& later) {
    for (const auto* key : {"schema", "scope", "platform", "service"}) {
        require(usk::json::canonical(earlier.at(key)) == usk::json::canonical(later.at(key)),
            "publisher execution worker or held object identity changed between phases");
    }
    if (earlier.at("schema").as_string() == "usk.publisher_execution_observation.v7" ||
        earlier.at("schema").as_string() == "usk.publisher_execution_observation.v8") {
        require(usk::json::canonical(earlier.at("effect_worker")) == usk::json::canonical(later.at("effect_worker")) &&
            usk::json::canonical(publisher_effect_broker_immutable_record(earlier.at("broker_readback"))) ==
                usk::json::canonical(publisher_effect_broker_immutable_record(later.at("broker_readback"))),
            "publisher execution original child or broker native binding changed between phases");
    }
    auto handles = later.at("handles");
    if ((earlier.at("schema").as_string() == "usk.publisher_execution_observation.v5" ||
         earlier.at("schema").as_string() == "usk.publisher_execution_observation.v6" ||
         earlier.at("schema").as_string() == "usk.publisher_execution_observation.v7" ||
         earlier.at("schema").as_string() == "usk.publisher_execution_observation.v8") &&
        later.at("schema").as_string() == earlier.at("schema").as_string() &&
        earlier.at("phase").as_string() == "before_rename" && later.at("phase").as_string() == "visible_bound") {
        // The surrounding phase/call reader binds both names to the sealed and
        // visible native namespace. Every other same-handle fact stays equal.
        handles.as_array().at(6).as_object().at("object_observation").as_object().at("native_name") =
            earlier.at("handles").as_array().at(6).at("object_observation").at("native_name");
        if (earlier.contains("authenticated_client"))
            handles.as_array().at(6).as_object().at("authenticated_access").as_object().at("native_object_sha256") =
                earlier.at("handles").as_array().at(6).at("authenticated_access").at("native_object_sha256");
    }
    require(usk::json::canonical(earlier.at("handles")) == usk::json::canonical(handles),
        "publisher execution same-handle facts changed across phases");
    require(earlier.contains("authenticated_client") == later.contains("authenticated_client"),
        "publisher execution authenticated client disappeared between phases");
    if (earlier.contains("authenticated_client"))
        require(usk::json::canonical(earlier.at("authenticated_client")) == usk::json::canonical(later.at("authenticated_client")),
            "publisher execution authenticated token changed between phases");
    require(earlier.contains("process_boundary") == later.contains("process_boundary"),
        "publisher execution process boundary disappeared between phases");
    if (earlier.contains("process_boundary")) {
        require(usk::json::canonical(earlier.at("process_boundary")) ==
            usk::json::canonical(later.at("process_boundary")),
            "publisher execution process owner/DACL changed between phases");
    }
    require(earlier.contains("worker_security") == later.contains("worker_security"),
        "publisher execution worker security disappeared between phases");
    if (earlier.contains("worker_security")) {
        if (earlier.at("schema").as_string() == "usk.publisher_execution_observation.v8")
            require_publisher_worker_security_continuity(earlier.at("worker_security"), later.at("worker_security"));
        else require(usk::json::canonical(earlier.at("worker_security")) ==
            usk::json::canonical(later.at("worker_security")),
            "publisher execution token/default/thread security changed between phases");
    }
}
void require_publisher_execution_record_continuity(const Value& earlier, const Value& later) {
    const bool first_effect = earlier.at("schema").as_string() == "usk.publisher_execution_observation.v7" ||
        earlier.at("schema").as_string() == "usk.publisher_execution_observation.v8";
    const bool second_effect = later.at("schema").as_string() == "usk.publisher_execution_observation.v7" ||
        later.at("schema").as_string() == "usk.publisher_execution_observation.v8";
    const auto& first = earlier.at(first_effect ? "effect_worker" : "service");
    const auto& second = later.at(second_effect ? "effect_worker" : "service");
    const auto first_token = first_effect ? hex64(first.at("primary_token").at("token_id").as_unsigned()) : first.at("token_id").as_string();
    const auto second_token = second_effect ? hex64(second.at("primary_token").at("token_id").as_unsigned()) : second.at("token_id").as_string();
    if (first.at("process_id").as_unsigned() == second.at("process_id").as_unsigned() &&
        (first_token == second_token || (first_effect && second_effect &&
            first.at("process_birth").as_string() == second.at("process_birth").as_string()))) {
        require_publisher_execution_worker_match(earlier, later);
    }
}
} // namespace usk::platform::windows
#endif
