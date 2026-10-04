// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_execution_observation.h"
#include "usk_publisher_handle_observation.h"
#include "usk_publisher_process_boundary.h"
#include "usk_publisher_worker_security.h"

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
} // namespace

void require_publisher_execution_platform(const Value& value) { require_platform(value); }

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

Value observe_publisher_execution_phase(const std::wstring& service_name, const std::string& phase,
    const std::vector<PublisherPhaseHandle>& handles) {
    require(handles.size() == roles.size(), "publisher execution requires the seven distinct held roles");
    const auto before = observe_current_restricted_publisher_service(service_name);
    const auto process_before = observe_current_publisher_process_boundary();
    require_publisher_process_boundary(process_before, before.process_id, before.service_sid,
        before.token.process_groups);
    const auto security_before = observe_current_publisher_worker_security();
    require_publisher_worker_security(security_before, before);
    const auto platform = observe_publisher_execution_platform();
    require_platform(platform);
    Value::Array observations;
    std::vector<std::pair<std::string, std::string>> bindings;
    for (std::size_t index = 0; index < handles.size(); ++index) {
        const auto& item = handles[index];
        require(item.role == roles[index], "publisher execution handle roles are not ordered");
        const auto flags = observe_publisher_noninheritable_handle_flags(item.handle);
        const auto object = observe_publisher_directory_handle(item.handle);
        require(flags == 0 && observe_publisher_noninheritable_handle_flags(item.handle) == flags &&
            object.file_id == item.expected_file_id,
            "publisher execution held handle flags or object identity changed");
        observations.emplace_back(Value::Object{{"role", Value(item.role)}, {"file_id", Value(object.file_id)},
            {"handle_flags", Value(static_cast<std::uint64_t>(flags))}});
        bindings.emplace_back(item.role, item.expected_file_id);
    }
    const auto after = observe_current_restricted_publisher_service(service_name);
    const auto process_after = observe_current_publisher_process_boundary();
    require_publisher_process_boundary(process_after, after.process_id, after.service_sid,
        after.token.process_groups);
    const auto security_after = observe_current_publisher_worker_security();
    require_publisher_worker_security(security_after, after);
    require(usk::json::canonical(service_json(before)) == usk::json::canonical(service_json(after)) &&
        usk::json::canonical(process_before) == usk::json::canonical(process_after) &&
        usk::json::canonical(security_before) == usk::json::canonical(security_after) &&
        usk::json::canonical(platform) == usk::json::canonical(observe_publisher_execution_platform()),
        "publisher execution service, process token or platform changed during observation");
    Value result(Value::Object{{"schema", Value("usk.publisher_execution_observation.v3")},
        {"scope", Value("supplied_held_service_handles_and_worker_security")}, {"phase", Value(phase)},
        {"platform", platform}, {"service", service_json(after)}, {"handles", Value(std::move(observations))},
        {"process_boundary", process_after}, {"worker_security", security_after}});
    require_publisher_execution_phase(result, service_name, after.service_sid, phase, bindings);
    return result;
}

void require_publisher_execution_phase(const Value& value, const std::wstring& service_name,
    const std::string& service_sid, const std::string& phase,
    const std::vector<std::pair<std::string, std::string>>& object_bindings) {
    const bool worker_bound = value.at("schema").as_string() == "usk.publisher_execution_observation.v3";
    const bool process_bound = worker_bound || value.at("schema").as_string() == "usk.publisher_execution_observation.v2";
    require(value.as_object().size() == (worker_bound ? 8u : process_bound ? 7u : 6u) &&
        (process_bound || value.at("schema").as_string() == "usk.publisher_execution_observation.v1") &&
        value.at("scope").as_string() == (worker_bound ? "supplied_held_service_handles_and_worker_security" :
            process_bound ? "supplied_held_service_handles_and_process_owner_dacl" : "supplied_held_service_handles") &&
        value.at("phase").as_string() == phase &&
        (phase == "protected_empty" || phase == "sealed" || phase == "publish_prepared" ||
            phase == "before_rename" || phase == "visible_bound"),
        "publisher execution observation is not the closed phase schema");
    require_platform(value.at("platform"));
    const auto& service = value.at("service");
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
        require_publisher_worker_security(value.at("worker_security"), observed);
    }
    const auto& handles = value.at("handles").as_array();
    require(handles.size() == roles.size() && object_bindings.size() == roles.size(),
        "publisher execution retained handle-role closure is incomplete");
    std::set<std::string> identities;
    std::string volume;
    for (std::size_t index = 0; index < roles.size(); ++index) {
        const auto& object = handles[index];
        const auto& id = object.at("file_id").as_string();
        require(object.as_object().size() == 3 && object.at("role").as_string() == roles[index] &&
            object_bindings[index].first == roles[index] && id == object_bindings[index].second &&
            object.at("handle_flags").as_unsigned() == 0 && id.size() == 49 && id[16] == ':' &&
            hex(id.substr(0, 16), 16) && hex(id.substr(17), 32) && identities.insert(id).second,
            "publisher execution retained handle flags, role or file binding is invalid");
        if (index == 0) volume = id.substr(0, 16);
        require(id.substr(0, 16) == volume, "publisher execution retained handles span volumes");
    }
}

void require_publisher_execution_worker_match(const Value& earlier, const Value& later) {
    for (const auto* key : {"schema", "scope", "platform", "service", "handles"}) {
        require(usk::json::canonical(earlier.at(key)) == usk::json::canonical(later.at(key)),
            "publisher execution worker or held object identity changed between phases");
    }
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
        require(usk::json::canonical(earlier.at("worker_security")) ==
            usk::json::canonical(later.at("worker_security")),
            "publisher execution token/default/thread security changed between phases");
    }
}
void require_publisher_execution_record_continuity(const Value& earlier, const Value& later) {
    const auto& first = earlier.at("service");
    const auto& second = later.at("service");
    if (first.at("process_id").as_unsigned() == second.at("process_id").as_unsigned() &&
        first.at("token_id").as_string() == second.at("token_id").as_string()) {
        require_publisher_execution_worker_match(earlier, later);
    }
}
} // namespace usk::platform::windows
#endif
