// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_process_boundary.h"
#include "usk_publisher_execution_observation.h"
#include "usk_protected_install_publisher_internal.h"
#include "usk_publisher_worker_security.h"
#include "usk_publisher_effect_broker_internal.h"
#include "usk_publisher_effect_execution_internal.h"
#include "usk_publisher_handle_observation.h"
#include "usk_install_lease.h"
#include "usk_publisher_creation_observation.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_sha256.h"
#include <sddl.h>
#include <winternl.h>
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <vector>

using usk::json::Value;
using namespace usk::platform::windows;

namespace {
const std::string service_sid = "S-1-5-80-1-2-3-4-5";
const std::string consumer_sid = "S-1-5-21-1-2-3-1000";
const std::vector<ObservedTokenGroup> groups{
    {service_sid, SE_GROUP_ENABLED}, {"S-1-5-5-0-900", SE_GROUP_LOGON_ID | SE_GROUP_ENABLED}};
constexpr std::uint32_t query_rights = SYNCHRONIZE | READ_CONTROL |
    PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void system_thread_census_buffer_controls() {
    // Supplied bytes exercise parsing only. Existing owned-thread lifetime,
    // broker acquisition and retirement controls exercise the actual query.
    constexpr DWORD pid = 500, tid = 600;
    const auto first_size = sizeof(SYSTEM_PROCESS_INFORMATION) + 2u * sizeof(SYSTEM_THREAD_INFORMATION);
    std::vector<std::uint8_t> good(first_size + sizeof(SYSTEM_PROCESS_INFORMATION));
    SYSTEM_PROCESS_INFORMATION process{};
    process.NextEntryOffset = static_cast<ULONG>(first_size); process.NumberOfThreads = 2;
    process.UniqueProcessId = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(pid));
    std::memcpy(good.data(), &process, sizeof(process));
    SYSTEM_THREAD_INFORMATION thread{};
    thread.ClientId.UniqueProcess = process.UniqueProcessId;
    thread.ClientId.UniqueThread = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(tid + 1));
    std::memcpy(good.data() + sizeof(process), &thread, sizeof(thread));
    thread.ClientId.UniqueThread = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(tid));
    std::memcpy(good.data() + sizeof(process) + sizeof(thread), &thread, sizeof(thread));
    SYSTEM_PROCESS_INFORMATION other{};
    other.UniqueProcessId = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(pid + 1));
    std::memcpy(good.data() + first_size, &other, sizeof(other));
    check(detail::parse_publisher_system_thread_census(good.data(), good.size(), pid, tid) ==
        std::vector<DWORD>({tid, tid + 1}), "independent census parser lost complete sorted current population");
    const auto refuses = [&](const std::vector<std::uint8_t>& bytes) {
        bool rejected = false;
        try { (void)detail::parse_publisher_system_thread_census(bytes.data(), bytes.size(), pid, tid); }
        catch (const std::exception&) { rejected = true; }
        check(rejected, "independent census parser accepted malformed or incomplete population");
    };
    auto bad = good; bad.resize(sizeof(process) - 1u); refuses(bad);
    const auto change_process = [&](SYSTEM_PROCESS_INFORMATION value) {
        auto bytes = good; std::memcpy(bytes.data(), &value, sizeof(value)); refuses(bytes);
    };
    auto changed = process; changed.NextEntryOffset = 1; change_process(changed);
    changed = process; changed.NextEntryOffset = static_cast<ULONG>(good.size() + 8u); change_process(changed);
    changed = process; changed.NextEntryOffset = static_cast<ULONG>(sizeof(process)); change_process(changed);
    changed = process; changed.NumberOfThreads = MAXDWORD; change_process(changed);
    changed = process; changed.UniqueProcessId = other.UniqueProcessId; change_process(changed);
    bad.resize(2u * first_size);
    std::memcpy(bad.data(), good.data(), first_size);
    std::memcpy(bad.data() + first_size, good.data(), first_size);
    changed = process; changed.NextEntryOffset = 0;
    std::memcpy(bad.data() + first_size, &changed, sizeof(changed)); refuses(bad);
    thread.ClientId.UniqueProcess = other.UniqueProcessId;
    bad = good; std::memcpy(bad.data() + sizeof(process), &thread, sizeof(thread)); refuses(bad);
    thread.ClientId.UniqueProcess = process.UniqueProcessId;
    // Duplicate original and missing execution ID both refuse.
    bad = good; std::memcpy(bad.data() + sizeof(process), &thread, sizeof(thread)); refuses(bad);
    thread.ClientId.UniqueThread = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(tid + 2));
    bad = good; std::memcpy(bad.data() + sizeof(process) + sizeof(thread), &thread, sizeof(thread)); refuses(bad);
}

Value ace(const std::string& sid, std::uint32_t mask) {
    return Value(Value::Object{{"type", Value(std::uint64_t{0})},
        {"flags", Value(std::uint64_t{0})}, {"access_mask", Value(static_cast<std::uint64_t>(mask))},
        {"sid", Value(sid)}});
}

Value boundary() {
    return Value(Value::Object{{"schema", Value("usk.publisher_process_boundary.v1")},
        {"scope", Value("stored_current_process_owner_dacl")}, {"process_id", Value(std::uint64_t{500})},
        {"owner_sid", Value("S-1-5-18")}, {"dacl_present", Value(true)}, {"dacl_protected", Value(false)},
        {"dacl_aces", Value(Value::Array{ace("S-1-5-18", PROCESS_ALL_ACCESS),
            ace(service_sid, PROCESS_ALL_ACCESS), ace(consumer_sid, query_rights)})}});
}
Value::Object security_object(std::uint32_t query) {
    return {{"owner_sid", Value("S-1-5-18")}, {"dacl_present", Value(true)}, {"dacl_protected", Value(false)},
        {"dacl_aces", Value(Value::Array{ace("S-1-5-18", 0x1fffffu), ace(service_sid, 0x1fffffu), ace(consumer_sid, query)})}};
}
Value worker_security() {
    auto primary = security_object(TOKEN_QUERY | TOKEN_QUERY_SOURCE | READ_CONTROL);
    primary.emplace("token_id", Value("0000000000000500"));
    primary.emplace("authentication_id", Value("0000000000000900"));
    primary.emplace("modified_id", Value("0000000000000501"));
    primary.emplace("default_owner_sid", Value("S-1-5-18"));
    primary.emplace("default_dacl_aces", Value(Value::Array{ace("S-1-5-18", GENERIC_ALL),
        ace(service_sid, GENERIC_ALL), ace(consumer_sid, READ_CONTROL)}));
    auto thread = security_object(SYNCHRONIZE | READ_CONTROL | THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION);
    thread.emplace("thread_id", Value(std::uint64_t{700}));
    thread.emplace("creation_time", Value("0000000000000700"));
    thread.emplace("thread_impersonating", Value(false));
    return Value(Value::Object{{"schema", Value("usk.publisher_worker_security.v1")},
        {"scope", Value("stored_primary_token_defaults_and_process_thread_owner_dacls")},
        {"process_id", Value(std::uint64_t{500})}, {"current_thread_id", Value(std::uint64_t{700})},
        {"primary_token", Value(std::move(primary))}, {"threads", Value(Value::Array{Value(std::move(thread))})}});
}
Value retirement_security(const Value& baseline, const std::vector<std::uint64_t>& retired_ids = {}) {
    auto result = baseline;
    result.as_object().at("schema") = Value("usk.publisher_worker_security.v2");
    result.as_object().at("scope") = Value("original_pinned_token_defaults_and_native_thread_retirement_partition");
    result.as_object().emplace("original_baseline", baseline);
    Value::Array live, retired;
    for (const auto& thread : baseline.at("threads").as_array()) {
        const auto id = thread.at("thread_id").as_unsigned();
        if (std::find(retired_ids.begin(), retired_ids.end(), id) == retired_ids.end()) live.push_back(thread);
        else retired.emplace_back(Value::Object{{"thread_id", thread.at("thread_id")},
            {"creation_time", thread.at("creation_time")}, {"exit_time", Value("0000000000009999")}});
    }
    result.as_object().at("threads") = Value(std::move(live));
    result.as_object().emplace("retired_threads", Value(std::move(retired)));
    return result;
}
void worker_retirement_data_controls() {
    auto baseline = worker_security();
    auto helper = baseline.at("threads").as_array().front();
    helper.as_object().at("thread_id") = Value(std::uint64_t{701});
    helper.as_object().at("creation_time") = Value("0000000000000701");
    baseline.as_object().at("threads").as_array().push_back(helper);
    PublisherServiceObservation service{};
    service.process_id = 500; service.service_sid = service_sid; service.token.process_groups = groups;
    service.token.identity = {0x500, 0x900, 0x501, TokenPrimary};
    const auto before = retirement_security(baseline), after = retirement_security(baseline, {701});
    require_publisher_worker_security(before, service);
    require_publisher_worker_security(after, service);
    require_publisher_worker_security_continuity(before, after);
    require_publisher_worker_security_continuity(after, after);
    const auto refuses = [&](const std::function<void(Value&)>& change) {
        auto value = after; change(value); bool refused = false;
        try { require_publisher_worker_security(value, service); } catch (const std::exception&) { refused = true; }
        check(refused, "retirement data admitted an incomplete or contradictory original partition");
    };
    refuses([](Value& v) { v.as_object().erase("original_baseline"); });
    refuses([](Value& v) { v.as_object().erase("retired_threads"); });
    refuses([](Value& v) { v.as_object().at("retired_threads") = Value(Value::Array{}); });
    refuses([](Value& v) { v.as_object().at("retired_threads").as_array().push_back(v.at("retired_threads").as_array().front()); });
    for (const char* key : {"creation_time", "exit_time"})
        refuses([&](Value& v) { v.as_object().at("retired_threads").as_array().front().as_object().at(key) = Value("0000000000000001"); });
    refuses([](Value& v) { v.as_object().at("retired_threads").as_array().front().as_object().at("thread_id") = Value(true); });
    refuses([](Value& v) { v.as_object().at("retired_threads").as_array().front().as_object().emplace("authority", Value("granted")); });
    refuses([](Value& v) { v.as_object().at("threads").as_array().front().as_object().at("dacl_protected") = Value(true); });
    refuses([](Value& v) { v.as_object().at("threads").as_array().push_back(v.at("original_baseline").at("threads").as_array().back()); });
    bool refused = false;
    try { require_publisher_worker_security_continuity(after, before); } catch (const std::exception&) { refused = true; }
    check(refused, "original retirement was revived");
    auto changed_exit = after;
    changed_exit.as_object().at("retired_threads").as_array().front().as_object().at("exit_time") = Value("0000000000009998");
    require_publisher_worker_security(changed_exit, service); refused = false;
    try { require_publisher_worker_security_continuity(after, changed_exit); } catch (const std::exception&) { refused = true; }
    check(refused, "original exit time was refreshed");
    auto omitted = baseline; omitted.as_object().at("threads").as_array().pop_back(); refused = false;
    try { require_publisher_worker_security_continuity(baseline, omitted); } catch (const std::exception&) { refused = true; }
    check(refused, "legacy omission was promoted into retirement proof");
}
Value broker_lifetime_security(const Value& baseline, const std::vector<std::uint64_t>& retired = {}) {
    auto result = retirement_security(baseline, retired);
    result.as_object().at("schema") = Value("usk.publisher_broker_worker_security.v1");
    result.as_object().at("scope") = Value("completed_policy_original_native_custody_and_pending_additions");
    result.as_object().emplace("admitted_baseline", result.at("original_baseline"));
    result.as_object().erase("original_baseline");
    return result;
}
void worker_security_controls() {
    const auto observed = observe_current_publisher_worker_security();
    check(observed.as_object().size() == 6 && observed.at("process_id").as_unsigned() == GetCurrentProcessId() &&
        observed.at("current_thread_id").as_unsigned() == GetCurrentThreadId() &&
        observed.at("primary_token").as_object().size() == 9 && !observed.at("threads").as_array().empty(),
        "actual primary-token/default-DACL/own-thread security unavailable");
    PublisherServiceObservation service{};
    service.process_id = 500; service.service_sid = service_sid; service.token.process_groups = groups;
    service.token.identity = {0x500, 0x900, 0x501, TokenPrimary};
    require_publisher_worker_security(worker_security(), service);
    const PublisherWorkerTokenContext same_worker{service.process_id, service.service_sid, service.token};
    require_publisher_worker_security(worker_security(), same_worker);
    const auto refuses = [&](const std::function<void(Value&)>& change) {
        auto value = worker_security(); change(value);
        bool refused = false;
        try { require_publisher_worker_security(value, service); }
        catch (const std::exception&) { refused = true; }
        check(refused, "worker security admitted an outside capability or contradictory record");
        refused = false;
        try { require_publisher_worker_security(value, same_worker); }
        catch (const std::exception&) { refused = true; }
        check(refused, "distinct worker context weakened the stored security policy");
    };
    const std::uint32_t rights[] = {TOKEN_QUERY | TOKEN_QUERY_SOURCE | READ_CONTROL, READ_CONTROL,
        SYNCHRONIZE | READ_CONTROL | THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION};
    for (unsigned target = 0; target < 3; ++target) {
        for (unsigned bit = 0; bit < 32; ++bit) {
            const std::uint32_t right = std::uint32_t{1} << bit;
            if (rights[target] & right) continue;
            refuses([&](Value& value) {
                auto& aces = target == 2 ? value.as_object().at("threads").as_array().front().as_object().at("dacl_aces") :
                    value.as_object().at("primary_token").as_object().at(target == 1 ? "default_dacl_aces" : "dacl_aces");
                aces.as_array().back().as_object().at("access_mask") = Value(static_cast<std::uint64_t>(rights[target] | right));
            });
        }
    }
    refuses([](Value& value) { value.as_object().at("primary_token").as_object().at("owner_sid") = Value(consumer_sid); });
    refuses([](Value& value) { value.as_object().at("primary_token").as_object().at("default_owner_sid") = Value(consumer_sid); });
    refuses([](Value& value) { value.as_object().at("current_thread_id") = Value(std::uint64_t{701}); });
    refuses([](Value& value) { value.as_object().at("threads").as_array().clear(); });
    refuses([](Value& value) { value.as_object().at("threads").as_array().push_back(value.at("threads").as_array().front()); });
    refuses([](Value& value) { value.as_object().at("primary_token").as_object().at("token_id") = Value("0000000000000502"); });
    refuses([](Value& value) { value.as_object().at("threads").as_array().front().as_object().at("thread_impersonating") = Value(true); });
    // Separate deterministic child token/PID policy projection, not an actual
    // SCM/child launch or effect admission. Original service facts stay500.
    auto child = worker_security();
    child.as_object().at("process_id") = Value(std::uint64_t{600});
    child.as_object().at("primary_token").as_object().at("token_id") = Value("0000000000000600");
    child.as_object().at("primary_token").as_object().at("modified_id") = Value("0000000000000601");
    auto child_token = service.token;
    child_token.identity = {0x600, 0x900, 0x601, TokenPrimary};
    const PublisherWorkerTokenContext child_context{600, service_sid, child_token};
    require_publisher_worker_security(child, child_context);
    bool original_refused = false;
    try { require_publisher_worker_security(child, service); }
    catch (const std::exception&) { original_refused = true; }
    check(original_refused && service.process_id == 500 && service.token.identity.token_id == 0x500,
        "child policy projection reinterpreted or rewrote the original SCM identity");
}
void effect_execution_record_controls() {
    // Pure retained-record controls. No SCM/child process, native creator,
    // authenticated token, activation or runtime qualification is claimed.
    const std::wstring name = L"USK_Record_Child_Broker";
    const auto token = [](bool child) {
        Value::Array observed_groups;
        for (const auto& group : groups) observed_groups.emplace_back(Value::Object{
            {"sid", Value(group.sid)}, {"attributes", Value(static_cast<std::uint64_t>(group.attributes))}});
        return Value(Value::Object{{"user_sid", Value("S-1-5-18")}, {"groups", Value(observed_groups)},
            {"restricted_sids", Value(Value::Array{Value(Value::Object{{"sid", Value(service_sid)}, {"attributes", Value(std::uint64_t{0})}})})},
            {"observing_thread_impersonating", Value(false)}, {"token_id", Value(std::uint64_t{child ? 0x600u : 0x500u})},
            {"authentication_id", Value(std::uint64_t{0x900})}, {"modified_id", Value(std::uint64_t{child ? 0x601u : 0x501u})},
            {"token_type", Value(std::uint64_t{TokenPrimary})}});
    };
    const Value client(Value::Object{{"schema", Value("usk.publisher_authenticated_client_observation.v1")},
        {"scope", Value("held_authenticated_identification_token")}, {"captured_process_id", Value(std::uint64_t{800})},
        {"token_id", Value(std::uint64_t{800})}, {"authentication_id", Value(std::uint64_t{801})},
        {"modified_id", Value(std::uint64_t{802})}, {"user_sid", Value(consumer_sid)},
        {"token_type", Value(std::uint64_t{TokenImpersonation})}, {"impersonation_level", Value(std::uint64_t{SecurityIdentification})},
        {"groups", Value(Value::Array{})}, {"restricted_sids", Value(Value::Array{})}, {"privileges", Value(Value::Array{})}});
    const auto object_id = [](std::size_t index) { return "0000000000001234:" + std::string(31, '0') + static_cast<char>('1' + index); };
    const auto object = [&](std::size_t index) {
        return Value(Value::Object{{"file_id", Value(object_id(index))}, {"native_name", Value(index ? "\\publication\\role" + std::to_string(index) : "\\")},
            {"owner_sid", Value("S-1-5-18")}, {"dacl_protected", Value(true)},
            {"dacl_aces", Value(Value::Array{ace("S-1-5-18", FILE_ALL_ACCESS), ace(service_sid, FILE_ALL_ACCESS)})},
            {"attributes", Value(std::uint64_t{FILE_ATTRIBUTE_DIRECTORY})}, {"reparse_tag", Value(std::uint64_t{0})},
            {"link_count", Value(std::uint64_t{1})}, {"case_sensitive", Value(false)}});
    };
    const Value image(Value::Object{{"volume_id", Value("volume")}, {"file_id", Value("image")},
        {"size_bytes", Value(std::uint64_t{1})}, {"sha256", Value(std::string(64, 'a'))}});
    auto admitted_image = image;
    admitted_image.as_object().emplace("path", Value("C:\\publisher.exe"));
    const Value admitted(Value::Object{{"schema", Value("usk.publisher_registered_admission_observation.v1")},
        {"scope", Value("held_registered_service_image_and_controller_target_admission")},
        {"service_name", Value("USK_Record_Child_Broker")}, {"service_sid", Value(service_sid)},
        {"process_id", Value(std::uint64_t{500})}, {"configured_caller_sid", Value(consumer_sid)}, {"publisher_image", admitted_image},
        {"registration_sha256", Value(std::string(64, 'b'))}, {"target_admitted_sha256", Value(std::string(64, 'c'))},
        {"target_identity", Value(Value::Object{{"volume_identity", Value(Value::Object{
            {"root_file_id", Value(object_id(0))}, {"volume_root", Value("C:\\")}})}})}});
    const Value custody(Value::Object{{"schema", Value("usk.publisher_effect_transport_custody.v1")}, {"authority", Value("none")},
        {"current_process_id", Value(std::uint64_t{500})}, {"current_process_birth", Value("0000000000000500")},
        {"peer_process_id", Value(std::uint64_t{600})}, {"peer_process_birth", Value("0000000000000600")}, {"image", image},
        {"request_sha256", Value(std::string(64, 'd'))}, {"owned_job_active_process_limit", Value(std::uint64_t{1})},
        {"owned_job_kill_on_close", Value(true)}});
    const std::string command = "C:\\publisher.exe --service USK_Record_Child_Broker --no-receipt C:\\ --recover-reviewed --service-admitted-client --authorized-client-sid " + consumer_sid;
    const Value configuration(Value::Object{{"schema", Value("usk.publisher_registered_execution_configuration.v1")},
        {"scope", Value("original_held_scm_configuration")}, {"command", Value(command)},
        {"arguments", Value(Value::Array{Value("C:\\publisher.exe"), Value("--service"), Value("USK_Record_Child_Broker"),
            Value("--no-receipt"), Value("C:\\"), Value("--recover-reviewed"), Value("--service-admitted-client"),
            Value("--authorized-client-sid"), Value(consumer_sid)})},
        {"account", Value("LocalSystem")}, {"display_name", Value("USK_Record_Child_Broker")},
        {"service_type", Value(std::uint64_t{SERVICE_WIN32_OWN_PROCESS})}, {"start_type", Value(std::uint64_t{SERVICE_DEMAND_START})},
        {"service_sid_type", Value(std::uint64_t{SERVICE_SID_TYPE_RESTRICTED})}});
    const Value service(Value::Object{{"service_name", Value("USK_Record_Child_Broker")}, {"service_sid", Value(service_sid)},
        {"service_sid_type", Value(std::uint64_t{SERVICE_SID_TYPE_RESTRICTED})}, {"service_type", Value(std::uint64_t{SERVICE_WIN32_OWN_PROCESS})},
        {"service_state", Value(std::uint64_t{SERVICE_RUNNING})}, {"process_id", Value(std::uint64_t{500})}, {"primary_token", token(false)}});
    const Value broker(Value::Object{{"schema", Value("usk.publisher_effect_broker_native_readback.v2")}, {"authority", Value("read_only_observation")},
        {"request_sha256", Value(std::string(64, 'd'))}, {"service", service}, {"effect_primary_token", token(true)},
        {"registered_admission", admitted}, {"custody", custody}, {"volume_root", object(0)}, {"authenticated_client", client},
        {"broker_volume_granted_access", Value(std::uint64_t{READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE})},
        {"service_configuration", configuration}, {"broker_security", Value(Value::Object{{"process_boundary", boundary()}, {"worker_security", worker_security()}})}});
    auto child_boundary = boundary();
    child_boundary.as_object().at("process_id") = Value(std::uint64_t{600});
    auto child_security = worker_security();
    child_security.as_object().at("process_id") = Value(std::uint64_t{600});
    child_security.as_object().at("primary_token").as_object().at("token_id") = Value("0000000000000600");
    child_security.as_object().at("primary_token").as_object().at("modified_id") = Value("0000000000000601");
    const Value worker(Value::Object{{"process_id", Value(std::uint64_t{600})}, {"process_birth", Value("0000000000000600")},
        {"service_sid", Value(service_sid)}, {"primary_token", token(true)}});
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    ULONG descriptor_size = 0;
    const std::string sddl = "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;" + service_sid + ")";
    check(ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl.c_str(), SDDL_REVISION_1, &descriptor, &descriptor_size) != FALSE,
        "synthetic descriptor construction failed");
    std::string descriptor_hex;
    const auto bytes = static_cast<const unsigned char*>(descriptor);
    constexpr char digits[] = "0123456789abcdef";
    for (ULONG index = 0; index < descriptor_size; ++index) {
        descriptor_hex.push_back(digits[bytes[index] >> 4]); descriptor_hex.push_back(digits[bytes[index] & 15u]);
    }
    LocalFree(descriptor);
    const std::pair<const char*, DWORD> rights[] = {{"write_or_add_file", FILE_WRITE_DATA}, {"append_or_add_directory", FILE_APPEND_DATA},
        {"write_ea", FILE_WRITE_EA}, {"delete_child", FILE_DELETE_CHILD}, {"write_attributes", FILE_WRITE_ATTRIBUTES},
        {"delete", DELETE}, {"write_dac", WRITE_DAC}, {"write_owner", WRITE_OWNER}, {"maximum_allowed", MAXIMUM_ALLOWED}};
    Value::Object checks;
    for (const auto& [key, requested] : rights) checks.emplace(key, Value(Value::Object{{"requested", Value(static_cast<std::uint64_t>(requested))},
        {"granted", Value(std::uint64_t{0})}, {"allowed", Value(false)}}));
    const char* roles[] = {"volume_root", "publication_root", "staging_anchor", "destination_parent", "state_anchor", "journal_anchor", "payload_root"};
    Value::Array handles;
    std::vector<std::pair<std::string, std::string>> bindings;
    for (std::size_t index = 0; index < 7; ++index) {
        const auto facts = object(index);
        const Value access(Value::Object{{"schema", Value("usk.publisher_authenticated_object_access.v1")},
            {"scope", Value("fresh_held_authenticated_token_and_file_descriptor")}, {"client_sha256", Value(usk::json::sha256_canonical(client))},
            {"native_object_sha256", Value(usk::json::sha256_canonical(facts))}, {"descriptor_api", Value("GetSecurityInfo:SE_FILE_OBJECT:OWNER_GROUP_DACL")},
            {"observed_group_sid", Value("S-1-5-18")}, {"descriptor_hex", Value(descriptor_hex)}, {"checks", Value(checks)}});
        handles.emplace_back(Value::Object{{"role", Value(roles[index])}, {"file_id", Value(object_id(index))},
            {"handle_flags", Value(std::uint64_t{0})}, {"granted_access", Value(std::uint64_t{READ_CONTROL | FILE_READ_ATTRIBUTES})},
            {"granted_access_api", Value("NtQueryObject:ObjectBasicInformation")}, {"object_observation", facts}, {"authenticated_access", access}});
        bindings.emplace_back(roles[index], object_id(index));
    }
    // Every identity in this fixture is synthetic. Its supported x64 platform
    // is data too; the test executable's bitness cannot qualify this record.
    const Value synthetic_platform(Value::Object{{"os_family", Value("Windows NT")},
        {"native_arch", Value("x64")}, {"process_arch", Value("x64")},
        {"major_version", Value(std::uint64_t{10})}, {"minor_version", Value(std::uint64_t{0})},
        {"windows_build", Value(std::uint64_t{20348})}, {"minimum_windows_build", Value(std::uint64_t{17763})},
        {"sdk_version", Value("10.0.26100.0")}});
    const Value valid(Value::Object{{"schema", Value("usk.publisher_execution_observation.v7")},
        {"scope", Value("supplied_held_child_handles_authenticated_broker_access_and_pinned_worker_security")}, {"phase", Value("sealed")},
        {"platform", synthetic_platform}, {"service", service}, {"broker_readback", broker}, {"effect_worker", worker},
        {"handles", Value(handles)}, {"process_boundary", child_boundary}, {"worker_security", child_security}, {"authenticated_client", client}});
    require_publisher_execution_phase(valid, name, service_sid, "sealed", bindings);
    require_publisher_execution_record_continuity(valid, valid);
    auto unsupported = valid;
    unsupported.as_object().at("platform").as_object().at("process_arch") = Value("x86");
    bool unsupported_refused = false;
    try { require_publisher_execution_phase(unsupported, name, service_sid, "sealed", bindings); }
    catch (const std::exception&) { unsupported_refused = true; }
    check(unsupported_refused, "synthetic child record promoted unsupported x86 execution");
    const auto actual_platform = observe_publisher_execution_platform();
    check(actual_platform.at("process_arch").as_string() == (sizeof(void*) == 8 ? "x64" : "x86"),
        "actual test process architecture differs from native platform observation");
    // Terminal grammar is retained data only. Live native peer/SCM fences
    // and confirmed job/child/I/O closure remain the broker's separate work.
    const Value terminal_response(Value::Object{{"schema", Value("usk.publisher_lab_service_observation.v1")},
        {"status", Value("pass")}, {"service_name", service.at("service_name")}, {"service_sid", service.at("service_sid")},
        {"process_id", service.at("process_id")}, {"request_sha256", broker.at("request_sha256")}});
    const Value terminal(Value::Object{{"schema", Value("usk.publisher_effect_worker_terminal.v1")},
        {"request_sha256", broker.at("request_sha256")}, {"status", Value("success")}, {"response", terminal_response},
        {"error", Value("")}, {"error_code", Value("")}, {"operation_inspection_ref", Value("")},
        {"effects_may_exist", Value(true)}, {"definite_preflight_refusal", Value(false)}});
    require_publisher_effect_terminal_record(terminal, broker);
    const auto refuses_terminal = [&](const std::function<void(Value&)>& mutate) {
        auto changed = terminal; mutate(changed); bool refused = false;
        try { require_publisher_effect_terminal_record(changed, broker); }
        catch (const std::exception&) { refused = true; }
        check(refused, "synthetic terminal grammar accepted contradictory original identity/result");
    };
    refuses_terminal([](Value& v) { v.as_object().emplace("supplied_authority", Value(true)); });
    refuses_terminal([](Value& v) { v.as_object().at("request_sha256") = Value(std::string(64, 'a')); });
    refuses_terminal([](Value& v) { v.as_object().at("response").as_object().at("process_id") = Value(std::uint64_t{600}); });
    refuses_terminal([](Value& v) { v.as_object().at("definite_preflight_refusal") = Value(true); });
    refuses_terminal([](Value& v) { v.as_object().at("effects_may_exist") = Value(std::uint64_t{0}); });
    auto failure = terminal;
    failure.as_object().at("status") = Value("failure"); failure.as_object().at("response") = Value{};
    failure.as_object().at("error") = Value("synthetic stale plan"); failure.as_object().at("error_code") = Value("stale_plan");
    failure.as_object().at("effects_may_exist") = Value(false); failure.as_object().at("definite_preflight_refusal") = Value(true);
    require_publisher_effect_terminal_record(failure, broker);
    // An original-peer diagnostic is error data, never an assertion about
    // terminal effects, preflight, closure or authority. These are data only.
    const Value diagnostic(Value::Object{{"schema", Value("usk.publisher_effect_worker_failure_diagnostic.v1")},
        {"message", Value("synthetic original child failure")}});
    require_publisher_effect_failure_diagnostic(diagnostic);
    bool diagnostic_not_terminal = false;
    try { require_publisher_effect_terminal_record(diagnostic, broker); }
    catch (const std::exception&) { diagnostic_not_terminal = true; }
    check(diagnostic_not_terminal, "child diagnostic promoted to confirmed terminal");
    const auto refuses_diagnostic = [&](const std::function<void(Value&)>& mutate) {
        auto changed = diagnostic; mutate(changed); bool refused = false;
        try { require_publisher_effect_failure_diagnostic(changed); }
        catch (const std::exception&) { refused = true; }
        check(refused, "child diagnostic accepted an authority/result field or unbounded error");
    };
    refuses_diagnostic([](Value& v) { v.as_object().emplace("effects_may_exist", Value(false)); });
    refuses_diagnostic([](Value& v) { v.as_object().emplace("definite_preflight_refusal", Value(true)); });
    refuses_diagnostic([](Value& v) { v.as_object().emplace("status", Value("success")); });
    refuses_diagnostic([](Value& v) { v.as_object().emplace("error_code", Value("stale_plan")); });
    refuses_diagnostic([](Value& v) { v.as_object().at("message") = Value(std::string(4097, 'a')); });
    refuses_diagnostic([](Value& v) { v.as_object().at("message") = Value(""); });
    refuses_diagnostic([](Value& v) { v.as_object().at("message") = Value(std::string("a\0b", 3)); });
    refuses_diagnostic([](Value& v) { v.as_object().at("message") = Value(std::uint64_t{1}); });
    refuses_diagnostic([](Value& v) { v.as_object().at("schema") = Value("usk.publisher_effect_worker_terminal.v1"); });
    // The new child creation certificate binds the same actual-worker fields
    // as execution. These graphs/descriptors remain deterministic data only.
    const Value anchors(Value::Object{{"boundary", object(0)},
        {"chain", Value(Value::Array{Value(Value::Object{{"component", Value("publication")}, {"object", object(1)}})})},
        {"staging", object(2)}, {"destination_parent", object(3)}, {"state", object(4)}, {"journal", object(5)}});
    const Value tree(Value::Object{{"root", object(6)}, {"descendants", Value(Value::Array{})}});
    const auto graph = publisher_creation_graph(anchors, tree);
    const auto creation_bytes = make_publisher_directory_security_descriptor(std::wstring(service_sid.begin(), service_sid.end()));
    std::string creation_hex;
    for (const auto byte : creation_bytes) { creation_hex.push_back(digits[byte >> 4]); creation_hex.push_back(digits[byte & 15u]); }
    usk::base::Sha256 descriptor_digest;
    descriptor_digest.update(creation_bytes.data(), creation_bytes.size());
    const Value native_call(Value::Object{{"api", Value("NtCreateFile")}, {"create_disposition", Value(std::uint64_t{2})},
        {"creation_result", Value(std::uint64_t{2})}, {"ntstatus", Value(std::uint64_t{0})}, {"object_attribute_flags", Value(std::uint64_t{0x40})},
        {"share_access", Value(std::uint64_t{7})}, {"directory_create_options", Value(std::uint64_t{0x00200021})},
        {"file_create_options", Value(std::uint64_t{0x00200062})}, {"directory_file_attributes", Value(std::uint64_t{FILE_ATTRIBUTE_DIRECTORY})},
        {"file_file_attributes", Value(std::uint64_t{FILE_ATTRIBUTE_NORMAL})},
        {"directory_access_mask", Value(std::uint64_t{FILE_READ_ATTRIBUTES | FILE_TRAVERSE | FILE_LIST_DIRECTORY | FILE_ADD_FILE |
            FILE_ADD_SUBDIRECTORY | DELETE | READ_CONTROL | SYNCHRONIZE})},
        {"file_access_mask", Value(std::uint64_t{FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES |
            DELETE | READ_CONTROL | SYNCHRONIZE})}});
    const Value certificate(Value::Object{{"schema", Value("usk.publisher.creation_observation.v4")},
        {"scope", Value("successful_child_file_create_calls_and_pinned_worker_security_to_bound_graph")},
        {"creator", Value(Value::Object{{"service_name", service.at("service_name")}, {"service_sid", Value(service_sid)},
            {"broker_process_id", Value(std::uint64_t{500})}, {"effect_worker", worker}})},
        {"native_call", native_call}, {"process_boundary", child_boundary}, {"worker_security", child_security},
        {"broker_readback", broker}, {"handle_flags", Value(std::uint64_t{0})}, {"volume_boundary_file_id", Value(object_id(0))},
        {"creation_descriptor_sha256", Value(descriptor_digest.finish())}, {"creation_descriptor_hex", Value(creation_hex)},
        {"created_object_count", Value(static_cast<std::uint64_t>(graph.as_array().size()))},
        {"created_graph_sha256", Value(usk::json::sha256_canonical(graph))}});
    require_publisher_creation_certificate(certificate, anchors, tree, valid);
    // Full v10 retained install phase/control joins. Every PID, birth, object,
    // creator and request below is synthetic; no native admission is claimed.
    const std::string volume_guid = "\\\\?\\Volume{00000000-0000-0000-0000-000000000123}\\";
    auto phase_broker = broker;
    auto& phase_target = phase_broker.as_object().at("registered_admission").as_object().at("target_identity")
        .as_object().at("volume_identity").as_object();
    phase_target.at("volume_root") = Value(volume_guid);
    phase_target.emplace("volume_serial", Value("4660"));
    auto& phase_configuration = phase_broker.as_object().at("service_configuration").as_object();
    phase_configuration.at("arguments") = Value(Value::Array{Value("C:\\publisher.exe"), Value("--service"),
        Value("USK_Record_Child_Broker"), Value("--no-receipt"), Value(volume_guid),
        Value("--reviewed-plan-envelope"), Value("C:\\envelope.json"), Value(std::string(64, 'a')),
        Value("--service-admitted-client"), Value("--authorized-client-sid"), Value(consumer_sid)});
    phase_configuration.at("command") = Value("C:\\publisher.exe --service USK_Record_Child_Broker --no-receipt " +
        volume_guid + " --reviewed-plan-envelope C:\\envelope.json " + std::string(64, 'a') +
        " --service-admitted-client --authorized-client-sid " + consumer_sid);
    // Closed child original-custody controls are synthetic retained data.
    // They install no route and do not execute maintenance or recovery.
    const Value maintenance_request(Value::Object{{"schema", Value("usk.repair_apply_request.v1")},
        {"transaction_id", Value("repair.synthetic")}, {"reviewed_plan_digest", Value(std::string(64, 'e'))},
        {"plan_request", Value(Value::Object{{"install_id", Value("org.example.synthetic")}})}});
    auto maintenance_broker = phase_broker;
    const auto maintenance_request_sha = usk::json::sha256_canonical(maintenance_request);
    maintenance_broker.as_object().at("request_sha256") = Value(maintenance_request_sha);
    maintenance_broker.as_object().at("custody").as_object().at("request_sha256") = Value(maintenance_request_sha);
    const Value lease_root(Value::Object{{"file_id", Value(std::string(31, '0') + "1")}, {"volume_serial", Value("4660")}});
    const Value lease_holder(Value::Object{{"process_id", Value(std::uint64_t{600})},
        {"process_creation_time", Value("0000000000000600")}});
    const usk::transaction::InstallLeaseRequest lease_request{"org.example.synthetic", "repair", "repair.synthetic",
        "attempt.synthetic", std::string(64, 'b'), false, std::string(64, 'f')};
    const auto maintenance_lease = usk::transaction::derive_install_lease_ownership({}, lease_request,
        lease_root, lease_holder, std::string(64, 'b'));
    const Value maintenance_original(Value::Object{{"schema", Value("usk.publisher.maintenance_original_custody.v3")},
        {"transaction_id", Value("repair.synthetic")}, {"operation", Value("repair")}, {"plan_digest", Value(std::string(64, 'e'))},
        {"original_context_sha256", Value(std::string(64, 'f'))}, {"original_lease_ownership", maintenance_lease},
        {"worker_security", child_security}, {"process_boundary", child_boundary},
        {"registration_sha256", Value(usk::json::sha256_canonical(maintenance_broker.at("registered_admission")))},
        {"authenticated_client", client}, {"original_consumer_completion", Value{}}, {"installed_root", object(6)},
        {"installed_root_journal_identity", Value("synthetic")}, {"original_objects", Value(Value::Array{})},
        {"broker_readback", maintenance_broker}});
    require_publisher_effect_maintenance_original_record(maintenance_original, maintenance_request, name);
    auto current_original = maintenance_original;
    current_original.as_object().at("schema") = Value("usk.publisher.maintenance_original_custody.v4");
    current_original.as_object().at("worker_security") = retirement_security(child_security);
    require_publisher_effect_maintenance_original_record(current_original, maintenance_request, name);
    for (bool downgrade : {false, true}) {
        auto invalid = current_original;
        if (downgrade) invalid.as_object().at("schema") = Value("usk.publisher.maintenance_original_custody.v3");
        else invalid.as_object().at("worker_security") = child_security;
        bool refused = false;
        try { require_publisher_effect_maintenance_original_record(invalid, maintenance_request, name); }
        catch (const std::exception&) { refused = true; }
        check(refused, "maintenance original custody reinterpreted its retirement provenance family");
    }
    const auto refuses_maintenance = [&](const std::function<void(Value&)>& mutate) {
        auto changed = maintenance_original; mutate(changed); bool refused = false;
        try { require_publisher_effect_maintenance_original_record(changed, maintenance_request, name); }
        catch (const std::exception&) { refused = true; }
        check(refused, "synthetic child maintenance original custody accepted contradictory provenance");
    };
    refuses_maintenance([](Value& v) { v.as_object().at("schema") = Value("usk.publisher.maintenance_original_custody.v2"); });
    refuses_maintenance([](Value& v) { v.as_object().erase("broker_readback"); });
    refuses_maintenance([](Value& v) { v.as_object().emplace("supplied_authority", Value(true)); });
    refuses_maintenance([](Value& v) { v.as_object().at("worker_security").as_object().at("process_id") = Value(std::uint64_t{500}); });
    refuses_maintenance([](Value& v) { v.as_object().at("process_boundary").as_object().at("process_id") = Value(std::uint64_t{500}); });
    refuses_maintenance([](Value& v) { v.as_object().at("broker_readback").as_object().at("custody").as_object()
        .at("peer_process_birth") = Value("0000000000000601"); });
    refuses_maintenance([](Value& v) { v.as_object().at("broker_readback").as_object().at("request_sha256") = Value(std::string(64, 'a'));
        v.as_object().at("broker_readback").as_object().at("custody").as_object().at("request_sha256") = Value(std::string(64, 'a')); });
    refuses_maintenance([](Value& v) { v.as_object().at("registration_sha256") = Value(std::string(64, 'a')); });
    refuses_maintenance([](Value& v) { v.as_object().at("authenticated_client").as_object().at("token_id") = Value(std::uint64_t{803}); });
    refuses_maintenance([](Value& v) { v.as_object().at("plan_digest") = Value(std::string(64, 'a')); });
    auto other_request = maintenance_request;
    other_request.as_object().at("transaction_id") = Value("repair.another");
    bool other_request_refused = false;
    try { require_publisher_effect_maintenance_original_record(maintenance_original, other_request, name); }
    catch (const std::exception&) { other_request_refused = true; }
    check(other_request_refused, "synthetic custody reused another original reviewed request");
    // Distinct minimal-recovery selections: retained data only. The ordinary
    // test process cannot construct the actual SCM/channel original reader.
    for (const std::string operation : {"repair", "move", "uninstall", "install_local"}) {
        const bool install = operation == "install_local";
        Value minimum(Value::Object{{"schema", Value(install ? "usk.publisher_recovery_request.v1" : "usk.publisher_maintenance_recovery_request.v1")},
            {"install_id", Value("org.example.synthetic")}, {"transaction_id", Value("maintenance.synthetic")},
            {"operation", Value(operation)}});
        if (install) { minimum.as_object().erase("operation"); minimum.as_object().emplace("request_id", Value("recover.synthetic")); }
        auto recovery_broker = phase_broker;
        const auto minimum_sha = usk::json::sha256_canonical(minimum);
        recovery_broker.as_object().at("request_sha256") = Value(minimum_sha);
        recovery_broker.as_object().at("custody").as_object().at("request_sha256") = Value(minimum_sha);
        Value plan_request(Value::Object{{"schema", Value("usk." + operation + "_plan_request.v1")},
            {"plan_id", Value("plan.synthetic")}, {"install_id", minimum.at("install_id")}});
        if (install) plan_request.as_object().emplace("request_id", Value("plan.synthetic"));
        const Value apply(Value::Object{{"schema", Value("usk." + operation + "_apply_request.v1")},
            {"plan_request", plan_request}, {"reviewed_plan_id", Value("plan.synthetic")},
            {"reviewed_plan_digest", Value(std::string(64, 'e'))}, {"transaction_id", minimum.at("transaction_id")},
            {"applied_at", Value("2026-10-07T00:00:00Z")}, {"confirmation", Value("APPLY")}});
        const Value envelope(Value::Object{{"schema", Value(install ? "usk.publisher.lab_reviewed_plan_envelope.v2" :
            "usk.publisher.maintenance_reviewed_plan_envelope.v1")},
            {"activation", Value("operator_acceptance_candidate")}, {"state_root", Value("Q:\\setup")},
            {"acceptance_root", Value("Q:\\")}, {"plan_request", plan_request},
            {"reviewed_plan_digest", Value(std::string(64, 'e'))}, {"apply_request", apply}});
        const Value approval(Value::Object{{"schema", Value("usk.publisher_reviewed_operation_approval.v1")},
            {"request_sha256", Value(usk::json::sha256_canonical(apply))},
            {"registration_sha256", recovery_broker.at("registered_admission").at("registration_sha256")},
            {"target_admitted_sha256", recovery_broker.at("registered_admission").at("target_admitted_sha256")},
            {"caller_sid", Value(consumer_sid)}, {"envelope_sha256", Value(std::string(64, 'a'))},
            {"envelope_size_bytes", Value(static_cast<std::uint64_t>(usk::json::canonical(envelope).size()))}});
        // Use the actual native serializer and the controller-store policy,
        // rather than relabel SYSTEM/service target facts as enrollment files.
        const auto enrollment_file = [&](bool envelope_role) {
            PublisherHandleObservation facts{};
            facts.file_id = object_id(envelope_role ? 7 : 6);
            const auto digest = approval.at("request_sha256").as_string();
            facts.native_name = L"\\Program Files\\Universal Setup\\Publisher\\" + name + L".operation-" +
                std::wstring(digest.begin(), digest.end()) + (envelope_role ? L".envelope.json" : L".approval.json");
            facts.attributes = FILE_ATTRIBUTE_NORMAL;
            facts.link_count = 1;
            facts.owner_sid = "S-1-5-32-544";
            facts.dacl_protected = true;
            facts.dacl_aces = {{ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS, "S-1-5-18"},
                {ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS, "S-1-5-32-544"}};
            return publisher_handle_observation_json(facts);
        };
        const Value enrollment(Value::Object{{"schema", Value("usk.publisher_selected_reviewed_operation_observation.v1")},
            {"scope", Value("authenticated_exact_request_and_held_protected_enrollment_files")}, {"approval", approval},
            {"approval_sha256", Value(usk::json::sha256_canonical(approval))}, {"envelope_sha256", approval.at("envelope_sha256")},
            {"approval_file", enrollment_file(false)}, {"envelope_file", enrollment_file(true)}});
        const auto install_name = "install-" + usk::json::sha256_canonical(minimum.at("install_id"));
        const auto intent_name = "operation-" + usk::json::sha256_canonical(minimum.at("transaction_id")) + ".json";
        const std::string native_names[]{"\\", "\\installation-operations", "\\installation-operations\\" + install_name,
            "\\installation-operations\\" + install_name + "\\" + intent_name};
        const char* intent_roles[]{"volume", "operations", "install", "intent"};
        Value::Array original_chain;
        for (std::size_t index = 0; index != 4; ++index) {
            auto facts = object(index);
            facts.as_object().at("native_name") = Value(native_names[index]);
            if (index == 3) facts.as_object().at("attributes") = Value(std::uint64_t{FILE_ATTRIBUTE_NORMAL});
            original_chain.emplace_back(Value::Object{{"role", Value(intent_roles[index])}, {"object", facts},
                {"granted_access", Value(std::uint64_t{READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_DATA | SYNCHRONIZE})}});
        }
        const Value intent(Value::Object{{"schema", Value(install ? "usk.publisher_protected_original_installation_intent.v1" :
            "usk.publisher_protected_original_maintenance_intent.v1")},
            {"scope", Value("native_read_only_fixed_original_namespace")}, {"transport_request_sha256", Value(minimum_sha)},
            {"intent_context_sha256", Value(std::string(64, 'b'))}, {"intent_record_sha256", Value(std::string(64, 'c'))},
            {"original_apply_request", apply}, {"native_chain", Value(original_chain)}, {"volume_root_identity", lease_root}});
        const Value selection(Value::Object{{"schema", Value(install ? "usk.publisher_effect_original_installation_selection.v1" :
            "usk.publisher_effect_original_maintenance_selection.v1")},
            {"scope", Value("actual_minimal_request_to_native_protected_original_and_held_enrollment")}, {"present", Value(true)},
            {"intent", intent}, {"envelope", envelope}, {"observation", enrollment}});
        const auto validate_selection = [&](const Value& v, const Value& min) {
            if (install) require_publisher_effect_original_installation_selection(v, min, recovery_broker);
            else require_publisher_effect_original_maintenance_selection(v, min, recovery_broker);
        };
        validate_selection(selection, minimum);
        // New closed selection bracket: retained-data controls only. BOTH
        // original broker endpoints and the exact enrolled request must join;
        // a parsed tuple cannot manufacture the concrete native owner.
        auto fresh_broker = recovery_broker;
        const auto apply_sha = usk::json::sha256_canonical(apply);
        fresh_broker.as_object().at("request_sha256") = Value(apply_sha);
        fresh_broker.as_object().at("custody").as_object().at("request_sha256") = Value(apply_sha);
        const Value fresh_selection(Value::Object{{"schema", Value("usk.publisher_effect_selected_operation_readback.v1")},
            {"scope", Value("original_native_held_exact_request_selection")}, {"present", Value(true)},
            {"envelope", envelope}, {"observation", enrollment}});
        const Value fresh_reply(Value::Object{{"schema", Value("usk.publisher_effect_broker_readback_response.v5")},
            {"kind", Value("selected_operation_bracket")}, {"profile_before", fresh_broker},
            {"profile", fresh_broker}, {"result", fresh_selection}});
        require_publisher_effect_selection_readback(fresh_reply, apply);
        const Value recovery_reply(Value::Object{{"schema", Value("usk.publisher_effect_broker_readback_response.v5")},
            {"kind", Value(install ? "original_installation_recovery_bracket" : "original_maintenance_recovery_bracket")},
            {"profile_before", recovery_broker}, {"profile", recovery_broker}, {"result", selection}});
        require_publisher_effect_selection_readback(recovery_reply, minimum);
        // Closed v6 retained-data controls. Synthetic descriptors/results do
        // not claim a live token query, native owner, selection or effect.
        PSECURITY_DESCRIPTOR access_descriptor = nullptr;
        ULONG access_descriptor_size = 0;
        const auto access_sddl = "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;" + service_sid + ")";
        check(ConvertStringSecurityDescriptorToSecurityDescriptorA(access_sddl.c_str(), SDDL_REVISION_1,
            &access_descriptor, &access_descriptor_size) != FALSE, "synthetic grouped descriptor serialization failed");
        std::unique_ptr<void, decltype(&LocalFree)> access_descriptor_owner(access_descriptor, &LocalFree);
        std::string access_descriptor_hex;
        const auto* descriptor_data = static_cast<const unsigned char*>(access_descriptor);
        for (ULONG index = 0; index < access_descriptor_size; ++index) {
            access_descriptor_hex.push_back(digits[descriptor_data[index] >> 4]);
            access_descriptor_hex.push_back(digits[descriptor_data[index] & 15u]);
        }
        const std::vector<std::pair<const char*, DWORD>> denied_rights{
            {"write_or_add_file", FILE_WRITE_DATA}, {"append_or_add_directory", FILE_APPEND_DATA},
            {"write_ea", FILE_WRITE_EA}, {"delete_child", FILE_DELETE_CHILD},
            {"write_attributes", FILE_WRITE_ATTRIBUTES}, {"delete", DELETE},
            {"write_dac", WRITE_DAC}, {"write_owner", WRITE_OWNER}, {"maximum_allowed", MAXIMUM_ALLOWED}};
        const auto access_row = [&](const Value& native) {
            Value::Object checks;
            for (const auto& [right_name, mask] : denied_rights)
                checks.emplace(right_name, Value(Value::Object{{"requested", Value(static_cast<std::uint64_t>(mask))},
                    {"allowed", Value(false)}, {"granted", Value(std::uint64_t{0})}}));
            return Value(Value::Object{{"schema", Value("usk.publisher_authenticated_object_access.v1")},
                {"scope", Value("fresh_held_authenticated_token_and_file_descriptor")},
                {"client", client}, {"native_object", native},
                {"descriptor_api", Value("GetSecurityInfo:SE_FILE_OBJECT:OWNER_GROUP_DACL")},
                {"descriptor_hex", Value(access_descriptor_hex)}, {"observed_group_sid", Value("S-1-5-18")},
                {"checks", Value(std::move(checks))}});
        };
        const Value ordered_objects(Value::Array{object(2), object(0), object(2)});
        // A transported query-closed marker is only sequencing data. These
        // controls cannot invoke the private callback or create native proof.
        const Value marker_objects(Value::Array{object(2), object(2)});
        const auto marker_kind = std::string("object_access_batch_bracket");
        const Value marker(Value::Object{
            {"schema", Value("usk.publisher_effect_queries_closed.v1")}, {"kind", Value(marker_kind)},
            {"native_query_count", Value(std::uint64_t{2})},
            {"native_objects_sha256", Value(usk::json::sha256_canonical(marker_objects))}});
        require_publisher_effect_queries_closed_marker(marker, marker_kind, marker_objects);
        const auto marker_refused = [&](Value candidate, const std::string& kind, const Value& objects) {
            bool refused = false;
            try { require_publisher_effect_queries_closed_marker(candidate, kind, objects); }
            catch (const std::runtime_error&) { refused = true; }
            check(refused, "query-closed marker accepted a changed exchange binding");
        };
        for (const auto key : {"schema", "kind", "native_query_count", "native_objects_sha256"}) {
            auto missing = marker; missing.as_object().erase(key);
            marker_refused(std::move(missing), marker_kind, marker_objects);
        }
        auto unknown_marker = marker; unknown_marker.as_object().emplace("result", Value(Value::Array{}));
        marker_refused(std::move(unknown_marker), marker_kind, marker_objects);
        auto wrong_marker = marker; wrong_marker.as_object().at("schema") = Value("usk.publisher_effect_queries_closed.v2");
        marker_refused(std::move(wrong_marker), marker_kind, marker_objects);
        wrong_marker = marker; wrong_marker.as_object().at("native_query_count") = Value(std::uint64_t{1});
        marker_refused(std::move(wrong_marker), marker_kind, marker_objects);
        wrong_marker = marker; wrong_marker.as_object().at("native_objects_sha256") = Value(std::string(64, 'a'));
        marker_refused(std::move(wrong_marker), marker_kind, marker_objects);
        marker_refused(marker, "service_admission_bracket", marker_objects);
        marker_refused(marker, "selected_operation_object_access_batch_bracket", marker_objects);
        marker_refused(marker, marker_kind, Value(Value::Array{}));
        marker_refused(marker, marker_kind, Value(Value::Array(9, object(2))));
        auto changed_objects = marker_objects; changed_objects.as_array()[1].as_object().at("file_id") = Value("changed");
        marker_refused(marker, marker_kind, changed_objects);
        auto dropped_duplicate = marker_objects; dropped_duplicate.as_array().pop_back();
        marker_refused(marker, marker_kind, dropped_duplicate);
        // Independently cover closed selector families and both count bounds.
        for (const auto kind : {"object_access_batch_bracket", "selected_operation_object_access_batch_bracket",
            "original_maintenance_recovery_object_access_batch_bracket", "original_installation_recovery_object_access_batch_bracket"}) {
            for (const auto count : {std::size_t{1}, std::size_t{8}}) {
                const Value objects(Value::Array(count, object(2)));
                auto bound_marker = marker;
                bound_marker.as_object().at("kind") = Value(kind);
                bound_marker.as_object().at("native_query_count") = Value(static_cast<std::uint64_t>(count));
                bound_marker.as_object().at("native_objects_sha256") = Value(usk::json::sha256_canonical(objects));
                require_publisher_effect_queries_closed_marker(bound_marker, kind, objects);
            }
        }
        for (const auto count : {std::size_t{0}, std::size_t{9}}) {
            const Value objects(Value::Array(count, object(2)));
            auto bound_marker = marker;
            bound_marker.as_object().at("native_query_count") = Value(static_cast<std::uint64_t>(count));
            bound_marker.as_object().at("native_objects_sha256") = Value(usk::json::sha256_canonical(objects));
            marker_refused(std::move(bound_marker), marker_kind, objects);
        }
        auto ordered_marker = marker;
        ordered_marker.as_object().at("native_query_count") = Value(std::uint64_t{3});
        ordered_marker.as_object().at("native_objects_sha256") = Value(usk::json::sha256_canonical(ordered_objects));
        require_publisher_effect_queries_closed_marker(ordered_marker, marker_kind, ordered_objects);
        auto reordered_objects = ordered_objects;
        std::swap(reordered_objects.as_array()[0], reordered_objects.as_array()[1]);
        marker_refused(ordered_marker, marker_kind, reordered_objects);
        auto boolean_count = marker; boolean_count.as_object().at("native_query_count") = Value(true);
        marker_refused(std::move(boolean_count), marker_kind, marker_objects);
        const auto composed_reply = [&](const Value& selected_reply, bool recovery, const Value& objects) {
            auto result = selected_reply;
            result.as_object().at("schema") = Value("usk.publisher_effect_broker_readback_response.v6");
            result.as_object().at("kind") = Value(recovery ? (install ?
                "original_installation_recovery_object_access_batch_bracket" :
                "original_maintenance_recovery_object_access_batch_bracket") : "selected_operation_object_access_batch_bracket");
            result.as_object().emplace("selection", result.at("result"));
            Value::Array access;
            for (const auto& native : objects.as_array()) access.push_back(access_row(native));
            result.as_object().at("result") = Value(std::move(access));
            return result;
        };
        for (const bool recovery : {false, true}) {
            const auto& actual = recovery ? minimum : apply;
            const auto& selected_reply = recovery ? recovery_reply : fresh_reply;
            const auto composed = composed_reply(selected_reply, recovery, ordered_objects);
            const auto original_composed = usk::json::canonical(composed);
            require_publisher_effect_selected_object_access_batch_readback(composed, actual, ordered_objects);
            check(usk::json::canonical(composed) == original_composed,
                "selected access validation changed the retained raw proof");
            Value::Array eight;
            for (std::size_t index = 0; index < publisher_object_access_batch_limit; ++index) eight.push_back(object(index % 3));
            const Value bound(eight);
            require_publisher_effect_selected_object_access_batch_readback(composed_reply(selected_reply, recovery, bound), actual, bound);
            const auto refuses_composed = [&](const std::function<void(Value&)>& mutate) {
                auto invalid = composed; mutate(invalid); bool refused = false;
                try { require_publisher_effect_selected_object_access_batch_readback(invalid, actual, ordered_objects); }
                catch (const std::exception&) { refused = true; }
                check(refused, "synthetic selected access accepted incomplete or contradictory ordered proof");
            };
            for (const auto* key : {"selection", "profile_before", "profile", "result"})
                refuses_composed([&](Value& v) { v.as_object().erase(key); });
            refuses_composed([](Value& v) { v.as_object().emplace("authority", Value("effect")); });
            refuses_composed([](Value& v) { v.as_object().at("schema") = Value("usk.publisher_effect_broker_readback_response.v3"); });
            refuses_composed([](Value& v) { v.as_object().at("kind") = Value("object_access_batch_bracket"); });
            refuses_composed([](Value& v) { v.as_object().at("kind") = Value("original_installation_recovery_bracket"); });
            refuses_composed([](Value& v) { v.as_object().at("result").as_array().pop_back(); });
            refuses_composed([](Value& v) { std::swap(v.as_object().at("result").as_array()[0], v.as_object().at("result").as_array()[1]); });
            refuses_composed([](Value& v) { v.as_object().at("result").as_array()[1] = v.at("result").as_array()[0]; });
            refuses_composed([](Value& v) { v.as_object().at("result").as_array()[0].as_object().at("client")
                .as_object().at("token_id") = Value(std::uint64_t{803}); });
            refuses_composed([](Value& v) { v.as_object().at("result").as_array()[0].as_object().at("descriptor_hex") = Value("00"); });
            refuses_composed([](Value& v) { v.as_object().at("result").as_array()[0].as_object()
                .emplace("unexpected_retained_field", Value("must not be discarded")); });
            refuses_composed([](Value& v) { v.as_object().at("result").as_array()[0].as_object()
                .emplace("client_sha256", Value(std::string(64, 'f'))); });
            refuses_composed([](Value& v) { v.as_object().at("result").as_array()[0].as_object()
                .emplace("native_object_sha256", Value(std::string(64, 'f'))); });
            refuses_composed([](Value& v) { v.as_object().at("selection").as_object().at("present") = Value(false); });
            refuses_composed([](Value& v) { v.as_object().at("selection").as_object().at("envelope")
                .as_object().at("reviewed_plan_digest") = Value(std::string(64, 'f')); });
            for (const auto* endpoint : {"profile_before", "profile"}) {
                refuses_composed([&](Value& v) { v.as_object().at(endpoint).as_object().at("custody")
                    .as_object().at("peer_process_birth") = Value("0000000000000601"); });
                refuses_composed([&](Value& v) { v.as_object().at(endpoint).as_object().at("service_configuration")
                    .as_object().at("command") = Value("forged"); });
                refuses_composed([&](Value& v) { v.as_object().at(endpoint).as_object().at("request_sha256") = Value(std::string(64, 'f')); });
                refuses_composed([&](Value& v) { v.as_object().at(endpoint).as_object().at("registered_admission")
                    .as_object().at("registration_sha256") = Value(std::string(64, 'f')); });
            }
            for (const auto& [right_name, mask] : denied_rights) {
                (void)mask;
                refuses_composed([&](Value& v) { v.as_object().at("result").as_array()[0].as_object().at("checks")
                    .as_object().erase(right_name); });
                refuses_composed([&](Value& v) { v.as_object().at("result").as_array()[0].as_object().at("checks")
                    .as_object().at(right_name).as_object().at("granted") = Value(std::uint64_t{1} << 32); });
            }
            if (recovery) refuses_composed([](Value& v) { v.as_object().at("selection").as_object().at("intent")
                .as_object().at("original_apply_request").as_object().at("transaction_id") = Value("another.original"); });
            for (const Value& outside : {Value(Value::Array{}), Value(Value::Array(9, object(0)))}) {
                bool refused = false;
                try { require_publisher_effect_selected_object_access_batch_readback(
                    composed_reply(selected_reply, recovery, outside), actual, outside); }
                catch (const std::exception&) { refused = true; }
                check(refused, "synthetic selected access widened max-eight or accepted empty batch");
            }
        }
        const auto refuses_bracket = [&](const Value& original_reply, const Value& actual,
            const std::function<void(Value&)>& mutate) {
            auto invalid = original_reply; mutate(invalid); bool refused = false;
            try { require_publisher_effect_selection_readback(invalid, actual); }
            catch (const std::exception&) { refused = true; }
            check(refused, "synthetic selected bracket accepted contradictory native/enrollment binding");
        };
        refuses_bracket(fresh_reply, apply, [](Value& v) { v.as_object().erase("profile_before"); });
        refuses_bracket(fresh_reply, apply, [](Value& v) {
            v.as_object().at("schema") = Value("usk.publisher_effect_broker_readback_response.v4"); });
        refuses_bracket(fresh_reply, apply, [](Value& v) { v.as_object().at("kind") = Value("service_admission_bracket"); });
        refuses_bracket(fresh_reply, apply, [](Value& v) { v.as_object().emplace("authority", Value("effect")); });
        refuses_bracket(fresh_reply, apply, [](Value& v) {
            v.as_object().at("profile_before").as_object().at("custody").as_object().at("peer_process_birth") =
                Value("0000000000000601"); });
        // The broker now completes one native packet bracket. Changes in any
        // retained immutable family must still fail at either endpoint. These
        // are record controls, not a claim of native interval coverage.
        for (const char* endpoint : {"profile_before", "profile"}) {
            refuses_bracket(fresh_reply, apply, [&](Value& v) {
                v.as_object().at(endpoint).as_object().at("service_configuration").as_object().at("display_name") =
                    Value("changed original service"); });
            refuses_bracket(fresh_reply, apply, [&](Value& v) {
                v.as_object().at(endpoint).as_object().at("registered_admission").as_object().at("registration_sha256") =
                    Value(std::string(64, 'a')); });
            refuses_bracket(fresh_reply, apply, [&](Value& v) {
                v.as_object().at(endpoint).as_object().at("volume_root").as_object().at("file_id") =
                    Value("0000000000001234:" + std::string(31, '0') + "4"); });
            refuses_bracket(fresh_reply, apply, [&](Value& v) {
                v.as_object().at(endpoint).as_object().at("broker_volume_granted_access") =
                    Value(std::uint64_t{FILE_ALL_ACCESS}); });
            refuses_bracket(fresh_reply, apply, [&](Value& v) {
                v.as_object().at(endpoint).as_object().at("broker_security").as_object().at("process_boundary")
                    .as_object().emplace("authority", Value("effect")); });
            refuses_bracket(recovery_reply, minimum, [&](Value& v) {
                v.as_object().at(endpoint).as_object().at("service_configuration").as_object().at("display_name") =
                    Value("changed original recovery service"); });
        }
        // Identical endpoints with a changed registration still cannot rebind
        // the unchanged original approval to a different admitted registration.
        refuses_bracket(fresh_reply, apply, [](Value& v) {
            for (const auto key : {"profile_before", "profile"})
                v.as_object().at(key).as_object().at("registered_admission").as_object().at("registration_sha256") =
                    Value(std::string(64, 'a')); });
        refuses_bracket(recovery_reply, minimum, [](Value& v) {
            v.as_object().at("result").as_object().at("intent").as_object().at("original_apply_request").as_object()
                .at("transaction_id") = Value("different.original"); });
        refuses_bracket(recovery_reply, minimum, [](Value& v) {
            v.as_object().at("kind") = Value("selected_operation_bracket"); });
        auto reordered = selection;
        for (const auto role : {"approval_file", "envelope_file"}) {
            auto& aces = reordered.as_object().at("observation").as_object().at(role).as_object().at("dacl_aces").as_array();
            const auto first = aces.at(0); aces.at(0) = aces.at(1); aces.at(1) = first;
        }
        validate_selection(reordered, minimum); // Both orders satisfy the original controller policy.
        const auto refuses_selection = [&](const std::function<void(Value&)>& mutate) {
            auto changed = selection; mutate(changed); bool refused = false;
            try { validate_selection(changed, minimum); }
            catch (const std::exception&) { refused = true; }
            check(refused, "synthetic original recovery selection accepted contradictory selection");
        };
        refuses_selection([](Value& v) { v.as_object().at("schema") = Value("usk.publisher_effect_selected_operation_readback.v1"); });
        refuses_selection([](Value& v) { v.as_object().emplace("selector", Value("caller-controlled")); });
        refuses_selection([](Value& v) { v.as_object().at("intent").as_object().at("transport_request_sha256") = Value(std::string(64, 'a')); });
        refuses_selection([](Value& v) { v.as_object().at("intent").as_object().at("original_apply_request").as_object()
            .at("transaction_id") = Value("other.original"); });
        refuses_selection([](Value& v) { v.as_object().at("intent").as_object().at("original_apply_request").as_object()
            .at("plan_request").as_object().at("install_id") = Value("other.install"); });
        refuses_selection([](Value& v) { v.as_object().at("intent").as_object().at("native_chain").as_array().at(2)
            .as_object().at("object").as_object().at("native_name") = Value("\\installation-operations\\install-other"); });
        refuses_selection([](Value& v) { v.as_object().at("intent").as_object().at("native_chain").as_array().at(3)
            .as_object().at("granted_access") = Value(std::uint64_t{FILE_ALL_ACCESS}); });
        refuses_selection([](Value& v) { v.as_object().at("intent").as_object().at("native_chain").as_array().at(3)
            .as_object().at("object").as_object().at("owner_sid") = Value(consumer_sid); });
        refuses_selection([](Value& v) { v.as_object().at("intent").as_object().at("native_chain").as_array().at(3)
            .as_object().at("object").as_object().at("file_id") = Value("0000000000001234:" + std::string(31, '0') + "3"); });
        refuses_selection([](Value& v) { v.as_object().at("observation").as_object().at("approval").as_object()
            .at("caller_sid") = Value("S-1-5-21-1-2-3-1002"); });
        refuses_selection([](Value& v) { v.as_object().at("envelope").as_object().at("apply_request").as_object()
            .at("transaction_id") = Value("other.enrollment"); });
        for (const auto role : {"approval_file", "envelope_file"}) {
            const auto refuses_enrollment = [&](const std::function<void(Value&)>& mutate) {
                refuses_selection([&](Value& v) { mutate(v.as_object().at("observation").as_object().at(role)); });
            };
            refuses_enrollment([](Value& f) { f.as_object().at("owner_sid") = Value("S-1-5-18"); });
            refuses_enrollment([](Value& f) { f.as_object().at("dacl_protected") = Value(false); });
            refuses_enrollment([](Value& f) { f.as_object().at("attributes") = Value(std::uint64_t{FILE_ATTRIBUTE_DIRECTORY}); });
            refuses_enrollment([](Value& f) { f.as_object().at("attributes") = Value(std::uint64_t{0x100000000ull}); });
            refuses_enrollment([](Value& f) { f.as_object().at("reparse_tag") = Value(std::uint64_t{1}); });
            refuses_enrollment([](Value& f) { f.as_object().at("link_count") = Value(std::uint64_t{2}); });
            refuses_enrollment([](Value& f) { f.as_object().at("case_sensitive") = Value(true); });
            refuses_enrollment([](Value& f) { f.as_object().at("file_id") = Value(std::string(49, 'z')); });
            refuses_enrollment([](Value& f) { f.as_object().at("native_name") = Value("\\Program Files\\Universal Setup\\Publisher\\other.approval.json"); });
            refuses_enrollment([](Value& f) { f.as_object().at("native_name") = Value(std::string("Q:\\..\\") + f.at("native_name").as_string()); });
            refuses_enrollment([](Value& f) { f.as_object().at("native_name") = Value(std::string("\\..") + f.at("native_name").as_string()); });
            refuses_enrollment([](Value& f) { auto n = f.at("native_name").as_string(); n.insert(1, 1, '\0'); f.as_object().at("native_name") = Value(n); });
            refuses_enrollment([](Value& f) { f.as_object().emplace("authority", Value("native")); });
            refuses_enrollment([](Value& f) { f.as_object().at("dacl_aces").as_array().push_back(f.at("dacl_aces").as_array().front()); });
            refuses_enrollment([](Value& f) { f.as_object().at("dacl_aces").as_array().front().as_object().at("type") = Value(std::uint64_t{ACCESS_DENIED_ACE_TYPE}); });
            refuses_enrollment([](Value& f) { f.as_object().at("dacl_aces").as_array().front().as_object().at("flags") = Value(std::uint64_t{INHERITED_ACE}); });
            refuses_enrollment([](Value& f) { f.as_object().at("dacl_aces").as_array().front().as_object().at("access_mask") = Value(std::uint64_t{FILE_GENERIC_READ}); });
            refuses_enrollment([](Value& f) { f.as_object().at("dacl_aces").as_array().front().as_object().at("sid") = Value(service_sid); });
            refuses_enrollment([](Value& f) { f.as_object().at("dacl_aces").as_array().front() = f.at("dacl_aces").as_array().back(); });
            refuses_enrollment([](Value& f) { f.as_object().at("dacl_aces").as_array().front().as_object().emplace("extra", Value(true)); });
        }
        refuses_selection([](Value& v) { v.as_object().at("observation").as_object().at("envelope_file").as_object().at("file_id") =
            v.at("observation").at("approval_file").at("file_id"); });
        refuses_selection([](Value& v) { v.as_object().at("observation").as_object().at("approval_file").as_object().at("native_name") =
            v.at("observation").at("envelope_file").at("native_name"); });
        auto absent = selection;
        absent.as_object().at("present") = Value(false);
        refuses_selection([](Value& v) { v.as_object().at("present") = Value(false); });
        absent.as_object().erase("intent"); absent.as_object().erase("envelope"); absent.as_object().erase("observation");
        validate_selection(absent, minimum);
        auto supplied_minimum = minimum;
        supplied_minimum.as_object().emplace("original_apply_request", apply);
        bool supplied_minimum_refused = false;
        try { validate_selection(selection, supplied_minimum); }
        catch (const std::exception&) { supplied_minimum_refused = true; }
        check(supplied_minimum_refused, "minimal recovery accepted a supplied original selector");
    }
    auto phase_execution = valid;
    phase_execution.as_object().at("broker_readback") = phase_broker;
    phase_execution.as_object().at("handles").as_array().at(3).as_object().at("granted_access") =
        Value(std::uint64_t{READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_ADD_SUBDIRECTORY});
    phase_execution.as_object().at("handles").as_array().at(6).as_object().at("granted_access") =
        Value(std::uint64_t{READ_CONTROL | FILE_READ_ATTRIBUTES | DELETE});
    auto phase_certificate = certificate;
    phase_certificate.as_object().at("broker_readback") = phase_broker;
    const Value descendants(Value::Object{{"schema", Value("usk.publisher_authenticated_descendant_access.v1")},
        {"scope", Value("fresh_held_descriptors_for_bound_tree_no_content_rehash")},
        {"client_sha256", Value(usk::json::sha256_canonical(client))}, {"objects", Value(Value::Array{})}});
    const auto phase = [&](const char* label, const Value& bound_tree) {
        auto execution = phase_execution;
        execution.as_object().at("phase") = Value(label);
        auto& payload = execution.as_object().at("handles").as_array().at(6).as_object();
        payload.at("object_observation") = bound_tree.at("root");
        payload.at("authenticated_access").as_object().at("native_object_sha256") =
            Value(usk::json::sha256_canonical(bound_tree.at("root")));
        return Value(Value::Object{{"execution", execution},
            {"protected_anchors_sha256", Value(usk::json::sha256_canonical(anchors))},
            {"tree_sha256", Value(usk::json::sha256_canonical(bound_tree))}, {"authenticated_descendants", descendants}});
    };
    const Value operation_admission(Value::Object{{"schema", Value("usk.publisher_operation_admission.v1")},
        {"scope", Value("live_registered_request_and_held_volume_before_effects")},
        {"route", Value("registered_service_admitted_production")}, {"service_name", service.at("service_name")},
        {"service_sid", Value(service_sid)}, {"service_process_id", Value(std::uint64_t{500})},
        {"configured_caller_sid", Value(consumer_sid)}, {"authenticated_client_sha256", Value(usk::json::sha256_canonical(client))},
        {"captured_client_process_id", client.at("captured_process_id")}, {"registration_sha256", admitted.at("registration_sha256")},
        {"target_admitted_sha256", admitted.at("target_admitted_sha256")}, {"publisher_image_sha256", image.at("sha256")},
        {"volume_guid_root", Value(volume_guid)}, {"root_file_id", Value(object_id(0))}, {"volume_serial", Value(std::uint64_t{4660})},
        {"reviewed_plan_digest", Value(std::string(64, 'e'))}, {"reviewed_plan_snapshot_sha256", Value(std::string(64, 'f'))},
        {"transaction_id", Value("install.synthetic")}});
    const Value prepared(Value::Object{{"schema", Value("usk.publisher.lab_phase_evidence.v10")},
        {"phase", Value("lab_prepared_evidence")}, {"service_sid", Value(service_sid)}, {"volume_serial", Value(std::uint64_t{4660})},
        {"source_file_id", Value(object_id(6))}, {"destination_parent_file_id", Value(object_id(3))}, {"destination_name", Value("visible")},
        {"selected_file_set_digest", Value(std::string(64, 'a'))}, {"source_binding", Value(Value::Object{
            {"reviewed_plan_digest", Value(std::string(64, 'e'))}, {"reviewed_plan_snapshot_sha256", Value(std::string(64, 'f'))},
            {"plan_envelope_sha256", Value(std::string(64, 'a'))}})}, {"protected_anchors", anchors}, {"sealed_tree", tree},
        {"execution_origin", Value("created_empty_in_current_worker")}, {"operation_admission", operation_admission},
        {"creation_evidence", phase_certificate}, {"execution_phases", Value(Value::Array{
            phase("protected_empty", tree), phase("sealed", tree), phase("publish_prepared", tree)})}});
    auto visible_tree = tree;
    visible_tree.as_object().at("root").as_object().at("native_name") = Value("\\publication\\role3\\visible");
    const Value rename(Value::Object{{"schema", Value("usk.publisher_bound_rename_call.v2")}, {"api", Value("NtSetInformationFile")},
        {"source_file_id", Value(object_id(6))}, {"destination_parent_file_id", Value(object_id(3))}, {"destination_component", Value("visible")},
        {"former_name", tree.at("root").at("native_name")}, {"visible_name", visible_tree.at("root").at("native_name")},
        {"destination_absence_status", Value(std::uint64_t{0xc0000034u})}, {"information_class", Value(std::uint64_t{10})},
        {"information_bytes", Value(static_cast<std::uint64_t>(sizeof(FILE_RENAME_INFO) + 14))}, {"file_name_bytes", Value(std::uint64_t{14})},
        {"replace_if_exists", Value(false)}, {"native_status", Value(std::uint64_t{0})}, {"io_status", Value(std::uint64_t{0})},
        {"source_granted_access", phase_execution.at("handles").as_array().at(6).at("granted_access")},
        {"destination_parent_granted_access", phase_execution.at("handles").as_array().at(3).at("granted_access")},
        {"handle_access_api", Value("NtQueryObject:ObjectBasicInformation")}, {"clock", Value("qpc")},
        {"start_tick", Value(std::uint64_t{100})}, {"end_tick", Value(std::uint64_t{110})}, {"frequency", Value(std::uint64_t{1000})}});
    const Value visible(Value::Object{{"schema", Value("usk.publisher.lab_phase_evidence.v10")}, {"phase", Value("lab_visible_evidence")},
        {"source_file_id", Value(object_id(6))}, {"destination_parent_file_id", Value(object_id(3))}, {"destination_name", Value("visible")},
        {"selected_file_set_digest", Value(std::string(64, 'a'))}, {"prepared_record_sha256", Value(std::string(64, 'b'))},
        {"protected_anchors", anchors}, {"visible_tree", visible_tree}, {"execution_transition", Value("renamed_by_current_worker")},
        {"rename_call", rename}, {"execution_phases", Value(Value::Array{phase("before_rename", tree), phase("visible_bound", visible_tree)})}});
    require_candidate_publisher_execution_records(prepared, visible, name, service_sid);
    // New family carries explicit original-held retirement partitions. These
    // synthetic records qualify only the reader joins, never actual creation.
    auto current_prepared = prepared, current_visible = visible;
    current_prepared.as_object().at("schema") = Value("usk.publisher.lab_phase_evidence.v11");
    current_visible.as_object().at("schema") = Value("usk.publisher.lab_phase_evidence.v11");
    auto original_child_security = child_security;
    auto original_helper = original_child_security.at("threads").as_array().front();
    original_helper.as_object().at("thread_id") = Value(std::uint64_t{701});
    original_helper.as_object().at("creation_time") = Value("0000000000000701");
    original_child_security.as_object().at("threads").as_array().push_back(original_helper);
    const auto initial_security = retirement_security(original_child_security);
    const auto completed_security = retirement_security(original_child_security, {701});
    for (auto* record : {&current_prepared, &current_visible})
        for (auto& item : record->as_object().at("execution_phases").as_array()) {
            auto& execution = item.as_object().at("execution").as_object();
            execution.at("schema") = Value("usk.publisher_execution_observation.v8");
            execution.at("scope") = Value("supplied_held_child_handles_authenticated_broker_access_and_native_retirement_partition");
            execution.at("worker_security") = item.at("execution").at("phase").as_string() == "protected_empty" ?
                initial_security : completed_security;
        }
    auto& current_certificate = current_prepared.as_object().at("creation_evidence").as_object();
    current_certificate.at("schema") = Value("usk.publisher.creation_observation.v5");
    current_certificate.at("scope") = Value("successful_child_file_create_calls_and_original_native_retirement_partition_to_bound_graph");
    current_certificate.at("worker_security") = initial_security;
    current_certificate.emplace("completed_worker_security", completed_security);
    require_candidate_publisher_execution_records(current_prepared, current_visible, name, service_sid);
    // ACTUAL producer order: empty -> sealed -> certificate current -> prepared
    // -> visible. Growing broker history must not be compared backwards.
    auto lifetime_prepared = current_prepared, lifetime_visible = current_visible;
    auto original_broker_security = worker_security();
    const auto initial_broker = broker_lifetime_security(original_broker_security);
    auto broker_helper = original_broker_security.at("threads").as_array().front();
    broker_helper.as_object().at("thread_id") = Value(std::uint64_t{701});
    broker_helper.as_object().at("creation_time") = Value("0000000000000701");
    original_broker_security.as_object().at("threads").as_array().push_back(broker_helper);
    const auto sealed_broker = broker_lifetime_security(original_broker_security);
    const auto certificate_broker = broker_lifetime_security(original_broker_security, {701});
    broker_helper.as_object().at("thread_id") = Value(std::uint64_t{702});
    broker_helper.as_object().at("creation_time") = Value("0000000000000702");
    original_broker_security.as_object().at("threads").as_array().push_back(broker_helper);
    const auto prepared_broker = broker_lifetime_security(original_broker_security, {701});
    const auto visible_broker = broker_lifetime_security(original_broker_security, {701, 702});
    auto future_security = original_broker_security;
    broker_helper.as_object().at("thread_id") = Value(std::uint64_t{703});
    broker_helper.as_object().at("creation_time") = Value("0000000000000703");
    future_security.as_object().at("threads").as_array().push_back(broker_helper);
    const auto future_broker = broker_lifetime_security(future_security, {701});
    const auto set_broker = [](Value& broker, const Value& security) {
        broker.as_object().at("schema") = Value("usk.publisher_effect_broker_native_readback.v3");
        broker.as_object().at("broker_security").as_object().at("worker_security") = security;
    };
    auto& lifetime_phases = lifetime_prepared.as_object().at("execution_phases").as_array();
    for (std::size_t index = 0; index != 3; ++index)
        set_broker(lifetime_phases[index].as_object().at("execution").as_object().at("broker_readback"),
            index == 0 ? initial_broker : index == 1 ? sealed_broker : prepared_broker);
    set_broker(lifetime_prepared.as_object().at("creation_evidence").as_object().at("broker_readback"), certificate_broker);
    for (auto& item : lifetime_visible.as_object().at("execution_phases").as_array())
        set_broker(item.as_object().at("execution").as_object().at("broker_readback"), visible_broker);
    require_candidate_publisher_execution_records(lifetime_prepared, lifetime_visible, name, service_sid);
    for (const auto& wrong : {initial_broker, sealed_broker, visible_broker, future_broker}) {
        auto invalid = lifetime_prepared;
        set_broker(invalid.as_object().at("creation_evidence").as_object().at("broker_readback"), wrong);
        bool refused = false;
        try { require_candidate_publisher_execution_records(invalid, lifetime_visible, name, service_sid); }
        catch (const std::exception&) { refused = true; }
        // sealed is allowed at certificate if retirement occurs later; only
        // earlier omission and future retirement violate adjacent history.
        if (usk::json::canonical(wrong) != usk::json::canonical(sealed_broker))
            check(refused, "broker certificate omitted an admitted original or claimed future retirement");
        else check(!refused, "broker certificate required retirement before it actually occurred");
    }
    auto revived_prepared = lifetime_prepared;
    set_broker(revived_prepared.as_object().at("execution_phases").as_array().back().as_object()
        .at("execution").as_object().at("broker_readback"), broker_lifetime_security(original_broker_security));
    bool revival_refused = false;
    try { require_candidate_publisher_execution_records(revived_prepared, lifetime_visible, name, service_sid); }
    catch (const std::exception&) { revival_refused = true; }
    check(revival_refused, "broker publication revived a certificate's retired original");
    const auto refuses_current = [&](const std::function<void(Value&, Value&)>& change) {
        auto p = current_prepared, v = current_visible; change(p, v); bool refused = false;
        try { require_candidate_publisher_execution_records(p, v, name, service_sid); }
        catch (const std::exception&) { refused = true; }
        check(refused, "current native phase/certificate admitted missing retirement proof or original broker joins");
    };
    refuses_current([](Value& p, Value&) { p.as_object().at("creation_evidence").as_object().erase("completed_worker_security"); });
    refuses_current([](Value& p, Value&) { p.as_object().at("creation_evidence").as_object().at("schema") = Value("usk.publisher.creation_observation.v4"); });
    refuses_current([](Value& p, Value&) { p.as_object().at("execution_phases").as_array().back().as_object().at("execution").as_object().at("worker_security") =
        p.at("execution_phases").as_array().front().at("execution").at("worker_security"); });
    refuses_current([](Value& p, Value& v) { p.as_object().at("schema") = Value("usk.publisher.lab_phase_evidence.v10"); v.as_object().at("schema") = p.at("schema"); });
    // Retirement evidence keeps the v10 registration/image/target/envelope
    // joins. These forged admissions must fail against the original broker.
    refuses_current([](Value& p, Value&) { p.as_object().at("operation_admission") = Value{}; });
    for (const char* key : {"registration_sha256", "target_admitted_sha256", "publisher_image_sha256"})
        refuses_current([&](Value& p, Value&) { p.as_object().at("operation_admission").as_object().at(key) = Value(std::string(64, '1')); });
    refuses_current([](Value& p, Value&) { p.as_object().at("source_binding").as_object().at("plan_envelope_sha256") = Value(std::string(64, '1')); });
    const auto refuses_phases = [&](const std::function<void(Value&, Value&)>& change) {
        auto changed_prepared = prepared, changed_visible = visible;
        change(changed_prepared, changed_visible); bool refused = false;
        try { require_candidate_publisher_execution_records(changed_prepared, changed_visible, name, service_sid); }
        catch (const std::exception&) { refused = true; }
        check(refused, "synthetic v10 accepted changed native child/creator/operation/phase joins");
    };
    refuses_phases([](Value& p, Value&) { p.as_object().at("operation_admission") = Value{}; });
    refuses_phases([](Value& p, Value&) { p.as_object().at("operation_admission").as_object().at("service_process_id") = Value(std::uint64_t{600}); });
    for (const char* key : {"registration_sha256", "target_admitted_sha256", "publisher_image_sha256", "volume_guid_root"})
        refuses_phases([&](Value& p, Value&) { p.as_object().at("operation_admission").as_object().at(key) = Value(std::string(64, '1')); });
    refuses_phases([](Value& p, Value&) { p.as_object().at("source_binding").as_object().at("plan_envelope_sha256") = Value(std::string(64, '1')); });
    refuses_phases([](Value& p, Value&) { p.as_object().at("creation_evidence").as_object().at("schema") = Value("usk.publisher.creation_observation.v3"); });
    refuses_phases([](Value& p, Value& v) { p.as_object().at("schema") = Value("usk.publisher.lab_phase_evidence.v9"); v.as_object().at("schema") = p.at("schema"); });
    refuses_phases([](Value&, Value& v) { v.as_object().at("execution_phases").as_array().back().as_object().at("execution")
        .as_object().at("effect_worker").as_object().at("process_birth") = Value("0000000000000601"); });
    const auto refuses_certificate = [&](const std::function<void(Value&)>& change) {
        auto invalid = certificate; change(invalid); bool refused = false;
        try { require_publisher_creation_certificate(invalid, anchors, tree, valid); }
        catch (const std::exception&) { refused = true; }
        check(refused, "child creation certificate admitted changed native creator/broker/graph facts");
    };
    refuses_certificate([](Value& v) { v.as_object().at("creator").as_object().at("effect_worker").as_object().at("process_id") = Value(std::uint64_t{500}); });
    refuses_certificate([](Value& v) { v.as_object().at("creator").as_object().at("broker_process_id") = Value(std::uint64_t{600}); });
    refuses_certificate([](Value& v) { v.as_object().at("worker_security") = worker_security(); });
    refuses_certificate([](Value& v) { v.as_object().at("schema") = Value("usk.publisher.creation_observation.v3"); });
    refuses_certificate([](Value& v) { v.as_object().at("native_call").as_object().at("creation_result") = Value(std::uint64_t{1}); });
    refuses_certificate([](Value& v) { v.as_object().at("broker_readback").as_object().at("request_sha256") = Value(std::string(64, 'e')); });
    const auto refuses = [&](const std::function<void(Value&)>& change) {
        auto invalid = valid; change(invalid); bool refused = false;
        try { require_publisher_execution_phase(invalid, name, service_sid, "sealed", bindings); }
        catch (const std::exception&) { refused = true; }
        check(refused, "compound execution parser accepted a contradictory child/broker binding");
    };
    refuses([](Value& v) { v.as_object().at("process_boundary") = boundary(); });
    refuses([](Value& v) { v.as_object().at("worker_security") = worker_security(); });
    refuses([](Value& v) { v.as_object().at("effect_worker").as_object().at("process_id") = Value(std::uint64_t{500}); });
    refuses([](Value& v) { v.as_object().at("effect_worker").as_object().at("process_birth") = Value("0000000000000601"); });
    refuses([](Value& v) { v.as_object().at("service").as_object().at("process_id") = Value(std::uint64_t{600}); });
    refuses([](Value& v) { v.as_object().at("broker_readback").as_object().at("authority") = Value("effect_admission"); });
    refuses([](Value& v) { v.as_object().at("broker_readback").as_object().at("broker_volume_granted_access") = Value(std::uint64_t{FILE_ALL_ACCESS}); });
    refuses([](Value& v) { v.as_object().at("broker_readback").as_object().at("service_configuration").as_object().at("command") = Value("forged"); });
    refuses([](Value& v) { v.as_object().at("broker_readback").as_object().at("broker_security").as_object().at("worker_security")
        .as_object().at("threads").as_array().front().as_object().at("dacl_aces").as_array().back().as_object().at("access_mask") = Value(std::uint64_t{THREAD_SET_CONTEXT}); });
    refuses([](Value& v) { v.as_object().at("handles").as_array().back().as_object().at("authenticated_access")
        .as_object().at("checks").as_object().at("write_dac").as_object().at("allowed") = Value(true); });
    // A separately validated current broker thread population is allowed;
    // the child's original frozen continuity is never replaced by this data.
    auto later = valid;
    auto& parent_threads = later.as_object().at("broker_readback").as_object().at("broker_security").as_object()
        .at("worker_security").as_object().at("threads").as_array();
    auto parent_thread = parent_threads.front();
    parent_thread.as_object().at("thread_id") = Value(std::uint64_t{701});
    parent_thread.as_object().at("creation_time") = Value("0000000000000701");
    parent_threads.push_back(parent_thread);
    require_publisher_execution_phase(later, name, service_sid, "sealed", bindings);
    require_publisher_execution_worker_match(valid, later);
    later = valid;
    later.as_object().at("worker_security").as_object().at("threads").as_array().push_back(parent_thread);
    require_publisher_execution_phase(later, name, service_sid, "sealed", bindings);
    bool refused = false;
    try { require_publisher_execution_worker_match(valid, later); } catch (const std::exception&) { refused = true; }
    check(refused, "same child record refreshed its original frozen thread population");
    later = valid;
    later.as_object().at("effect_worker").as_object().at("primary_token").as_object().at("token_id") = Value(std::uint64_t{0x602});
    refused = false;
    try { require_publisher_execution_record_continuity(valid, later); } catch (const std::exception&) { refused = true; }
    check(refused, "same native child PID/birth evaded continuity with a changed token");
}
class TestThread {
public:
    explicit TestThread(LPTHREAD_START_ROUTINE routine = nullptr, void* parameter = nullptr) {
        stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        check(stop_ != nullptr, "test thread release event unavailable");
        thread_ = CreateThread(nullptr, 0, routine ? routine : wait_for_release,
            routine ? parameter : stop_, 0, &id_);
        if (!thread_) { CloseHandle(stop_); throw std::runtime_error("test helper thread unavailable"); }
    }
    ~TestThread() {
        if (!SetEvent(stop_) || WaitForSingleObject(thread_, 5000u) != WAIT_OBJECT_0) {
            std::cerr << "test helper still active; fail-stop before releasing its dependencies\n";
            std::_Exit(1);
        }
        CloseHandle(thread_); CloseHandle(stop_);
    }
    TestThread(const TestThread&) = delete;
    TestThread& operator=(const TestThread&) = delete;
    HANDLE handle() const { return thread_; }
    static std::uintptr_t default_start_address() {
        return reinterpret_cast<std::uintptr_t>(&wait_for_release);
    }
    DWORD id() const { return id_; }
    void retire() {
        check(SetEvent(stop_) && WaitForSingleObject(thread_, 5000u) == WAIT_OBJECT_0,
            "actual test thread did not end");
    }
private:
    static DWORD WINAPI wait_for_release(void* parameter) {
        return WaitForSingleObject(static_cast<HANDLE>(parameter), INFINITE) == WAIT_OBJECT_0 ? 0u : 1u;
    }
    HANDLE stop_ = nullptr, thread_ = nullptr;
    DWORD id_ = 0;
};
class TestQueryDenialContext {
public:
    TestQueryDenialContext() {
        HANDLE raw = nullptr;
        check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &raw),
            "test query-denial process token unavailable");
        token_.reset(raw);
        check(LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &debug_) != FALSE,
            "test query-denial debug privilege identity unavailable");
        original_ = privileges();
    }
    ~TestQueryDenialContext() {
        if (changed_ && !restore()) std::cerr << "test query-denial privilege restoration failed\n";
    }
    void disable_checked() {
        // Only this ordinary test process is changed. An enabled debug
        // privilege bypasses OpenThread DACL checks; never skip the denial.
        check(privileges() == original_, "test query-denial privileges changed before setup");
        const auto found = original_.find(key(debug_));
        if (found != original_.end() && (found->second & SE_PRIVILEGE_ENABLED)) {
            TOKEN_PRIVILEGES change{};
            change.PrivilegeCount = 1; change.Privileges[0].Luid = debug_;
            DWORD size = 0;
            SetLastError(ERROR_SUCCESS);
            const auto adjusted = AdjustTokenPrivileges(token_.get(), FALSE, &change,
                sizeof(previous_), &previous_, &size);
            const auto error = GetLastError();
            changed_ = adjusted && previous_.PrivilegeCount == 1;
            check(adjusted && error == ERROR_SUCCESS && changed_ && size == sizeof(previous_) &&
                key(previous_.Privileges[0].Luid) == key(debug_) && previous_.Privileges[0].Attributes == found->second,
                "test query-denial debug privilege disable unconfirmed");
        }
        auto expected = original_;
        if (expected.count(key(debug_))) expected.at(key(debug_)) &= ~SE_PRIVILEGE_ENABLED;
        check(privileges() == expected, "test query-denial changed unrelated privileges or retained debug bypass");
    }
    void restore_checked() { check(restore(), "test query-denial original privileges not restored"); }
    bool changed() const { return changed_; }
private:
    struct CloseToken { void operator()(HANDLE value) const { if (value) CloseHandle(value); } };
    static std::uint64_t key(const LUID& value) {
        return (static_cast<std::uint64_t>(static_cast<std::uint32_t>(value.HighPart)) << 32) | value.LowPart;
    }
    std::map<std::uint64_t, DWORD> privileges() const {
        DWORD size = 0;
        check(!GetTokenInformation(token_.get(), TokenPrivileges, nullptr, 0, &size) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER && size >= sizeof(DWORD) && size <= 1024u * 1024u,
            "test query-denial token privileges size unavailable");
        std::vector<unsigned char> bytes(size);
        check(GetTokenInformation(token_.get(), TokenPrivileges, bytes.data(), size, &size) && size <= bytes.size(),
            "test query-denial token privileges unavailable");
        DWORD count = 0; std::memcpy(&count, bytes.data(), sizeof(count));
        check(count <= 4096u && size == offsetof(TOKEN_PRIVILEGES, Privileges) + count * sizeof(LUID_AND_ATTRIBUTES),
            "test query-denial token privileges truncated or exceed bound");
        std::map<std::uint64_t, DWORD> result;
        for (DWORD index = 0; index != count; ++index) {
            LUID_AND_ATTRIBUTES item{};
            std::memcpy(&item, bytes.data() + offsetof(TOKEN_PRIVILEGES, Privileges) + index * sizeof(item), sizeof(item));
            check(result.emplace(key(item.Luid), item.Attributes).second, "test query-denial token privileges duplicated");
        }
        return result;
    }
    bool restore() noexcept {
        try {
            if (changed_) {
                SetLastError(ERROR_SUCCESS);
                if (!AdjustTokenPrivileges(token_.get(), FALSE, &previous_, 0, nullptr, nullptr) ||
                    GetLastError() != ERROR_SUCCESS) return false;
                changed_ = false;
            }
            return privileges() == original_;
        } catch (...) { return false; }
    }
    std::unique_ptr<void, CloseToken> token_;
    LUID debug_{};
    TOKEN_PRIVILEGES previous_{};
    std::map<std::uint64_t, DWORD> original_;
    bool changed_ = false;
};
class TestThreadDacl {
public:
    explicit TestThreadDacl(HANDLE thread, DWORD denied_rights = THREAD_SET_INFORMATION) : thread_(thread) {
        DWORD size = 0;
        constexpr auto information = DACL_SECURITY_INFORMATION;
        check(!GetKernelObjectSecurity(thread_, information, nullptr, 0, &size) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER && size && size <= 1024u * 1024u,
            "test thread original descriptor size unavailable");
        original_.resize(size);
        check(GetKernelObjectSecurity(thread_, information, original_.data(), size, &size) != FALSE,
            "test thread original descriptor unavailable");
        SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
        check(GetSecurityDescriptorControl(original_.data(), &control, &revision) != FALSE,
            "test thread original descriptor control unavailable");
        original_protected_ = (control & SE_DACL_PROTECTED) != 0;
        BOOL present = FALSE, defaulted = FALSE; PACL dacl = nullptr;
        check(GetSecurityDescriptorDacl(original_.data(), &present, &dacl, &defaulted) && present && dacl,
            "test thread original DACL unavailable");
        unsigned char sid[SECURITY_MAX_SID_SIZE]{}; DWORD sid_size = sizeof(sid);
        check(CreateWellKnownSid(WinWorldSid, nullptr, sid, &sid_size) != FALSE,
            "test thread control SID unavailable");
        const auto size_with_deny = static_cast<DWORD>(dacl->AclSize + sizeof(ACCESS_DENIED_ACE) - sizeof(DWORD) + sid_size);
        std::vector<unsigned char> changed(size_with_deny);
        auto* changed_acl = reinterpret_cast<PACL>(changed.data());
        check(InitializeAcl(changed_acl, size_with_deny, ACL_REVISION) &&
            AddAccessDeniedAce(changed_acl, ACL_REVISION, denied_rights, sid),
            "test thread control deny ACE unavailable");
        for (DWORD index = 0; index != dacl->AceCount; ++index) {
            void* ace_value = nullptr;
            check(GetAce(dacl, index, &ace_value) && AddAce(changed_acl, ACL_REVISION, MAXDWORD, ace_value,
                static_cast<ACE_HEADER*>(ace_value)->AceSize), "test thread original ACE copy failed");
        }
        SECURITY_DESCRIPTOR descriptor{};
        check(InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) &&
            SetSecurityDescriptorDacl(&descriptor, TRUE, changed_acl, FALSE) &&
            SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, original_protected_ ? SE_DACL_PROTECTED : 0) &&
            SetKernelObjectSecurity(thread_, information, &descriptor), "test thread stored DACL change failed");
    }
    ~TestThreadDacl() { restore(); }
    TestThreadDacl(const TestThreadDacl&) = delete;
    TestThreadDacl& operator=(const TestThreadDacl&) = delete;
    void restore_checked() { check(restore(), "test thread descriptor restoration failed"); }
private:
    bool restore() {
        if (restored_) return true;
        restored_ = SetKernelObjectSecurity(thread_, DACL_SECURITY_INFORMATION | (original_protected_ ?
            PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION), original_.data()) != FALSE;
        return restored_;
    }
    HANDLE thread_;
    std::vector<unsigned char> original_;
    bool original_protected_ = false, restored_ = false;
};
struct ExecutionThreadControl {
    const PublisherWorkerSecurityContinuity& continuity;
    std::string diagnostic;
    static DWORD WINAPI run(void* parameter) {
        auto& control = *static_cast<ExecutionThreadControl*>(parameter);
        try { (void)control.continuity.observe_current(); }
        catch (const std::exception& error) { control.diagnostic = error.what(); }
        return 0;
    }
};
Value require_added_thread_diagnostic(const std::string& diagnostic, const Value& baseline,
    const TestThread& added, const char* census) {
    const std::string marker = "; diagnostic=";
    const auto position = diagnostic.find(marker);
    check(position != std::string::npos && diagnostic.size() - position - marker.size() <= 8192u,
        "actual addition refusal lost its bounded diagnostic");
    const auto evidence = usk::json::parse(diagnostic.substr(position + marker.size()));
    check(evidence.at("schema").as_string() == "usk.publisher_worker_thread_addition_diagnostic.v1" &&
        evidence.at("scope").as_string() == "bounded_native_refusal_readback_no_authority" &&
        evidence.at("census").as_string() == census &&
        evidence.at("process_id").as_unsigned() == GetCurrentProcessId() &&
        evidence.at("current_thread_id").as_unsigned() == GetCurrentThreadId() &&
        evidence.at("baseline_sha256").as_string() == usk::json::sha256_canonical(baseline) &&
        evidence.at("baseline_thread_count").as_unsigned() == baseline.at("threads").as_array().size() &&
        evidence.at("added_thread_count").as_unsigned() >= 1u,
        "addition diagnostic changed the actual baseline or census context");
    std::size_t matches = 0;
    for (const auto& thread : evidence.at("added_threads").as_array()) {
        if (thread.at("census_thread_id").as_unsigned() != added.id()) continue;
        ++matches;
        FILETIME creation{}, exit{}, kernel{}, user{};
        check(GetThreadTimes(added.handle(), &creation, &exit, &kernel, &user) != FALSE,
            "independent held added-thread birth unavailable");
        check(thread.at("identity_matches_census").as_boolean() && thread.at("identity_stable").as_boolean() &&
            thread.at("thread_id").as_unsigned() == added.id() &&
            thread.at("process_id").as_unsigned() == GetCurrentProcessId() &&
            thread.at("wait_result").as_unsigned() == WAIT_TIMEOUT &&
            std::stoull(thread.at("creation_time").as_string(), nullptr, 16) ==
                ((static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime),
            "addition diagnostic lost the actually held owned-thread identity");
        if (thread.contains("start_address") && thread.contains("start_module")) {
            check(std::stoull(thread.at("start_address").as_string(), nullptr, 16) == TestThread::default_start_address() &&
                !thread.at("start_module").at("value").as_string().empty(),
                "optional native thread start differs from its actual creator routine");
        }
    }
    check(matches == 1u, "actual added-thread diagnostic is absent or repeated");
    return evidence;
}
void worker_lifetime_controls() {
    // Ordinary owned test threads only; no service, token mutation or native
    // effect scope. The continuity observer itself has query-only handles.
    TestThread original;
    const auto baseline = observe_current_publisher_worker_security();
    const auto frozen = usk::json::canonical(baseline);
    PublisherWorkerSecurityContinuity continuity(baseline);
    check(usk::json::canonical(continuity.observe_current()) == frozen,
        "unchanged actual worker continuity failed");
    const auto refuses_baseline = [&](const std::function<void(Value&)>& change) {
        auto forged = baseline; change(forged);
        std::string diagnostic;
        try { PublisherWorkerSecurityContinuity invalid(forged); }
        catch (const std::exception& error) { diagnostic = error.what(); }
        check(diagnostic.find("differs from actual worker before thread pinning") != std::string::npos,
            "forged baseline was admitted or refused for an unrelated reason");
    };
    refuses_baseline([](Value& value) { value.as_object().at("primary_token").as_object().at("token_id") = Value("0000000000000000"); });
    refuses_baseline([](Value& value) { value.as_object().at("current_thread_id") = Value(std::uint64_t{0}); });
    refuses_baseline([](Value& value) { value.as_object().at("threads").as_array().clear(); });
    refuses_baseline([](Value& value) { value.as_object().at("threads").as_array().front().as_object().at("creation_time") = Value("0000000000000001"); });
    {
        TestThread added;
        std::string diagnostic;
        try { (void)continuity.observe_current("ordinary-added-thread-control"); }
        catch (const std::exception& error) { diagnostic = error.what(); }
        check(diagnostic.find("added a thread after its frozen baseline") != std::string::npos,
            "actual added thread was admitted or refused for an unrelated reason");
        const auto evidence = require_added_thread_diagnostic(diagnostic, baseline, added, "first_population_snapshot");
        check(evidence.at("owner_context").as_string() == "ordinary-added-thread-control" &&
            !evidence.at("owner_context_truncated").as_boolean() && usk::json::canonical(baseline) == frozen,
            "refusal diagnostic changed the original baseline or supplied only failure context");
        added.retire();
    }
    {
        std::vector<std::unique_ptr<TestThread>> added;
        for (unsigned index = 0; index != 9u; ++index) added.push_back(std::make_unique<TestThread>());
        std::string diagnostic;
        try { (void)continuity.observe_current(std::string(1024u, '\1')); }
        catch (const std::exception& error) { diagnostic = error.what(); }
        const auto marker = diagnostic.find("; diagnostic=");
        check(marker != std::string::npos && diagnostic.size() - marker - 13u <= 8192u,
            "multiple actual additions exceeded the final diagnostic bound");
        const auto evidence = usk::json::parse(diagnostic.substr(marker + 13u));
        check(evidence.at("added_thread_count").as_unsigned() >= 9u &&
            evidence.at("added_threads").as_array().size() == 8u &&
            evidence.at("optional_details_omitted").as_boolean() &&
            evidence.at("owner_context_truncated").as_boolean() && usk::json::canonical(baseline) == frozen,
            "bounded optional diagnostics admitted additions or hid its truncation");
        for (const auto& thread : added) thread->retire();
        (void)continuity.observe_current();
    }
    {
        ExecutionThreadControl control{continuity, {}};
        TestThread different(ExecutionThreadControl::run, &control);
        different.retire();
        check(control.diagnostic.find("original execution thread changed") != std::string::npos,
            "different actual execution thread was admitted or refused for an unrelated reason");
    }
    {
        TestThreadDacl changed(original.handle());
        check(usk::json::canonical(observe_current_publisher_worker_security()) != frozen,
            "test thread stored security control did not change native facts");
        std::string diagnostic;
        try { (void)continuity.observe_current(); }
        catch (const std::exception& error) { diagnostic = error.what(); }
        changed.restore_checked();
        if (diagnostic.find("surviving original thread facts changed") == std::string::npos)
            std::cerr << "actual security-control refusal: " << diagnostic << '\n';
        check(diagnostic.find("surviving original thread facts changed") != std::string::npos,
            "changed actual surviving thread security was admitted or refused for an unrelated reason");
    }
    (void)continuity.observe_current();
    const auto original_partition = continuity.observe_current_with_retirement();
    check(original_partition.at("schema").as_string() == "usk.publisher_worker_security.v2" &&
        usk::json::canonical(original_partition.at("original_baseline")) == frozen,
        "actual original retirement provenance baseline differs");
    original.retire();
    for (unsigned repeat = 0; repeat != 2; ++repeat) {
        const auto current = continuity.observe_current();
        for (const auto& thread : current.at("threads").as_array())
            check(thread.at("thread_id").as_unsigned() != original.id(), "ended original test thread still reported live");
        check(usk::json::canonical(baseline) == frozen, "original worker baseline was refreshed");
        const auto proof = continuity.observe_current_with_retirement();
        require_publisher_worker_security_continuity(original_partition, proof);
        FILETIME birth{}, exit{}, kernel{}, user{};
        check(GetThreadTimes(original.handle(), &birth, &exit, &kernel, &user) &&
            WaitForSingleObject(original.handle(), 0) == WAIT_OBJECT_0, "actual owned thread retirement unavailable");
        bool found = false;
        for (const auto& retired : proof.at("retired_threads").as_array())
            if (retired.at("thread_id").as_unsigned() == original.id()) {
                found = true;
                check(std::stoull(retired.at("exit_time").as_string(), nullptr, 16) ==
                    ((static_cast<std::uint64_t>(exit.dwHighDateTime) << 32) | exit.dwLowDateTime) &&
                    std::stoull(retired.at("creation_time").as_string(), nullptr, 16) ==
                    ((static_cast<std::uint64_t>(birth.dwHighDateTime) << 32) | birth.dwLowDateTime),
                    "native retirement proof differs from actual original-held birth/exit");
            }
        check(found && usk::json::canonical(proof.at("original_baseline")) == frozen,
            "actual retired original is absent from its immutable partition");
    }
    std::cout << "actual retained-thread retirement and addition/security/execution/forgery controls passed\n";
}
void worker_retirement_readback_controls() {
    // Stop actual owned originals at the observation windows. The private
    // callback controls timing only; production obtains all facts natively.
    for (const auto* window : {"after_population_snapshot", "after_live_readback"}) {
        TestThread original;
        const auto baseline = observe_current_publisher_worker_security();
        const auto frozen = usk::json::canonical(baseline);
        PublisherWorkerSecurityContinuity continuity(baseline);
        bool retired = false;
        unsigned samples = 0;
        const auto current = detail::observe_publisher_worker_continuity_for_test(continuity,
            [&](const char* checkpoint) {
                if (std::string(checkpoint) == "after_population_snapshot") ++samples;
                if (!retired && std::string(checkpoint) == window) { original.retire(); retired = true; }
            });
        check(retired && samples && (std::string(window) != "after_live_readback" || samples >= 2),
            "actual retirement did not exercise its bounded readback window");
        for (const auto& thread : current.at("threads").as_array())
            check(thread.at("thread_id").as_unsigned() != original.id(), "mid-readback ended original still reported live");
        check(usk::json::canonical(current.at("primary_token")) == usk::json::canonical(baseline.at("primary_token")) &&
            current.at("current_thread_id").as_unsigned() == baseline.at("current_thread_id").as_unsigned() &&
            usk::json::canonical(baseline) == frozen, "mid-readback retirement refreshed original security");
        (void)continuity.observe_current();
    }
    {
        TestThread retiring, surviving;
        const auto baseline = observe_current_publisher_worker_security();
        const auto frozen = usk::json::canonical(baseline);
        PublisherWorkerSecurityContinuity continuity(baseline);
        std::unique_ptr<TestThreadDacl> changed;
        std::string diagnostic;
        try {
            (void)detail::observe_publisher_worker_continuity_for_test(continuity, [&](const char* checkpoint) {
                if (std::string(checkpoint) == "after_live_readback" && !changed) {
                    retiring.retire();
                    changed = std::make_unique<TestThreadDacl>(surviving.handle());
                }
            });
        } catch (const std::exception& error) { diagnostic = error.what(); }
        check(changed != nullptr, "late security control did not reach actual native mutation");
        changed->restore_checked();
        check(diagnostic.find("surviving original thread facts changed") != std::string::npos,
            "proved retirement masked a surviving original security change");
        check(usk::json::canonical(baseline) == frozen, "late security refusal refreshed original baseline");
        (void)continuity.observe_current();
    }
    {
        TestThread original;
        const auto baseline = observe_current_publisher_worker_security();
        PublisherWorkerSecurityContinuity continuity(baseline);
        std::unique_ptr<TestThread> added;
        std::string diagnostic;
        try {
            (void)detail::observe_publisher_worker_continuity_for_test(continuity, [&](const char* checkpoint) {
                if (std::string(checkpoint) == "after_live_readback" && !added)
                    added = std::make_unique<TestThread>();
            });
        } catch (const std::exception& error) { diagnostic = error.what(); }
        check(added && diagnostic.find("added a thread after its frozen baseline") != std::string::npos,
            "native population bracket admitted a newly added actual thread");
        (void)require_added_thread_diagnostic(diagnostic, baseline, *added, "final_population_snapshot");
        added->retire();
        (void)continuity.observe_current();
    }
    std::cout << "actual census/readback retirement windows and coupled security/addition refusals passed\n";
}
void broker_worker_native_acquisition_controls() {
    // Ordinary owned objects only. These do not activate a restricted SCM
    // broker, grant product effects or qualify the hosted public journey.
    const auto capture = [](const std::function<void(const char*)>& checkpoint) {
        return detail::observe_publisher_broker_worker_security_for_test(checkpoint);
    };
    {
        TestThread live;
        const auto legacy = observe_current_publisher_worker_security();
        std::vector<std::string> first_acquisition;
        const auto native = capture([&](const char* checkpoint) {
            if (first_acquisition.size() < 4 &&
                    std::string(checkpoint).find("broker_native_before_original_first_probe.") != 0)
                first_acquisition.emplace_back(checkpoint);
        });
        check(first_acquisition == std::vector<std::string>{
                "broker_native_before_initial_native_walk", "broker_native_after_native_walk",
                "broker_native_before_first_independent_census", "broker_native_after_first_independent_census"},
            "first broker acquisition sampled a numeric population before holding original native objects");
        check(usk::json::canonical(native) == usk::json::canonical(legacy),
            "native broker acquisition changed complete stable v1 worker facts");
        const auto& rows = native.at("threads").as_array();
        const auto found = std::find_if(rows.begin(), rows.end(), [&](const Value& row) {
            return row.at("thread_id").as_unsigned() == live.id();
        });
        FILETIME birth{}, exit{}, kernel{}, user{};
        check(found != rows.end() && GetThreadTimes(live.handle(), &birth, &exit, &kernel, &user) &&
            std::stoull(found->at("creation_time").as_string(), nullptr, 16) ==
                ((static_cast<std::uint64_t>(birth.dwHighDateTime) << 32) | birth.dwLowDateTime) &&
            WaitForSingleObject(live.handle(), 0) == WAIT_TIMEOUT,
            "native broker acquisition omitted or rebound an actual owned live thread");
    }
    const auto census_diagnostic = [](const std::string& diagnostic) {
        const auto marker = diagnostic.find("; census=");
        check(marker != std::string::npos, "native acquisition census refusal lacked its actual bounded sets");
        const auto value = usk::json::parse(diagnostic.substr(marker + 9));
        check(value.at("scope").as_string() == "bounded_original_census_refusal_no_authority",
            "native acquisition census diagnostic claimed authority");
        return value;
    };
    for (const auto window : {"broker_native_after_independent_before", "broker_native_after_native_walk"}) {
        std::unique_ptr<TestThread> added;
        unsigned read_rounds = 0;
        const auto native = capture([&](const char* checkpoint) {
            if (std::string(checkpoint) == window && !added) added = std::make_unique<TestThread>();
            if (std::string(checkpoint) == "broker_native_before_thread_readback") ++read_rounds;
        });
        check(added != nullptr, "native acquisition addition control did not create its actual owned thread");
        const auto& rows = native.at("threads").as_array();
        const auto found = std::find_if(rows.begin(), rows.end(), [&](const Value& row) {
            return row.at("thread_id").as_unsigned() == added->id();
        });
        FILETIME birth{}, exit{}, kernel{}, user{};
        check(found != rows.end() && GetThreadTimes(added->handle(), &birth, &exit, &kernel, &user) &&
            std::stoull(found->at("creation_time").as_string(), nullptr, 16) ==
                ((static_cast<std::uint64_t>(birth.dwHighDateTime) << 32) | birth.dwLowDateTime) &&
            WaitForSingleObject(added->handle(), 0) == WAIT_TIMEOUT &&
            read_rounds == 2u,
            "native acquisition admitted an addition without its original native facts and complete read rounds");
    }
    for (const auto scenario : {0u, 1u, 2u}) {
        TestThread original;
        std::string diagnostic;
        bool retired = false, optional_failure = false;
        const bool first_probe_ended = scenario == 1u;
        const auto target = first_probe_ended ? "broker_native_before_original_first_probe." + std::to_string(original.id()) :
            std::string("broker_native_after_native_walk");
        try {
            (void)capture([&](const char* checkpoint) {
                if (std::string(checkpoint) == target && !retired) {
                    original.retire(); retired = true;
                }
                if (scenario == 2u && std::string(checkpoint) == "broker_native_before_missing_original_probe") {
                    optional_failure = true;
                    throw std::runtime_error("synthetic optional original-handle diagnostic failure");
                }
            });
        } catch (const std::exception& error) { diagnostic = error.what(); }
        if (scenario == 2u) {
            check(retired && optional_failure && diagnostic ==
                "SCM broker native thread enumeration differs from independent complete census",
                "optional original-handle readback replaced the captured census refusal");
            continue;
        }
        const auto facts = census_diagnostic(diagnostic);
        const auto& missing = facts.at("native_missing_after_prefix").as_array();
        check(retired && !facts.at("before_census_observed").as_boolean() &&
            facts.at("before_count").type() == Value::Type::null_value &&
            !facts.as_object().count("before_missing_native_count") &&
            !facts.as_object().count("mandatory_missing_before_count") &&
            facts.at("native_walk_completed").as_boolean() &&
            facts.at("native_missing_after_count").as_unsigned() != 0 &&
            std::any_of(missing.begin(), missing.end(), [&](const Value& id) { return id.as_unsigned() == original.id(); }),
            "native acquisition silently omitted an originally held thread lost before AFTER");
        const auto& probes = facts.at("native_missing_after_original_prefix").as_array();
        const auto found = std::find_if(probes.begin(), probes.end(), [&](const Value& row) {
            return row.at("thread_id").as_unsigned() == original.id();
        });
        FILETIME birth{}, exit{}, kernel{}, user{};
        check(found != probes.end() && GetThreadTimes(original.handle(), &birth, &exit, &kernel, &user) &&
            WaitForSingleObject(original.handle(), 0) == WAIT_OBJECT_0,
            "missing-original lifetime diagnostic lacks actual owned thread facts");
        const auto birth_value = (static_cast<std::uint64_t>(birth.dwHighDateTime) << 32) | birth.dwLowDateTime;
        const auto exit_value = (static_cast<std::uint64_t>(exit.dwHighDateTime) << 32) | exit.dwLowDateTime;
        const auto& first_probe = found->at("first_probe");
        const auto& refusal_probe = found->at("refusal_probe");
        check(found->at("scope").as_string() == "same_original_handle_sampled_lifetime_no_authority" &&
            found->at("lifetime_status").as_string() == (first_probe_ended ? "signaled_at_first_probe" :
                "observed_live_then_signaled") &&
            first_probe.at("process_id").as_unsigned() == GetCurrentProcessId() &&
            first_probe.at("thread_id").as_unsigned() == original.id() && first_probe.at("get_thread_times").as_boolean() &&
            first_probe.at("get_thread_times_error").as_unsigned() == ERROR_SUCCESS &&
            std::stoull(first_probe.at("creation_time").as_string(), nullptr, 16) == birth_value &&
            first_probe.at("wait_result").as_unsigned() == (first_probe_ended ? WAIT_OBJECT_0 : WAIT_TIMEOUT) &&
            first_probe.at("wait_error").as_unsigned() == ERROR_SUCCESS &&
            refusal_probe.at("identity_matches").as_boolean() && refusal_probe.at("birth_matches_first_probe").as_boolean() &&
            std::stoull(refusal_probe.at("creation_time").as_string(), nullptr, 16) == birth_value &&
            refusal_probe.at("wait_result").as_unsigned() == WAIT_OBJECT_0 &&
            refusal_probe.at("post_signal_times_error").as_unsigned() == ERROR_SUCCESS &&
            refusal_probe.at("post_signal_wait_result").as_unsigned() == WAIT_OBJECT_0 &&
            std::stoull(refusal_probe.at("confirmed_exit_time").as_string(), nullptr, 16) == exit_value &&
            exit_value >= birth_value && probes.size() <= 8 && diagnostic.size() <= 12384,
            "missing-original diagnostic conflated first signal with acquisition or rebound native lifetime facts");
    }
    for (const bool fail_optional_diagnostic : {false, true}) {
        std::unique_ptr<TestThread> pending;
        bool retired = false, optional_failure = false;
        std::string diagnostic;
        try {
            (void)capture([&](const char* checkpoint) {
                if (std::string(checkpoint) == "broker_native_after_native_walk" && !pending)
                    pending = std::make_unique<TestThread>();
                if (std::string(checkpoint) == "broker_native_before_final_census" && pending && !retired) {
                    pending->retire(); retired = true;
                }
                if (std::string(checkpoint) == "broker_native_before_census_refusal_diagnostic" && fail_optional_diagnostic) {
                    optional_failure = true;
                    throw std::runtime_error("synthetic optional census diagnostic failure");
                }
            });
        } catch (const std::exception& error) { diagnostic = error.what(); }
        check(pending && retired, "pending native coverage loss control did not retire its actual observed thread");
        if (fail_optional_diagnostic) {
            check(optional_failure && diagnostic ==
                "SCM broker native thread enumeration differs from independent complete census",
                "optional census formatting failure replaced the original refusal");
        } else {
            const auto facts = census_diagnostic(diagnostic);
            const auto& missing = facts.at("mandatory_missing_before_prefix").as_array();
            check(!facts.at("native_walk_completed").as_boolean() && !facts.at("after_census_observed").as_boolean() &&
                facts.at("mandatory_missing_before_count").as_unsigned() != 0 &&
                !facts.as_object().count("native_count") && !facts.as_object().count("after_count") &&
                std::any_of(missing.begin(), missing.end(), [&](const Value& id) { return id.as_unsigned() == pending->id(); }),
                "native acquisition dropped a pending observation or fabricated later census evidence");
        }
    }
    for (const auto window : {"broker_native_threads_pinned", "broker_native_before_thread_readback",
            "broker_native_initial_times_read", "broker_native_repeated_times_read"}) {
        TestThread original;
        const bool inter_call = std::string(window).find("times_read") != std::string::npos;
        const bool initial = std::string(window) == "broker_native_threads_pinned" ||
            std::string(window) == "broker_native_initial_times_read";
        const auto target_checkpoint = std::string(window) + (inter_call ? "." + std::to_string(original.id()) : "");
        bool live_after_timing = false;
        std::string diagnostic;
        try {
            (void)capture([&](const char* checkpoint) {
                if (std::string(checkpoint) == target_checkpoint) {
                    if (inter_call) {
                        check(WaitForSingleObject(original.handle(), 0) == WAIT_TIMEOUT,
                            "inter-call retirement control was not live after the original timing read");
                        live_after_timing = true;
                    }
                    original.retire();
                }
            });
        } catch (const std::exception& error) { diagnostic = error.what(); }
        check(!inter_call || live_after_timing, "native broker control missed the between-timing-and-wait retirement window");
        check(diagnostic.find(initial ? "observed thread is unavailable or exited" :
                "held thread exited or changed identity") != std::string::npos,
            "native broker acquisition silently omitted a pinned thread retirement");
        FILETIME birth{}, exit{}, kernel{}, user{};
        check(GetThreadTimes(original.handle(), &birth, &exit, &kernel, &user) &&
            (birth.dwHighDateTime || birth.dwLowDateTime) && (exit.dwHighDateTime || exit.dwLowDateTime) &&
            WaitForSingleObject(original.handle(), 0) == WAIT_OBJECT_0,
            "native broker retirement diagnostic lacks actual original-held exit facts");
        const auto birth_value = (static_cast<std::uint64_t>(birth.dwHighDateTime) << 32) | birth.dwLowDateTime;
        const auto exit_value = (static_cast<std::uint64_t>(exit.dwHighDateTime) << 32) | exit.dwLowDateTime;
        check(diagnostic.find("; held_process_id=" + std::to_string(GetCurrentProcessId()) + ";") != std::string::npos &&
            diagnostic.find("; held_thread_id=" + std::to_string(original.id()) + ";") != std::string::npos &&
            diagnostic.find(std::string("; checkpoint=") + (initial ? "initial_held_thread_read" :
                "repeated_held_thread_read") + ";") != std::string::npos &&
            diagnostic.find("; get_thread_times=true; get_thread_times_error=0;") != std::string::npos &&
            diagnostic.find("; creation_filetime=" + std::to_string(birth_value) + ";") != std::string::npos &&
            diagnostic.find("; confirmed_exit_filetime=" + std::to_string(exit_value) + ";") != std::string::npos &&
            diagnostic.find("; exit_filetime=") == std::string::npos &&
            diagnostic.find("; wait_result=0; wait_error=0;") != std::string::npos,
            "native broker retirement diagnostic replaced the actual held identity, birth, exit or wait result");
    }
    {
        TestThread original;
        bool optional_failure = false;
        std::string diagnostic;
        try {
            (void)capture([&](const char* checkpoint) {
                if (std::string(checkpoint) == "broker_native_threads_pinned") original.retire();
                if (std::string(checkpoint) == "broker_native_before_refusal_diagnostic") {
                    optional_failure = true;
                    throw std::runtime_error("synthetic optional refusal diagnostic failure");
                }
            });
        } catch (const std::exception& error) { diagnostic = error.what(); }
        check(optional_failure && diagnostic == "publisher worker observed thread is unavailable or exited",
            "optional native broker diagnostic failure replaced the original held-thread refusal");
    }
    {
        TestThread surviving;
        std::unique_ptr<TestThreadDacl> changed;
        std::string diagnostic;
        try {
            (void)capture([&](const char* checkpoint) {
                if (std::string(checkpoint) == "broker_native_before_thread_readback" && !changed)
                    changed = std::make_unique<TestThreadDacl>(surviving.handle());
            });
        } catch (const std::exception& error) { diagnostic = error.what(); }
        check(changed && diagnostic.find("held thread security changed across population readback") != std::string::npos,
            "native broker acquisition refreshed a surviving thread security change");
        changed.reset();
    }
    {
        TestQueryDenialContext query_context;
        query_context.disable_checked();
        TestThread inaccessible;
        TestThreadDacl denied(inaccessible.handle(), THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION);
        std::exception_ptr control_error;
        try {
            const auto opened = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION | READ_CONTROL | SYNCHRONIZE,
                FALSE, inaccessible.id());
            const auto error = opened ? ERROR_SUCCESS : GetLastError();
            if (opened) CloseHandle(opened);
            if (opened || error != ERROR_ACCESS_DENIED)
                std::cerr << "native broker query-denial setup: opened=" << (opened != nullptr) << " error=" << error
                    << " debug_privilege_disabled=" << query_context.changed() << '\n';
            check(!opened && error == ERROR_ACCESS_DENIED, "native broker incomplete-census control did not deny actual query access");
            const auto census = detail::observe_publisher_system_thread_census_for_test();
            check(std::binary_search(census.begin(), census.end(), inaccessible.id()),
                "independent system census omitted actual query-denied owned thread");
            std::string diagnostic;
            try { (void)capture([](const char*) {}); }
            catch (const std::exception& failure) { diagnostic = failure.what(); }
            check(diagnostic.find("independent complete census") != std::string::npos ||
                diagnostic.find("native thread enumeration failed") != std::string::npos,
                "native broker acquisition accepted incomplete access-filtered coverage");
        } catch (...) { control_error = std::current_exception(); }
        bool acl_restored = false, privileges_restored = false;
        try { denied.restore_checked(); acl_restored = true; }
        catch (const std::exception& failure) { std::cerr << failure.what() << '\n'; }
        try { query_context.restore_checked(); privileges_restored = true; }
        catch (const std::exception& failure) { std::cerr << failure.what() << '\n'; }
        check(acl_restored && privileges_restored, "native broker query-denial control restoration unconfirmed");
        if (control_error) std::rethrow_exception(control_error);
    }
    {
        TestQueryDenialContext query_context;
        query_context.disable_checked();
        std::unique_ptr<TestThread> pending;
        std::unique_ptr<TestThreadDacl> denied;
        bool actual_denial = false;
        std::exception_ptr control_error;
        try {
            std::string diagnostic;
            try {
                (void)capture([&](const char* checkpoint) {
                    if (std::string(checkpoint) == "broker_native_after_native_walk" && !pending) {
                        pending = std::make_unique<TestThread>();
                        denied = std::make_unique<TestThreadDacl>(pending->handle(),
                            THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION);
                        const auto opened = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION |
                            READ_CONTROL | SYNCHRONIZE, FALSE, pending->id());
                        const auto error = opened ? ERROR_SUCCESS : GetLastError();
                        if (opened) CloseHandle(opened);
                        check(!opened && error == ERROR_ACCESS_DENIED,
                            "late native coverage control did not deny actual query access");
                        actual_denial = true;
                    }
                });
            } catch (const std::exception& error) { diagnostic = error.what(); }
            check(pending && denied && actual_denial, "late native query-denial control missed its actual acquisition window");
            if (diagnostic.find("; census=") != std::string::npos) {
                const auto facts = census_diagnostic(diagnostic);
                const auto& missing = facts.at("before_missing_native_prefix").as_array();
                check(facts.at("before_missing_native_count").as_unsigned() != 0 &&
                    std::any_of(missing.begin(), missing.end(), [&](const Value& id) { return id.as_unsigned() == pending->id(); }),
                    "native acquisition treated an access-filtered pending object as an optional addition");
            } else check(diagnostic.find("native thread enumeration failed") != std::string::npos,
                "native acquisition admitted late access-filtered coverage");
        } catch (...) { control_error = std::current_exception(); }
        bool acl_restored = !denied, privileges_restored = false;
        if (denied) try { denied->restore_checked(); acl_restored = true; }
        catch (const std::exception& failure) { std::cerr << failure.what() << '\n'; }
        try { query_context.restore_checked(); privileges_restored = true; }
        catch (const std::exception& failure) { std::cerr << failure.what() << '\n'; }
        check(acl_restored && privileges_restored, "late native query-denial restoration unconfirmed");
        if (control_error) std::rethrow_exception(control_error);
    }
    {
        std::vector<std::unique_ptr<TestThread>> pending;
        bool retired = false;
        std::string diagnostic;
        try {
            (void)capture([&](const char* checkpoint) {
                if (std::string(checkpoint) == "broker_native_after_native_walk" && pending.empty())
                    for (unsigned index = 0; index != 12; ++index) pending.push_back(std::make_unique<TestThread>());
                if (std::string(checkpoint) == "broker_native_before_final_census" && !retired) {
                    for (auto& thread : pending) thread->retire();
                    retired = true;
                }
            });
        } catch (const std::exception& error) { diagnostic = error.what(); }
        const auto facts = census_diagnostic(diagnostic);
        const auto& missing = facts.at("mandatory_missing_before_prefix").as_array();
        check(pending.size() == 12 && retired && facts.at("mandatory_missing_before_count").as_unsigned() == 12 &&
            missing.size() == 8 && diagnostic.size() <= 4096 &&
            std::all_of(missing.begin(), missing.end(), [&](const Value& id) {
                return std::any_of(pending.begin(), pending.end(), [&](const auto& thread) { return thread->id() == id.as_unsigned(); });
            }), "native census refusal lost actual difference counts or exceeded its bounded prefix");
    }
    {
        std::vector<std::unique_ptr<TestThread>> added;
        std::string diagnostic;
        try {
            (void)capture([&](const char* checkpoint) {
                if (std::string(checkpoint) == "broker_native_before_final_census")
                    added.push_back(std::make_unique<TestThread>());
            });
        } catch (const std::exception& error) { diagnostic = error.what(); }
        check(added.size() == 4u && diagnostic.find("did not settle within its observation bound") != std::string::npos,
            "native broker acquisition exceeded its finite additive observation bound");
    }
    PublisherServiceObservation wrong{};
    bool refused = false;
    try { (void)observe_current_publisher_broker_worker_security(wrong); }
    catch (const std::exception& error) { refused = std::string(error.what()).find("another process") != std::string::npos; }
    check(refused, "native broker sampler admitted another process context");
    std::cout << "native broker complete held-thread acquisition and retirement/security/coverage/churn refusals passed\n";
}
} // namespace

void broker_worker_lifetime_controls() {
    using namespace usk::platform::windows;
    const auto observe = [](detail::BrokerWorkerSecurityTestOwner& owner) {
        return detail::observe_broker_worker_security_for_test(owner, [](const char*) {});
    };
    {
        TestThread original;
        auto owner = detail::pin_broker_worker_security_for_test();
        const auto first = observe(*owner);
        original.retire();
        const auto retired = observe(*owner);
        // A numerical census entry is not identified by an OLD object's exit.
        // These supplied entries exercise the shared gate, not a kernel census.
        for (const HANDLE candidate : {static_cast<HANDLE>(nullptr), GetCurrentThread()}) {
            std::string diagnostic;
            try { detail::require_broker_retired_census_binding_for_test(*owner, original.id(), candidate); }
            catch (const std::exception& error) { diagnostic = error.what(); }
            check(diagnostic.find(candidate ? "another object" : "lacks same-object") != std::string::npos,
                "broker assigned a census-only/alien native object to an old retired original");
        }
        require_publisher_broker_worker_security_continuity(first, retired);
        const auto& proofs = retired.at("retired_threads").as_array();
        const auto found = std::find_if(proofs.begin(), proofs.end(), [&](const Value& row) {
            return row.at("thread_id").as_unsigned() == original.id();
        });
        FILETIME birth{}, exit{}, kernel{}, user{};
        check(found != proofs.end() && WaitForSingleObject(original.handle(), 0) == WAIT_OBJECT_0 &&
            GetThreadTimes(original.handle(), &birth, &exit, &kernel, &user) &&
            std::stoull(found->at("creation_time").as_string(), nullptr, 16) ==
                ((static_cast<std::uint64_t>(birth.dwHighDateTime) << 32) | birth.dwLowDateTime) &&
            std::stoull(found->at("exit_time").as_string(), nullptr, 16) ==
                ((static_cast<std::uint64_t>(exit.dwHighDateTime) << 32) | exit.dwLowDateTime),
            "broker retirement lacks actual original-held native birth/defined exit");
        TestThread added;
        const auto admitted = observe(*owner);
        require_publisher_broker_worker_security_continuity(retired, admitted);
        check(admitted.at("admitted_baseline").at("threads").as_array().size() ==
            retired.at("admitted_baseline").at("threads").as_array().size() + 1,
            "broker additional original was not committed by complete policy observation");
        added.retire();
        const auto later = observe(*owner);
        require_publisher_broker_worker_security_continuity(admitted, later);
        check(later.at("retired_threads").as_array().size() == retired.at("retired_threads").as_array().size() + 1,
            "broker newly admitted original did not retain its prospective retirement custody");
    }
    for (const auto window : {"broker_native_after_mandatory_original_readback",
            "broker_native_after_before_original_readback"}) {
        TestThread original;
        auto owner = detail::pin_broker_worker_security_for_test();
        bool ended = false, reached_native_boundary = false;
        Value current;
        std::string diagnostic;
        try {
            current = detail::observe_broker_worker_security_for_test(*owner, [&](const char* point) {
                if (!ended && std::string(point) == window) { original.retire(); ended = true; }
                if (ended && std::string(point) == "broker_native_after_independent_before")
                    reached_native_boundary = true;
            });
        } catch (const std::exception& error) { diagnostic = error.what(); }
        check(ended, "broker census projection control did not retire the actual held original");
        if (std::string(window) == "broker_native_after_mandatory_original_readback") {
            check(reached_native_boundary,
                "broker compared stale live projections before acquiring current same-object census coverage");
            if (!diagnostic.empty()) {
                check(diagnostic.find("census-present retired ID lacks same-object native coverage") != std::string::npos,
                    "broker census projection masked a different native failure");
                diagnostic.clear();
                try { (void)observe(*owner); } catch (const std::exception& error) { diagnostic = error.what(); }
                check(diagnostic.find("owner failed") != std::string::npos,
                    "broker reused its owner after unavailable same-object census coverage");
                continue;
            }
        } else check(diagnostic.empty(), "broker compared stale live projections after complete native census binding");
        const auto& proofs = current.at("retired_threads").as_array();
        const auto found = std::find_if(proofs.begin(), proofs.end(), [&](const Value& row) {
            return row.at("thread_id").as_unsigned() == original.id();
        });
        FILETIME birth{}, exit{}, kernel{}, user{};
        check(found != proofs.end() && WaitForSingleObject(original.handle(), 0) == WAIT_OBJECT_0 &&
            GetThreadTimes(original.handle(), &birth, &exit, &kernel, &user) &&
            std::stoull(found->at("creation_time").as_string(), nullptr, 16) ==
                ((static_cast<std::uint64_t>(birth.dwHighDateTime) << 32) | birth.dwLowDateTime) &&
            std::stoull(found->at("exit_time").as_string(), nullptr, 16) ==
                ((static_cast<std::uint64_t>(exit.dwHighDateTime) << 32) | exit.dwLowDateTime),
            "broker completed a census projection without exact original-held native retirement");
    }
    for (const auto window : {"broker_native_after_native_walk", "broker_native_initial_times_read",
            "broker_native_before_final_census"}) {
        auto owner = detail::pin_broker_worker_security_for_test();
        TestThread pending;
        bool ended = false;
        std::string diagnostic;
        try {
            (void)detail::observe_broker_worker_security_for_test(*owner, [&](const char* point) {
                const auto match = std::string(window) == "broker_native_initial_times_read" ?
                    std::string(point) == std::string(window) + "." + std::to_string(pending.id()) : std::string(point) == window;
                if (match && !ended) { pending.retire(); ended = true; }
            });
        } catch (const std::exception& error) { diagnostic = error.what(); }
        check(ended && !diagnostic.empty(), "broker allowed unknown/partially read thread retirement");
        diagnostic.clear();
        try { (void)observe(*owner); } catch (const std::exception& error) { diagnostic = error.what(); }
        check(diagnostic.find("owner failed") != std::string::npos, "broker reused an owner after failed pending admission");
    }
    {
        TestThread original;
        auto owner = detail::pin_broker_worker_security_for_test();
        original.retire();
        TestThreadDacl changed(original.handle());
        std::string diagnostic;
        try { (void)observe(*owner); } catch (const std::exception& error) { diagnostic = error.what(); }
        changed.restore_checked();
        check(diagnostic.find("stored thread security changed") != std::string::npos,
            "broker positive retirement masked changed original stored security");
    }
    {
        TestThread original;
        auto owner = detail::pin_broker_worker_security_for_test();
        bool ended = false;
        const auto current = detail::observe_broker_worker_security_for_test(*owner, [&](const char* point) {
            if (!ended && std::string(point) == "broker_native_after_native_walk") { original.retire(); ended = true; }
        });
        check(ended && !current.at("retired_threads").as_array().empty(),
            "broker failed to account for completed-policy original retirement during its native walk");
    }
    {
        TestQueryDenialContext query_context;
        query_context.disable_checked();
        auto owner = detail::pin_broker_worker_security_for_test();
        TestThread unknown;
        TestThreadDacl denied(unknown.handle(), THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION);
        std::exception_ptr failure;
        try {
            const auto opened = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION | READ_CONTROL | SYNCHRONIZE,
                FALSE, unknown.id());
            const auto error = opened ? ERROR_SUCCESS : GetLastError();
            if (opened) CloseHandle(opened);
            check(!opened && error == ERROR_ACCESS_DENIED, "broker lifetime query-filter control did not deny native access");
            std::string diagnostic;
            try { (void)observe(*owner); } catch (const std::exception& error) { diagnostic = error.what(); }
            check(diagnostic.find("independent complete census") != std::string::npos ||
                diagnostic.find("native thread enumeration failed") != std::string::npos,
                "broker original retirement bypassed unknown access-filtered census coverage");
        } catch (...) { failure = std::current_exception(); }
        denied.restore_checked();
        owner.reset();
        query_context.restore_checked();
        if (failure) std::rethrow_exception(failure);
    }
    std::cout << "broker prospective original retirement/addition and unknown/pending/security refusals passed\n";
}
int main() {
    try {
        // Ordinary-process readback and owned test-thread controls only. No
        // SCM or opens against another process; no publisher effect authority.
        const auto actual = observe_current_publisher_process_boundary();
        check(actual.as_object().size() == 7 && actual.at("process_id").as_unsigned() == GetCurrentProcessId() &&
            actual.at("dacl_present").as_boolean() && !actual.at("owner_sid").as_string().empty(),
            "current process owner/DACL facts were not observed");
        system_thread_census_buffer_controls();
        worker_security_controls();
        worker_retirement_data_controls();
        effect_execution_record_controls();
        worker_lifetime_controls();
        worker_retirement_readback_controls();
        broker_worker_native_acquisition_controls();
        broker_worker_lifetime_controls();

        // Synthetic policy controls are separate from the native observation.
        require_publisher_process_boundary(boundary(), 500, service_sid, groups);
        for (const auto& owner : {std::string("S-1-5-18"), std::string("S-1-5-32-544"),
                                 service_sid, std::string("S-1-5-5-0-900")}) {
            auto value = boundary();
            value.as_object().at("owner_sid") = Value(owner);
            require_publisher_process_boundary(value, 500, service_sid, groups);
        }
        auto deny = boundary();
        auto denied = ace(consumer_sid, PROCESS_ALL_ACCESS);
        denied.as_object().at("type") = Value(std::uint64_t{1});
        deny.as_object().at("dacl_aces").as_array().push_back(denied);
        require_publisher_process_boundary(deny, 500, service_sid, groups);

        const auto refuses = [&](const std::function<void(Value&)>& change) {
            auto value = boundary();
            change(value);
            bool refused = false;
            try { require_publisher_process_boundary(value, 500, service_sid, groups); }
            catch (const std::exception&) { refused = true; }
            check(refused, "process boundary admitted an outside capability or contradictory record");
        };
        for (unsigned bit = 0; bit < 32; ++bit) {
            const std::uint32_t right = std::uint32_t{1} << bit;
            if (query_rights & right) continue;
            refuses([&](Value& value) {
                value.as_object().at("dacl_aces").as_array().back().as_object().at("access_mask") =
                    Value(static_cast<std::uint64_t>(query_rights | right));
            });
        }
        refuses([](Value& value) { value.as_object().at("process_id") = Value(true); });
        refuses([](Value& value) { value.as_object().at("owner_sid") = Value(consumer_sid); });
        refuses([](Value& value) { value.as_object().at("dacl_present") = Value(false); });
        refuses([](Value& value) {
            value.as_object().at("dacl_aces").as_array().back().as_object().at("flags") =
                Value(std::uint64_t{INHERITED_ACE});
        });
        bool refused = false;
        try {
            require_publisher_process_boundary(boundary(), 500, service_sid,
                {{"S-1-5-5-900", SE_GROUP_LOGON_ID | SE_GROUP_ENABLED}});
        } catch (const std::exception&) { refused = true; }
        check(refused, "process boundary admitted an invalid publisher logon SID");

        // Pure cross-record continuity controls; phase admission is separate.
        const Value earlier(Value::Object{{"schema", Value("usk.publisher_execution_observation.v2")},
            {"scope", Value("supplied_held_service_handles_and_process_owner_dacl")},
            {"platform", Value(Value::Object{})}, {"handles", Value(Value::Array{})},
            {"service", Value(Value::Object{{"process_id", Value(std::uint64_t{500})},
                {"token_id", Value("0000000000000500")}})}, {"process_boundary", boundary()}});
        require_publisher_execution_record_continuity(earlier, earlier);
        auto later = earlier;
        later.as_object().at("process_boundary").as_object().at("dacl_protected") = Value(true);
        refused = false;
        try { require_publisher_execution_record_continuity(earlier, later); }
        catch (const std::exception&) { refused = true; }
        check(refused, "same-worker prepared/visible process boundary changed");
        later = earlier;
        later.as_object().at("schema") = Value("usk.publisher_execution_observation.v1");
        later.as_object().at("scope") = Value("supplied_held_service_handles");
        later.as_object().erase("process_boundary");
        refused = false;
        try { require_publisher_execution_record_continuity(earlier, later); }
        catch (const std::exception&) { refused = true; }
        check(refused, "same-worker visible record downgraded its process boundary");
        later = earlier;
        later.as_object().at("service").as_object().at("process_id") = Value(std::uint64_t{600});
        later.as_object().at("service").as_object().at("token_id") = Value("0000000000000600");
        later.as_object().at("process_boundary").as_object().at("process_id") = Value(std::uint64_t{600});
        require_publisher_execution_record_continuity(earlier, later);
        std::cout << "actual read-only current process boundary and synthetic policy controls passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
