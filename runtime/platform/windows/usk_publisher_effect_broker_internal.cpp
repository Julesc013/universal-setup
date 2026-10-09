// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_effect_broker_internal.h"
#if defined(_WIN32)
#include "usk_publisher_registration.h"
#include "usk_publisher_effect_execution_internal.h"
#include "usk_publisher_request_channel.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_execution_observation.h"
#include "usk_publisher_tree_observation.h"
#include "usk_publisher_process_boundary.h"
#include "usk_publisher_installation_lease.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_volume_stream_observation.h"
#include "usk_sha256.h"
#include "usk_record_io.h"
#include <atomic>
#include <algorithm>
#include <array>
#include <optional>
#include <cstring>
#include <filesystem>
#include <limits>
#include <set>
#include <sddl.h>
#include <shellapi.h>
#include <stdexcept>

namespace usk::platform::windows {
namespace {
using usk::json::Value;
std::atomic<void*> active_query{nullptr};
constexpr DWORD query_rights = FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
void require(bool okay, const char* reason) { if (!okay) throw std::runtime_error(reason); }
DWORD readback_remaining(ULONGLONG started, DWORD timeout, const char* message) {
    // Subtraction charges elapsed monotonic time without an absolute-tick
    // addition overflow. All new phases share the original <=120s budget.
    const auto elapsed = GetTickCount64() - started;
    require(timeout && timeout <= 120000 && elapsed < timeout, message);
    return static_cast<DWORD>(timeout - elapsed);
}
void require_batch_packet_budget(const Value& body) {
    // Include the real transport wrapper's worst-case sequence and binding
    // lengths, both profiles and every descriptor. Use its unchanged closed
    // reader limits before sending any batch; an overflow is a failed route.
    usk::json::ParseLimits limits;
    limits.max_string_bytes = limits.max_bytes;
    const Value sequence(std::numeric_limits<std::uint64_t>::max()), binding(std::string(64u, 'a'));
    usk::json::require_canonical_object_parse_limits({
        {"sequence", std::cref(sequence)}, {"binding_sha256", std::cref(binding)},
        {"body", std::cref(body)}}, limits);
}
bool same(const Value& left, const Value& right) {
    return usk::json::equal_values(left, right);
}
constexpr const char* record_byte_kind = "original_maintenance_record_bytes_bracket";
constexpr const char* record_byte_schema = "usk.publisher_effect_record_byte_scope.v1";
constexpr const char* authority_record_kind = "original_maintenance_authority_record_bytes_bracket";
constexpr const char* authority_record_schema = "usk.publisher_effect_authority_record_byte_scope.v1";
Value record_phase(const Value& scope, const std::string& phase) {
    auto fields = scope.as_object();
    fields.emplace("schema", Value(scope.at("kind").as_string() == authority_record_kind ? authority_record_schema : record_byte_schema));
    fields.emplace("phase", Value(phase));
    return Value(std::move(fields));
}
void record_require_packet(const Value& packet, const Value& scope, const std::string& phase,
    const std::set<std::string>& extra = {}) {
    auto expected = record_phase(scope, phase);
    require(packet.as_object().size() == expected.as_object().size() + extra.size(),
        "record byte scope packet has unexpected fields");
    for (const auto& [name, value] : expected.as_object())
        require(same(packet.at(name), value), "record byte scope sequence/ledger/phase differs");
    for (const auto& name : extra) (void)packet.at(name);
    require_batch_packet_budget(packet);
}
Value record_scope_from_begin(const Value& begin, std::uint64_t sequence, bool authority = false) {
    Value::Object fields;
    for (const auto* name : {"kind", "scope_sequence", "occurrence_count", "chunk_count", "ledger_sha256"})
        fields.emplace(name, begin.at(name));
    if (authority) {
        fields.emplace("selected_kind", begin.at("selected_kind"));
        fields.emplace("request_sha256", begin.at("request_sha256"));
    }
    Value scope(std::move(fields));
    record_require_packet(begin, scope, "begin");
    const auto count = scope.at("occurrence_count").as_unsigned();
    const auto chunks = scope.at("chunk_count").as_unsigned();
    const auto& sha = scope.at("ledger_sha256").as_string();
    if (authority) {
        const auto& kind = scope.at("selected_kind").as_string();
        const auto& request = scope.at("request_sha256").as_string();
        require((kind == "selected_operation_bracket" || kind == "original_maintenance_recovery_bracket") &&
            request.size() == 64u && std::all_of(request.begin(), request.end(), [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }),
            "authority record scope selected family/request digest differs");
    }
    require(scope.at("kind").as_string() == (authority ? authority_record_kind : record_byte_kind) &&
        sequence && scope.at("scope_sequence").as_unsigned() == sequence && count &&
        count <= publisher_record_byte_occurrence_limit && chunks &&
        chunks <= publisher_record_byte_chunk_limit &&
        chunks == (count + publisher_object_access_batch_limit - 1u) / publisher_object_access_batch_limit &&
        sha.size() == 64u && std::all_of(sha.begin(), sha.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }),
        "record byte scope exceeds its closed original sequence/count/digest bounds");
    return scope;
}
void record_charge(std::size_t& cumulative, const Value& packet) {
    require_batch_packet_budget(packet);
    const auto bytes = usk::json::canonical(packet).size();
    require(bytes <= publisher_record_byte_proof_bytes_limit - cumulative,
        "record byte scope cumulative proof storage exceeds its bound");
    cumulative += bytes;
}
std::size_t record_chunk_size(const Value& scope, std::size_t index) {
    const auto count = static_cast<std::size_t>(scope.at("occurrence_count").as_unsigned());
    require(index < scope.at("chunk_count").as_unsigned(), "record byte scope chunk index exceeds its bound");
    return std::min(publisher_object_access_batch_limit, count - index * publisher_object_access_batch_limit);
}


bool canonical_sid(const std::string& text) {
    if (text.empty() || text.size() > 184) return false;
    PSID sid = nullptr;
    if (!ConvertStringSidToSidA(text.c_str(), &sid)) return false;
    LPSTR canonical = nullptr;
    const bool valid = IsValidSid(sid) && ConvertSidToStringSidA(sid, &canonical);
    const bool equal = valid && text == canonical;
    if (canonical) LocalFree(canonical);
    LocalFree(sid);
    return equal;
}
bool hex(const std::string& text, std::size_t size) {
    return text.size() == size && std::all_of(text.begin(), text.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'); });
}
std::vector<ObservedTokenGroup> record_groups(const Value& input) {
    require(input.as_array().size() <= 4096, "broker retained group bound exceeded");
    std::vector<ObservedTokenGroup> output;
    std::set<std::string> seen;
    for (const auto& item : input.as_array()) {
        const auto& sid = item.at("sid").as_string();
        const auto attributes = item.at("attributes").as_unsigned();
        require(item.as_object().size() == 2 && canonical_sid(sid) && seen.insert(sid).second && attributes <= 0xffffffffu,
            "broker retained token group differs from the closed grammar");
        output.push_back({sid, static_cast<std::uint32_t>(attributes)});
    }
    return output;
}
PublisherTokenObservation record_token(const Value& input) {
    require(input.as_object().size() == 8 && canonical_sid(input.at("user_sid").as_string()) &&
        input.at("token_id").as_unsigned() && input.at("authentication_id").as_unsigned() &&
        input.at("modified_id").as_unsigned() && input.at("token_type").as_unsigned() == TokenPrimary,
        "broker retained primary token differs from the closed grammar");
    return {input.at("user_sid").as_string(), record_groups(input.at("groups")), record_groups(input.at("restricted_sids")),
        input.at("observing_thread_impersonating").as_boolean(), {input.at("token_id").as_unsigned(),
        input.at("authentication_id").as_unsigned(), input.at("modified_id").as_unsigned(), TokenPrimary}};
}
Value groups(const std::vector<ObservedTokenGroup>& input) {
    Value::Array output;
    for (const auto& group : input) output.emplace_back(Value::Object{
        {"sid", Value(group.sid)}, {"attributes", Value(static_cast<std::uint64_t>(group.attributes))}});
    return Value(std::move(output));
}
Value token(const PublisherTokenObservation& input) {
    // This field is deliberately about the observer, never remote threads.
    Value::Object fields;
    fields.emplace("user_sid", Value(input.process_user_sid));
    fields.emplace("groups", groups(input.process_groups));
    fields.emplace("restricted_sids", groups(input.process_restricted_sids));
    fields.emplace("observing_thread_impersonating", Value(input.current_thread_impersonating));
    fields.emplace("token_id", Value(input.identity.token_id));
    fields.emplace("authentication_id", Value(input.identity.authentication_id));
    fields.emplace("modified_id", Value(input.identity.modified_id));
    fields.emplace("token_type", Value(static_cast<std::uint64_t>(input.identity.token_type)));
    return Value(std::move(fields));
}
bool same_inherited_facts(const PublisherTokenObservation& parent, const PublisherTokenObservation& child) {
    return parent.process_user_sid == child.process_user_sid &&
        parent.identity.authentication_id == child.identity.authentication_id &&
        parent.identity.token_type == TokenPrimary && child.identity.token_type == TokenPrimary &&
        parent.identity.token_id && child.identity.token_id && parent.identity.modified_id && child.identity.modified_id &&
        same(groups(parent.process_groups), groups(child.process_groups)) &&
        same(groups(parent.process_restricted_sids), groups(child.process_restricted_sids));
}
Value service(const PublisherServiceObservation& input) {
    Value::Object fields;
    fields.emplace("service_name", Value(std::filesystem::path(input.service_name).u8string()));
    fields.emplace("service_sid", Value(input.service_sid));
    fields.emplace("service_sid_type", Value(static_cast<std::uint64_t>(input.service_sid_type)));
    fields.emplace("service_type", Value(static_cast<std::uint64_t>(input.service_type)));
    fields.emplace("service_state", Value(static_cast<std::uint64_t>(input.service_state)));
    fields.emplace("process_id", Value(static_cast<std::uint64_t>(input.process_id)));
    fields.emplace("primary_token", token(input.token));
    return Value(std::move(fields));
}
Value object(HANDLE handle) {
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    require(GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) != FALSE,
        "broker object type is unavailable");
    return publisher_handle_observation_json((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ?
        observe_publisher_directory_handle(handle) : observe_publisher_file_handle(handle));
}
unsigned char nibble(char value) {
    if (value >= '0' && value <= '9') return static_cast<unsigned char>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<unsigned char>(value - 'a' + 10);
    throw std::runtime_error("broker file ID is not canonical native hex");
}
FILE_ID_DESCRIPTOR ntfs_id(const std::string& id, const std::string& volume_id) {
    require(id.size() == 49 && volume_id.size() == 49 && id[16] == ':' &&
        id.compare(0, 17, volume_id, 0, 17) == 0, "broker object belongs to another native volume");
    FILE_ID_DESCRIPTOR result{};
    result.dwSize = sizeof(result);
    // NTFS's documented 64-bit file index must losslessly match our complete
    // FILE_ID_INFO projection. No extended-ID/legacy-ID retry or truncation.
    result.Type = FileIdType;
    unsigned char bytes[16]{};
    for (std::size_t index = 0; index < sizeof(bytes); ++index)
        bytes[index] = static_cast<unsigned char>((nibble(id[17 + index * 2]) << 4) | nibble(id[18 + index * 2]));
    for (std::size_t index = 8; index < sizeof(bytes); ++index)
        require(bytes[index] == 0, "broker NTFS file ID is not losslessly representable");
    std::memcpy(&result.FileId, bytes, sizeof(result.FileId));
    return result;
}
void require_ntfs_root(HANDLE root, const Value& facts) {
    require(facts.at("native_name").as_string() == "\\" &&
        (facts.at("attributes").as_unsigned() & FILE_ATTRIBUTE_DIRECTORY) &&
        !(facts.at("attributes").as_unsigned() & FILE_ATTRIBUTE_REPARSE_POINT) &&
        !facts.at("case_sensitive").as_boolean(), "broker hint is not its original native volume root");
    wchar_t filesystem[32]{};
    require(GetVolumeInformationByHandleW(root, nullptr, 0, nullptr, nullptr, nullptr, filesystem,
        static_cast<DWORD>(std::size(filesystem))) && std::wstring(filesystem) == L"NTFS",
        "broker query requires its original native NTFS volume");
    require(observe_publisher_noninheritable_handle_flags(root) == 0,
        "broker original volume is inheritable");
}
void require_projection(const Value& profile, const Value& custody, const PublisherTokenObservation& parent,
    const PublisherTokenObservation& child, bool child_view) {
    require(profile.as_object().size() == 12 && (profile.at("schema").as_string() ==
        "usk.publisher_effect_broker_native_readback.v2" || profile.at("schema").as_string() ==
        "usk.publisher_effect_broker_native_readback.v3") &&
        profile.at("authority").as_string() == "read_only_observation" &&
        profile.at("request_sha256").as_string() == custody.at("request_sha256").as_string(),
        "broker native readback schema or request differs");
    auto parent_custody = profile.at("custody");
    if (child_view) {
        require(parent_custody.as_object().size() == 10 &&
            parent_custody.at("owned_job_active_process_limit").as_unsigned() == 1 &&
            parent_custody.at("owned_job_kill_on_close").as_boolean(), "broker job projection differs");
        parent_custody.as_object().erase("owned_job_active_process_limit");
        parent_custody.as_object().erase("owned_job_kill_on_close");
        std::swap(parent_custody.as_object().at("current_process_id"), parent_custody.as_object().at("peer_process_id"));
        std::swap(parent_custody.as_object().at("current_process_birth"), parent_custody.as_object().at("peer_process_birth"));
    }
    require(same(parent_custody, custody), "broker actual peer process/birth/image custody differs");
    const auto& original = profile.at("service");
    const auto& admitted = profile.at("registered_admission");
    const auto& sid = original.at("service_sid").as_string();
    require(custody.as_object().size() == (child_view ? 8u : 10u) &&
        custody.at("schema").as_string() == "usk.publisher_effect_transport_custody.v1" &&
        custody.at("authority").as_string() == "none" &&
        custody.at("current_process_id").as_unsigned() > 0 && custody.at("current_process_id").as_unsigned() <= 0xffffffffu &&
        custody.at("peer_process_id").as_unsigned() > 0 && custody.at("peer_process_id").as_unsigned() <= 0xffffffffu &&
        custody.at("peer_process_id").as_unsigned() != custody.at("current_process_id").as_unsigned() &&
        hex(custody.at("current_process_birth").as_string(), 16) && custody.at("current_process_birth").as_string() != "0000000000000000" &&
        hex(custody.at("peer_process_birth").as_string(), 16) && custody.at("peer_process_birth").as_string() != "0000000000000000" &&
        hex(custody.at("request_sha256").as_string(), 64) && canonical_sid(sid) &&
        profile.at("custody").at("owned_job_active_process_limit").as_unsigned() == 1 &&
        profile.at("custody").at("owned_job_kill_on_close").as_boolean(),
        "broker native custody is not the closed process/birth/image/job binding");
    require(original.as_object().size() == 7 && original.at("service_sid_type").as_unsigned() == SERVICE_SID_TYPE_RESTRICTED &&
        original.at("service_type").as_unsigned() == SERVICE_WIN32_OWN_PROCESS &&
        original.at("service_state").as_unsigned() == SERVICE_RUNNING &&
        original.at("process_id").as_unsigned() == (child_view ? custody.at("peer_process_id").as_unsigned() :
            custody.at("current_process_id").as_unsigned()) &&
        same(original.at("primary_token"), token(parent)) && same(profile.at("effect_primary_token"), token(child)) &&
        has_restricted_publisher_token_facts(parent, sid) && has_restricted_publisher_token_facts(child, sid) &&
        same_inherited_facts(parent, child) &&
        admitted.at("schema").as_string() == "usk.publisher_registered_admission_observation.v1" &&
        admitted.at("service_name").as_string() == original.at("service_name").as_string() &&
        admitted.at("service_sid").as_string() == sid &&
        admitted.at("process_id").as_unsigned() == original.at("process_id").as_unsigned(),
        "broker actual service and separate effect primary-token binding differs");
    const auto& image = profile.at("custody").at("image");
    const auto& admitted_image = admitted.at("publisher_image");
    require(image.as_object().size() == 4 && admitted.as_object().size() == 10 &&
        admitted.at("scope").as_string() == "held_registered_service_image_and_controller_target_admission" &&
        admitted_image.as_object().size() == 5 && hex(image.at("sha256").as_string(), 64) &&
        image.at("size_bytes").as_unsigned() > 0 && !image.at("volume_id").as_string().empty() &&
        !image.at("file_id").as_string().empty() && !admitted_image.at("path").as_string().empty() &&
        hex(admitted.at("registration_sha256").as_string(), 64) && hex(admitted.at("target_admitted_sha256").as_string(), 64),
        "broker held image/registration projection differs from its closed grammar");
    for (const auto field : {"volume_id", "file_id", "size_bytes", "sha256"})
        require(same(image.at(field), admitted_image.at(field)), "broker held original executable differs from registration");
    const auto& target = admitted.at("target_identity").at("volume_identity");
    require(profile.at("volume_root").at("file_id").as_string() == target.at("root_file_id").as_string() &&
        profile.at("broker_volume_granted_access").as_unsigned() == query_rights &&
        profile.at("authenticated_client").at("user_sid").as_string() == admitted.at("configured_caller_sid").as_string(),
        "broker original target or authenticated caller differs from registration");
    const auto& configuration = profile.at("service_configuration");
    const auto& arguments = configuration.at("arguments").as_array();
    require(configuration.as_object().size() == 9 && configuration.at("schema").as_string() ==
        "usk.publisher_registered_execution_configuration.v1" &&
        configuration.at("scope").as_string() == "original_held_scm_configuration" &&
        configuration.at("service_type").as_unsigned() == SERVICE_WIN32_OWN_PROCESS &&
        configuration.at("start_type").as_unsigned() == SERVICE_DEMAND_START &&
        configuration.at("service_sid_type").as_unsigned() == SERVICE_SID_TYPE_RESTRICTED &&
        !configuration.at("command").as_string().empty() && !configuration.at("account").as_string().empty() &&
        !configuration.at("display_name").as_string().empty() && arguments.size() >= 8 && arguments.size() <= 16 &&
        arguments.at(0).as_string() == admitted_image.at("path").as_string() &&
        arguments.at(1).as_string() == "--service" && arguments.at(2).as_string() == original.at("service_name").as_string() &&
        arguments.at(3).as_string() == "--no-receipt" && arguments.at(4).as_string() == target.at("volume_root").as_string() &&
        arguments.at(arguments.size() - 3).as_string() == "--service-admitted-client" &&
        arguments.at(arguments.size() - 2).as_string() == "--authorized-client-sid" &&
        arguments.back().as_string() == admitted.at("configured_caller_sid").as_string(),
        "broker original registered execution configuration differs");
    const auto command = std::filesystem::u8path(configuration.at("command").as_string()).wstring();
    int count = 0;
    LPWSTR* parsed = CommandLineToArgvW(command.c_str(), &count);
    require(parsed != nullptr, "broker original service command cannot be parsed");
    bool command_matches = count >= 0 && static_cast<std::size_t>(count) == arguments.size();
    try {
        for (int index = 0; command_matches && index < count; ++index)
            command_matches = std::filesystem::path(parsed[index]).u8string() == arguments.at(static_cast<std::size_t>(index)).as_string();
    } catch (...) { LocalFree(parsed); throw; }
    LocalFree(parsed);
    const auto& mode = arguments.at(5).as_string();
    const auto account = std::filesystem::u8path(configuration.at("account").as_string()).wstring();
    require(command_matches && CompareStringOrdinal(account.c_str(), -1, L"LocalSystem", -1, TRUE) == CSTR_EQUAL &&
        ((arguments.size() == 9 && (mode == "--recover-reviewed" || mode == "--verify-installed")) ||
            (arguments.size() == 11 && mode == "--reviewed-plan-envelope" &&
                !arguments.at(6).as_string().empty() && hex(arguments.at(7).as_string(), 64))),
        "broker original service command/account is outside the closed registered grammar");
    const auto& security = profile.at("broker_security");
    require(security.as_object().size() == 2, "broker native security projection is not closed");
    const auto parent_pid = static_cast<std::uint32_t>(original.at("process_id").as_unsigned());
    require_publisher_process_boundary(security.at("process_boundary"), parent_pid, sid, parent.process_groups);
    if (profile.at("schema").as_string() == "usk.publisher_effect_broker_native_readback.v3")
        require_publisher_broker_worker_security(security.at("worker_security"), PublisherWorkerTokenContext{parent_pid, sid, parent});
    else {
        require(security.at("worker_security").at("schema").as_string() == "usk.publisher_worker_security.v1",
            "SCM broker reinterpreted original retirement provenance");
        require_publisher_worker_security(security.at("worker_security"), PublisherWorkerTokenContext{parent_pid, sid, parent});
    }
}
Value immutable_profile(const Value& profile) {
    // The SCM broker owns no product creator/effect handles. Its current
    // population may change; every fresh snapshot still passes the complete
    // stored policy above. Its process/token/default facts stay frozen. The
    // child's original pinned-thread policy remains unchanged.
    // Copy only the retained fields into an independent projection; none of
    // the original or freshly observed profile is mutated or retained by reference.
    const auto& broker_security = profile.at("broker_security").as_object();
    const auto& worker_security = broker_security.at("worker_security").as_object();
    const bool with_retirement = profile.at("schema").as_string() == "usk.publisher_effect_broker_native_readback.v3";
    Value::Object worker_fields;
    for (const auto& item : worker_security) {
        if (item.first == "threads" || (with_retirement &&
            (item.first == "admitted_baseline" || item.first == "retired_threads"))) continue;
        worker_fields.emplace(item.first, item.second);
    }
    Value::Object broker_fields;
    for (const auto& item : broker_security) {
        if (item.first == "worker_security")
            broker_fields.emplace(item.first, Value(std::move(worker_fields)));
        else broker_fields.emplace(item.first, item.second);
    }
    Value::Object profile_fields;
    for (const auto& item : profile.as_object()) {
        if (item.first == "broker_security")
            profile_fields.emplace(item.first, Value(std::move(broker_fields)));
        else profile_fields.emplace(item.first, item.second);
    }
    return Value(std::move(profile_fields));
}
bool paired_selection_kind(const std::string& kind) {
    return kind == "selected_operation_bracket" || kind == "original_maintenance_recovery_bracket" ||
        kind == "original_installation_recovery_bracket";
}
std::string selected_bracket_kind(PublisherEffectSelectionKind kind) {
    switch (kind) {
    case PublisherEffectSelectionKind::reviewed_operation: return "selected_operation_bracket";
    case PublisherEffectSelectionKind::original_maintenance_recovery: return "original_maintenance_recovery_bracket";
    case PublisherEffectSelectionKind::original_installation_recovery: return "original_installation_recovery_bracket";
    }
    throw std::runtime_error("effect selection kind is outside its closed bound");
}
bool selected_access_kind(const std::string& kind) {
    return kind == "selected_operation_object_access_batch_bracket" ||
        kind == "original_maintenance_recovery_object_access_batch_bracket" ||
        kind == "original_installation_recovery_object_access_batch_bracket";
}
PublisherEffectSelectionKind selection_selector(const std::string& kind) {
    if (kind == "selected_operation_bracket" || kind == "selected_operation_object_access_batch_bracket")
        return PublisherEffectSelectionKind::reviewed_operation;
    if (kind == "original_maintenance_recovery_bracket" || kind == "original_maintenance_recovery_object_access_batch_bracket")
        return PublisherEffectSelectionKind::original_maintenance_recovery;
    if (kind == "original_installation_recovery_bracket" || kind == "original_installation_recovery_object_access_batch_bracket")
        return PublisherEffectSelectionKind::original_installation_recovery;
    throw std::runtime_error("effect selected access kind is outside its closed bound");
}
std::string selected_access_bracket_kind(PublisherEffectSelectionKind kind) {
    auto base = selected_bracket_kind(kind);
    base.resize(base.size() - std::string("_bracket").size());
    return base + "_object_access_batch_bracket";
}
Value selected_operation(bool present, Value envelope, Value observation, const std::string& request) {
    Value result(Value::Object{{"schema", Value("usk.publisher_effect_selected_operation_readback.v1")},
        {"scope", Value("original_native_held_exact_request_selection")},
        {"present", Value(present)}});
    if (present) {
        require(same(envelope.at("apply_request"), usk::json::parse(request)) &&
            observation.at("approval").at("request_sha256").as_string() == usk::json::sha256_canonical(usk::json::parse(request)),
            "broker selected operation is not the actual received exact request");
        result.as_object().emplace("envelope", std::move(envelope));
        result.as_object().emplace("observation", std::move(observation));
    }
    return result;
}
}
void require_publisher_effect_broker_readback_record(const Value& profile) {
    require_projection(profile, profile.at("custody"), record_token(profile.at("service").at("primary_token")),
        record_token(profile.at("effect_primary_token")), false);
}
Value publisher_effect_broker_immutable_record(const Value& profile) {
    require_publisher_effect_broker_readback_record(profile);
    return immutable_profile(profile);
}
void require_publisher_effect_broker_readback_continuity(const Value& earlier, const Value& later) {
    require_publisher_effect_broker_readback_record(earlier);
    require_publisher_effect_broker_readback_record(later);
    require(same(immutable_profile(earlier), immutable_profile(later)), "broker immutable native profile changed");
    if (earlier.at("schema").as_string() == "usk.publisher_effect_broker_native_readback.v3")
        require_publisher_broker_worker_security_continuity(earlier.at("broker_security").at("worker_security"),
            later.at("broker_security").at("worker_security"));
}
PublisherWorkerTokenContext publisher_effect_worker_record_context(const Value& profile) {
    require_publisher_effect_broker_readback_record(profile);
    return {static_cast<std::uint32_t>(profile.at("custody").at("peer_process_id").as_unsigned()),
        profile.at("service").at("service_sid").as_string(), record_token(profile.at("effect_primary_token"))};
}
PublisherServiceObservation publisher_effect_broker_service_record(const Value& profile) {
    require_publisher_effect_broker_readback_record(profile);
    const auto& original = profile.at("service");
    return {std::filesystem::u8path(original.at("service_name").as_string()).wstring(), original.at("service_sid").as_string(),
        SERVICE_SID_TYPE_RESTRICTED, SERVICE_WIN32_OWN_PROCESS, SERVICE_RUNNING,
        static_cast<std::uint32_t>(original.at("process_id").as_unsigned()), record_token(original.at("primary_token"))};
}

struct PublisherBrokerObjectQuery::State {
    HANDLE handle = INVALID_HANDLE_VALUE;
    HANDLE volume = nullptr;
    Value volume_facts;
    Value expected;
    bool claimed = false, attempted = false, closed = false;
    DWORD close_error = ERROR_SUCCESS;
    bool close() noexcept {
        if (!attempted) {
            attempted = true;
            closed = handle == INVALID_HANDLE_VALUE || CloseHandle(handle) != FALSE;
            if (!closed) close_error = GetLastError();
            if (closed) {
                handle = INVALID_HANDLE_VALUE;
                if (claimed) { void* original = this; active_query.compare_exchange_strong(original, nullptr); claimed = false; }
            }
        }
        return closed;
    }
    void fence() const {
        require(claimed && !attempted && handle != INVALID_HANDLE_VALUE &&
            same(object(volume), volume_facts) && same(object(handle), expected) &&
            observe_publisher_noninheritable_handle_flags(handle) == 0 &&
            observe_publisher_handle_granted_access(handle) == query_rights,
            "broker query lost its original native object/volume/query-only handle");
    }
};
PublisherBrokerObjectQuery::PublisherBrokerObjectQuery(HANDLE volume, const Value& expected) : state_(std::make_unique<State>()) {
    try {
        void* absent = nullptr;
        require(active_query.compare_exchange_strong(absent, state_.get()), "broker query owner is active or closure is unknown");
        state_->claimed = true;
        state_->volume = volume;
        state_->volume_facts = object(volume);
        require_ntfs_root(volume, state_->volume_facts);
        require(expected.as_object().size() == 9 && expected.at("attributes").as_unsigned() <= 0xffffffffu &&
            !(expected.at("attributes").as_unsigned() & FILE_ATTRIBUTE_REPARSE_POINT) &&
            expected.at("reparse_tag").as_unsigned() == 0 && expected.at("link_count").as_unsigned() == 1 &&
            !expected.at("case_sensitive").as_boolean(), "broker requested object is outside the native query profile");
        state_->expected = expected;
        auto id = ntfs_id(expected.at("file_id").as_string(), state_->volume_facts.at("file_id").as_string());
        state_->handle = OpenFileById(volume, &id, query_rights,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        require(state_->handle != INVALID_HANDLE_VALUE, "broker actual query-only file-ID reopen failed");
        state_->fence();
    } catch (...) {
        const auto original = std::current_exception();
        if (!state_->close()) {
            const auto error = state_->close_error;
            state_.release();
            throw PublisherBrokerQueryClosureUnknown(error, original);
        }
        std::rethrow_exception(original);
    }
}
PublisherBrokerObjectQuery::~PublisherBrokerObjectQuery() { if (state_ && !state_->close()) state_.release(); }
PublisherBrokerQueryClosureUnknown::PublisherBrokerQueryClosureUnknown(DWORD error, std::exception_ptr primary) :
    std::runtime_error("broker original native query closure is unknown; Win32 " + std::to_string(error)),
    error_(error), primary_(std::move(primary)) {}
bool PublisherBrokerObjectQuery::close() noexcept { return state_->close(); }
Value PublisherBrokerObjectQuery::observation() const { state_->fence(); return state_->expected; }
DWORD PublisherBrokerObjectQuery::granted_access() const { state_->fence(); return observe_publisher_handle_granted_access(state_->handle); }
Value PublisherBrokerObjectQuery::authenticated_access(const PublisherRequestChannel& channel) const {
    state_->fence();
    auto result = channel.observe_authenticated_object_access(state_->handle);
    state_->fence();
    require(same(result.at("native_object"), state_->expected), "broker authenticated access native object differs");
    return result;
}

namespace {
std::string raw_sha256(const std::string& text) {
    usk::base::Sha256 hash;
    hash.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
    return hash.finish();
}
PublisherOperationKind maintenance_kind(const std::string& operation) {
    if (operation == "repair") return PublisherOperationKind::repair;
    if (operation == "move") return PublisherOperationKind::move;
    if (operation == "uninstall") return PublisherOperationKind::uninstall;
    throw std::runtime_error("broker original intent requires a maintenance operation");
}
std::array<std::wstring, 4> original_intent_names(const Value& minimum) {
    const auto install = usk::json::sha256_canonical(minimum.at("install_id"));
    const auto operation = usk::json::sha256_canonical(minimum.at("transaction_id"));
    return {L"", L"installation-operations", L"install-" + std::wstring(install.begin(), install.end()),
        L"operation-" + std::wstring(operation.begin(), operation.end()) + L".json"};
}
Value parse_original_installation_minimum(const std::string& text) {
    const auto value = usk::json::parse(text);
    require(value.as_object().size() == 4 && value.at("schema").as_string() == "usk.publisher_recovery_request.v1" &&
        usk::record_io::valid_identifier(value.at("request_id").as_string()) &&
        usk::record_io::valid_identifier(value.at("install_id").as_string()) &&
        usk::record_io::valid_identifier(value.at("transaction_id").as_string()),
        "broker original installation recovery requires its closed actual minimal request");
    return value;
}
bool is_installation_minimum(const Value& value) {
    return value.at("schema").as_string() == "usk.publisher_recovery_request.v1";
}
Value parse_original_minimum(const std::string& text) {
    return is_installation_minimum(usk::json::parse(text)) ? parse_original_installation_minimum(text) :
        parse_publisher_maintenance_recovery_request(text);
}
std::string listed_file_id(const PublisherDirectoryEntry& entry, const Value& volume) {
    static constexpr char digits[] = "0123456789abcdef";
    auto id = volume.at("file_id").as_string().substr(0, 17);
    for (const auto byte : entry.file_id) { id += digits[byte >> 4]; id += digits[byte & 15]; }
    return id;
}
PublisherDirectoryEntry original_intent_child(HANDLE parent, const std::wstring& name) {
    std::optional<PublisherDirectoryEntry> found;
    for (const auto& entry : observe_publisher_directory_entries(parent)) {
        if (CompareStringOrdinal(entry.name.c_str(), -1, name.c_str(), -1, TRUE) == CSTR_EQUAL) {
            require(entry.name == name && !found, "broker original intent spelling is ambiguous");
            found = entry;
        }
    }
    require(found.has_value(), "broker original protected intent is absent");
    return *found;
}
}
struct PublisherOriginalRecoveryIntentQuery::State {
    const RegisteredPublisherAdmission& admission;
    const PublisherRequestChannel& channel;
    HANDLE volume;
    const DWORD process_id = GetCurrentProcessId(), thread_id = GetCurrentThreadId();
    std::array<HANDLE, 4> handles{INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
    std::array<Value, 4> facts;
    std::array<std::wstring, 4> names;
    std::string request, service_sid, text;
    Value registered, volume_facts, client, minimum, record;
    bool claimed = false, attempted = false, closed = false;
    DWORD error = ERROR_SUCCESS;
    static constexpr DWORD read_rights = query_rights | FILE_READ_DATA;
    State(const RegisteredPublisherAdmission& a, const PublisherRequestChannel& c, HANDLE v) :
        admission(a), channel(c), volume(v) {}
    bool close() noexcept {
        if (!attempted) {
            attempted = true; closed = true;
            for (std::size_t index = handles.size(); index != 0; --index) {
                auto& handle = handles[index - 1];
                if (handle != INVALID_HANDLE_VALUE && handle) {
                    if (CloseHandle(handle)) handle = INVALID_HANDLE_VALUE;
                    else { if (closed) error = GetLastError(); closed = false; }
                }
            }
            if (closed && claimed) {
                void* original = this;
                active_query.compare_exchange_strong(original, nullptr);
                claimed = false;
            }
        }
        return closed;
    }
    void require_caller(HANDLE handle, const Value& native) const {
        auto access = channel.observe_authenticated_object_access(handle);
        require(same(access.at("client"), client) && same(access.at("native_object"), native),
            "broker original intent authenticated caller/object changed");
        access.as_object().erase("client"); access.as_object().erase("native_object");
        access.as_object().emplace("client_sha256", Value(usk::json::sha256_canonical(client)));
        access.as_object().emplace("native_object_sha256", Value(usk::json::sha256_canonical(native)));
        require_publisher_authenticated_object_access(access, client, native);
        constexpr DWORD mutation = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD |
            FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER;
        for (const auto& [name, check] : access.at("checks").as_object())
            require(name == "maximum_allowed" ? (check.at("granted").as_unsigned() & mutation) == 0 :
                !check.at("allowed").as_boolean() && check.at("granted").as_unsigned() == 0,
                "broker original intent caller retains mutation access");
    }
    void require_handle(std::size_t index) const {
        const auto handle = handles[index];
        const auto observed = index == 3 ? observe_publisher_file_handle(handle) : observe_publisher_directory_handle(handle);
        require_publisher_object_security_shape(observed, service_sid);
        require_publisher_stream_shape(handle);
        require(observe_publisher_noninheritable_handle_flags(handle) == 0 &&
            observe_publisher_handle_granted_access(handle) == read_rights &&
            same(publisher_handle_observation_json(observed), facts[index]),
            "broker original intent read-only observer changed");
        require_caller(handle, facts[index]);
    }
    std::string read() const {
        require_handle(3);
        const auto handle = handles[3];
        LARGE_INTEGER zero{}, size{}, after_size{};
        FILE_BASIC_INFO before{}, after{};
        const std::size_t limit = is_installation_minimum(minimum) ? 4u * 1024u * 1024u : 16u * 1024u * 1024u;
        require(GetFileSizeEx(handle, &size) && size.QuadPart > 0 && static_cast<std::uint64_t>(size.QuadPart) <= limit &&
            GetFileInformationByHandleEx(handle, FileBasicInfo, &before, sizeof(before)) &&
            SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN), "broker original intent read budget/facts unavailable");
        std::string bytes(static_cast<std::size_t>(size.QuadPart), '\0'); DWORD read_bytes = 0;
        require(ReadFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &read_bytes, nullptr) &&
            read_bytes == bytes.size() && GetFileSizeEx(handle, &after_size) &&
            GetFileInformationByHandleEx(handle, FileBasicInfo, &after, sizeof(after)) &&
            size.QuadPart == after_size.QuadPart && before.LastWriteTime.QuadPart == after.LastWriteTime.QuadPart &&
            before.ChangeTime.QuadPart == after.ChangeTime.QuadPart, "broker original protected intent changed during read");
        require_handle(3);
        return bytes;
    }
    void fence() const {
        require(claimed && !attempted && GetCurrentProcessId() == process_id && GetCurrentThreadId() == thread_id &&
            request == channel.authenticated_canonical_request() && same(admission.evidence(), registered) &&
            same(object(volume), volume_facts) && observe_publisher_handle_granted_access(volume) == query_rights,
            "broker original intent owner/request/registration/volume changed");
        for (std::size_t index = 0; index < handles.size(); ++index) {
            require_handle(index);
            if (index) {
                const auto listed = original_intent_child(handles[index - 1], names[index]);
                require(listed_file_id(listed, volume_facts) == facts[index].at("file_id").as_string() &&
                    !(listed.attributes & FILE_ATTRIBUTE_REPARSE_POINT) && listed.reparse_tag == 0 &&
                    ((listed.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == (index != 3),
                    "broker original intent lost its native parent/listed identity");
            }
        }
        require(read() == text, "broker original protected intent bytes changed");
    }
    void begin() {
        request = channel.authenticated_canonical_request();
        minimum = parse_original_minimum(request);
        names = original_intent_names(minimum);
        registered = admission.evidence();
        require(registered.at("process_id").as_unsigned() == process_id,
            "broker original intent requires its actual original SCM process");
        service_sid = registered.at("service_sid").as_string();
        volume_facts = object(volume);
        require_ntfs_root(volume, volume_facts);
        require(observe_publisher_handle_granted_access(volume) == query_rights &&
            registered.at("target_identity").at("volume_identity").at("root_file_id").as_string() ==
                volume_facts.at("file_id").as_string(), "broker original intent has another query-only target");
        client = channel.observe_authenticated_object_access(volume).at("client");
        require(client.at("user_sid").as_string() == registered.at("configured_caller_sid").as_string(),
            "broker original intent caller differs from native registration");
        for (std::size_t index = 0; index < handles.size(); ++index) {
            std::string id = volume_facts.at("file_id").as_string();
            if (index) {
                const auto listed = original_intent_child(handles[index - 1], names[index]);
                require(!(listed.attributes & FILE_ATTRIBUTE_REPARSE_POINT) && listed.reparse_tag == 0 &&
                    ((listed.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == (index != 3),
                    "broker original intent has another native object type");
                id = listed_file_id(listed, volume_facts);
            }
            auto descriptor = ntfs_id(id, volume_facts.at("file_id").as_string());
            // Adopt the actual result before any post-open validation. No
            // helper can discard an unobserved native close on failure.
            handles[index] = OpenFileById(volume, &descriptor, read_rights,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
            require(handles[index] && handles[index] != INVALID_HANDLE_VALUE, "broker original intent native by-ID read open failed");
            facts[index] = object(handles[index]);
            std::string native = index ? facts[index - 1].at("native_name").as_string() : "\\";
            if (index) {
                if (native.back() != '\\') native += '\\';
                native += std::filesystem::path(names[index]).u8string();
            }
            require(facts[index].at("file_id").as_string() == id && facts[index].at("native_name").as_string() == native &&
                ((facts[index].at("attributes").as_unsigned() & FILE_ATTRIBUTE_DIRECTORY) != 0) == (index != 3),
                "broker original intent native ancestry differs");
            require_handle(index);
        }
        text = read();
        const bool install = is_installation_minimum(minimum);
        usk::json::ParseLimits limits;
        limits.max_bytes = install ? 4u * 1024u * 1024u : 16u * 1024u * 1024u;
        if (!install) limits.max_values = 2000000u;
        record = usk::json::parse(text, limits);
        const std::set<std::string> fields{"schema", "install_id", "operation", "operation_id",
            "volume_root_identity", "initial_state_revision", "reviewed_snapshot", "context_sha256"};
        require(record.as_object().size() == fields.size(), "broker original intent is not a closed context");
        for (const auto& item : record.as_object()) require(fields.count(item.first) != 0, "broker original intent field is unknown");
        auto unsealed = record; unsealed.as_object().erase("context_sha256");
        require(record.at("schema").as_string() == (install ? "usk.installation_operation_context.v1" : "usk.installation_operation_context.v2") &&
            record.at("install_id").as_string() == minimum.at("install_id").as_string() &&
            record.at("operation_id").as_string() == minimum.at("transaction_id").as_string() &&
            record.at("operation").as_string() == (install ? "install_local" : minimum.at("operation").as_string()) &&
            record.at("context_sha256").as_string() == usk::json::sha256_canonical(unsealed) &&
            same(record.at("volume_root_identity"), observe_publisher_lease_root_identity(handles[0])) &&
            (install || same(record.at("volume_root_identity"), record.at("reviewed_snapshot").at("volume_root_identity"))) &&
            usk::json::canonical(record) + "\n" == text, "broker original intent seal/IDs/operation/native volume differ");
        if (install) {
            const auto& snapshot = record.at("reviewed_snapshot");
            const auto& apply = snapshot.at("apply_request");
            const auto snapshot_schema = snapshot.at("schema").as_string();
            std::set<std::string> snapshot_fields{"schema", "plan_digest", "plan_envelope_sha256", "archive_sha256",
                "archive_identity_digest", "entry_set_digest", "selected_file_set_digest", "target_root", "setup_root",
                "transaction_id", "applied_at", "policy_digest", "restart_policy_context", "plan_request", "planned_entries", "apply_request"};
            if (snapshot_schema == "usk.publisher.lab_reviewed_plan_snapshot.v4") snapshot_fields.insert("consumer_read_sid");
            require(snapshot.as_object().size() == snapshot_fields.size(), "broker original installation snapshot is not closed");
            for (const auto& item : snapshot.as_object()) require(snapshot_fields.count(item.first) != 0,
                "broker original installation snapshot field is unknown");
            require((snapshot_schema == "usk.publisher.lab_reviewed_plan_snapshot.v3" ||
                snapshot_schema == "usk.publisher.lab_reviewed_plan_snapshot.v4") &&
                snapshot.as_object().size() == (snapshot_schema == "usk.publisher.lab_reviewed_plan_snapshot.v4" ? 17u : 16u) &&
                record.at("initial_state_revision").as_string() == usk::json::sha256_canonical(Value(Value::Array{})) &&
                apply.as_object().size() == 7 && apply.at("schema").as_string() == "usk.install_local_apply_request.v1" &&
                apply.at("confirmation").as_string() == "APPLY" &&
                apply.at("plan_request").at("install_id").as_string() == minimum.at("install_id").as_string() &&
                apply.at("transaction_id").as_string() == minimum.at("transaction_id").as_string() &&
                snapshot.at("transaction_id").as_string() == minimum.at("transaction_id").as_string() &&
                snapshot.at("plan_digest").as_string() == apply.at("reviewed_plan_digest").as_string() &&
                snapshot.at("applied_at").as_string() == apply.at("applied_at").as_string() &&
                same(snapshot.at("plan_request"), apply.at("plan_request")), "broker original installation snapshot/apply binding differs");
        } else {
            require(record.at("reviewed_snapshot").at("schema").as_string() == "usk.publisher.maintenance_reviewed_snapshot.v2",
                "broker original maintenance snapshot family differs");
            require_publisher_maintenance_snapshot_binding(record.at("reviewed_snapshot"),
                maintenance_kind(minimum.at("operation").as_string()), minimum.at("install_id").as_string(),
                minimum.at("transaction_id").as_string(), record.at("initial_state_revision").as_string());
        }
        fence();
    }
};
PublisherOriginalRecoveryIntentQuery::PublisherOriginalRecoveryIntentQuery(const RegisteredPublisherAdmission& admission,
    const PublisherRequestChannel& channel, HANDLE volume) : state_(std::make_unique<State>(admission, channel, volume)) {
    try {
        void* absent = nullptr;
        require(active_query.compare_exchange_strong(absent, state_.get()), "broker query owner is active or closure is unknown");
        state_->claimed = true;
        state_->begin();
    } catch (...) {
        const auto original = std::current_exception();
        if (!state_->close()) {
            const auto error = state_->error; state_.release();
            throw PublisherBrokerQueryClosureUnknown(error, original);
        }
        std::rethrow_exception(original);
    }
}
PublisherOriginalRecoveryIntentQuery::~PublisherOriginalRecoveryIntentQuery() {
    if (state_ && !state_->close()) state_.release();
}
bool PublisherOriginalRecoveryIntentQuery::close() noexcept { return state_->close(); }
DWORD PublisherOriginalRecoveryIntentQuery::close_error() const noexcept { return state_->error; }
Value PublisherOriginalRecoveryIntentQuery::observation() const {
    state_->fence();
    Value::Array chain;
    for (std::size_t index = 0; index < state_->handles.size(); ++index)
        chain.emplace_back(Value::Object{{"role", Value(index == 0 ? "volume" : index == 1 ? "operations" : index == 2 ? "install" : "intent")},
            {"object", state_->facts[index]}, {"granted_access", Value(static_cast<std::uint64_t>(State::read_rights))}});
    return Value(Value::Object{{"schema", Value(is_installation_minimum(state_->minimum) ?
        "usk.publisher_protected_original_installation_intent.v1" : "usk.publisher_protected_original_maintenance_intent.v1")},
        {"scope", Value("native_read_only_fixed_original_namespace")},
        {"transport_request_sha256", Value(usk::json::sha256_canonical(state_->minimum))},
        {"intent_context_sha256", state_->record.at("context_sha256")}, {"intent_record_sha256", Value(raw_sha256(state_->text))},
        {"original_apply_request", state_->record.at("reviewed_snapshot").at("apply_request")},
        {"native_chain", Value(std::move(chain))}, {"volume_root_identity", state_->record.at("volume_root_identity")}});
}

namespace {
void require_closed(const Value& value, const std::set<std::string>& fields) {
    require(value.as_object().size() == fields.size(), "broker original selection record is not closed");
    for (const auto& item : value.as_object()) require(fields.count(item.first) != 0, "broker original selection field is unknown");
}
// These are administrative controller-store files, distinct from the
// SYSTEM/service-owned target and original custody. This is data validation;
// only the original held broker selection can supply native authority.
void require_administrative_enrollment_file(const Value& facts, const std::string& expected_suffix) {
    require_closed(facts, {"file_id", "native_name", "owner_sid", "dacl_protected", "attributes",
        "reparse_tag", "link_count", "case_sensitive", "dacl_aces"});
    const auto& id = facts.at("file_id").as_string();
    const auto& name = facts.at("native_name").as_string();
    require(id.size() == 49 && id[16] == ':' && hex(id.substr(0, 16), 16) && hex(id.substr(17), 32) &&
        !name.empty() && name.front() == '\\' && name.find('\0') == std::string::npos &&
        name.find('/') == std::string::npos && name.find(':') == std::string::npos &&
        name.find("\\\\") == std::string::npos && name.find("\\.\\") == std::string::npos &&
        name.find("\\..\\") == std::string::npos &&
        name.size() >= expected_suffix.size() &&
        name.compare(name.size() - expected_suffix.size(), expected_suffix.size(), expected_suffix) == 0 &&
        facts.at("owner_sid").as_string() == "S-1-5-32-544" && facts.at("dacl_protected").as_boolean() &&
        facts.at("attributes").as_unsigned() <= 0xffffffffu &&
        !(facts.at("attributes").as_unsigned() & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
        facts.at("reparse_tag").as_unsigned() == 0 && facts.at("link_count").as_unsigned() == 1 &&
        !facts.at("case_sensitive").as_boolean(),
        "effect administrative enrollment file identity or stored policy differs");
    const auto& aces = facts.at("dacl_aces").as_array();
    require(aces.size() == 2, "effect administrative enrollment ACL is not closed");
    bool system = false, administrators = false;
    for (const auto& ace : aces) {
        require_closed(ace, {"type", "flags", "access_mask", "sid"});
        require(ace.at("type").as_unsigned() == ACCESS_ALLOWED_ACE_TYPE &&
            ace.at("flags").as_unsigned() == 0 && ace.at("access_mask").as_unsigned() == FILE_ALL_ACCESS,
            "effect administrative enrollment ACE differs");
        const auto& sid = ace.at("sid").as_string();
        if (sid == "S-1-5-18") { require(!system, "effect administrative enrollment SYSTEM ACE repeats"); system = true; }
        else if (sid == "S-1-5-32-544") {
            require(!administrators, "effect administrative enrollment administrator ACE repeats"); administrators = true;
        } else throw std::runtime_error("effect administrative enrollment grants another principal");
    }
    require(system && administrators, "effect administrative enrollment ACL membership differs");
}
void require_enrollment(const Value& envelope, const Value& observation, const Value& request, const Value& profile) {
    (void)parse_publisher_reviewed_operation_envelope(usk::json::canonical(envelope), usk::json::canonical(request));
    const auto& approval = observation.at("approval");
    const auto& admitted = profile.at("registered_admission");
    require(observation.as_object().size() == 7 && observation.at("schema").as_string() ==
        "usk.publisher_selected_reviewed_operation_observation.v1" && observation.at("scope").as_string() ==
        "authenticated_exact_request_and_held_protected_enrollment_files" &&
        approval.as_object().size() == 7 && approval.at("schema").as_string() == "usk.publisher_reviewed_operation_approval.v1" &&
        approval.at("request_sha256").as_string() == usk::json::sha256_canonical(request) &&
        approval.at("registration_sha256").as_string() == admitted.at("registration_sha256").as_string() &&
        approval.at("target_admitted_sha256").as_string() == admitted.at("target_admitted_sha256").as_string() &&
        approval.at("caller_sid").as_string() == profile.at("authenticated_client").at("user_sid").as_string() &&
        approval.at("envelope_size_bytes").as_unsigned() > 0 && approval.at("envelope_size_bytes").as_unsigned() <= 1024u * 1024u &&
        observation.at("approval_sha256").as_string() == usk::json::sha256_canonical(approval) &&
        hex(approval.at("envelope_sha256").as_string(), 64) &&
        observation.at("envelope_sha256").as_string() == approval.at("envelope_sha256").as_string(),
        "effect original reviewed enrollment/request/caller binding differs");
    const auto stem = "\\Universal Setup\\Publisher\\" + admitted.at("service_name").as_string() +
        ".operation-" + usk::json::sha256_canonical(request);
    require_administrative_enrollment_file(observation.at("approval_file"), stem + ".approval.json");
    require_administrative_enrollment_file(observation.at("envelope_file"), stem + ".envelope.json");
    require(observation.at("approval_file").at("file_id").as_string() !=
        observation.at("envelope_file").at("file_id").as_string(), "effect administrative enrollment files alias");
}
void require_reviewed_selection(const Value& selection, const Value& request, const Value& profile) {
    const bool present = selection.at("present").as_boolean();
    require(selection.as_object().size() == (present ? 5u : 3u) &&
        selection.at("schema").as_string() == "usk.publisher_effect_selected_operation_readback.v1" &&
        selection.at("scope").as_string() == "original_native_held_exact_request_selection",
        "effect selected operation observation is not closed");
    if (present) require_enrollment(selection.at("envelope"), selection.at("observation"), request, profile);
}
void require_protected_stored_object(const Value& value, const std::string& sid) {
    require_closed(value, {"file_id", "native_name", "owner_sid", "dacl_protected", "attributes", "reparse_tag",
        "link_count", "case_sensitive", "dacl_aces"});
    require(value.at("attributes").as_unsigned() <= 0xffffffffu && value.at("reparse_tag").as_unsigned() <= 0xffffffffu &&
        value.at("link_count").as_unsigned() <= 0xffffffffu && value.at("dacl_aces").as_array().size() == 2,
        "broker original native object projection is out of range");
    PublisherHandleObservation observed{};
    observed.file_id = value.at("file_id").as_string();
    const auto& name = value.at("native_name").as_string();
    require(!name.empty() && name.size() <= 32767 && std::all_of(name.begin(), name.end(),
        [](unsigned char ch) { return ch != 0 && ch <= 0x7f; }), "broker original native name is outside its ASCII profile");
    observed.native_name.assign(name.begin(), name.end());
    observed.attributes = static_cast<DWORD>(value.at("attributes").as_unsigned());
    observed.reparse_tag = static_cast<DWORD>(value.at("reparse_tag").as_unsigned());
    observed.link_count = static_cast<DWORD>(value.at("link_count").as_unsigned());
    observed.case_sensitive = value.at("case_sensitive").as_boolean();
    observed.owner_sid = value.at("owner_sid").as_string();
    observed.dacl_protected = value.at("dacl_protected").as_boolean();
    for (const auto& ace : value.at("dacl_aces").as_array()) {
        require_closed(ace, {"type", "flags", "access_mask", "sid"});
        require(ace.at("type").as_unsigned() <= 255 && ace.at("flags").as_unsigned() <= 255 &&
            ace.at("access_mask").as_unsigned() <= 0xffffffffu, "broker original native ACE is out of range");
        observed.dacl_aces.push_back({static_cast<std::uint8_t>(ace.at("type").as_unsigned()),
            static_cast<std::uint8_t>(ace.at("flags").as_unsigned()), static_cast<DWORD>(ace.at("access_mask").as_unsigned()),
            ace.at("sid").as_string()});
    }
    require_publisher_object_security_shape(observed, sid);
}
}
namespace {
void require_original_selection(const Value& selected, const Value& minimal, const Value& broker, bool install) {
    const auto minimum = install ? parse_original_installation_minimum(usk::json::canonical(minimal)) :
        parse_publisher_maintenance_recovery_request(usk::json::canonical(minimal));
    require_publisher_effect_broker_readback_record(broker);
    const bool present = selected.at("present").as_boolean();
    require_closed(selected, present ? std::set<std::string>{"schema", "scope", "present", "intent", "envelope", "observation"} :
        std::set<std::string>{"schema", "scope", "present"});
    require(selected.at("schema").as_string() == (install ? "usk.publisher_effect_original_installation_selection.v1" :
        "usk.publisher_effect_original_maintenance_selection.v1") &&
        selected.at("scope").as_string() == "actual_minimal_request_to_native_protected_original_and_held_enrollment" &&
        broker.at("request_sha256").as_string() == usk::json::sha256_canonical(minimum),
        "broker original recovery selection has another family or actual transport request");
    if (!present) return;
    const auto& intent = selected.at("intent");
    require_closed(intent, {"schema", "scope", "transport_request_sha256", "intent_context_sha256", "intent_record_sha256",
        "original_apply_request", "native_chain", "volume_root_identity"});
    const auto& request = intent.at("original_apply_request");
    require_closed(request, {"schema", "plan_request", "reviewed_plan_id", "reviewed_plan_digest", "transaction_id", "applied_at", "confirmation"});
    require(intent.at("schema").as_string() == (install ? "usk.publisher_protected_original_installation_intent.v1" :
        "usk.publisher_protected_original_maintenance_intent.v1") &&
        intent.at("scope").as_string() == "native_read_only_fixed_original_namespace" &&
        intent.at("transport_request_sha256").as_string() == broker.at("request_sha256").as_string() &&
        hex(intent.at("intent_context_sha256").as_string(), 64) && hex(intent.at("intent_record_sha256").as_string(), 64) &&
        request.at("schema").as_string() == (install ? "usk.install_local_apply_request.v1" :
            "usk." + minimum.at("operation").as_string() + "_apply_request.v1") &&
        request.at("transaction_id").as_string() == minimum.at("transaction_id").as_string() &&
        request.at("plan_request").at("install_id").as_string() == minimum.at("install_id").as_string() &&
        request.at("confirmation").as_string() == "APPLY" &&
        selected.at("envelope").at("schema").as_string() == (install ? "usk.publisher.lab_reviewed_plan_envelope.v2" :
            "usk.publisher.maintenance_reviewed_plan_envelope.v1"),
        "broker original intent differs from the actual minimal recovery relation");
    require_enrollment(selected.at("envelope"), selected.at("observation"), request, broker);
    const auto& root = broker.at("volume_root");
    const auto& volume = intent.at("volume_root_identity");
    require_closed(volume, {"file_id", "volume_serial"});
    require(volume.at("file_id").as_string() == root.at("file_id").as_string().substr(17) &&
        volume.at("volume_serial").as_string() == broker.at("registered_admission").at("target_identity")
            .at("volume_identity").at("volume_serial").as_string(), "broker original intent belongs to another native volume");
    const auto names = original_intent_names(minimum);
    const auto& chain = intent.at("native_chain").as_array();
    require(chain.size() == names.size(), "broker original intent lacks its complete fixed native ancestry");
    std::set<std::string> ids;
    std::string native = "\\";
    for (std::size_t index = 0; index < chain.size(); ++index) {
        require_closed(chain[index], {"role", "object", "granted_access"});
        const auto& observed = chain[index].at("object");
        require_protected_stored_object(observed, broker.at("service").at("service_sid").as_string());
        if (index) { if (native.back() != '\\') native += '\\'; native += std::filesystem::path(names[index]).u8string(); }
        const auto& id = observed.at("file_id").as_string();
        require(chain[index].at("role").as_string() == (index == 0 ? "volume" : index == 1 ? "operations" : index == 2 ? "install" : "intent") &&
            chain[index].at("granted_access").as_unsigned() == (query_rights | FILE_READ_DATA) &&
            observed.at("native_name").as_string() == native && id.size() == 49 && id[16] == ':' &&
            id.substr(0, 17) == root.at("file_id").as_string().substr(0, 17) && hex(id.substr(17), 32) && ids.insert(id).second &&
            ((observed.at("attributes").as_unsigned() & FILE_ATTRIBUTE_DIRECTORY) != 0) == (index != 3) &&
            (index != 0 || same(observed, root)), "broker original intent fixed native chain/query rights differ");
    }
}
}
void require_publisher_effect_original_maintenance_selection(const Value& selected, const Value& minimal, const Value& broker) {
    require_original_selection(selected, minimal, broker, false);
}
void require_publisher_effect_original_installation_selection(const Value& selected, const Value& minimal, const Value& broker) {
    require_original_selection(selected, minimal, broker, true);
}

struct PublisherEffectBrokerReadback::State {
    const RegisteredPublisherAdmission& admission;
    const PublisherRequestChannel& channel;
    HANDLE volume;
    PublisherEffectWorkerCustody& custody;
    DWORD process_id = GetCurrentProcessId(), thread_id = GetCurrentThreadId();
    std::string request;
    Value baseline;
    Value selected_baseline;
    Value recovery_baseline;
    mutable std::unique_ptr<PublisherBrokerWorkerSecurity> worker_security;
    bool maintenance_recovery = false;
    bool installation_recovery = false;
    bool failed = false;
    std::uint64_t record_scope_sequence = 0;
    State(const RegisteredPublisherAdmission& a, const PublisherRequestChannel& c, HANDLE v,
        PublisherEffectWorkerCustody& owner) : admission(a), channel(c), volume(v), custody(owner),
        request(c.authenticated_canonical_request()) {
        maintenance_recovery = usk::json::parse(request).at("schema").as_string() ==
            "usk.publisher_maintenance_recovery_request.v1";
        if (maintenance_recovery) (void)parse_publisher_maintenance_recovery_request(request);
        installation_recovery = is_installation_minimum(usk::json::parse(request));
        if (installation_recovery) (void)parse_original_installation_minimum(request);
    }
    // A collected endpoint is not completed proof. Only complete() can create
    // a result eligible for retention or a reply, after checking both endpoints.
    struct PendingObservation { Value profile, selection; };
    class CompletedObservation final {
    public:
        const Value& profile() const { return profile_; }
        const Value& selection() const { return selection_; }
        Value take_profile() { return std::move(profile_); }
        Value take_selection() { return std::move(selection_); }
    private:
        friend struct State;
        explicit CompletedObservation(PendingObservation observation) :
            profile_(std::move(observation.profile)), selection_(std::move(observation.selection)) {}
        Value profile_, selection_;
    };
    Value recovery_current(bool select_original = false) const {
        require(maintenance_recovery || installation_recovery, "broker original selection requires its actual minimal request");
        PublisherOriginalRecoveryIntentQuery query(admission, channel, volume);
        Value result(Value::Object{});
        try {
            const auto intent = query.observation();
            const auto original_request = usk::json::canonical(intent.at("original_apply_request"));
            if (select_original && !admission.has_selected_reviewed_operation()) {
                std::wstring path; std::string sha;
                (void)admission.select_reviewed_operation(original_request, channel, path, sha);
            }
            result = Value(Value::Object{{"schema", Value(installation_recovery ? "usk.publisher_effect_original_installation_selection.v1" :
                "usk.publisher_effect_original_maintenance_selection.v1")},
                {"scope", Value("actual_minimal_request_to_native_protected_original_and_held_enrollment")},
                {"present", Value(admission.has_selected_reviewed_operation())}});
            if (admission.has_selected_reviewed_operation()) {
                const auto envelope = admission.selected_reviewed_envelope();
                require(same(envelope.at("apply_request"), intent.at("original_apply_request")),
                    "broker native original intent differs from its actual held reviewed operation");
                result.as_object().emplace("intent", intent);
                result.as_object().emplace("envelope", envelope);
                result.as_object().emplace("observation", admission.selected_reviewed_operation_observation());
            }
            require(same(query.observation(), intent), "broker protected original intent changed across enrollment");
        } catch (...) {
            const auto original = std::current_exception();
            if (!query.close()) throw PublisherBrokerQueryClosureUnknown(query.close_error(), original);
            std::rethrow_exception(original);
        }
        if (!query.close()) throw PublisherBrokerQueryClosureUnknown(query.close_error(), {});
        return result;
    }
    PendingObservation collect() const {
        require(!failed && process_id == GetCurrentProcessId() && thread_id == GetCurrentThreadId() &&
            request == channel.authenticated_canonical_request() && request == custody.canonical_request(),
            "broker original native owner/thread/authenticated request changed");
        auto execution = admission.observe_native_execution();
        auto selection = selected_operation(
            !(maintenance_recovery || installation_recovery) && execution.has_selection(),
            execution.take_selected_envelope(), execution.take_selected_observation(), request);
        auto admitted = execution.take_admission();
        const auto& actual_service = execution.service();
        auto process = observe_current_publisher_process_boundary();
        require_publisher_process_boundary(process, actual_service.process_id, actual_service.service_sid,
            actual_service.token.process_groups);
        if (!worker_security) worker_security = std::make_unique<PublisherBrokerWorkerSecurity>(actual_service);
        auto security = worker_security->observe_current(actual_service);
        auto configuration = execution.take_configuration();
        auto actual_custody = custody.observation();
        const auto child = custody.peer_primary_token();
        const auto volume_facts = observe_publisher_directory_handle(volume);
        require_ntfs_root(volume, publisher_handle_observation_json(volume_facts));
        require(observe_publisher_handle_granted_access(volume) == query_rights,
            "broker original volume handle has authority beyond its read-only query profile");
        require_publisher_object_security_shape(volume_facts, actual_service.service_sid);
        const auto access = channel.observe_authenticated_object_access(volume);
        require(same(access.at("native_object"), publisher_handle_observation_json(volume_facts)),
            "broker authenticated original volume changed");
        // Transfer owned subtrees once; retained proofs remain independent.
        Value::Object fields;
        fields.emplace("schema", Value("usk.publisher_effect_broker_native_readback.v3"));
        fields.emplace("authority", Value("read_only_observation"));
        fields.emplace("request_sha256", actual_custody.at("request_sha256"));
        fields.emplace("service", service(actual_service));
        fields.emplace("effect_primary_token", token(child));
        fields.emplace("registered_admission", std::move(admitted));
        fields.emplace("custody", std::move(actual_custody));
        fields.emplace("volume_root", publisher_handle_observation_json(volume_facts));
        fields.emplace("service_configuration", std::move(configuration));
        fields.emplace("broker_volume_granted_access",
            Value(static_cast<std::uint64_t>(observe_publisher_handle_granted_access(volume))));
        Value::Object security_fields;
        security_fields.emplace("process_boundary", std::move(process));
        security_fields.emplace("worker_security", std::move(security));
        fields.emplace("broker_security", Value(std::move(security_fields)));
        Value result(std::move(fields));
        const auto& collected_custody = result.at("custody");
        // The original authenticated caller is an independently
        // observed native fact, never the child's supplied SID.
        result.as_object().emplace("authenticated_client", access.at("client"));
        require_projection(result, collected_custody, actual_service.token, child, false);
        return PendingObservation{std::move(result), std::move(selection)};
    }
    CompletedObservation complete(const PendingObservation& before, PendingObservation after) const {
        // Each endpoint independently performed all original native reads and
        // projection checks. Continuity compares every immutable field plus the
        // original worker retirement relation; no intermediate instant is claimed.
        require_publisher_effect_broker_readback_continuity(before.profile, after.profile);
        require(same(before.selection, after.selection),
            "broker held exact-request selection changed across the native bracket");
        return CompletedObservation(std::move(after));
    }
    CompletedObservation fresh() const {
        const auto before = collect();
        return complete(before, collect());
    }
};
PublisherEffectBrokerReadback::PublisherEffectBrokerReadback(const RegisteredPublisherAdmission& a,
    const PublisherRequestChannel& c, HANDLE v, PublisherEffectWorkerCustody& owner) : state_(std::make_unique<State>(a, c, v, owner)) {
    auto initial = state_->fresh();
    state_->baseline = initial.take_profile();
    state_->selected_baseline = initial.take_selection();
    if (state_->maintenance_recovery || state_->installation_recovery) state_->recovery_baseline = state_->recovery_current(true);
    if (state_->maintenance_recovery) require_publisher_effect_original_maintenance_selection(
        state_->recovery_baseline, usk::json::parse(state_->request), state_->fresh().profile());
    if (state_->installation_recovery) require_publisher_effect_original_installation_selection(
        state_->recovery_baseline, usk::json::parse(state_->request), state_->fresh().profile());
}
PublisherEffectBrokerReadback::~PublisherEffectBrokerReadback() = default;
namespace {
void require_selected_endpoints(const Value& selected, const Value& actual_request,
    const Value& before, const Value& after, PublisherEffectSelectionKind kind) {
    require_publisher_effect_broker_readback_continuity(before, after);
    require(same(immutable_profile(before), immutable_profile(after)) &&
        before.at("request_sha256").as_string() == usk::json::sha256_canonical(actual_request) &&
        after.at("request_sha256").as_string() == usk::json::sha256_canonical(actual_request),
        "effect selected readback original request or native binding changed");
    for (const auto* endpoint : {&before, &after}) {
        if (kind == PublisherEffectSelectionKind::reviewed_operation)
            require_reviewed_selection(selected, actual_request, *endpoint);
        else if (kind == PublisherEffectSelectionKind::original_maintenance_recovery)
            require_publisher_effect_original_maintenance_selection(selected, actual_request, *endpoint);
        else require_publisher_effect_original_installation_selection(selected, actual_request, *endpoint);
    }
}
}
void require_publisher_effect_selection_readback(const Value& reply, const Value& actual_request) {
    require_closed(reply, {"schema", "kind", "profile_before", "profile", "result"});
    const auto& kind = reply.at("kind").as_string();
    require(reply.at("schema").as_string() == "usk.publisher_effect_broker_readback_response.v5" &&
        paired_selection_kind(kind), "effect selected readback grammar differs");
    require_selected_endpoints(reply.at("result"), actual_request,
        reply.at("profile_before"), reply.at("profile"), selection_selector(kind));
    require_batch_packet_budget(reply);
}
void require_publisher_effect_failure_diagnostic(const Value& diagnostic) {
    require(diagnostic.as_object().size() == 2 &&
        diagnostic.at("schema").as_string() == "usk.publisher_effect_worker_failure_diagnostic.v1" &&
        !diagnostic.at("message").as_string().empty() &&
        diagnostic.at("message").as_string().size() <= 4096 &&
        diagnostic.at("message").as_string().find('\0') == std::string::npos,
        "effect worker failure diagnostic is not closed bounded error data");
}
void require_publisher_effect_terminal_record(const Value& value, const Value& broker) {
    require_publisher_effect_broker_readback_record(broker);
    require_closed(value, {"schema", "request_sha256", "status", "response", "error", "error_code",
        "operation_inspection_ref", "effects_may_exist", "definite_preflight_refusal"});
    const auto status = value.at("status").as_string();
    const auto code = value.at("error_code").as_string();
    const auto error = value.at("error").as_string();
    const auto inspection = value.at("operation_inspection_ref").as_string();
    const bool before_effects = value.at("definite_preflight_refusal").as_boolean();
    (void)value.at("effects_may_exist").as_boolean();
    require(value.at("schema").as_string() == "usk.publisher_effect_worker_terminal.v1" &&
        value.at("request_sha256").as_string() == broker.at("request_sha256").as_string() &&
        error.size() <= 4096 && inspection.size() <= 1024 &&
        (code.empty() || code == "operation_conflict" || code == "operation_cancelled" || code == "lease_stale" ||
            code == "state_revision_stale" || code == "stale_plan"), "effect terminal request or finite diagnostic grammar differs");
    if (status == "success") {
        const auto& response = value.at("response");
        require(error.empty() && code.empty() && inspection.empty() && !before_effects &&
            response.at("schema").as_string() == "usk.publisher_lab_service_observation.v1" &&
            response.at("status").as_string() == "pass" &&
            response.at("process_id").as_unsigned() == broker.at("service").at("process_id").as_unsigned() &&
            response.at("service_name").as_string() == broker.at("service").at("service_name").as_string() &&
            response.at("service_sid").as_string() == broker.at("service").at("service_sid").as_string(),
            "effect terminal result differs from the actual SCM/public identity");
        if (response.contains("request_sha256")) require(response.at("request_sha256").as_string() ==
            broker.at("request_sha256").as_string(), "effect terminal result has another actual request");
    } else require(status == "failure" && !error.empty() && value.at("response").type() == Value::Type::null_value &&
        (!before_effects || code == "stale_plan" || code == "state_revision_stale"), "effect terminal failure projection differs");
}
void PublisherEffectBrokerReadback::respond_to_one_readback(DWORD timeout) {
    if (respond_to_one_packet(timeout)) {
        state_->failed = true;
        throw std::runtime_error("broker readback-only entry received a terminal packet");
    }
}
std::optional<Value> PublisherEffectBrokerReadback::respond_to_one_packet(DWORD timeout) {
    auto& state = *state_;
    const auto packet_started = GetTickCount64();
    try {
        auto pending_before = state.collect();
        auto& before = pending_before.profile;
        require_publisher_effect_broker_readback_continuity(state.baseline, before);
        require(same(immutable_profile(before), immutable_profile(state.baseline)), "broker original service/target/caller/worker binding changed");
        require(same(pending_before.selection, state.selected_baseline),
            "broker original held selection changed before readback");
        const auto request = state.custody.receive(timeout);
        if (request.at("schema").as_string() == "usk.publisher_effect_worker_failure_diagnostic.v1") {
            require_publisher_effect_failure_diagnostic(request);
            // Supply a cause only through conservative failure and checked
            // original closure. Never return it as terminal or narrow effects.
            throw std::runtime_error("private effect worker failed before confirmed terminal: " +
                request.at("message").as_string());
        }
        if (request.at("schema").as_string() == "usk.publisher_effect_worker_terminal.v1") {
            const auto completed = state.complete(pending_before, state.collect());
            const auto& after = completed.profile();
            require(same(immutable_profile(before), immutable_profile(after)) &&
                same(completed.selection(), state.selected_baseline) &&
                (!(state.maintenance_recovery || state.installation_recovery) || same(state.recovery_current(), state.recovery_baseline)),
                "broker original native scope changed across terminal selection");
            require_publisher_effect_terminal_record(request, after);
            // No further packet or readback may follow the terminal. Native
            // custody remains live for the caller's explicit shutdown proof.
            state.failed = true;
            return request;
        }
        const bool authority_record = request.at("schema").as_string() == authority_record_schema;
        if (request.at("schema").as_string() == record_byte_schema || authority_record) {
            require(state.record_scope_sequence != std::numeric_limits<std::uint64_t>::max(),
                "broker record byte scope sequence exhausted");
            const auto scope = record_scope_from_begin(request, ++state.record_scope_sequence, authority_record);
            const auto remaining = [&]() {
                return readback_remaining(packet_started, timeout, "broker complete record byte scope exceeded its original deadline");
            };
            std::size_t proof_bytes = 0;
            record_charge(proof_bytes, request);
            std::optional<Value> selected_before;
            if (authority_record) {
                const auto kind = selection_selector(scope.at("selected_kind").as_string());
                require(scope.at("request_sha256").as_string() == raw_sha256(state.request) &&
                    !state.installation_recovery &&
                    ((kind == PublisherEffectSelectionKind::original_maintenance_recovery) == state.maintenance_recovery),
                    "broker authority record scope differs from its actual original request family");
                selected_before.emplace(state.maintenance_recovery ? state.recovery_current() : pending_before.selection);
                require(same(*selected_before, state.maintenance_recovery ? state.recovery_baseline : state.selected_baseline),
                    "broker authority record original selection changed before readiness");
                require_selected_endpoints(*selected_before, usk::json::parse(state.request), before, before, kind);
                auto ready = record_phase(scope, "selection_ready");
                ready.as_object().emplace("profile_before", before);
                ready.as_object().emplace("selection", *selected_before);
                record_charge(proof_bytes, ready);
                state.custody.send(ready, remaining());
            }
            Value::Array ledger;
            std::array<std::vector<Value>, 2u> results;
            const auto chunks = static_cast<std::size_t>(scope.at("chunk_count").as_unsigned());
            ledger.reserve(static_cast<std::size_t>(scope.at("occurrence_count").as_unsigned()));
            for (std::size_t round = 0; round < 2u; ++round) {
                results[round].reserve(chunks);
                for (std::size_t index = 0; index < chunks; ++index) {
                    const auto packet = state.custody.receive(remaining());
                    record_require_packet(packet, scope, "query_chunk", {"round", "chunk_index", "native_objects"});
                    require(packet.at("round").as_unsigned() == round && packet.at("chunk_index").as_unsigned() == index,
                        "broker record byte scope received a duplicate/out-of-order chunk");
                    const auto& objects = packet.at("native_objects").as_array();
                    require(objects.size() == record_chunk_size(scope, index), "broker record byte scope chunk count differs");
                    record_charge(proof_bytes, packet);
                    Value::Array access_results;
                    access_results.reserve(objects.size());
                    for (std::size_t offset = 0; offset < objects.size(); ++offset) {
                        const auto& expected = objects[offset];
                        if (round == 0u) ledger.push_back(expected);
                        else require(same(expected, ledger[index * publisher_object_access_batch_limit + offset]),
                            "broker record byte second round changed an ordered occurrence");
                        PublisherBrokerObjectQuery query(state.volume, expected);
                        auto access = query.authenticated_access(state.channel);
                        require(query.close(), "broker record byte query handle closure is unknown");
                        // Literal shared raw9/client/object/mutation predicate MUST
                        // precede every sequencing acknowledgement and the read.
                        require_publisher_maintenance_read_only_access(access, before.at("authenticated_client"), expected);
                        access_results.push_back(std::move(access));
                        (void)remaining();
                    }
                    if (round == 0u && index + 1u == chunks)
                        require(usk::json::sha256_canonical(Value(ledger)) == scope.at("ledger_sha256").as_string(),
                            "broker complete first-round ordered ledger digest differs");
                    auto final_chunk = record_phase(scope, "results");
                    final_chunk.as_object().emplace("round", Value(static_cast<std::uint64_t>(round)));
                    final_chunk.as_object().emplace("chunk_index", Value(static_cast<std::uint64_t>(index)));
                    final_chunk.as_object().emplace("native_objects_sha256", Value(usk::json::sha256_canonical(packet.at("native_objects"))));
                    final_chunk.as_object().emplace("results", Value(std::move(access_results)));
                    record_charge(proof_bytes, final_chunk);
                    results[round].push_back(std::move(final_chunk));
                    auto marker = record_phase(scope, "chunk_closed");
                    marker.as_object().emplace("round", Value(static_cast<std::uint64_t>(round)));
                    marker.as_object().emplace("chunk_index", Value(static_cast<std::uint64_t>(index)));
                    marker.as_object().emplace("native_query_count", Value(static_cast<std::uint64_t>(objects.size())));
                    marker.as_object().emplace("native_objects_sha256", Value(usk::json::sha256_canonical(packet.at("native_objects"))));
                    require_batch_packet_budget(marker);
                    state.custody.send(marker, remaining());
                }
                if (round == 0u) {
                    const auto finished = state.custody.receive(remaining());
                    record_require_packet(finished, scope, "read_finished");
                    // This rendezvous carries no claimed byte proof or result.
                    // Only the inaccessible concrete child's reader can issue it.
                }
            }
            const auto queries_closed = record_phase(scope, "all_second_queries_closed");
            require_batch_packet_budget(queries_closed);
            state.custody.send(queries_closed, remaining());
            // Both actual query rounds and the successful fixed read rendezvous
            // precede these complete parent AFTER observations.
            auto completed = state.complete(pending_before, state.collect());
            const auto& after = completed.profile();
            require(same(immutable_profile(before), immutable_profile(after)) &&
                same(completed.selection(), state.selected_baseline),
                "broker record byte scope changed original selection/native ownership");
            std::optional<Value> selected_after;
            if (authority_record) {
                selected_after.emplace(state.maintenance_recovery ? state.recovery_current() : completed.selection());
                require(same(*selected_after, *selected_before) &&
                    same(*selected_after, state.maintenance_recovery ? state.recovery_baseline : state.selected_baseline),
                    "broker authority record protected original selection changed at completion");
                require_selected_endpoints(*selected_after, usk::json::parse(state.request), before, after,
                    selection_selector(scope.at("selected_kind").as_string()));
            } else require(!(state.maintenance_recovery || state.installation_recovery) ||
                same(state.recovery_current(), state.recovery_baseline),
                "broker record byte scope changed original recovery selection");
            auto final = record_phase(scope, "final");
            final.as_object().emplace("profile_before", before);
            final.as_object().emplace("profile", after);
            if (authority_record) {
                final.as_object().emplace("selection_before", *selected_before);
                final.as_object().emplace("selection", *selected_after);
            }
            record_charge(proof_bytes, final);
            state.custody.send(final, remaining());
            // Segment every independently owned raw result at the unchanged8
            // ceiling; never build/send one oversized aggregate result packet.
            for (const auto& round : results) for (const auto& chunk : round)
                state.custody.send(chunk, remaining());
            (void)remaining();
            return std::nullopt;
        }


        const auto kind = request.at("kind").as_string();
        const bool parallel_after = request.at("schema").as_string() ==
            "usk.publisher_effect_broker_readback_request.v7";
        const auto remaining = [&]() -> DWORD {
            return readback_remaining(packet_started, timeout,
                "broker parallel after-proof exchange exceeded its original deadline");
        };
        const bool selected_access = selected_access_kind(kind);
        const bool batch_access = kind == "object_access_batch_bracket" || selected_access;
        const bool paired_admission = kind == "service_admission_bracket";
        const bool paired_access = kind == "object_access_bracket" || batch_access;
        const bool paired_selection = paired_selection_kind(kind);
        const bool paired = paired_access || paired_admission || paired_selection;
        const auto selection_kind = selected_access ? selected_bracket_kind(selection_selector(kind)) : kind;
        require((request.at("schema").as_string() == "usk.publisher_effect_broker_readback_request.v1" &&
            (kind == "service_admission" || kind == "selected_operation" || kind == "object_access" ||
                kind == "original_maintenance_recovery" || kind == "original_installation_recovery") &&
            request.as_object().size() == (kind == "object_access" ? 3u : 2u)) ||
            (request.at("schema").as_string() == "usk.publisher_effect_broker_readback_request.v2" &&
                kind == "object_access_bracket" && request.as_object().size() == 3) ||
            (request.at("schema").as_string() == "usk.publisher_effect_broker_readback_request.v3" &&
                kind == "object_access_batch_bracket" && request.as_object().size() == 3) ||
            (request.at("schema").as_string() == "usk.publisher_effect_broker_readback_request.v4" &&
                paired_admission && request.as_object().size() == 2) ||
            (request.at("schema").as_string() == "usk.publisher_effect_broker_readback_request.v5" &&
                paired_selection && request.as_object().size() == 2) ||
            (request.at("schema").as_string() == "usk.publisher_effect_broker_readback_request.v6" &&
                selected_access && request.as_object().size() == 3) ||
            (parallel_after && batch_access && request.as_object().size() == 3),
            "broker readback request grammar differs");
        if (parallel_after) (void)remaining();
        if (paired_admission || paired_selection) require_batch_packet_budget(request);
        if (batch_access) {
            const auto& objects = request.at("native_objects").as_array();
            require(!objects.empty() && objects.size() <= publisher_object_access_batch_limit,
                "broker object access batch count exceeds its bound");
            require_batch_packet_budget(request);
        }
        Value result(Value::Object{});
        if (selection_kind == "selected_operation" || selection_kind == "selected_operation_bracket") {
            result = pending_before.selection;
            if (paired_selection || selected_access) require(same(result, state.selected_baseline),
                "broker selected bracket changed its original held selection");
        }
        if (selection_kind == "original_maintenance_recovery" || selection_kind == "original_installation_recovery" ||
            selection_kind == "original_maintenance_recovery_bracket" || selection_kind == "original_installation_recovery_bracket") {
            const std::string expected = state.installation_recovery ? "original_installation_recovery" : "original_maintenance_recovery";
            require((state.maintenance_recovery || state.installation_recovery) &&
                selection_kind == expected + ((paired_selection || selected_access) ? "_bracket" : ""),
                "broker original recovery query has another request family");
            result = state.recovery_current();
            if (paired_selection || selected_access) require(same(result, state.recovery_baseline),
                "broker recovery bracket changed its original protected selection");
        }
        Value selected;
        if (selected_access) selected = std::move(result);
        if (batch_access) {
            Value::Array results;
            for (const auto& expected : request.at("native_objects").as_array()) {
                PublisherBrokerObjectQuery query(state.volume, expected);
                auto access = query.authenticated_access(state.channel);
                require(same(access.at("client"), before.at("authenticated_client")),
                    "broker original authenticated batch caller changed");
                // Every occurrence retains the original complete kernel proof.
                // No query custody can survive to the next occurrence or reply.
                require(query.close(), "broker original native batch query handle closure is unknown");
                results.push_back(std::move(access));
            }
            result = Value(std::move(results));
        }
        else if (kind == "object_access" || paired_access) {
            PublisherBrokerObjectQuery query(state.volume, request.at("native_object"));
            result = query.authenticated_access(state.channel);
            require(same(result.at("client"), before.at("authenticated_client")), "broker original authenticated caller changed");
            // No parent descendant handle may cross this reply or obstruct a
            // child's subsequent root rename. Unknown close stops the route.
            require(query.close(), "broker original native query handle closure is unknown");
        }
        if (parallel_after) {
            // Every actual ordered query, including duplicates, has finished
            // and positively closed. This marker contains no result/selection
            // or completed profile. It only orders the original child's local
            // AFTER sampling; no endpoint/result may be retained from it.
            const Value marker(Value::Object{
                {"schema", Value("usk.publisher_effect_queries_closed.v1")},
                {"kind", Value(kind)},
                {"native_query_count", Value(static_cast<std::uint64_t>(result.as_array().size()))},
                {"native_objects_sha256", Value(usk::json::sha256_canonical(request.at("native_objects")))}});
            require_publisher_effect_queries_closed_marker(marker, kind, request.at("native_objects"));
            state.custody.send(marker, remaining());
        }
        auto completed = state.complete(pending_before, state.collect());
        const auto& after = completed.profile();
        if (kind == "original_maintenance_recovery") require_publisher_effect_original_maintenance_selection(
            result, usk::json::parse(state.request), after);
        if (kind == "original_installation_recovery") require_publisher_effect_original_installation_selection(
            result, usk::json::parse(state.request), after);
        require(same(immutable_profile(before), immutable_profile(after)) &&
            same(completed.selection(), state.selected_baseline) &&
            (!(state.maintenance_recovery || state.installation_recovery) || same(state.recovery_current(), state.recovery_baseline)),
            "broker native scope or original selected operation changed across readback");
        Value::Object response;
        response.emplace("schema", Value(selected_access ? "usk.publisher_effect_broker_readback_response.v6" : paired_selection ? "usk.publisher_effect_broker_readback_response.v5" :
            paired_admission ? "usk.publisher_effect_broker_readback_response.v4" :
            batch_access ? "usk.publisher_effect_broker_readback_response.v3" :
            paired_access ? "usk.publisher_effect_broker_readback_response.v2" :
            "usk.publisher_effect_broker_readback_response.v1"));
        response.emplace("kind", Value(kind));
        // These are this packet's actual fresh native reads, not cached profiles.
        // Full native checks and checked query closure precede either reply.
        if (paired) response.emplace("profile_before", std::move(before));
        response.emplace("profile", completed.take_profile());
        response.emplace("result", std::move(result));
        if (selected_access) response.emplace("selection", std::move(selected));
        const Value reply(std::move(response));
        if (paired_selection) require_publisher_effect_selection_readback(reply, usk::json::parse(state.request));
        if (selected_access) require_publisher_effect_selected_object_access_batch_readback(
            reply, usk::json::parse(state.request), request.at("native_objects"));
        if (batch_access || paired_admission) require_batch_packet_budget(reply);
        state.custody.send(reply, parallel_after ? remaining() : timeout);
        return std::nullopt;
    } catch (...) { state.failed = true; throw; }
}

struct PublisherEffectWorkerReadback::State {
    PublisherEffectWorkerPeer& peer;
    DWORD process_id = GetCurrentProcessId(), thread_id = GetCurrentThreadId();
    std::string request;
    Value baseline;
    Value previous;
    Value recovery_selection;
    bool recovery_selection_observed = false;
    bool failed = false, initialized = false;
    std::uint64_t record_scope_sequence = 0;
    explicit State(PublisherEffectWorkerPeer& p) : peer(p), request(p.canonical_request()) {}
    Value read(const std::string& kind, const Value* native_object, DWORD timeout,
        const std::function<void()>& after_queries_closed = {}) {
        const auto exchange_started = GetTickCount64();
        require(!failed && process_id == GetCurrentProcessId() && thread_id == GetCurrentThreadId() &&
            peer.canonical_request() == request, "effect readback original native owner/thread/request changed");
        const bool selected_access = selected_access_kind(kind);
        const bool batch_access = kind == "object_access_batch_bracket" || selected_access;
        const bool paired_admission = kind == "service_admission_bracket";
        const bool paired_access = kind == "object_access_bracket" || batch_access;
        const bool paired_selection = paired_selection_kind(kind);
        const bool paired = paired_access || paired_admission || paired_selection;
        const bool parallel_after = static_cast<bool>(after_queries_closed);
        require(!parallel_after || batch_access, "effect parallel AFTER callback lacks its bounded object batch");
        const auto remaining = [&]() -> DWORD {
            return readback_remaining(exchange_started, timeout,
                "effect parallel after-proof exchange exceeded its original deadline");
        };
        require(!paired_access || (native_object && initialized), "effect paired access requires its original admitted readback");
        require(!(paired_admission || paired_selection) || (!native_object && initialized),
            "effect paired admission/selection requires its original initialized readback");
        if (batch_access) require(!native_object->as_array().empty() &&
            native_object->as_array().size() <= publisher_object_access_batch_limit,
            "effect object access batch count exceeds its bound");
        const auto before = peer.observation();
        const auto parent = peer.peer_primary_token();
        const auto child = observe_current_publisher_token();
        Value message(Value::Object{{"schema", Value(parallel_after ? "usk.publisher_effect_broker_readback_request.v7" :
            selected_access ? "usk.publisher_effect_broker_readback_request.v6" : paired_selection ? "usk.publisher_effect_broker_readback_request.v5" :
            paired_admission ? "usk.publisher_effect_broker_readback_request.v4" :
            batch_access ? "usk.publisher_effect_broker_readback_request.v3" :
            paired_access ? "usk.publisher_effect_broker_readback_request.v2" :
            "usk.publisher_effect_broker_readback_request.v1")}, {"kind", Value(kind)}});
        if (native_object) message.as_object().emplace(batch_access ? "native_objects" : "native_object", *native_object);
        if (batch_access || paired_admission || paired_selection) require_batch_packet_budget(message);
        peer.send(message, parallel_after ? remaining() : timeout);
        if (parallel_after) {
            const auto marker = peer.receive(remaining());
            require_publisher_effect_queries_closed_marker(marker, kind, *native_object);
            // Private synchronous original-thread native observation only.
            // No recursive IPC, effect, retention or usable result is exposed.
            after_queries_closed();
            // Charge callback elapsed time even when the final packet is
            // already queued. Never restart the budget after the marker.
            (void)remaining();
        }
        auto reply = peer.receive(parallel_after ? remaining() : timeout);
        require(reply.as_object().size() == (selected_access ? 6u : paired ? 5u : 4u) && reply.at("schema").as_string() ==
            (selected_access ? "usk.publisher_effect_broker_readback_response.v6" :
                paired_selection ? "usk.publisher_effect_broker_readback_response.v5" :
                paired_admission ? "usk.publisher_effect_broker_readback_response.v4" :
                batch_access ? "usk.publisher_effect_broker_readback_response.v3" :
                paired_access ? "usk.publisher_effect_broker_readback_response.v2" : "usk.publisher_effect_broker_readback_response.v1") &&
            reply.at("kind").as_string() == kind &&
            same(peer.observation(), before) && same(token(peer.peer_primary_token()), token(parent)) &&
            same(token(observe_current_publisher_token()), token(child)), "effect fresh readback reply or actual native token/custody changed");
        require_projection(reply.at("profile"), before, parent, child, true);
        if (paired) {
            require_projection(reply.at("profile_before"), before, parent, child, true);
            require_publisher_effect_broker_readback_continuity(previous, reply.at("profile_before"));
            require_publisher_effect_broker_readback_continuity(reply.at("profile_before"), reply.at("profile"));
        }
        else if (initialized) require_publisher_effect_broker_readback_continuity(previous, reply.at("profile"));
        else { baseline = reply.at("profile"); initialized = true; }
        if (kind == "service_admission" || paired_admission) {
            require(reply.at("result").as_object().empty(), "effect service readback has an unexpected result");
            if (paired_admission) require_batch_packet_budget(reply);
        }
        else if (batch_access) {
            require_batch_packet_budget(reply);
            const auto& results = reply.at("result").as_array();
            const auto& objects = native_object->as_array();
            require(results.size() == objects.size(), "effect broker batch result count differs");
            for (std::size_t index = 0; index < objects.size(); ++index)
                require(same(results[index].at("native_object"), objects[index]) &&
                    same(results[index].at("client"), baseline.at("authenticated_client")),
                    "effect broker batch access belongs to another occurrence/caller");
        }
        else if (kind == "object_access" || paired_access) require(same(reply.at("result").at("native_object"), *native_object) &&
            same(reply.at("result").at("client"), baseline.at("authenticated_client")), "effect broker access belongs to another object/caller");
        if (paired_selection) require_publisher_effect_selection_readback(reply, usk::json::parse(request));
        if (selected_access) require_publisher_effect_selected_object_access_batch_readback(
            reply, usk::json::parse(request), *native_object);
        // The paired route retains its independent proof only after the
        // execution owner completes both local native brackets and all joins.
        if (!paired) previous = reply.at("profile");
        if (parallel_after) (void)remaining();
        return reply;
    }
};
namespace {
PublisherWorkerTokenContext actual_worker_context(const Value&);
void require_raw_object_access(const Value&, const Value&);
}
void require_publisher_effect_record_byte_phase(const Value& packet, const Value& scope, const std::string& phase) {
    require(phase == "begin" || phase == "read_finished" || phase == "all_second_queries_closed",
        "record byte scope has an unknown rendezvous phase");
    const auto checked = record_scope_from_begin(record_phase(scope, "begin"), scope.at("scope_sequence").as_unsigned());
    record_require_packet(packet, checked, phase);
}
void require_publisher_effect_authority_record_readback(const Value& ready, const Value& final,
    const Value& scope, const Value& actual_request) {
    const auto checked = record_scope_from_begin(record_phase(scope, "begin"),
        scope.at("scope_sequence").as_unsigned(), true);
    record_require_packet(ready, checked, "selection_ready", {"profile_before", "selection"});
    record_require_packet(final, checked, "final", {"profile_before", "profile", "selection_before", "selection"});
    require(checked.at("request_sha256").as_string() == usk::json::sha256_canonical(actual_request) &&
        same(final.at("profile_before"), ready.at("profile_before")) &&
        same(final.at("selection_before"), ready.at("selection")) &&
        same(final.at("selection"), ready.at("selection")),
        "authority record final substituted its exact provisional request/endpoint/selection");
    const auto kind = selection_selector(checked.at("selected_kind").as_string());
    require_selected_endpoints(ready.at("selection"), actual_request,
        ready.at("profile_before"), ready.at("profile_before"), kind);
    require_selected_endpoints(final.at("selection"), actual_request,
        final.at("profile_before"), final.at("profile"), kind);
}
void require_publisher_maintenance_read_only_access(Value access, const Value& client, const Value& native_object) {
    require(same(access.at("client"), client) && same(access.at("native_object"), native_object),
        "native maintenance authenticated object binding changed");
    access.as_object().erase("client"); access.as_object().erase("native_object");
    access.as_object().emplace("client_sha256", Value(usk::json::sha256_canonical(client)));
    access.as_object().emplace("native_object_sha256", Value(usk::json::sha256_canonical(native_object)));
    require_publisher_authenticated_object_access(access, client, native_object);
    constexpr DWORD mutation = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD |
        FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER;
    for (const auto& [name, check] : access.at("checks").as_object())
        if (name == "maximum_allowed" ? (check.at("granted").as_unsigned() & mutation) != 0 :
            check.at("allowed").as_boolean() || check.at("granted").as_unsigned() != 0)
            throw std::runtime_error("native maintenance caller retains object mutation rights");
}
struct PublisherEffectRecordByteRound::State {
    PublisherEffectWorkerPeer& peer;
    const Value& ledger;
    Value scope;
    ULONGLONG started;
    DWORD timeout;
    DWORD process_id = GetCurrentProcessId(), thread_id = GetCurrentThreadId();
    std::string request;
    Value custody, parent, child;
    std::size_t round = 0, chunk_index = 0, proof_bytes = 0;
    State(PublisherEffectWorkerPeer& p, const Value& l, Value s, ULONGLONG start, DWORD budget)
        : peer(p), ledger(l), scope(std::move(s)), started(start), timeout(budget), request(p.canonical_request()),
        custody(p.observation()), parent(token(p.peer_primary_token())), child(token(observe_current_publisher_token())) {}
    DWORD remaining() const {
        return readback_remaining(started, timeout, "child complete record byte scope exceeded its original deadline");
    }
    void require_binding() const {
        require(process_id == GetCurrentProcessId() && thread_id == GetCurrentThreadId() && peer.canonical_request() == request &&
            same(peer.observation(), custody) && same(token(peer.peer_primary_token()), parent) &&
            same(token(observe_current_publisher_token()), child), "child record byte scope actual token/peer/thread changed");
        (void)remaining();
    }
    void require_chunk_binding() const {
        require(process_id == GetCurrentProcessId() && thread_id == GetCurrentThreadId() && peer.canonical_request() == request,
            "child record byte chunk actual owner/thread/request changed");
        peer.require_record_chunk_custody(custody);
        require(same(token(peer.peer_primary_token()), parent) &&
            same(token(observe_current_publisher_token()), child), "child record byte chunk actual token changed");
        (void)remaining();
    }
    Value chunk_objects(std::size_t index) const {
        Value::Array objects;
        const auto count = record_chunk_size(scope, index);
        for (std::size_t offset = 0; offset < count; ++offset)
            objects.push_back(ledger.as_array()[index * publisher_object_access_batch_limit + offset]);
        return Value(std::move(objects));
    }
};
PublisherEffectRecordByteRound::PublisherEffectRecordByteRound(PublisherEffectWorkerPeer& peer, const Value& ledger,
    Value scope, ULONGLONG started, DWORD timeout)
    : state_(std::make_unique<State>(peer, ledger, std::move(scope), started, timeout)) {}
PublisherEffectRecordByteRound::~PublisherEffectRecordByteRound() = default;
void PublisherEffectRecordByteRound::query_chunk(const std::vector<HANDLE>& handles) {
    auto& s = *state_;
    s.require_chunk_binding();
    require(s.round < 2u && handles.size() == record_chunk_size(s.scope, s.chunk_index),
        "child record byte scope has another ordered pending chunk");
    Value::Array objects;
    objects.reserve(handles.size());
    for (const auto handle : handles) {
        require(observe_publisher_noninheritable_handle_flags(handle) == 0, "child record byte query handle is inheritable");
        objects.push_back(object(handle));
    }
    const Value observed(std::move(objects));
    require(same(observed, s.chunk_objects(s.chunk_index)), "child record byte actual occurrence differs from its frozen ledger");
    auto query = record_phase(s.scope, "query_chunk");
    query.as_object().emplace("round", Value(static_cast<std::uint64_t>(s.round)));
    query.as_object().emplace("chunk_index", Value(static_cast<std::uint64_t>(s.chunk_index)));
    query.as_object().emplace("native_objects", observed);
    record_charge(s.proof_bytes, query);
    s.peer.send(query, s.remaining());
    const auto marker = s.peer.receive(s.remaining());
    record_require_packet(marker, s.scope, "chunk_closed", {"round", "chunk_index", "native_query_count", "native_objects_sha256"});
    require(marker.at("round").as_unsigned() == s.round && marker.at("chunk_index").as_unsigned() == s.chunk_index &&
        marker.at("native_query_count").as_unsigned() == handles.size() &&
        marker.at("native_objects_sha256").as_string() == usk::json::sha256_canonical(observed),
        "child record byte chunk closure differs from its actual queries");
    // No usable raw result/authority is returned to the context. The broker's
    // actual shared read-only denial and checked closes precede this marker.
    for (std::size_t index = 0; index < handles.size(); ++index)
        require(same(object(handles[index]), observed.as_array()[index]) &&
            observe_publisher_noninheritable_handle_flags(handles[index]) == 0,
            "child record byte held object changed across provisional query");
    s.require_chunk_binding();
    ++s.chunk_index;
}
PublisherEffectWorkerReadback::ObjectAccessObservation
PublisherEffectWorkerReadback::original_maintenance_record_bytes_bracket(
    usk::lifecycle::detail::NativeMaintenanceRecordByteRead& reader, DWORD timeout,
    const std::function<void()>& after_queries_closed) {
    return maintenance_record_bytes_bracket(reader, timeout, after_queries_closed, nullptr, nullptr).objects;
}
PublisherEffectWorkerReadback::SelectedObjectAccessObservation
PublisherEffectWorkerReadback::authority_maintenance_record_bytes_bracket(
    usk::lifecycle::detail::NativeMaintenanceRecordByteRead& reader, DWORD timeout,
    PublisherEffectExecutionOwner& owner, const Value& native_before,
    const std::function<void()>& after_queries_closed) {
    auto observed = maintenance_record_bytes_bracket(reader, timeout, after_queries_closed, &owner, &native_before);
    require(observed.selection.has_value(), "child authority record scope lacks its completed selection");
    return {{std::move(observed.objects.before), std::move(observed.objects.after), std::move(*observed.selection)},
        std::move(observed.objects.access)};
}
PublisherEffectWorkerReadback::RecordByteObservation
PublisherEffectWorkerReadback::maintenance_record_bytes_bracket(
    usk::lifecycle::detail::NativeMaintenanceRecordByteRead& reader, DWORD timeout,
    const std::function<void()>& after_queries_closed, PublisherEffectExecutionOwner* authority_owner,
    const Value* authority_native_before) {
    const auto started = GetTickCount64();
    try {
        require(!state_->failed && state_->initialized && after_queries_closed &&
            state_->process_id == GetCurrentProcessId() && state_->thread_id == GetCurrentThreadId() &&
            state_->peer.canonical_request() == state_->request, "child record byte scope lacks its original initialized owner");
        const auto& ledger = reader.ledger();
        require(!ledger.as_array().empty() && ledger.as_array().size() <= publisher_record_byte_occurrence_limit &&
            state_->record_scope_sequence != std::numeric_limits<std::uint64_t>::max(),
            "child record byte scope count/sequence exceeds its bound");
        const auto selected_kind = reader.authority_selection_kind();
        require(static_cast<bool>(selected_kind) == (authority_owner && authority_native_before) &&
            (!selected_kind || *selected_kind != PublisherEffectSelectionKind::original_installation_recovery),
            "child record scope selection role differs from its sealed reader");
        const auto count = ledger.as_array().size();
        Value scope(Value::Object{{"kind", Value(selected_kind ? authority_record_kind : record_byte_kind)},
            {"scope_sequence", Value(++state_->record_scope_sequence)},
            {"occurrence_count", Value(static_cast<std::uint64_t>(count))},
            {"chunk_count", Value(static_cast<std::uint64_t>((count + publisher_object_access_batch_limit - 1u) / publisher_object_access_batch_limit))},
            {"ledger_sha256", Value(usk::json::sha256_canonical(ledger))}});
        if (selected_kind) {
            scope.as_object().emplace("selected_kind", Value(selected_bracket_kind(*selected_kind)));
            scope.as_object().emplace("request_sha256", Value(raw_sha256(state_->request)));
        }
        const auto begin = record_phase(scope, "begin");
        (void)record_scope_from_begin(begin, state_->record_scope_sequence, selected_kind.has_value());
        PublisherEffectRecordByteRound round(state_->peer, ledger, scope, started, timeout);
        auto& s = *round.state_;
        const auto before_peer = s.custody;
        const auto parent = state_->peer.peer_primary_token();
        const auto child = observe_current_publisher_token();
        s.require_binding();
        record_charge(s.proof_bytes, begin);
        s.peer.send(begin, s.remaining());
        std::optional<Value> provisional;
        if (selected_kind) {
            auto ready = s.peer.receive(s.remaining());
            record_require_packet(ready, scope, "selection_ready", {"profile_before", "selection"});
            record_charge(s.proof_bytes, ready);
            s.require_binding();
            require_projection(ready.at("profile_before"), before_peer, parent, child, true);
            require_publisher_effect_broker_readback_continuity(state_->previous, ready.at("profile_before"));
            (void)actual_worker_context(ready.at("profile_before"));
            require_selected_endpoints(ready.at("selection"), usk::json::parse(state_->request),
                ready.at("profile_before"), ready.at("profile_before"), *selected_kind);
            if (*selected_kind == PublisherEffectSelectionKind::original_maintenance_recovery && state_->recovery_selection_observed)
                require(same(ready.at("selection"), state_->recovery_selection),
                    "child authority record protected selection changed before readiness");
            // The original owner joins this actual broker BEFORE to the SAME
            // full native child BEFORE, then invokes only the sealed fixed
            // context predicate. No completed observation or retention exists.
            authority_owner->require_authority_record_selection(reader, ready.at("profile_before"),
                ready.at("selection"), *authority_native_before);
            provisional.emplace(std::move(ready));
            (void)s.remaining();
        }
        reader.run_round(round);
        require(s.chunk_index == scope.at("chunk_count").as_unsigned(), "child complete record first round is missing occurrences");
        (void)s.remaining();
        reader.read_original_bytes();
        (void)s.remaining();
        const auto finished = record_phase(scope, "read_finished");
        record_require_packet(finished, scope, "read_finished");
        s.peer.send(finished, s.remaining());
        s.round = 1u; s.chunk_index = 0;
        reader.run_round(round);
        require(s.chunk_index == scope.at("chunk_count").as_unsigned(), "child complete record second round is missing occurrences");
        const auto closed = s.peer.receive(s.remaining());
        record_require_packet(closed, scope, "all_second_queries_closed");
        // Distinct from read-finished: every second-round query has actually
        // positively closed before the original full local AFTER sample.
        after_queries_closed();
        (void)s.remaining();
        auto final = s.peer.receive(s.remaining());
        record_require_packet(final, scope, "final", selected_kind ?
            std::set<std::string>{"profile_before", "profile", "selection_before", "selection"} :
            std::set<std::string>{"profile_before", "profile"});
        record_charge(s.proof_bytes, final);
        Value::Array raw_results;
        raw_results.reserve(2u * count);
        for (std::size_t round_index = 0; round_index < 2u; ++round_index)
            for (std::size_t index = 0; index < scope.at("chunk_count").as_unsigned(); ++index) {
                auto packet = s.peer.receive(s.remaining());
                record_require_packet(packet, scope, "results", {"round", "chunk_index", "native_objects_sha256", "results"});
                const auto expected = s.chunk_objects(index);
                require(packet.at("round").as_unsigned() == round_index && packet.at("chunk_index").as_unsigned() == index &&
                    packet.at("native_objects_sha256").as_string() == usk::json::sha256_canonical(expected) &&
                    packet.at("results").as_array().size() == expected.as_array().size(),
                    "child record byte final raw result order/count/digest differs");
                record_charge(s.proof_bytes, packet);
                for (std::size_t offset = 0; offset < expected.as_array().size(); ++offset) {
                    auto& access = packet.as_object().at("results").as_array()[offset];
                    require_raw_object_access(access, expected.as_array()[offset]);
                    require_publisher_maintenance_read_only_access(access, state_->baseline.at("authenticated_client"), expected.as_array()[offset]);
                    raw_results.push_back(std::move(access));
                }
                (void)s.remaining();
            }
        s.require_binding(); // Actual post-final wire peer/image/token joins.
        require_projection(final.at("profile_before"), before_peer, parent, child, true);
        require_projection(final.at("profile"), before_peer, parent, child, true);
        require_publisher_effect_broker_readback_continuity(state_->previous, final.at("profile_before"));
        require_publisher_effect_broker_readback_continuity(final.at("profile_before"), final.at("profile"));
        (void)actual_worker_context(final.at("profile_before"));
        (void)actual_worker_context(final.at("profile"));
        std::optional<Value> selection;
        if (selected_kind) {
            require(reader.authority_selection_kind() == selected_kind,
                "child authority record selected role changed at completion");
            require_publisher_effect_authority_record_readback(*provisional, final, scope,
                usk::json::parse(state_->request));
            if (*selected_kind == PublisherEffectSelectionKind::original_maintenance_recovery && state_->recovery_selection_observed)
                require(same(final.at("selection"), state_->recovery_selection),
                    "child authority record protected selection changed at completion");
            selection.emplace(std::move(final.as_object().at("selection")));
        }
        (void)s.remaining();
        return {{std::move(final.as_object().at("profile_before")),
            std::move(final.as_object().at("profile")), Value(std::move(raw_results))}, std::move(selection)};
    } catch (...) { state_->failed = true; throw; }
}


PublisherEffectWorkerReadback::PublisherEffectWorkerReadback(PublisherEffectWorkerPeer& p) : state_(std::make_unique<State>(p)) {}
PublisherEffectWorkerReadback::~PublisherEffectWorkerReadback() = default;
Value PublisherEffectWorkerReadback::service_admission(DWORD timeout) {
    try {
        auto reply = state_->read("service_admission", nullptr, timeout);
        // read() has already retained independent baseline/previous proofs.
        return std::move(reply.as_object().at("profile"));
    }
    catch (...) { state_->failed = true; throw; }
}
PublisherWorkerTokenContext PublisherEffectWorkerReadback::worker_token_context(DWORD timeout) {
    try { return observe_current_worker(timeout).worker; }
    catch (...) { state_->failed = true; throw; }
}
namespace {
PublisherWorkerTokenContext actual_worker_context(const Value& profile) {
    const auto actual = observe_current_publisher_token();
    const auto& sid = profile.at("service").at("service_sid").as_string();
    require(same(token(actual), profile.at("effect_primary_token")) &&
        GetCurrentProcessId() == profile.at("custody").at("peer_process_id").as_unsigned() &&
        has_restricted_publisher_token_facts(actual, sid), "effect actual local primary-token context changed");
    return PublisherWorkerTokenContext{GetCurrentProcessId(), sid, actual};
}
void require_raw_object_access(const Value& result, const Value& native_object) {
    Value::Object fields;
    for (const auto& [name, value] : result.as_object())
        if (name != "client" && name != "native_object") fields.emplace(name, value);
    Value access(std::move(fields));
    // Unchanged closed raw-descriptor/native-object/client validation, including
    // all actual AccessCheck results. Preserve every other supplied field and
    // emplace precedence, without copying the two discarded proof subtrees.
    // The input remains independently owned; this projection is never authority.
    access.as_object().emplace("client_sha256", Value(usk::json::sha256_canonical(result.at("client"))));
    access.as_object().emplace("native_object_sha256", Value(usk::json::sha256_canonical(native_object)));
    require_publisher_authenticated_object_access(access, result.at("client"), native_object);
}
}
void require_publisher_effect_queries_closed_marker(const Value& marker,
    const std::string& kind, const Value& expected_native_objects) {
    require_closed(marker, {"schema", "kind", "native_query_count", "native_objects_sha256"});
    const auto& objects = expected_native_objects.as_array();
    require((kind == "object_access_batch_bracket" || selected_access_kind(kind)) &&
        !objects.empty() && objects.size() <= publisher_object_access_batch_limit &&
        marker.at("schema").as_string() == "usk.publisher_effect_queries_closed.v1" &&
        marker.at("kind").as_string() == kind &&
        marker.at("native_query_count").as_unsigned() == objects.size() &&
        marker.at("native_objects_sha256").as_string() == usk::json::sha256_canonical(expected_native_objects),
        "effect query-closed marker differs from its original ordered batch");
    require_batch_packet_budget(marker);
}
void require_publisher_effect_selected_object_access_batch_readback(const Value& reply,
    const Value& actual_request, const Value& expected_native_objects) {
    require_closed(reply, {"schema", "kind", "profile_before", "profile", "result", "selection"});
    const auto& kind = reply.at("kind").as_string();
    require(reply.at("schema").as_string() == "usk.publisher_effect_broker_readback_response.v6" &&
        selected_access_kind(kind), "effect selected access batch grammar differs");
    const auto& before = reply.at("profile_before");
    const auto& after = reply.at("profile");
    require_selected_endpoints(reply.at("selection"), actual_request, before, after, selection_selector(kind));
    const auto& objects = expected_native_objects.as_array();
    const auto& results = reply.at("result").as_array();
    require(!objects.empty() && objects.size() <= publisher_object_access_batch_limit && results.size() == objects.size(),
        "effect selected access batch count differs or exceeds its bound");
    for (std::size_t index = 0; index < objects.size(); ++index) {
        require(same(results[index].at("native_object"), objects[index]) &&
            same(results[index].at("client"), before.at("authenticated_client")) &&
            same(results[index].at("client"), after.at("authenticated_client")),
            "effect selected access belongs to another ordered occurrence/caller");
        require_raw_object_access(results[index], objects[index]);
    }
    require_batch_packet_budget(reply);
}
PublisherEffectWorkerReadback::CurrentWorkerObservation
PublisherEffectWorkerReadback::observe_current_worker(DWORD timeout) {
    try {
        auto profile = service_admission(timeout);
        const auto worker = actual_worker_context(profile);
        return CurrentWorkerObservation{std::move(profile), worker};
    } catch (...) { state_->failed = true; throw; }
}
Value PublisherEffectWorkerReadback::settled_worker_security(const PublisherWorkerTokenContext& worker) {
    try {
        require(!state_->failed && worker.process_id == GetCurrentProcessId(),
            "effect startup requires its active readback and actual current process");
        return observe_settled_publisher_worker_security(worker, state_->peer.cancellation_observer());
    } catch (...) { state_->failed = true; throw; }
}
Value PublisherEffectWorkerReadback::selected_reviewed_operation(DWORD timeout) {
    try {
        const auto reply = state_->read("selected_operation", nullptr, timeout);
        const auto& selection = reply.at("result");
        require_reviewed_selection(selection, usk::json::parse(state_->request), reply.at("profile"));
        return selection;
    } catch (...) { state_->failed = true; throw; }
}
Value PublisherEffectWorkerReadback::selected_original_maintenance_recovery(DWORD timeout) {
    try {
        const auto minimum = parse_publisher_maintenance_recovery_request(state_->request);
        const auto reply = state_->read("original_maintenance_recovery", nullptr, timeout);
        const auto& selected = reply.at("result");
        require_publisher_effect_original_maintenance_selection(selected, minimum, reply.at("profile"));
        if (state_->recovery_selection_observed) require(same(selected, state_->recovery_selection),
            "effect original protected maintenance selection changed");
        else { state_->recovery_selection = selected; state_->recovery_selection_observed = true; }
        return selected;
    } catch (...) { state_->failed = true; throw; }
}
Value PublisherEffectWorkerReadback::selected_original_installation_recovery(DWORD timeout) {
    try {
        const auto minimum = parse_original_installation_minimum(state_->request);
        const auto reply = state_->read("original_installation_recovery", nullptr, timeout);
        const auto& selected = reply.at("result");
        require_publisher_effect_original_installation_selection(selected, minimum, reply.at("profile"));
        if (state_->recovery_selection_observed) require(same(selected, state_->recovery_selection),
            "effect original protected installation selection changed");
        else { state_->recovery_selection = selected; state_->recovery_selection_observed = true; }
        return selected;
    } catch (...) { state_->failed = true; throw; }
}
Value PublisherEffectWorkerReadback::authenticated_object_access(HANDLE held, DWORD timeout) {
    try {
        require(observe_publisher_noninheritable_handle_flags(held) == 0, "effect access object is inheritable");
        const auto before = object(held);
        auto reply = state_->read("object_access", &before, timeout);
        require(same(object(held), before) && observe_publisher_noninheritable_handle_flags(held) == 0,
            "effect original held object changed across broker readback");
        require_raw_object_access(reply.at("result"), before);
        return std::move(reply.as_object().at("result"));
    } catch (...) { state_->failed = true; throw; }
}
PublisherEffectWorkerReadback::ObjectAccessObservation
PublisherEffectWorkerReadback::authenticated_object_access_bracket(HANDLE held, DWORD timeout) {
    try {
        require(observe_publisher_noninheritable_handle_flags(held) == 0, "effect access object is inheritable");
        const auto before = object(held);
        auto reply = state_->read("object_access_bracket", &before, timeout);
        require(same(object(held), before) && observe_publisher_noninheritable_handle_flags(held) == 0,
            "effect original held object changed across broker readback");
        // Retain the actual post-wire token/restricted-SID/PID joins for BOTH
        // fresh parent profiles, beyond the transport token/custody checks.
        (void)actual_worker_context(reply.at("profile_before"));
        (void)actual_worker_context(reply.at("profile"));
        require_raw_object_access(reply.at("result"), before);
        return ObjectAccessObservation{std::move(reply.as_object().at("profile_before")),
            std::move(reply.as_object().at("profile")), std::move(reply.as_object().at("result"))};
    } catch (...) { state_->failed = true; throw; }
}
PublisherEffectWorkerReadback::ObjectAccessObservation
PublisherEffectWorkerReadback::authenticated_object_access_batch_bracket(const std::vector<HANDLE>& held, DWORD timeout,
    const std::function<void()>& after_queries_closed) {
    const auto bracket_started = GetTickCount64();
    try {
        require(!held.empty() && held.size() <= publisher_object_access_batch_limit,
            "effect original held-object batch count exceeds its bound");
        Value::Array objects;
        for (const auto handle : held) {
            require(observe_publisher_noninheritable_handle_flags(handle) == 0, "effect batch access object is inheritable");
            objects.push_back(object(handle));
        }
        const Value before(std::move(objects));
        auto reply = state_->read("object_access_batch_bracket", &before, after_queries_closed ? readback_remaining(bracket_started, timeout,
            "effect full parallel object bracket exceeded its original deadline") : timeout, after_queries_closed);
        for (std::size_t index = 0; index < held.size(); ++index) {
            require(same(object(held[index]), before.as_array()[index]) &&
                observe_publisher_noninheritable_handle_flags(held[index]) == 0,
                "effect original held batch object changed across broker readback");
            require_raw_object_access(reply.at("result").as_array()[index], before.as_array()[index]);
        }
        (void)actual_worker_context(reply.at("profile_before"));
        (void)actual_worker_context(reply.at("profile"));
        if (after_queries_closed) (void)readback_remaining(bracket_started, timeout,
            "effect completed parallel object bracket exceeded its original deadline");
        return ObjectAccessObservation{std::move(reply.as_object().at("profile_before")),
            std::move(reply.as_object().at("profile")), std::move(reply.as_object().at("result"))};
    } catch (...) { state_->failed = true; throw; }
}
PublisherEffectWorkerReadback::SelectedObjectAccessObservation
PublisherEffectWorkerReadback::selected_object_access_batch_bracket(PublisherEffectSelectionKind kind,
    const std::vector<HANDLE>& held, DWORD timeout, const std::function<void()>& after_queries_closed) {
    const auto bracket_started = GetTickCount64();
    try {
        require(!held.empty() && held.size() <= publisher_object_access_batch_limit,
            "effect selected held-object batch count exceeds its bound");
        Value::Array objects;
        for (const auto handle : held) {
            require(observe_publisher_noninheritable_handle_flags(handle) == 0, "effect selected access object is inheritable");
            objects.push_back(object(handle));
        }
        const Value before(std::move(objects));
        auto reply = state_->read(selected_access_bracket_kind(kind), &before, after_queries_closed ? readback_remaining(bracket_started, timeout,
            "effect full parallel object bracket exceeded its original deadline") : timeout, after_queries_closed);
        for (std::size_t index = 0; index < held.size(); ++index) {
            require(same(object(held[index]), before.as_array()[index]) &&
                observe_publisher_noninheritable_handle_flags(held[index]) == 0,
                "effect original selected batch object changed across broker readback");
        }
        (void)actual_worker_context(reply.at("profile_before"));
        (void)actual_worker_context(reply.at("profile"));
        const auto& selected = reply.at("selection");
        if (kind != PublisherEffectSelectionKind::reviewed_operation && state_->recovery_selection_observed)
            require(same(selected, state_->recovery_selection), "effect original protected selected access changed");
        if (after_queries_closed) (void)readback_remaining(bracket_started, timeout,
            "effect completed parallel selected bracket exceeded its original deadline");
        return SelectedObjectAccessObservation{SelectionObservation{
            std::move(reply.as_object().at("profile_before")), std::move(reply.as_object().at("profile")),
            std::move(reply.as_object().at("selection"))}, std::move(reply.as_object().at("result"))};
    } catch (...) { state_->failed = true; throw; }
}
PublisherEffectWorkerReadback::AdmissionObservation
PublisherEffectWorkerReadback::service_admission_bracket(DWORD timeout) {
    try {
        auto reply = state_->read("service_admission_bracket", nullptr, timeout);
        (void)actual_worker_context(reply.at("profile_before"));
        (void)actual_worker_context(reply.at("profile"));
        return AdmissionObservation{std::move(reply.as_object().at("profile_before")),
            std::move(reply.as_object().at("profile"))};
    } catch (...) { state_->failed = true; throw; }
}
PublisherEffectWorkerReadback::SelectionObservation
PublisherEffectWorkerReadback::selected_operation_bracket(PublisherEffectSelectionKind kind, DWORD timeout) {
    try {
        auto reply = state_->read(selected_bracket_kind(kind), nullptr, timeout);
        (void)actual_worker_context(reply.at("profile_before"));
        (void)actual_worker_context(reply.at("profile"));
        const auto& selected = reply.at("result");
        if (kind != PublisherEffectSelectionKind::reviewed_operation) {
            if (state_->recovery_selection_observed) require(same(selected, state_->recovery_selection),
                "effect original protected bracket selection changed");
            // Retain this original selection only after BOTH native local proofs
            // have completed, alongside the existing readback continuity proof.
        }
        return SelectionObservation{std::move(reply.as_object().at("profile_before")),
            std::move(reply.as_object().at("profile")), std::move(reply.as_object().at("result"))};
    } catch (...) { state_->failed = true; throw; }
}
void PublisherEffectWorkerReadback::poison() noexcept { state_->failed = true; }
void PublisherEffectWorkerReadback::retain_readback_bracket(const Value& before, const Value& after) {
    try {
        require(!state_->failed && state_->initialized && state_->process_id == GetCurrentProcessId() &&
            state_->thread_id == GetCurrentThreadId() && state_->peer.canonical_request() == state_->request,
            "effect paired access original retention owner/thread/request changed");
        require_publisher_effect_broker_readback_continuity(state_->previous, before);
        require_publisher_effect_broker_readback_continuity(before, after);
        state_->previous = after;
    } catch (...) { state_->failed = true; throw; }
}
void PublisherEffectWorkerReadback::retain_selection_bracket(const SelectionObservation& observed,
    PublisherEffectSelectionKind kind) {
    try {
        if (kind != PublisherEffectSelectionKind::reviewed_operation && state_->recovery_selection_observed)
            require(same(observed.selection, state_->recovery_selection), "effect original protected selection changed at retention");
        retain_readback_bracket(observed.before, observed.after);
        if (kind != PublisherEffectSelectionKind::reviewed_operation && !state_->recovery_selection_observed) {
            state_->recovery_selection = observed.selection;
            state_->recovery_selection_observed = true;
        }
    } catch (...) { state_->failed = true; throw; }
}
namespace {
Value worker_context(const PublisherWorkerTokenContext& worker) {
    Value::Object fields;
    fields.emplace("process_id", Value(static_cast<std::uint64_t>(worker.process_id)));
    fields.emplace("service_sid", Value(worker.service_sid));
    fields.emplace("primary_token", token(worker.token));
    return Value(std::move(fields));
}
}
struct PublisherEffectWorkerNativeSecurity::State {
    PublisherEffectWorkerReadback& readback;
    const DWORD thread_id = GetCurrentThreadId();
    const PublisherWorkerTokenContext original;
    const Value process;
    std::unique_ptr<PublisherWorkerSecurityContinuity> continuity;
    bool failed = false;
    explicit State(PublisherEffectWorkerReadback& r) : readback(r), original(r.worker_token_context()),
        process(observe_current_publisher_process_boundary()) {
        require(GetCurrentProcessId() == original.process_id &&
            has_restricted_publisher_token_facts(original.token, original.service_sid),
            "effect security owner requires its own actual restricted primary token");
        require_publisher_process_boundary(process, original.process_id, original.service_sid, original.token.process_groups);
        const auto settled = readback.settled_worker_security(original);
        continuity = std::make_unique<PublisherWorkerSecurityContinuity>(settled);
        (void)observe_brokered();
    }
    PublisherEffectWorkerNativeSecurity::BrokeredObservation observe_brokered(
        const std::string& failure_context = {}) {
        try {
            require(!failed && thread_id == GetCurrentThreadId() && GetCurrentProcessId() == original.process_id,
                "effect security original execution process/thread changed");
            auto before = readback.observe_current_worker();
            const auto& current = before.worker;
            auto native = observe_local(current, failure_context);
            // Preserve the post-token/process native read before the final wire
            // observation, including its independent actual local token join.
            auto after = readback.observe_current_worker();
            require(same(worker_context(after.worker), worker_context(original)),
                "effect security native token/process/broker changed across original-thread readback");
            return PublisherEffectWorkerNativeSecurity::BrokeredObservation{
                std::move(before.broker), std::move(after.broker), std::move(native)};
        } catch (...) { failed = true; throw; }
    }
    Value observe_local(const PublisherWorkerTokenContext& current, const std::string& failure_context) {
        require(!failed && thread_id == GetCurrentThreadId() && GetCurrentProcessId() == original.process_id,
            "effect security original execution process/thread changed");
        require(same(worker_context(current), worker_context(original)), "effect security original primary-token binding changed");
        auto current_process = observe_current_publisher_process_boundary();
        require_publisher_process_boundary(current_process, current.process_id, current.service_sid, current.token.process_groups);
        require(same(current_process, process), "effect security original process owner/DACL changed");
        auto security = continuity->observe_current_with_retirement(failure_context);
        require_publisher_worker_security(security, current);
        require(same(token(observe_current_publisher_token()), token(original.token)) &&
            same(observe_current_publisher_process_boundary(), process),
            "effect security native token/process/broker changed across original-thread readback");
        Value::Object native_fields;
        native_fields.emplace("schema", Value("usk.publisher_effect_worker_native_security.v2"));
        native_fields.emplace("authority", Value("read_only_observation"));
        native_fields.emplace("scope", Value("actual_current_child_with_original_native_retirement_partition"));
        native_fields.emplace("worker", worker_context(current));
        native_fields.emplace("process_boundary", std::move(current_process));
        native_fields.emplace("worker_security", std::move(security));
        return Value(std::move(native_fields));
    }
    Value observe_local_current(const std::string& failure_context) {
        try {
            require(!failed && thread_id == GetCurrentThreadId() && GetCurrentProcessId() == original.process_id,
                "effect security original execution process/thread changed");
            const auto actual = observe_current_publisher_token();
            require(has_restricted_publisher_token_facts(actual, original.service_sid),
                "effect security actual local restricted primary token changed");
            // The SID is held by the original native owner; no response JSON
            // supplies this context or replaces the pinned continuity baseline.
            return observe_local(PublisherWorkerTokenContext{GetCurrentProcessId(), original.service_sid, actual}, failure_context);
        } catch (...) { failed = true; throw; }
    }
};
PublisherEffectWorkerNativeSecurity::PublisherEffectWorkerNativeSecurity(PublisherEffectWorkerReadback& r) :
    state_(std::make_unique<State>(r)) {}
PublisherEffectWorkerNativeSecurity::~PublisherEffectWorkerNativeSecurity() = default;
Value PublisherEffectWorkerNativeSecurity::observe_current(const std::string& context) {
    return state_->observe_brokered(context).native;
}
PublisherEffectWorkerNativeSecurity::BrokeredObservation
PublisherEffectWorkerNativeSecurity::observe_brokered(const std::string& context) {
    return state_->observe_brokered(context);
}
Value PublisherEffectWorkerNativeSecurity::observe_local_current(const std::string& context) {
    return state_->observe_local_current(context);
}
}
void usk::lifecycle::detail::NativeMaintenanceRecordByteRead::require_authority_selection(
    const usk::json::Value&, const usk::json::Value&, const usk::json::Value&) {
    throw std::runtime_error("ordinary record reader cannot validate authority selection");
}
void usk::lifecycle::detail::NativeMaintenanceRecordByteRead::observe_chunk(
    usk::platform::windows::PublisherEffectRecordByteRound& round, const std::vector<HANDLE>& handles) {
    round.query_chunk(handles);
}

#endif
