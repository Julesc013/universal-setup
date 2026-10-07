// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_effect_broker_internal.h"
#if defined(_WIN32)
#include "usk_publisher_registration.h"
#include "usk_publisher_request_channel.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_execution_observation.h"
#include "usk_publisher_tree_observation.h"
#include "usk_publisher_process_boundary.h"
#include <atomic>
#include <algorithm>
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
bool same(const Value& left, const Value& right) {
    return usk::json::canonical(left) == usk::json::canonical(right);
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
    return Value(Value::Object{{"user_sid", Value(input.process_user_sid)},
        {"groups", groups(input.process_groups)}, {"restricted_sids", groups(input.process_restricted_sids)},
        {"observing_thread_impersonating", Value(input.current_thread_impersonating)},
        {"token_id", Value(input.identity.token_id)}, {"authentication_id", Value(input.identity.authentication_id)},
        {"modified_id", Value(input.identity.modified_id)},
        {"token_type", Value(static_cast<std::uint64_t>(input.identity.token_type))}});
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
    return Value(Value::Object{{"service_name", Value(std::filesystem::path(input.service_name).u8string())},
        {"service_sid", Value(input.service_sid)},
        {"service_sid_type", Value(static_cast<std::uint64_t>(input.service_sid_type))},
        {"service_type", Value(static_cast<std::uint64_t>(input.service_type))},
        {"service_state", Value(static_cast<std::uint64_t>(input.service_state))},
        {"process_id", Value(static_cast<std::uint64_t>(input.process_id))}, {"primary_token", token(input.token)}});
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
    require(profile.as_object().size() == 12 && profile.at("schema").as_string() ==
        "usk.publisher_effect_broker_native_readback.v2" &&
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
    require_publisher_worker_security(security.at("worker_security"), PublisherWorkerTokenContext{parent_pid, sid, parent});
}
Value immutable_profile(Value profile) {
    // The SCM broker owns no product creator/effect handles. Its current
    // population may change; every fresh snapshot still passes the complete
    // stored policy above. Its process/token/default facts stay frozen. The
    // child's original pinned-thread policy remains unchanged.
    profile.as_object().at("broker_security").as_object().at("worker_security").as_object().erase("threads");
    return profile;
}
Value selected_operation(const RegisteredPublisherAdmission& admission, const std::string& request) {
    Value result(Value::Object{{"schema", Value("usk.publisher_effect_selected_operation_readback.v1")},
        {"scope", Value("original_native_held_exact_request_selection")},
        {"present", Value(admission.has_selected_reviewed_operation())}});
    if (admission.has_selected_reviewed_operation()) {
        const auto envelope = admission.selected_reviewed_envelope();
        const auto observation = admission.selected_reviewed_operation_observation();
        require(same(envelope.at("apply_request"), usk::json::parse(request)) &&
            observation.at("approval").at("request_sha256").as_string() == usk::json::sha256_canonical(usk::json::parse(request)),
            "broker selected operation is not the actual received exact request");
        result.as_object().emplace("envelope", envelope);
        result.as_object().emplace("observation", observation);
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

struct PublisherEffectBrokerReadback::State {
    const RegisteredPublisherAdmission& admission;
    const PublisherRequestChannel& channel;
    HANDLE volume;
    PublisherEffectWorkerCustody& custody;
    DWORD process_id = GetCurrentProcessId(), thread_id = GetCurrentThreadId();
    std::string request;
    Value baseline;
    Value selected_baseline;
    bool failed = false;
    State(const RegisteredPublisherAdmission& a, const PublisherRequestChannel& c, HANDLE v,
        PublisherEffectWorkerCustody& owner) : admission(a), channel(c), volume(v), custody(owner),
        request(c.authenticated_canonical_request()) {}
    Value fresh() const {
        require(!failed && process_id == GetCurrentProcessId() && thread_id == GetCurrentThreadId() &&
            request == channel.authenticated_canonical_request() && request == custody.canonical_request(),
            "broker original native owner/thread/authenticated request changed");
        const auto admitted = admission.evidence();
        const auto name = std::filesystem::u8path(admitted.at("service_name").as_string()).wstring();
        const auto actual_service = observe_current_restricted_publisher_service(name);
        const auto process = observe_current_publisher_process_boundary();
        require_publisher_process_boundary(process, actual_service.process_id, actual_service.service_sid,
            actual_service.token.process_groups);
        const auto security = observe_current_publisher_worker_security();
        require_publisher_worker_security(security, actual_service);
        const auto configuration = admission.execution_configuration_observation();
        const auto actual_custody = custody.observation();
        const auto child = custody.peer_primary_token();
        const auto volume_facts = observe_publisher_directory_handle(volume);
        require_ntfs_root(volume, publisher_handle_observation_json(volume_facts));
        require(observe_publisher_handle_granted_access(volume) == query_rights,
            "broker original volume handle has authority beyond its read-only query profile");
        require_publisher_object_security_shape(volume_facts, actual_service.service_sid);
        const auto access = channel.observe_authenticated_object_access(volume);
        require(same(access.at("native_object"), publisher_handle_observation_json(volume_facts)),
            "broker authenticated original volume changed");
        auto result = Value(Value::Object{{"schema", Value("usk.publisher_effect_broker_native_readback.v2")},
            {"authority", Value("read_only_observation")}, {"request_sha256", actual_custody.at("request_sha256")},
            {"service", service(actual_service)}, {"effect_primary_token", token(child)},
            {"registered_admission", admitted}, {"custody", actual_custody},
            {"volume_root", publisher_handle_observation_json(volume_facts)}, {"service_configuration", configuration},
            {"broker_volume_granted_access", Value(static_cast<std::uint64_t>(observe_publisher_handle_granted_access(volume)))},
            {"broker_security", Value(Value::Object{{"process_boundary", process}, {"worker_security", security}})}});
        // The original authenticated caller is an independently
        // observed native fact, never the child's supplied SID.
        result.as_object().emplace("authenticated_client", access.at("client"));
        require_projection(result, actual_custody, actual_service.token, child, false);
        const auto final_security = observe_current_publisher_worker_security();
        require_publisher_worker_security(final_security, actual_service);
        require(same(observe_current_publisher_process_boundary(), process) &&
            same(final_security.at("primary_token"), security.at("primary_token")) &&
            same(admission.execution_configuration_observation(), configuration) && same(admission.evidence(), admitted) &&
            same(service(observe_current_restricted_publisher_service(name)), service(actual_service)) &&
            same(custody.observation(), actual_custody) && same(token(custody.peer_primary_token()), token(child)) &&
            same(object(volume), result.at("volume_root")) && observe_publisher_handle_granted_access(volume) == query_rights,
            "broker native facts changed during collection");
        result.as_object().at("broker_security").as_object().at("worker_security") = final_security;
        return result;
    }
};
PublisherEffectBrokerReadback::PublisherEffectBrokerReadback(const RegisteredPublisherAdmission& a,
    const PublisherRequestChannel& c, HANDLE v, PublisherEffectWorkerCustody& owner) : state_(std::make_unique<State>(a, c, v, owner)) {
    state_->baseline = state_->fresh();
    state_->selected_baseline = selected_operation(a, state_->request);
}
PublisherEffectBrokerReadback::~PublisherEffectBrokerReadback() = default;
void PublisherEffectBrokerReadback::respond_to_one_readback(DWORD timeout) {
    auto& state = *state_;
    try {
        const auto before = state.fresh();
        require(same(immutable_profile(before), immutable_profile(state.baseline)), "broker original service/target/caller/worker binding changed");
        const auto request = state.custody.receive(timeout);
        const auto kind = request.at("kind").as_string();
        require(request.at("schema").as_string() == "usk.publisher_effect_broker_readback_request.v1" &&
            (kind == "service_admission" || kind == "selected_operation" || kind == "object_access") &&
            request.as_object().size() == (kind == "object_access" ? 3u : 2u), "broker readback request grammar differs");
        Value result(Value::Object{});
        if (kind == "selected_operation") result = selected_operation(state.admission, state.request);
        if (kind == "object_access") {
            PublisherBrokerObjectQuery query(state.volume, request.at("native_object"));
            result = query.authenticated_access(state.channel);
            require(same(result.at("client"), before.at("authenticated_client")), "broker original authenticated caller changed");
            // No parent descendant handle may cross this reply or obstruct a
            // child's subsequent root rename. Unknown close stops the route.
            require(query.close(), "broker original native query handle closure is unknown");
        }
        const auto after = state.fresh();
        require(same(immutable_profile(before), immutable_profile(after)) &&
            same(selected_operation(state.admission, state.request), state.selected_baseline),
            "broker native scope or original selected operation changed across readback");
        state.custody.send(Value(Value::Object{{"schema", Value("usk.publisher_effect_broker_readback_response.v1")},
            {"kind", Value(kind)}, {"profile", after}, {"result", result}}), timeout);
    } catch (...) { state.failed = true; throw; }
}

struct PublisherEffectWorkerReadback::State {
    PublisherEffectWorkerPeer& peer;
    DWORD process_id = GetCurrentProcessId(), thread_id = GetCurrentThreadId();
    std::string request;
    Value baseline;
    bool failed = false, initialized = false;
    explicit State(PublisherEffectWorkerPeer& p) : peer(p), request(p.canonical_request()) {}
    Value read(const std::string& kind, const Value* native_object, DWORD timeout) {
        require(!failed && process_id == GetCurrentProcessId() && thread_id == GetCurrentThreadId() &&
            peer.canonical_request() == request, "effect readback original native owner/thread/request changed");
        const auto before = peer.observation();
        const auto parent = peer.peer_primary_token();
        const auto child = observe_current_publisher_token();
        Value message(Value::Object{{"schema", Value("usk.publisher_effect_broker_readback_request.v1")}, {"kind", Value(kind)}});
        if (native_object) message.as_object().emplace("native_object", *native_object);
        peer.send(message, timeout);
        const auto reply = peer.receive(timeout);
        require(reply.as_object().size() == 4 && reply.at("schema").as_string() ==
            "usk.publisher_effect_broker_readback_response.v1" && reply.at("kind").as_string() == kind &&
            same(peer.observation(), before) && same(token(peer.peer_primary_token()), token(parent)) &&
            same(token(observe_current_publisher_token()), token(child)), "effect fresh readback reply or actual native token/custody changed");
        require_projection(reply.at("profile"), before, parent, child, true);
        if (initialized) require(same(immutable_profile(reply.at("profile")), immutable_profile(baseline)), "effect original broker/worker binding changed");
        else { baseline = reply.at("profile"); initialized = true; }
        if (kind == "service_admission") require(reply.at("result").as_object().empty(), "effect service readback has an unexpected result");
        else if (kind == "object_access") require(same(reply.at("result").at("native_object"), *native_object) &&
            same(reply.at("result").at("client"), baseline.at("authenticated_client")), "effect broker access belongs to another object/caller");
        return reply;
    }
};
PublisherEffectWorkerReadback::PublisherEffectWorkerReadback(PublisherEffectWorkerPeer& p) : state_(std::make_unique<State>(p)) {}
PublisherEffectWorkerReadback::~PublisherEffectWorkerReadback() = default;
Value PublisherEffectWorkerReadback::service_admission(DWORD timeout) {
    try { return state_->read("service_admission", nullptr, timeout).at("profile"); }
    catch (...) { state_->failed = true; throw; }
}
PublisherWorkerTokenContext PublisherEffectWorkerReadback::worker_token_context(DWORD timeout) {
    try {
        const auto profile = service_admission(timeout);
        const auto actual = observe_current_publisher_token();
        const auto& sid = profile.at("service").at("service_sid").as_string();
        require(same(token(actual), profile.at("effect_primary_token")) &&
            GetCurrentProcessId() == profile.at("custody").at("peer_process_id").as_unsigned() &&
            has_restricted_publisher_token_facts(actual, sid), "effect actual local primary-token context changed");
        return PublisherWorkerTokenContext{GetCurrentProcessId(), sid, actual};
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
        const bool present = selection.at("present").as_boolean();
        require(selection.as_object().size() == (present ? 5u : 3u) &&
            selection.at("schema").as_string() == "usk.publisher_effect_selected_operation_readback.v1" &&
            selection.at("scope").as_string() == "original_native_held_exact_request_selection",
            "effect selected operation observation is not closed");
        if (present) {
            (void)parse_publisher_reviewed_operation_envelope(usk::json::canonical(selection.at("envelope")), state_->request);
            const auto& observation = selection.at("observation");
            const auto& approval = observation.at("approval");
            const auto& admitted = reply.at("profile").at("registered_admission");
            require(observation.as_object().size() == 7 && observation.at("schema").as_string() ==
                "usk.publisher_selected_reviewed_operation_observation.v1" && observation.at("scope").as_string() ==
                "authenticated_exact_request_and_held_protected_enrollment_files" &&
                approval.as_object().size() == 7 && approval.at("schema").as_string() ==
                "usk.publisher_reviewed_operation_approval.v1" &&
                approval.at("request_sha256").as_string() == usk::json::sha256_canonical(usk::json::parse(state_->request)) &&
                approval.at("registration_sha256").as_string() == admitted.at("registration_sha256").as_string() &&
                approval.at("target_admitted_sha256").as_string() == admitted.at("target_admitted_sha256").as_string() &&
                approval.at("caller_sid").as_string() == reply.at("profile").at("authenticated_client").at("user_sid").as_string() &&
                approval.at("envelope_size_bytes").as_unsigned() > 0 && approval.at("envelope_size_bytes").as_unsigned() <= 1024u * 1024u &&
                observation.at("approval_sha256").as_string() == usk::json::sha256_canonical(approval) &&
                observation.at("envelope_sha256").as_string() == approval.at("envelope_sha256").as_string(),
                "effect original reviewed enrollment/request/caller binding differs");
            for (const auto field : {"approval_file", "envelope_file"})
                require(observation.at(field).as_object().size() == 9 &&
                    observation.at(field).at("owner_sid").as_string() == "S-1-5-18" &&
                    !(observation.at(field).at("attributes").as_unsigned() & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
                    observation.at(field).at("reparse_tag").as_unsigned() == 0 &&
                    observation.at(field).at("link_count").as_unsigned() == 1 &&
                    !observation.at(field).at("case_sensitive").as_boolean(),
                    "effect native enrollment file observation differs");
        }
        return selection;
    } catch (...) { state_->failed = true; throw; }
}
Value PublisherEffectWorkerReadback::authenticated_object_access(HANDLE held, DWORD timeout) {
    try {
        require(observe_publisher_noninheritable_handle_flags(held) == 0, "effect access object is inheritable");
        const auto before = object(held);
        const auto reply = state_->read("object_access", &before, timeout);
        require(same(object(held), before) && observe_publisher_noninheritable_handle_flags(held) == 0,
            "effect original held object changed across broker readback");
        auto access = reply.at("result");
        // Run the unchanged closed raw-descriptor/native-object/client checks;
        // this validates the fresh broker result, never supplied ACE authority.
        access.as_object().erase("client"); access.as_object().erase("native_object");
        access.as_object().emplace("client_sha256", Value(usk::json::sha256_canonical(reply.at("result").at("client"))));
        access.as_object().emplace("native_object_sha256", Value(usk::json::sha256_canonical(before)));
        require_publisher_authenticated_object_access(access, reply.at("result").at("client"), before);
        return reply.at("result");
    } catch (...) { state_->failed = true; throw; }
}
namespace {
Value worker_context(const PublisherWorkerTokenContext& worker) {
    return Value(Value::Object{{"process_id", Value(static_cast<std::uint64_t>(worker.process_id))},
        {"service_sid", Value(worker.service_sid)}, {"primary_token", token(worker.token)}});
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
        (void)observe();
    }
    Value observe(const std::string& failure_context = {}) {
        try {
            require(!failed && thread_id == GetCurrentThreadId() && GetCurrentProcessId() == original.process_id,
                "effect security original execution process/thread changed");
            const auto current = readback.worker_token_context();
            require(same(worker_context(current), worker_context(original)), "effect security original primary-token binding changed");
            const auto current_process = observe_current_publisher_process_boundary();
            require_publisher_process_boundary(current_process, current.process_id, current.service_sid, current.token.process_groups);
            require(same(current_process, process), "effect security original process owner/DACL changed");
            const auto security = continuity->observe_current(failure_context);
            require_publisher_worker_security(security, current);
            require(same(token(observe_current_publisher_token()), token(original.token)) &&
                same(observe_current_publisher_process_boundary(), process) &&
                same(worker_context(readback.worker_token_context()), worker_context(original)),
                "effect security native token/process/broker changed across original-thread readback");
            return Value(Value::Object{{"schema", Value("usk.publisher_effect_worker_native_security.v1")},
                {"authority", Value("read_only_observation")},
                {"scope", Value("actual_current_child_with_original_pinned_threads")},
                {"worker", worker_context(current)}, {"process_boundary", current_process}, {"worker_security", security}});
        } catch (...) { failed = true; throw; }
    }
};
PublisherEffectWorkerNativeSecurity::PublisherEffectWorkerNativeSecurity(PublisherEffectWorkerReadback& r) :
    state_(std::make_unique<State>(r)) {}
PublisherEffectWorkerNativeSecurity::~PublisherEffectWorkerNativeSecurity() = default;
Value PublisherEffectWorkerNativeSecurity::observe_current(const std::string& context) { return state_->observe(context); }
}
#endif
