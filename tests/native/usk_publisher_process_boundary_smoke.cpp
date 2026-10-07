// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_process_boundary.h"
#include "usk_publisher_execution_observation.h"
#include "usk_protected_install_publisher_internal.h"
#include "usk_publisher_worker_security.h"
#include "usk_publisher_effect_broker_internal.h"
#include "usk_publisher_effect_execution_internal.h"
#include "usk_install_lease.h"
#include "usk_publisher_creation_observation.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_sha256.h"
#include <sddl.h>
#include <functional>
#include <cstdlib>
#include <iostream>
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
    const Value valid(Value::Object{{"schema", Value("usk.publisher_execution_observation.v7")},
        {"scope", Value("supplied_held_child_handles_authenticated_broker_access_and_pinned_worker_security")}, {"phase", Value("sealed")},
        {"platform", observe_publisher_execution_platform()}, {"service", service}, {"broker_readback", broker}, {"effect_worker", worker},
        {"handles", Value(handles)}, {"process_boundary", child_boundary}, {"worker_security", child_security}, {"authenticated_client", client}});
    require_publisher_execution_phase(valid, name, service_sid, "sealed", bindings);
    require_publisher_execution_record_continuity(valid, valid);
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
class TestThreadDacl {
public:
    explicit TestThreadDacl(HANDLE thread) : thread_(thread) {
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
            AddAccessDeniedAce(changed_acl, ACL_REVISION, THREAD_SET_INFORMATION, sid),
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
    original.retire();
    for (unsigned repeat = 0; repeat != 2; ++repeat) {
        const auto current = continuity.observe_current();
        for (const auto& thread : current.at("threads").as_array())
            check(thread.at("thread_id").as_unsigned() != original.id(), "ended original test thread still reported live");
        check(usk::json::canonical(baseline) == frozen, "original worker baseline was refreshed");
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
} // namespace

int main() {
    try {
        // Ordinary-process readback and owned test-thread controls only. No
        // SCM or opens against another process; no publisher effect authority.
        const auto actual = observe_current_publisher_process_boundary();
        check(actual.as_object().size() == 7 && actual.at("process_id").as_unsigned() == GetCurrentProcessId() &&
            actual.at("dacl_present").as_boolean() && !actual.at("owner_sid").as_string().empty(),
            "current process owner/DACL facts were not observed");
        worker_security_controls();
        effect_execution_record_controls();
        worker_lifetime_controls();
        worker_retirement_readback_controls();

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
