// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_anchor_create.h"
#include "usk_publisher_staged_stream.h"
#include "usk_publisher_volume_operation_guard.h"
#include "usk_publisher_installation_lease.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_archive_payload.h"
#include "usk_json.h"
#include "usk_sha256.h"
#include "usk_stable_file.h"
#include "usk_public_lifecycle.h"
#include "usk_protected_install_publisher_internal.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_token_observation.h"
#include "usk_publisher_tree_observation.h"
#include "usk_publisher_volume_stream_observation.h"
#include "usk_publisher_request_channel.h"
#include "usk_publisher_registration.h"
#include "usk_publisher_effect_execution_internal.h"
#include "usk_publisher_effect_broker_internal.h"

#if defined(USK_PRODUCTION_PUBLISHER) && defined(USK_TEST_REGISTERED_FAULT_GATE)
#error Production publisher cannot include the registered fault gate
#endif

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <stdexcept>
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace {
std::wstring service_name;
std::wstring receipt_path;
std::wstring volume_root;
bool prepublish_gate = false;
bool poststage_gate = false;
bool postrename_gate = false;
bool postjournal_gate = false;
bool recover_prepared = false;
bool recover_snapshot_only = false;
bool recover_reviewed = false;
bool recover_sealed_journal = false;
bool recover_visible_bound = false;
bool verify_installed = false;
bool reviewed_install_reentry = false;
bool require_preprotected_boundary = false;
bool registered_reviewed_mode = false;

bool selected_archive_mode = false;
std::wstring selected_archive_path;
std::string selected_archive_sha256;
std::wstring reviewed_plan_envelope_path;
std::string reviewed_plan_envelope_sha256;
std::wstring authorized_client_sid;
bool grant_client_read = false;
bool admit_client_observer = false;
bool service_admitted_client = false;
bool interrupt_consumer_grant = false;
SERVICE_STATUS_HANDLE status_handle = nullptr;
HANDLE stop_event = nullptr;
DWORD service_exit_code = ERROR_SUCCESS;
using usk::platform::windows::StaleReviewedInstallRequest;
bool campaign_vm_id_matches(const std::wstring& expected) {
    if (expected.size() != 36) return false;
    for (std::size_t index = 0; index < expected.size(); ++index) {
        const wchar_t ch = expected[index];
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (ch != L'-') return false;
        } else if (!((ch >= L'0' && ch <= L'9') ||
                (ch >= L'a' && ch <= L'f') ||
                (ch >= L'A' && ch <= L'F'))) {
            return false;
        }
    }
    wchar_t observed[64]{};
    DWORD bytes = sizeof(observed);
    const LONG result = RegGetValueW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        L"VirtualMachineId", RRF_RT_REG_SZ, nullptr, observed, &bytes);
    return result == ERROR_SUCCESS &&
        CompareStringOrdinal(expected.c_str(), -1, observed, -1,
            TRUE) == CSTR_EQUAL;
}

bool generated_service_name(const std::wstring& name,
    const std::wstring& prefix) {
    if (name.size() != prefix.size() + 32 ||
        name.compare(0, prefix.size(), prefix) != 0) return false;
    for (std::size_t index = prefix.size(); index < name.size(); ++index) {
        const wchar_t ch = name[index];
        if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) {
            return false;
        }
    }
    return true;
}

bool campaign_recovery_receipt_path(const std::wstring& path) {
    const std::wstring prefix = L"C:\\USK-Lab\\vm-recovery-";
    const std::wstring suffix = L".json";
    if (path.size() <= prefix.size() + suffix.size() ||
        path.compare(0, prefix.size(), prefix) != 0 ||
        path.compare(path.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return false;
    }
    for (std::size_t index = prefix.size();
            index < path.size() - suffix.size(); ++index) {
        const wchar_t ch = path[index];
        if (!((ch >= L'a' && ch <= L'z') ||
                (ch >= L'0' && ch <= L'9') || ch == L'-')) return false;
    }
    return true;
}

bool campaign_selected_receipt_path(const std::wstring& path) {
    const std::wstring prefix = L"C:\\USK-Lab\\vm-selected-";
    const std::wstring suffix = L".json";
    if (path.size() <= prefix.size() + suffix.size() ||
        path.compare(0, prefix.size(), prefix) != 0 ||
        path.compare(path.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return false;
    }
    for (std::size_t index = prefix.size();
            index < path.size() - suffix.size(); ++index) {
        const wchar_t ch = path[index];
        if (!((ch >= L'a' && ch <= L'z') ||
                (ch >= L'0' && ch <= L'9') || ch == L'-')) return false;
    }
    return true;
}

bool campaign_selected_archive_path(const std::wstring& path) {
    const std::wstring prefix = L"C:\\USK-Lab\\selected-";
    const std::wstring suffix = L".zip";
    if (path.size() <= prefix.size() + suffix.size() ||
        path.compare(0, prefix.size(), prefix) != 0 ||
        path.compare(path.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return false;
    }
    for (std::size_t index = prefix.size();
            index < path.size() - suffix.size(); ++index) {
        const wchar_t ch = path[index];
        if (!((ch >= L'a' && ch <= L'z') ||
                (ch >= L'0' && ch <= L'9') || ch == L'-')) return false;
    }
    return true;
}

bool campaign_reviewed_plan_envelope_path(const std::wstring& path) {
    const std::wstring prefix = L"C:\\USK-Lab\\plan-";
    const std::wstring suffix = L".json";
    if (path.size() <= prefix.size() + suffix.size() ||
        path.compare(0, prefix.size(), prefix) != 0 ||
        path.compare(path.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return false;
    }
    for (std::size_t index = prefix.size();
            index < path.size() - suffix.size(); ++index) {
        const wchar_t ch = path[index];
        if (!((ch >= L'a' && ch <= L'z') ||
                (ch >= L'0' && ch <= L'9') || ch == L'-')) return false;
    }
    return true;
}

bool lower_sha256(const std::wstring& value) {
    if (value.size() != 64) return false;
    for (const wchar_t ch : value) {
        if (!((ch >= L'0' && ch <= L'9') ||
                (ch >= L'a' && ch <= L'f'))) return false;
    }
    return true;
}

void report_status(DWORD state, DWORD accepted = 0, DWORD error = ERROR_SUCCESS) {
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = accepted;
    status.dwWin32ExitCode = error;
    status.dwWaitHint = state == SERVICE_START_PENDING ? 10000 : 0;
    if (!SetServiceStatus(status_handle, &status)) {
        throw std::runtime_error("cannot report publisher lab service status");
    }
}

std::string ascii(const std::wstring& value) {
    std::string result;
    for (const wchar_t ch : value) {
        if (ch < 0x20 || ch > 0x7e) throw std::runtime_error("lab CLI value is not ASCII");
        result.push_back(static_cast<char>(ch));
    }
    return result;
}

std::string json_quote(const std::string& value) {
    std::string result = "\"";
    constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char ch : value) {
        if (ch == '\\' || ch == '"') { result.push_back('\\'); result.push_back(static_cast<char>(ch)); }
        else if (ch < 32) {
            result += "\\u00";
            result.push_back(hex[ch >> 4]);
            result.push_back(hex[ch & 15]);
        } else result.push_back(static_cast<char>(ch));
    }
    result.push_back('"');
    return result;
}

void write_receipt(const std::string& data) {
    HANDLE handle = CreateFileW(receipt_path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("cannot create publisher lab service receipt");
    }
    DWORD written = 0;
    const bool okay = data.size() <= MAXDWORD &&
        WriteFile(handle, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) &&
        written == data.size() && FlushFileBuffers(handle);
    CloseHandle(handle);
    if (!okay) throw std::runtime_error("cannot flush publisher lab service receipt");
}

DWORD WINAPI control_handler(DWORD control, DWORD, LPVOID, LPVOID) {
    if (control == SERVICE_CONTROL_STOP && stop_event) {
        SetEvent(stop_event);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

std::string native_operation_error(const std::exception& error) {
    using namespace usk::platform::windows;
    using namespace usk::transaction;
    return dynamic_cast<const PublisherVolumeBusy*>(&error) || dynamic_cast<const PublisherInstallBusy*>(&error) ||
        dynamic_cast<const InstallLeaseConflict*>(&error) ? "operation_conflict" :
        dynamic_cast<const PublisherOperationCancelled*>(&error) ? "operation_cancelled" :
        dynamic_cast<const InstallLeaseStale*>(&error) ? "lease_stale" :
        dynamic_cast<const InstallStateRevisionStale*>(&error) ||
            dynamic_cast<const InstallStateRevisionChangedBeforeEffects*>(&error) ? "state_revision_stale" :
        dynamic_cast<const StaleReviewedInstallRequest*>(&error) ||
            dynamic_cast<const StaleReviewedMaintenanceRequest*>(&error) ? "stale_plan" : "";
}
std::string native_operation_inspection(const std::exception& error) {
    using namespace usk::platform::windows;
    if (const auto* busy = dynamic_cast<const PublisherVolumeBusy*>(&error)) return busy->inspection_reference();
    if (const auto* busy = dynamic_cast<const PublisherInstallBusy*>(&error)) return busy->inspection_reference();
    if (const auto* cancelled = dynamic_cast<const PublisherOperationCancelled*>(&error)) return cancelled->inspection_reference();
    return {};
}
bool native_definite_preflight_refusal(const std::exception& error) {
    using namespace usk::platform::windows;
    return dynamic_cast<const StaleReviewedInstallRequest*>(&error) ||
        dynamic_cast<const StaleReviewedMaintenanceRequest*>(&error) ||
        dynamic_cast<const InstallStateRevisionChangedBeforeEffects*>(&error);
}
int private_effect_worker_main(int argc, wchar_t** argv) {
    using namespace usk::platform::windows;
    using usk::json::Value;
    std::unique_ptr<PublisherEffectWorkerPeer> original_peer;
    bool terminal_attempted = false;
    const auto report_failure = [&original_peer, &terminal_attempted](const char* message) noexcept {
        if (original_peer && !terminal_attempted) {
            try {
                Value diagnostic(Value::Object{{"schema", Value("usk.publisher_effect_worker_failure_diagnostic.v1")},
                    {"message", Value(std::string(message).substr(0, 4096))}});
                require_publisher_effect_failure_diagnostic(diagnostic);
                original_peer->send(diagnostic);
                // Preserve this actual peer for conservative failure and
                // checked parent disposal. No effects, scope or retry.
                (void)original_peer->await_parent_retirement();
            } catch (...) {} // Unavailable original transport stays unknown.
        }
        return 5;
    };
    try {
        original_peer = std::make_unique<PublisherEffectWorkerPeer>(argc, argv);
        auto& peer = *original_peer;
        // Only a fresh actual-parent readback can supply the service name.
        PublisherEffectWorkerReadback initial(peer);
        const auto original = initial.service_admission();
        const auto name = std::filesystem::u8path(original.at("service").at("service_name").as_string()).wstring();
        Value terminal;
        {
            PublisherEffectExecutionOwner owner(peer, name);
            const auto profile = owner.service_admission();
            const auto& arguments = profile.at("service_configuration").at("arguments").as_array();
            CandidatePublisherConfiguration config;
            config.effect_execution = &owner;
            config.service_name = name;
            config.volume_root = std::filesystem::u8path(arguments.at(4).as_string()).wstring();
            config.consumer_read_sid = profile.at("authenticated_client").at("user_sid").as_string();
            const auto request = peer.canonical_request();
            const auto schema = usk::json::parse(request).at("schema").as_string();
            if (schema == "usk.publisher_installed_verify_request.v1") {
                config.verify_installed = true;
                config.submitted_verify_request = request;
            } else if (schema == "usk.publisher_recovery_request.v1" || schema == "usk.publisher_maintenance_recovery_request.v1") {
                config.recover_reviewed = true;
                config.submitted_recovery_request = request;
            } else if (schema == "usk.install_local_apply_request.v1" || schema == "usk.repair_apply_request.v1" ||
                schema == "usk.move_apply_request.v1" || schema == "usk.uninstall_apply_request.v1") {
                if (arguments.at(5).as_string() != "--reviewed-plan-envelope")
                    throw std::runtime_error("private apply lacks its original reviewed SCM configuration");
                config.selected_archive_mode = true;
                config.reviewed_plan_envelope_path = std::filesystem::u8path(arguments.at(6).as_string()).wstring();
                config.reviewed_plan_envelope_sha256 = arguments.at(7).as_string();
                config.submitted_apply_request = request;
            } else throw std::runtime_error("private effect request schema is unavailable");
            bool effects = false;
            terminal = Value(Value::Object{{"schema", Value("usk.publisher_effect_worker_terminal.v1")},
                {"request_sha256", Value(usk::json::sha256_canonical(usk::json::parse(request)))},
                {"status", Value("success")}, {"response", Value{}}, {"error", Value("")}, {"error_code", Value("")},
                {"operation_inspection_ref", Value("")}, {"effects_may_exist", Value(false)},
                {"definite_preflight_refusal", Value(false)}});
            try {
                terminal.as_object().at("response") = usk::json::parse(execute_candidate_restricted_publisher(config, effects));
            } catch (const std::exception& error) {
                terminal.as_object().at("status") = Value("failure");
                terminal.as_object().at("error") = Value(std::string(error.what()).substr(0, 4096));
                terminal.as_object().at("error_code") = Value(native_operation_error(error));
                terminal.as_object().at("operation_inspection_ref") = Value(native_operation_inspection(error).substr(0, 1024));
                terminal.as_object().at("definite_preflight_refusal") = Value(native_definite_preflight_refusal(error));
            }
            terminal.as_object().at("effects_may_exist") = Value(effects);
            // The engine and all its guard/lease/creator/effect scopes have
            // ended. Failed native observation cannot manufacture a terminal.
            require_publisher_effect_terminal_record(terminal, owner.service_admission());
        }
        terminal_attempted = true; // No diagnostic or other packet after this attempt.
        peer.send(terminal);
        // Keep the original peer alive through live validation and explicit
        // parent job closure. No SCM dispatch, callbacks or extra readback.
        (void)peer.await_parent_retirement();
        return 5; // Parent disposal normally terminates this child in its job.
    } catch (const std::exception& error) { return report_failure(error.what()); }
    catch (...) { return report_failure("non-standard failure before confirmed terminal"); }
}
class BrokerVolumeObserver final {
public:
    explicit BrokerVolumeObserver(const std::wstring& root) {
        handle_ = CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot open original query-only broker volume");
    }
    ~BrokerVolumeObserver() { if (!attempted_) (void)close(); }
    BrokerVolumeObserver(const BrokerVolumeObserver&) = delete;
    BrokerVolumeObserver& operator=(const BrokerVolumeObserver&) = delete;
    HANDLE get() const { return handle_; }
    bool close() noexcept {
        if (!attempted_) {
            attempted_ = true;
            closed_ = CloseHandle(handle_) != FALSE;
            if (closed_) handle_ = INVALID_HANDLE_VALUE;
            else error_ = GetLastError(); // Retain the original numeric handle until process disposal.
        }
        return closed_;
    }
    DWORD error() const noexcept { return error_; }
private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    bool attempted_ = false, closed_ = false;
    DWORD error_ = ERROR_SUCCESS;
};
usk::json::Value execute_registered_child(usk::platform::windows::RegisteredPublisherAdmission& admission,
    usk::platform::windows::PublisherRequestChannel& channel, bool& effects_may_exist) {
    using namespace usk::platform::windows;
    using usk::json::Value;
    BrokerVolumeObserver volume(volume_root);
    std::unique_ptr<PublisherEffectWorkerCustody> child;
    Value terminal;
    try {
        // Losing the wire can hide effects. Only an actual terminal followed
        // by confirmed native disposal can narrow this retained classification.
        effects_may_exist = true;
        child = admission.launch_effect_worker(channel, stop_event);
        {
            PublisherEffectBrokerReadback broker(admission, channel, volume.get(), *child);
            for (;;) {
                const auto packet = broker.respond_to_one_packet();
                if (packet) { terminal = *packet; break; }
            }
        }
    } catch (...) {
        const auto primary = std::current_exception();
        if (child) {
            const auto closure = child->close();
            if (!closure.confirmed()) throw PublisherEffectWorkerClosureUnknown(closure, primary);
        }
        if (!volume.close()) throw PublisherBrokerQueryClosureUnknown(volume.error(), primary);
        std::rethrow_exception(primary);
    }
    const auto closure = child->close();
    if (!closure.confirmed()) throw PublisherEffectWorkerClosureUnknown(closure, {});
    if (!volume.close()) throw PublisherBrokerQueryClosureUnknown(volume.error(), {});
    effects_may_exist = terminal.at("effects_may_exist").as_boolean();
    if (terminal.at("status").as_string() == "success") return terminal.at("response");
    service_exit_code = ERROR_SERVICE_SPECIFIC_ERROR;
    Value result(Value::Object{{"schema", Value("usk.publisher_lab_service_observation.v1")},
        {"status", Value(terminal.at("definite_preflight_refusal").as_boolean() || !effects_may_exist ? "failed" : "recovery_required")},
        {"error", terminal.at("error")}});
    if (!terminal.at("error_code").as_string().empty()) result.as_object().emplace("error_code", terminal.at("error_code"));
    if (!terminal.at("operation_inspection_ref").as_string().empty())
        result.as_object().emplace("operation_inspection_ref", terminal.at("operation_inspection_ref"));
    if (terminal.at("definite_preflight_refusal").as_boolean() && terminal.at("error_code").as_string() == "state_revision_stale" &&
        admission.has_selected_reviewed_operation())
        result.as_object().emplace("reviewed_operation_admission", admission.selected_reviewed_operation_observation());
    return result;
}
VOID WINAPI service_main(DWORD, LPWSTR*) {
    status_handle = RegisterServiceCtrlHandlerExW(service_name.c_str(), control_handler, nullptr);
    if (!status_handle) return;
    bool publication_effects_may_exist = false;
    std::unique_ptr<usk::platform::windows::PublisherRequestChannel> request_channel;
    std::unique_ptr<usk::platform::windows::RegisteredPublisherAdmission> registered_admission;
    std::string capability_request_id;
        unsigned capability_protocol_version = 2;
    try {
        report_status(SERVICE_START_PENDING);
        stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stop_event) throw std::runtime_error("cannot create publisher lab stop event");
        report_status(SERVICE_RUNNING, SERVICE_ACCEPT_STOP);
        usk::platform::windows::CandidatePublisherConfiguration config;
        config.service_name=service_name;
        config.receipt_path=receipt_path;
        config.volume_root=volume_root;
        config.prepublish_gate=prepublish_gate;
        config.poststage_gate=poststage_gate;
        config.postrename_gate=postrename_gate;
        config.postjournal_gate=postjournal_gate;
        config.recover_prepared=recover_prepared;
        config.recover_snapshot_only=recover_snapshot_only;
        config.recover_reviewed=recover_reviewed;
        config.recover_sealed_journal=recover_sealed_journal;
        config.recover_visible_bound=recover_visible_bound;
        config.verify_installed=verify_installed;
        config.selected_archive_mode=selected_archive_mode;
        config.selected_archive_path=selected_archive_path;
        config.selected_archive_sha256=selected_archive_sha256;
        config.reviewed_plan_envelope_path=reviewed_plan_envelope_path;
        config.reviewed_plan_envelope_sha256=reviewed_plan_envelope_sha256;
        config.stop_event=stop_event;
        if (!authorized_client_sid.empty()) {
            if (service_admitted_client) {
                registered_admission = std::make_unique<usk::platform::windows::RegisteredPublisherAdmission>(
                    service_name, volume_root, authorized_client_sid);
                config.registered_admission=registered_admission.get();
            }
            const auto service=usk::platform::windows::observe_current_restricted_publisher_service(service_name);
            if (grant_client_read || admit_client_observer)
                usk::platform::windows::admit_current_publisher_client_observer(service_name, authorized_client_sid);
            request_channel=std::make_unique<usk::platform::windows::PublisherRequestChannel>(
                service_name, std::wstring(service.service_sid.begin(),service.service_sid.end()),
                authorized_client_sid, stop_event, 120000);
            const std::string request=request_channel->receive();
            config.authenticated_request=request_channel.get();
            const auto submitted=usk::json::parse(request);
            const auto schema=submitted.at("schema").as_string();
            if (schema == "usk.publisher_capability_request.v2" || schema == "usk.publisher_capability_request.v4") {
                capability_protocol_version = schema == "usk.publisher_capability_request.v4" ? 4u : 2u;
                if (!registered_admission || submitted.as_object().size() != 2)
                    throw std::runtime_error("service capability request lacks registered admission");
                capability_request_id=submitted.at("request_id").as_string();
                if (capability_request_id.empty() || capability_request_id.size() > 128 ||
                    capability_request_id.find_first_not_of(
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != std::string::npos)
                    throw std::runtime_error("service capability request identity differs");
            } else if (registered_reviewed_mode) {
                // The registered command binds the original reviewed envelope.
                // Later requests may select only verification or source-free
                // recovery of that protected installation. Neither mode may
                // inherit the envelope as fresh publication authority.
                if (schema == "usk.publisher_installed_verify_request.v1") {
                    config.verify_installed=true;
                    config.selected_archive_mode=false;
                    config.reviewed_plan_envelope_path.clear();
                    config.reviewed_plan_envelope_sha256.clear();
                    config.submitted_verify_request=request;
                } else if (schema == "usk.publisher_recovery_request.v1" ||
                    schema == "usk.publisher_maintenance_recovery_request.v1") {
                    if (schema == "usk.publisher_maintenance_recovery_request.v1")
                        (void)usk::platform::windows::parse_publisher_maintenance_recovery_request(request);
                    config.recover_reviewed=true;
                    config.selected_archive_mode=false;
                    config.reviewed_plan_envelope_path.clear();
                    config.reviewed_plan_envelope_sha256.clear();
                    config.submitted_recovery_request=request;
                } else if (schema == "usk.install_local_apply_request.v1") {
                    if (registered_admission)
                        (void)registered_admission->select_reviewed_operation(request, *request_channel,
                            config.reviewed_plan_envelope_path, config.reviewed_plan_envelope_sha256);
                    config.submitted_apply_request=request;
                } else if (schema == "usk.repair_apply_request.v1" || schema == "usk.move_apply_request.v1" ||
                    schema == "usk.uninstall_apply_request.v1") {
                    if (!registered_admission || !registered_admission->select_reviewed_operation(request, *request_channel,
                            config.reviewed_plan_envelope_path, config.reviewed_plan_envelope_sha256))
                        throw std::runtime_error("registered maintenance requires its own exact administrator-enrolled request");
                    config.submitted_apply_request=request;
                } else {
                    throw std::runtime_error("registered publisher request schema is unavailable");
                }
            } else if (verify_installed) config.submitted_verify_request=request;
            else if (recover_reviewed && schema == "usk.publisher_recovery_request.v1")
                config.submitted_recovery_request=request;
            else config.submitted_apply_request=request;
            if (grant_client_read) config.consumer_read_sid=ascii(authorized_client_sid);
            config.interrupt_consumer_grant=interrupt_consumer_grant;
        }
        // The reviewed-source candidate admits only an already protected
        // target. Its restricted service must not repair the volume ACL.
        if (!require_preprotected_boundary) config.prepare_disposable_boundary=[](HANDLE volume,const std::string& sid) {
            const auto descriptor=usk::platform::windows::make_publisher_directory_security_descriptor(
                std::wstring(sid.begin(),sid.end()));
            PSID owner=nullptr; BOOL owner_defaulted=FALSE, present=FALSE, dacl_defaulted=FALSE; PACL dacl=nullptr;
            if (!GetSecurityDescriptorOwner(const_cast<unsigned char*>(descriptor.data()),&owner,&owner_defaulted) ||
                !GetSecurityDescriptorDacl(const_cast<unsigned char*>(descriptor.data()),&present,&dacl,&dacl_defaulted) ||
                !owner || !present || !dacl || owner_defaulted || dacl_defaulted) {
                throw std::runtime_error("disposable volume descriptor is malformed");
            }
            const DWORD applied=SetSecurityInfo(volume,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION |
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,owner,nullptr,dacl,nullptr);
            if (applied != ERROR_SUCCESS) throw std::runtime_error(
                "cannot protect disposable volume root; Win32 "+std::to_string(applied));
        };
        usk::json::Value response;
        if (!capability_request_id.empty()) {
            using usk::json::Value;
            response=Value(Value::Object{
                {"schema", Value("usk.publisher_service_capability_observation.v1")},
                {"status", Value("observed")}, {"request_id", Value(capability_request_id)},
                {"service_name", Value(ascii(service_name))},
                {"service_sid", registered_admission->evidence().at("service_sid")},
                {"capability_observation", registered_admission->capability_observation(capability_request_id, capability_protocol_version)}});
        } else if (registered_admission) {
            response = execute_registered_child(*registered_admission, *request_channel, publication_effects_may_exist);
        } else {
            const auto observed=usk::platform::windows::execute_candidate_restricted_publisher(
                config,publication_effects_may_exist);
            response=usk::json::parse(observed);
        }
        if (registered_admission) {
            const auto pid = static_cast<std::uint64_t>(GetCurrentProcessId());
            if (response.contains("process_id") && response.at("process_id").as_unsigned() != pid)
                throw std::runtime_error("native response worker process differs from the live host");
            response.as_object().emplace("process_id", usk::json::Value(pid));
            response.as_object().emplace("registered_admission", registered_admission->evidence());
        }
        const auto data = usk::json::canonical(response);
        if (!receipt_path.empty()) write_receipt(data);
        if (request_channel) {
            request_channel->reply(data);
            request_channel->wait_for_client_disconnect();
        } else {
            WaitForSingleObject(stop_event, 120000);
        }
    } catch (const std::exception& error) {
        service_exit_code = ERROR_SERVICE_SPECIFIC_ERROR;
        using namespace usk::platform::windows;
        using namespace usk::transaction;
        const std::string operation_error =
            dynamic_cast<const PublisherVolumeBusy*>(&error) || dynamic_cast<const PublisherInstallBusy*>(&error) ||
                dynamic_cast<const InstallLeaseConflict*>(&error) ? "operation_conflict" :
            dynamic_cast<const PublisherOperationCancelled*>(&error) ? "operation_cancelled" :
            dynamic_cast<const InstallLeaseStale*>(&error) ? "lease_stale" :
            dynamic_cast<const InstallStateRevisionStale*>(&error) ||
                dynamic_cast<const InstallStateRevisionChangedBeforeEffects*>(&error) ? "state_revision_stale" :
            dynamic_cast<const StaleReviewedInstallRequest*>(&error) ||
                dynamic_cast<const StaleReviewedMaintenanceRequest*>(&error) ? "stale_plan" : "";
        std::string inspection_reference;
        if (const auto* busy = dynamic_cast<const PublisherVolumeBusy*>(&error))
            inspection_reference = busy->inspection_reference();
        else if (const auto* install_busy = dynamic_cast<const PublisherInstallBusy*>(&error))
            inspection_reference = install_busy->inspection_reference();
        else if (const auto* cancelled = dynamic_cast<const PublisherOperationCancelled*>(&error))
            inspection_reference = cancelled->inspection_reference();
        const std::string failure = "{\"schema\":\"usk.publisher_lab_service_observation.v1\","
                "\"status\":" +
                json_quote(dynamic_cast<const StaleReviewedInstallRequest*>(&error) ||
                    dynamic_cast<const StaleReviewedMaintenanceRequest*>(&error) ||
                    dynamic_cast<const InstallStateRevisionChangedBeforeEffects*>(&error) ?
                    "failed" : !verify_installed && (recover_visible_bound || reviewed_install_reentry ||
                    publication_effects_may_exist) ?
                    "recovery_required" : "failed") +
                ",\"error\":" + json_quote(error.what()) +
                (operation_error.empty() ? "" : ",\"error_code\":" + json_quote(operation_error)) +
                (inspection_reference.empty() ? "" :
                    ",\"operation_inspection_ref\":" + json_quote(inspection_reference)) +
                (registered_admission ? ",\"process_id\":" + std::to_string(GetCurrentProcessId()) +
                    ",\"registered_admission\":" + usk::json::canonical(registered_admission->evidence()) : "") +
                (registered_admission && registered_admission->has_selected_reviewed_operation() &&
                    dynamic_cast<const InstallStateRevisionChangedBeforeEffects*>(&error) ?
                    ",\"reviewed_operation_admission\":" + usk::json::canonical(
                        registered_admission->selected_reviewed_operation_observation()) : "") + "}\n";
        if (!receipt_path.empty()) { try { write_receipt(failure); } catch (...) {} }
        // An authenticated peer receives the actual refusal/retained-effects
        // result when delivery is possible; loss of transport stays unknown.
        if (request_channel) {
            try {
                request_channel->reply(failure);
                request_channel->wait_for_client_disconnect();
            } catch (...) {}
        }
    }
    if (stop_event) CloseHandle(stop_event);
    report_status(SERVICE_STOPPED, 0, service_exit_code);
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc > 1 && argv && argv[1] && std::wstring(argv[1]) ==
            usk::platform::windows::publisher_effect_worker_transport_switch)
        return private_effect_worker_main(argc, argv);
    grant_client_read = argc > 1 && std::wstring(argv[argc-1]) == L"--grant-client-read";
    if (grant_client_read) --argc;
    const bool external_client = argc >= 3 && std::wstring(argv[argc-2]) == L"--authorized-client-sid";
    if (external_client) { authorized_client_sid=argv[argc-1]; argc-=2; }
    admit_client_observer = argc > 1 && std::wstring(argv[argc-1]) == L"--admit-client-observer";
    if (admit_client_observer) --argc;
    service_admitted_client = argc > 1 && std::wstring(argv[argc-1]) == L"--service-admitted-client";
    if (service_admitted_client) { --argc; grant_client_read = true; }
    interrupt_consumer_grant = argc > 1 && std::wstring(argv[argc-1]) == L"--interrupt-consumer-grant";
    if (interrupt_consumer_grant) --argc;
    if ((grant_client_read && (!external_client || admit_client_observer)) ||
        (interrupt_consumer_grant && !grant_client_read)) return 2;
    if (admit_client_observer && (!external_client || grant_client_read || interrupt_consumer_grant)) return 2;
    if (argc < 5 || std::wstring(argv[1]) != L"--service") return 2;
    const std::wstring name(argv[2]);
    const bool hosted = (argc == 5 || argc == 6) &&
        generated_service_name(name, L"USK_WU006_") &&
        (argc != 6 || std::wstring(argv[5]) == L"--prepublish-gate");
    const bool campaign_vm = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        std::wstring(argv[5]) == L"--prepublish-gate" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_recovery = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_recovery_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--recover-prepared" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_replay = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_recovery_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--recover-visible-bound" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_snapshot_recovery = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_recovery_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--recover-snapshot-only" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_reviewed_recovery = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_recovery_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--recover-reviewed" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_sealed_journal = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_recovery_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--recover-sealed-journal" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_postrename = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        std::wstring(argv[5]) == L"--postrename-gate" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_postjournal = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        std::wstring(argv[5]) == L"--postjournal-gate" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_selected = (argc == 10 || argc == 11) &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_selected_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--selected-zip" &&
        campaign_selected_archive_path(argv[6]) &&
        lower_sha256(argv[7]) &&
        std::wstring(argv[8]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[9]) &&
        (argc == 10 || std::wstring(argv[10]) == L"--prepublish-gate" ||
            std::wstring(argv[10]) == L"--postrename-gate" ||
            std::wstring(argv[10]) == L"--postjournal-gate");
    const bool campaign_vm_selected_plan = (argc == 13 || argc == 14) &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_selected_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--selected-zip" &&
        campaign_selected_archive_path(argv[6]) &&
        lower_sha256(argv[7]) &&
        std::wstring(argv[8]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[9]) &&
        std::wstring(argv[10]) == L"--reviewed-plan-envelope" &&
        campaign_reviewed_plan_envelope_path(argv[11]) &&
        lower_sha256(argv[12]) &&
        (argc == 13 || std::wstring(argv[13]) == L"--prepublish-gate" ||
            std::wstring(argv[13]) == L"--postrename-gate" ||
            std::wstring(argv[13]) == L"--postjournal-gate" ||
            std::wstring(argv[13]) == L"--poststage-gate");
    const bool campaign_vm_reviewed_source = (argc == 10 || argc == 11) &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_selected_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--reviewed-plan-envelope" &&
        campaign_reviewed_plan_envelope_path(argv[6]) &&
        lower_sha256(argv[7]) &&
        std::wstring(argv[8]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[9]) &&
        (argc == 10 || std::wstring(argv[10]) == L"--prepublish-gate" ||
            std::wstring(argv[10]) == L"--postrename-gate" ||
            std::wstring(argv[10]) == L"--postjournal-gate" ||
            std::wstring(argv[10]) == L"--poststage-gate");
    // A separately provisioned restricted service can use the same reviewed
    // engine on an already protected dedicated volume. Its authenticated peer
    // receives the result; this mode has no service-chosen receipt pathname,
    // lab-only ACL setup, campaign VM dependency, or fault-injection gate.
    bool registered_reviewed = false;
    if (argc == 8 && external_client &&
            !interrupt_consumer_grant && generated_service_name(name, L"USK_PUB_") &&
            std::wstring(argv[3]) == L"--no-receipt" &&
            std::wstring(argv[5]) == L"--reviewed-plan-envelope" &&
            lower_sha256(argv[7])) {
        try {
            (void)usk::platform::windows::publisher_volume_operation_guard_name(argv[4]);
            const std::filesystem::path envelope(argv[6]);
            registered_reviewed = envelope.is_absolute() &&
                envelope.lexically_normal() == envelope && !envelope.empty();
        } catch (const std::exception&) { registered_reviewed = false; }
    }
#if defined(USK_TEST_REGISTERED_FAULT_GATE)
    // Only the separately built disposable-test executable accepts this
    // receipt-backed interruption grammar. The normal service stays gate-free.
    const bool registered_fault = argc == 11 && external_client &&
        !grant_client_read && !interrupt_consumer_grant &&
        generated_service_name(name, L"USK_PUB_") &&
        std::wstring(argv[3]) == L"--no-receipt" &&
        std::wstring(argv[5]) == L"--reviewed-plan-envelope" &&
        lower_sha256(argv[7]) &&
        std::wstring(argv[8]) == L"--test-gate-receipt" &&
        campaign_selected_receipt_path(argv[9]) &&
        (std::wstring(argv[10]) == L"--poststage-gate" ||
            std::wstring(argv[10]) == L"--prepublish-gate" ||
            std::wstring(argv[10]) == L"--postrename-gate");
#else
    const bool registered_fault = false;
#endif
    const bool registered_recovery = argc == 6 && external_client &&
        !interrupt_consumer_grant &&
        generated_service_name(name, L"USK_PUB_") &&
        std::wstring(argv[3]) == L"--no-receipt" &&
        std::wstring(argv[5]) == L"--recover-reviewed" &&
        [&] {
            try {
                (void)usk::platform::windows::publisher_volume_operation_guard_name(argv[4]);
                return true;
            } catch (const std::exception&) { return false; }
        }();
    const bool registered_verify = argc == 6 && external_client &&
        !interrupt_consumer_grant &&
        generated_service_name(name, L"USK_PUB_") &&
        std::wstring(argv[3]) == L"--no-receipt" &&
        std::wstring(argv[5]) == L"--verify-installed" &&
        [&] {
            try {
                (void)usk::platform::windows::publisher_volume_operation_guard_name(argv[4]);
                return true;
            } catch (const std::exception&) { return false; }
        }();
    const bool registered_mode = registered_reviewed || registered_fault ||
        registered_recovery || registered_verify;
#if defined(USK_PRODUCTION_PUBLISHER)
    // The packaged service exposes only the externally authenticated
    // registered path. Disposable receipt, VM and fault-gate grammars remain
    // in separately named lab binaries.
    if (!registered_mode) return 2;
#endif
    if (!hosted && !campaign_vm && !campaign_vm_recovery &&
        !campaign_vm_replay &&
        !campaign_vm_snapshot_recovery && !campaign_vm_reviewed_recovery &&
        !campaign_vm_sealed_journal &&
        !campaign_vm_postrename && !campaign_vm_postjournal &&
        !campaign_vm_selected && !campaign_vm_selected_plan &&
        !campaign_vm_reviewed_source && !registered_mode) return 2;
    if (external_client && !campaign_vm_selected_plan &&
        !campaign_vm_snapshot_recovery && !campaign_vm_reviewed_recovery &&
        !campaign_vm_reviewed_source && !registered_mode) return 2;
    if ((campaign_vm_reviewed_recovery || campaign_vm_reviewed_source) &&
        !external_client) return 2;
    if (admit_client_observer && !registered_mode) return 2;
    if (service_admitted_client && !registered_mode) return 2;
    service_name = argv[2];
    receipt_path = registered_fault ? argv[9] : registered_mode ? L"" : argv[3];
    volume_root = argv[4];
    const std::wstring selected_gate =
        campaign_vm_selected && argc == 11 ? argv[10] :
        campaign_vm_selected_plan && argc == 14 ? argv[13] :
        campaign_vm_reviewed_source && argc == 11 ? argv[10] :
        registered_fault ? argv[10] : L"";
    prepublish_gate = (hosted && argc == 6) || campaign_vm ||
        selected_gate == L"--prepublish-gate";
    poststage_gate = selected_gate == L"--poststage-gate";
    postrename_gate = campaign_vm_postrename ||
        selected_gate == L"--postrename-gate";
    postjournal_gate = campaign_vm_postjournal ||
        selected_gate == L"--postjournal-gate";
    recover_prepared = campaign_vm_recovery || campaign_vm_replay ||
        campaign_vm_sealed_journal;
    recover_snapshot_only = campaign_vm_snapshot_recovery;
    recover_reviewed = campaign_vm_reviewed_recovery || registered_recovery;
    verify_installed = registered_verify;
    require_preprotected_boundary = campaign_vm_reviewed_source ||
        campaign_vm_selected_plan || registered_mode;
    recover_sealed_journal = campaign_vm_sealed_journal;
    recover_visible_bound = campaign_vm_replay || campaign_vm_sealed_journal;
    selected_archive_mode = campaign_vm_selected || campaign_vm_selected_plan ||
        campaign_vm_snapshot_recovery || campaign_vm_reviewed_source ||
        registered_fault ||
        registered_reviewed;
    if (campaign_vm_selected || campaign_vm_selected_plan) {
        selected_archive_path = argv[6];
        selected_archive_sha256 = ascii(argv[7]);
    }
    if (campaign_vm_selected_plan || campaign_vm_reviewed_source) {
        reviewed_plan_envelope_path = campaign_vm_selected_plan ? argv[11] : argv[6];
        reviewed_plan_envelope_sha256 = ascii(campaign_vm_selected_plan ? argv[12] : argv[7]);
    }
    if (registered_reviewed || registered_fault) {
        reviewed_plan_envelope_path = argv[6];
        reviewed_plan_envelope_sha256 = ascii(argv[7]);
    }
    registered_reviewed_mode = registered_reviewed;
    SERVICE_TABLE_ENTRYW table[] = {{service_name.data(), service_main}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) return 3;
    return service_exit_code == ERROR_SUCCESS ? 0 : 4;
}
#endif
