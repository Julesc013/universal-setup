// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_request_channel.h"
#include "usk_publisher_channel_io_internal.h"
#include "usk_publisher_recovery_request_internal.h"
#include "usk_publisher_response_internal.h"
#if defined(_WIN32)
#include "usk_effect_dispatch.h"
#include <algorithm>
#include <stdexcept>
namespace usk::platform::windows {
namespace {
using detail::channel_io::request_limit;
using detail::channel_io::response_limit;
using detail::channel_io::deadline;
using detail::channel_io::remaining;
using detail::channel_io::read_message;
using detail::channel_io::write_message;
constexpr DWORD client_access = FILE_READ_DATA | FILE_WRITE_DATA |
    FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE v) : value(v) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
struct ServiceHandle {
    SC_HANDLE value;
    explicit ServiceHandle(SC_HANDLE v) : value(v) {}
    ~ServiceHandle() { if (value) CloseServiceHandle(value); }
};
void require_request_not_cancelled(const PublisherRequestOptions& options,
    const std::string& inspection_reference) {
    if (!options.cancel_event) return;
    const DWORD result = WaitForSingleObject(options.cancel_event, 0);
    if (result == WAIT_OBJECT_0)
        throw usk::base::EffectRequestNotDispatched(
            usk::base::EffectRequestNotDispatched::Reason::operation_cancelled, inspection_reference);
    if (result != WAIT_TIMEOUT) throw std::runtime_error("publisher cancellation event unavailable");
}
DWORD service_process(SC_HANDLE service) {
    SERVICE_STATUS_PROCESS status{};
    DWORD size = 0;
    SERVICE_SID_INFO sid{};
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<BYTE*>(&status), sizeof(status), &size) ||
        status.dwServiceType != SERVICE_WIN32_OWN_PROCESS ||
        status.dwCurrentState != SERVICE_RUNNING || !status.dwProcessId ||
        !QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO,
            reinterpret_cast<BYTE*>(&sid), sizeof(sid), &size) || sid.dwServiceSidType != SERVICE_SID_TYPE_RESTRICTED) {
        throw std::runtime_error("publisher server is not a live own-process restricted service");
    }
    return status.dwProcessId;
}
DWORD await_service_process(SC_HANDLE service, ULONGLONG until,
    const PublisherRequestOptions& options, const std::string& inspection_reference) {
    SERVICE_SID_INFO sid{};
    DWORD size = 0;
    if (!QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO,
            reinterpret_cast<BYTE*>(&sid), sizeof(sid), &size) ||
        sid.dwServiceSidType != SERVICE_SID_TYPE_RESTRICTED) {
        throw std::runtime_error("publisher server is not a restricted service");
    }
    while (true) {
        require_request_not_cancelled(options, inspection_reference);
        SERVICE_STATUS_PROCESS status{};
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&status), sizeof(status), &size) ||
            status.dwServiceType != SERVICE_WIN32_OWN_PROCESS) {
            throw std::runtime_error("publisher server is not an own-process service");
        }
        if (status.dwCurrentState == SERVICE_RUNNING) {
            if (!remaining(until)) throw std::runtime_error("publisher server startup timed out");
            return service_process(service);
        }
        if (status.dwCurrentState != SERVICE_START_PENDING) {
            throw std::runtime_error("publisher server stopped before becoming ready");
        }
        const DWORD wait = std::min<DWORD>(remaining(until), 20);
        if (!wait) throw std::runtime_error("publisher server startup timed out");
        Sleep(wait);
    }
}
}
std::wstring publisher_request_pipe_name(const std::wstring& service_name) {
    if (service_name.empty() || service_name.size() > 80) throw std::runtime_error("publisher service name invalid");
    for (const auto ch : service_name) {
        if (!((ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z') ||
            (ch >= L'0' && ch <= L'9') || ch == L'_' || ch == L'-')) {
            throw std::runtime_error("publisher service name invalid");
        }
    }
    return L"\\\\.\\pipe\\USK-Publisher-" + service_name;
}
std::string publisher_request_inspection_reference(const std::wstring& service_name) {
    const auto name = publisher_request_pipe_name(service_name);
    std::string canonical;
    canonical.reserve(name.size());
    for (const auto ch : name)
        canonical.push_back(static_cast<char>(ch >= L'a' && ch <= L'z' ? ch - L'a' + L'A' : ch));
    return "usk.operation-inspection.v1:" + usk::json::sha256_canonical(usk::json::Value(canonical));
}
HANDLE connect_publisher_request_endpoint(const std::wstring& service_name,
    DWORD timeout_ms, const PublisherRequestOptions& options) {
    const auto until = deadline(timeout_ms);
    if (options.conflict_wait_milliseconds > publisher_request_max_conflict_wait_milliseconds)
        throw std::invalid_argument("publisher contention wait exceeds bound");
    const auto name = publisher_request_pipe_name(service_name);
    const auto inspection_reference = publisher_request_inspection_reference(service_name);
    ULONGLONG conflict_until = 0;
    const auto conflict = [&] {
        throw usk::base::EffectRequestNotDispatched(
            usk::base::EffectRequestNotDispatched::Reason::operation_conflict, inspection_reference);
    };
    while (true) {
        require_request_not_cancelled(options, inspection_reference);
        if (conflict_until && !remaining(conflict_until)) conflict();
        if (!remaining(until)) {
            if (conflict_until) conflict();
            throw std::runtime_error("publisher endpoint connection timed out before dispatch");
        }
        const HANDLE raw = CreateFileW(name.c_str(), client_access, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (raw != INVALID_HANDLE_VALUE) {
            try { require_request_not_cancelled(options, inspection_reference); }
            catch (...) { CloseHandle(raw); throw; }
            return raw;
        }
        const DWORD error = GetLastError();
        if (error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND)
            throw std::runtime_error("publisher endpoint refused connection before dispatch");
        if (error == ERROR_PIPE_BUSY) {
            if (!options.conflict_wait_milliseconds) conflict();
            if (!conflict_until)
                conflict_until = std::min<ULONGLONG>(until,
                    GetTickCount64() + options.conflict_wait_milliseconds);
        }
        const DWORD wait = std::min<DWORD>(10,
            remaining(conflict_until ? conflict_until : until));
        if (!wait) continue;
        // WaitNamedPipe returns immediately for an absent pipe. A separate
        // bounded pause prevents spinning while ServiceMain creates its endpoint.
        if (error == ERROR_FILE_NOT_FOUND) {
            if (options.cancel_event) WaitForSingleObject(options.cancel_event, wait);
            else Sleep(wait);
        } else {
            WaitNamedPipeW(name.c_str(), wait);
        }
    }
}
void require_publisher_response_binding(const std::wstring& service_name,
    const std::string& request, const std::string& response, DWORD expected_process_id) {
    usk::json::ParseLimits limits;
    limits.max_bytes = response_limit;
    limits.max_string_bytes = response_limit / 2u;
    const auto observed = usk::json::parse(response, limits);
    limits.max_bytes = request_limit;
    limits.max_string_bytes = request_limit / 2u;
    const auto submitted = usk::json::parse(request, limits);
    const std::string schema = submitted.at("schema").as_string();
    std::string expected_service;
    expected_service.reserve(service_name.size());
    for (const wchar_t ch : service_name) {
        if (ch < 0x20 || ch > 0x7e) {
            throw std::runtime_error("publisher service name is not ASCII");
        }
        expected_service.push_back(static_cast<char>(ch));
    }
    if (schema == "usk.publisher_capability_request.v2" || schema == "usk.publisher_capability_request.v3" ||
        schema == "usk.publisher_capability_request.v4" || schema == "usk.publisher_capability_request.v5") {
        const auto& request_id = submitted.at("request_id").as_string();
        if (submitted.as_object().size() != 2 || request_id.empty() || request_id.size() > 128 ||
            request_id.find_first_not_of(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != std::string::npos ||
            observed.as_object().size() != 8 ||
            observed.at("schema").as_string() != "usk.publisher_service_capability_observation.v1" ||
            observed.at("status").as_string() != "observed" ||
            observed.at("request_id").as_string() != request_id ||
            observed.at("service_name").as_string() != expected_service ||
            observed.at("service_sid").as_string().empty() ||
            observed.at("process_id").as_unsigned() == 0 ||
            observed.at("process_id").as_unsigned() > 0xffffffffu ||
            (expected_process_id != 0 && observed.at("process_id").as_unsigned() != expected_process_id) ||
            observed.at("registered_admission").type() != usk::json::Value::Type::object ||
            observed.at("capability_observation").type() != usk::json::Value::Type::object ||
            observed.at("capability_observation").at("schema").as_string() !=
                (schema == "usk.publisher_capability_request.v5" ? "usk.publisher_capability.v5" :
                 schema == "usk.publisher_capability_request.v4" ? "usk.publisher_capability.v4" :
                 schema == "usk.publisher_capability_request.v3" ? "usk.publisher_capability.v3" : "usk.publisher_capability.v2")) {
            throw std::runtime_error("publisher service observation differs from request or live server");
        }
        // The command validator checks the complete admission/capability leaves
        // before exposing them. Transport admission never grants authority.
        return;
    }
    if (observed.at("schema").as_string() !=
            "usk.publisher_lab_service_observation.v1") {
        throw std::runtime_error("publisher response schema differs");
    }
    const std::string status = observed.at("status").as_string();
    const bool completed_drift_report = status == "failed" &&
        observed.contains("verify_response");
    if (status == "recovery_required" ||
        (status == "failed" && !completed_drift_report)) return;
    if (status != "pass" && !completed_drift_report) {
        throw std::runtime_error("publisher response status differs");
    }

    if (observed.contains("service_name")) {
        if (observed.at("service_name").as_string() != expected_service) {
            throw std::runtime_error("publisher response service identity differs");
        }
    } else if (schema != "usk.publisher_installed_verify_request.v1") {
        throw std::runtime_error("publisher response service identity is absent");
    }

    if (schema == "usk.install_local_plan_request.v1") {
        usk::command::detail::require_public_install_plan_response(submitted, observed);
        if (expected_process_id && observed.at("process_id").as_unsigned() != expected_process_id)
            throw std::runtime_error("registered plan belongs to another live endpoint");
        return;
    }
    if (usk::command::detail::publisher_public_recovery_inspection(submitted)) {
        usk::command::detail::require_public_native_recovery_response(submitted, observed);
        if (observed.at("service_name").as_string() != expected_service ||
            (expected_process_id && observed.at("process_id").as_unsigned() != expected_process_id))
            throw std::runtime_error("native recovery response belongs to another live endpoint");
        const auto& admission = observed.at("registered_admission");
        if (admission.at("schema").as_string() != "usk.publisher_registered_admission_observation.v1" ||
            admission.at("service_name").as_string() != expected_service ||
            admission.at("service_sid").as_string() != observed.at("service_sid").as_string() ||
            admission.at("process_id").as_unsigned() != observed.at("process_id").as_unsigned())
            throw std::runtime_error("native recovery registered endpoint binding differs");
        return;
    }
    if (schema == "usk.repair_apply_request.v1" || schema == "usk.move_apply_request.v1" ||
        schema == "usk.uninstall_apply_request.v1" || schema == "usk.publisher_maintenance_recovery_request.v1") {
        const bool recovery = schema == "usk.publisher_maintenance_recovery_request.v1";
        const std::string operation = recovery ? submitted.at("operation").as_string() :
            schema == "usk.repair_apply_request.v1" ? "repair" :
            schema == "usk.move_apply_request.v1" ? "move" : "uninstall";
        if (recovery && (submitted.as_object().size() != 4 ||
            (operation != "repair" && operation != "move" && operation != "uninstall")))
            throw std::runtime_error("publisher maintenance recovery selector differs");
        const auto install_id = recovery ? submitted.at("install_id").as_string() :
            submitted.at("plan_request").at("install_id").as_string();
        const auto& public_response = observed.at(recovery ? "recovery_response" : "apply_response");
        const auto& report = public_response.at("payload");
        auto digest_body = report;
        digest_body.as_object().erase("report_digest");
        const auto& admission = observed.at("registered_admission");
        const auto report_status = report.at("status").as_string();
        const bool completed = recovery ? report_status == "completed" : operation == "move" ? report_status == "new_committed_old_retained" :
            (report_status == "completed" || (operation == "uninstall" && report_status == "retained_foreign_content"));
        if (observed.as_object().size() != 12 || status != "pass" || !completed ||
            observed.at("request_sha256").as_string() != usk::json::sha256_canonical(submitted) ||
            observed.at("operation").as_string() != operation ||
            observed.at("install_id").as_string() != install_id ||
            observed.at("transaction_id").as_string() != submitted.at("transaction_id").as_string() ||
            observed.at("process_id").as_unsigned() == 0 || observed.at("process_id").as_unsigned() > 0xffffffffu ||
            (expected_process_id && observed.at("process_id").as_unsigned() != expected_process_id) ||
            observed.at("service_sid").as_string().empty() ||
            observed.at("operation_admission").type() != usk::json::Value::Type::object ||
            admission.at("schema").as_string() != "usk.publisher_registered_admission_observation.v1" ||
            admission.at("service_name").as_string() != expected_service ||
            admission.at("service_sid").as_string() != observed.at("service_sid").as_string() ||
            admission.at("process_id").as_unsigned() != observed.at("process_id").as_unsigned() ||
            public_response.at("schema").as_string() != "usk.command_response.v1" ||
            public_response.at("status").as_string() != "ok" ||
            report.at("schema").as_string() != (recovery ? "usk.maintenance_recovery_report.v1" : "usk." + operation + "_report.v1") ||
            report.at("install_id").as_string() != install_id ||
            report.at("transaction_id").as_string() != submitted.at("transaction_id").as_string() ||
            (!recovery && report.at("plan_id").as_string() != submitted.at("plan_request").at("plan_id").as_string()) ||
            report.at("report_id").as_string() != (recovery ? "recovery." : "") + operation + "." + submitted.at("transaction_id").as_string() ||
            report.at("report_digest").as_string() != usk::json::sha256_canonical(digest_body) ||
            (!recovery && report.at("completed_at").as_string() != submitted.at("applied_at").as_string()))
            throw std::runtime_error("publisher completed maintenance differs from request or live server");
        if (recovery) {
            if (report.as_object().size() != 13 || report.at("operation").as_string() != operation ||
                report.at("plan_id").as_string().empty() || report.at("recorded_at").as_string().empty())
                throw std::runtime_error("publisher maintenance recovery result differs from original context");
            for (const auto field : {"plan_digest", "transaction_snapshot_sha256", "effect_history_sha256", "source_digest"}) {
                const auto& digest = report.at(field).as_string();
                if (digest.size() != 64 || digest.find_first_not_of("0123456789abcdef") != std::string::npos)
                    throw std::runtime_error("publisher maintenance recovery result binding is absent");
            }
        }
        return;
    }
    if (schema == "usk.install_local_apply_request.v1" ||
        schema == "usk.publisher_recovery_request.v1") {
        if (status != "pass") {
            throw std::runtime_error("publisher installation has a nonterminal success shape");
        }
        const std::string install_id = schema == "usk.install_local_apply_request.v1" ?
            submitted.at("plan_request").at("install_id").as_string() :
            submitted.at("install_id").as_string();
        // A retry of the original apply request completes through the same
        // source-free replay as an explicit recovery request. Exactly one
        // completed public result may identify this terminal observation.
        const bool direct = observed.at("apply_response").type() !=
            usk::json::Value::Type::null_value;
        const bool replayed = observed.at("recovery_installed_response").type() !=
            usk::json::Value::Type::null_value;
        if (direct == replayed ||
            (schema == "usk.publisher_recovery_request.v1" && direct)) {
            throw std::runtime_error("publisher completed installation result is ambiguous");
        }
        const auto& public_response = observed.at(direct ?
            "apply_response" : "recovery_installed_response");
        const auto& installed = public_response.at("payload");
        if (public_response.at("schema").as_string() != "usk.command_response.v1" ||
            public_response.at("status").as_string() != "ok" ||
            installed.at("schema").as_string() != "usk.installed_state.v1" ||
            installed.at("lifecycle_status").as_string() != "installed" ||
            installed.at("install_id").as_string() != install_id ||
            installed.at("transaction_id").as_string() !=
                submitted.at("transaction_id").as_string() ||
            (schema == "usk.install_local_apply_request.v1" &&
             installed.at("created_at").as_string() !=
                submitted.at("applied_at").as_string())) {
            throw std::runtime_error("publisher completed installation differs from request");
        }
        return;
    }
    if (schema == "usk.publisher_installed_verify_request.v1" ||
        schema == "usk.installed_verify_request.v1") {
        const bool public_request = schema == "usk.installed_verify_request.v1";
        const auto& public_response = observed.at("verify_response");
        const auto& report = public_response.at("payload");
        const auto& actual_transaction = observed.at("transaction_id").as_string();
        if (actual_transaction.empty() ||
            (!public_request && actual_transaction != submitted.at("transaction_id").as_string()) ||
            (public_request && (submitted.as_object().size() != 5 ||
                observed.as_object().size() != 10 ||
                observed.at("registered_admission").at("schema").as_string() !=
                    "usk.publisher_registered_admission_observation.v1" ||
                observed.at("registered_admission").at("service_name").as_string() != expected_service ||
                observed.at("registered_admission").at("service_sid").as_string() != observed.at("service_sid").as_string() ||
                observed.at("registered_admission").at("process_id").as_unsigned() != observed.at("process_id").as_unsigned() ||
                observed.at("request_sha256").as_string() != usk::json::sha256_canonical(submitted) ||
                observed.at("process_id").as_unsigned() == 0 ||
                (expected_process_id && observed.at("process_id").as_unsigned() != expected_process_id) ||
                observed.at("service_sid").as_string().empty())) ||
            public_response.at("schema").as_string() != "usk.command_response.v1" ||
            public_response.at("status").as_string() != "ok" ||
            report.at("schema").as_string() != "usk.verification_report.v1" ||
            (status == "pass" ? report.at("status").as_string() != "pass" :
                (report.at("status").as_string() != "fail" &&
                 report.at("status").as_string() != "warn" &&
                 report.at("status").as_string() != "unknown")) ||
            report.at("install_id").as_string() !=
                submitted.at("install_id").as_string() ||
            report.at("report_id").as_string() !=
                submitted.at("report_id").as_string() ||
            report.at("verified_at").as_string() !=
                submitted.at("verified_at").as_string() ||
            report.at("report_digest").as_string() !=
                observed.at("bound_report_digest").as_string()) {
            throw std::runtime_error("publisher completed verification differs from request");
        }
        return;
    }
    throw std::runtime_error("publisher success has no admitted request schema");
}

std::string submit_publisher_request(const std::wstring& service_name,
    const std::string& request, DWORD timeout_ms,
    const std::wstring& expected_process_image, const PublisherRequestOptions& options) {
    bool write_attempted = false;
    try {
    const auto until = deadline(timeout_ms);
    if (options.conflict_wait_milliseconds > publisher_request_max_conflict_wait_milliseconds)
        throw std::invalid_argument("publisher contention wait exceeds bound");
    const auto inspection_reference = publisher_request_inspection_reference(service_name);
    require_request_not_cancelled(options, inspection_reference);
    if (request.empty() || request.size() > request_limit) throw std::runtime_error("publisher request exceeds bound or is empty");
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.value) throw std::runtime_error("publisher SCM unavailable");
    ServiceHandle service(OpenServiceW(manager.value, service_name.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
    if (!service.value) throw std::runtime_error("publisher service unavailable");
    // StartServiceW returns while ServiceMain may still be START_PENDING.
    // Wait only for that transition, before opening or writing the pipe.
    const auto expected = await_service_process(service.value, until, options, inspection_reference);
    Handle process(nullptr);
    while (!process.value) {
        require_request_not_cancelled(options, inspection_reference);
        process.value = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, expected);
        if (process.value) break;
        const DWORD error = GetLastError();
        // RUNNING precedes the service-side consumer query grant. A standard
        // caller may arrive during that admission window. Wait only for that
        // grant, under the original deadline and unchanged live SCM identity.
        if (error != ERROR_ACCESS_DENIED || service_process(service.value) != expected ||
            !remaining(until)) throw std::runtime_error("publisher process unavailable");
        Sleep(std::min<DWORD>(remaining(until), 10));
    }
    if (WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT ||
        service_process(service.value) != expected) throw std::runtime_error("publisher process unavailable");
    require_request_not_cancelled(options, inspection_reference);
    if (!remaining(until)) throw std::runtime_error("publisher endpoint request deadline expired");
    Handle pipe(connect_publisher_request_endpoint(service_name, remaining(until), options));
    ULONG observed = 0;
    if (!GetNamedPipeServerProcessId(pipe.value, &observed) || observed != expected ||
        WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT || service_process(service.value) != expected) {
        throw std::runtime_error("publisher pipe server differs from live service");
    }
    if (!expected_process_image.empty()) {
        std::wstring image(32768, L'\0');
        DWORD size = static_cast<DWORD>(image.size());
        if (!QueryFullProcessImageNameW(process.value, 0, image.data(), &size) || size == 0)
            throw std::runtime_error("publisher process image is unavailable");
        image.resize(size);
        if (CompareStringOrdinal(image.c_str(), -1, expected_process_image.c_str(), -1, TRUE) != CSTR_EQUAL)
            throw std::runtime_error("publisher process image differs from admitted executable");
    }
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(pipe.value, &mode, nullptr, nullptr)) throw std::runtime_error("publisher endpoint message mode unavailable");
    if (!remaining(until)) throw std::runtime_error("publisher endpoint ready after request deadline");
    require_request_not_cancelled(options, inspection_reference);
        // Even a cancelled/partial first write may have reached the worker.
        write_attempted = true;
        write_message(pipe.value, request, request_limit, options.cancel_event, until);
        const std::string response = read_message(pipe.value, response_limit, options.cancel_event, until);
        require_publisher_response_binding(service_name, request, response, expected);
        if (usk::json::parse(request).at("schema").as_string() == "usk.install_local_plan_request.v1") {
            // The one-request query must release its original worker before a
            // following apply can start. Close this pipe exactly once, then
            // observe the held process and same SCM entry under THIS deadline.
            const HANDLE closing = pipe.value;
            pipe.value = nullptr;
            if (!CloseHandle(closing)) throw std::runtime_error("publisher query channel closure is unknown");
            for (;;) {
                require_request_not_cancelled(options, inspection_reference);
                if (!remaining(until)) throw std::runtime_error("publisher query disposal exceeded its deadline");
                SERVICE_STATUS_PROCESS status{};
                DWORD needed = 0;
                const DWORD ended = WaitForSingleObject(process.value, 0);
                if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO,
                        reinterpret_cast<BYTE*>(&status), sizeof(status), &needed) ||
                    (status.dwProcessId != 0 && status.dwProcessId != expected) ||
                    (ended != WAIT_TIMEOUT && ended != WAIT_OBJECT_0))
                    throw std::runtime_error("publisher query worker disposal is uncertain");
                if (ended == WAIT_OBJECT_0 && status.dwCurrentState == SERVICE_STOPPED && status.dwProcessId == 0) break;
                Sleep(std::min<DWORD>(remaining(until), 10));
            }
        }
        return response;
    } catch (const usk::base::EffectRequestNotDispatched&) {
        if (write_attempted) throw PublisherRequestOutcomeUnknown("request dispatch was attempted");
        throw;
    } catch(const std::exception& error) {
        if (write_attempted) throw PublisherRequestOutcomeUnknown(error.what());
        // Preserve the legacy raw candidate's generic failure ceiling. The
        // registered wrapper may classify this concrete pre-write exception.
        throw;
    }
}
}
#endif
