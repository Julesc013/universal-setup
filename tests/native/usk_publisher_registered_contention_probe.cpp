// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
// Owned hosted fixture for the registered pre-dispatch endpoint only.
#include "usk_publisher_request_channel.h"
#include "usk_publisher_registration.h"
#include "usk_one_shot.h"
#include "usk_stable_file.h"
#include "usk_json.h"
#if defined(_WIN32)
#include <atomic>
#include <exception>
#include <filesystem>
#include <iostream>
#include <thread>
#include <vector>
namespace {
using usk::json::Value;
using namespace usk::platform::windows;
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE handle) : value(handle) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
struct ServiceHandle {
    SC_HANDLE value;
    explicit ServiceHandle(SC_HANDLE handle) : value(handle) {}
    ~ServiceHandle() { if (value) CloseServiceHandle(value); }
};
DWORD worker_pid(SC_HANDLE service) {
    SERVICE_STATUS_PROCESS status{};
    SERVICE_SID_INFO sid{};
    DWORD size = 0;
    require(QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(&status), sizeof(status), &size) &&
        QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO,
            reinterpret_cast<BYTE*>(&sid), sizeof(sid), &size) &&
        status.dwServiceType == SERVICE_WIN32_OWN_PROCESS &&
        status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId &&
        sid.dwServiceSidType == SERVICE_SID_TYPE_RESTRICTED,
        "fixture worker is not a running restricted own-process service");
    return status.dwProcessId;
}
std::uint64_t birth(HANDLE process) {
    FILETIME created{}, exited{}, kernel{}, user{};
    require(GetProcessTimes(process, &created, &exited, &kernel, &user) != FALSE,
        "fixture process birth observation unavailable");
    return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32u) | created.dwLowDateTime;
}
std::string utf8(const std::wstring& text) {
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
        static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    require(size > 0, "fixture process image path conversion failed");
    std::string result(static_cast<std::size_t>(size), '\0');
    require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
        static_cast<int>(text.size()), result.data(), size, nullptr, nullptr) == size,
        "fixture process image path conversion changed");
    return result;
}
std::uint64_t counter() {
    LARGE_INTEGER value{};
    require(QueryPerformanceCounter(&value) && value.QuadPart > 0,
        "fixture call timing unavailable");
    return static_cast<std::uint64_t>(value.QuadPart);
}
struct CallTiming {
    std::atomic<std::uint64_t> started{0};
    std::atomic<std::uint64_t> completed{0};
};
struct CallCompletion {
    CallTiming* timing;
    ~CallCompletion() {
        LARGE_INTEGER value{};
        if (timing && QueryPerformanceCounter(&value) && value.QuadPart > 0)
            timing->completed.store(static_cast<std::uint64_t>(value.QuadPart));
    }
};
struct JoinThread {
    std::thread& thread;
    ~JoinThread() { if (thread.joinable()) thread.join(); }
};
Value outcome_case(const std::string& label, Value request, const std::wstring& service,
    const PublisherRequestOptions& options, const std::string& reference, const char* code,
    CallTiming* timing = nullptr) {
    request.as_object().at("request_id") = Value("registered-contention." + label);
    const auto began = GetTickCount64();
    const auto result = usk::command::run_publisher_one_shot(usk::json::canonical(request),
        [&](const std::string& payload) {
            if (timing) timing->started.store(counter());
            CallCompletion completion{timing};
            return submit_registered_publisher_request(service, payload, options);
        });
    const auto elapsed = GetTickCount64() - began;
    const auto response = usk::json::parse(result.document);
    require(result.exit_code == 4 && response.at("status").as_string() == "refused" &&
        response.at("error").at("code").as_string() == code &&
        response.at("result").as_object().size() == 3 &&
        response.at("result").at("schema").as_string() == "usk.publisher_operation_diagnostic.v1" &&
        response.at("result").at("error_code").as_string() == code &&
        response.at("result").at("inspection_reference").as_string() == reference && elapsed < 5000,
        "actual registered contention projection or timing differs");
    return Value(Value::Object{{"case", Value(label)}, {"elapsed_milliseconds", Value(elapsed)},
        {"exit_code", Value(std::uint64_t{4})}, {"response", response}});
}
int run(const std::wstring& service_name, const std::filesystem::path& request_path,
    const std::string& expected_image_sha256, DWORD held_worker_pid = 0,
    const std::string& held_worker_birth = {}) {
    // The SYSTEM fixture launcher enforces the owned hosted target. It creates
    // this ordinary client with an isolated user environment, so runner flags
    // are not inherited and cannot serve as this client's execution authority.
    require(service_name.size() == 40 && service_name.compare(0, 8, L"USK_PUB_") == 0 &&
        service_name.find_first_not_of(L"0123456789abcdef", 8) == std::wstring::npos,
        "registered fixture service name differs");
    usk::base::StableFile input(request_path);
    const auto size = input.identity().size_bytes;
    require(size && size <= 1024u * 1024u, "registered fixture request size differs");
    const auto bytes = input.read(0, static_cast<std::size_t>(size));
    input.verify_unchanged();
    const auto request = usk::json::parse(std::string(bytes.begin(), bytes.end()));
    require(request.at("schema").as_string() == "usk.oneshot_request.v1" &&
        request.at("command").as_string() == "install_local.apply" && !request.at("dry_run").as_boolean(),
        "registered fixture is not the original apply request");
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    require(manager.value != nullptr, "fixture SCM is unavailable");
    ServiceHandle service(OpenServiceW(manager.value, service_name.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
    require(service.value != nullptr, "fixture registration unavailable");
    const DWORD expected_pid = worker_pid(service.value);
    const bool active_holder = held_worker_pid != 0;
    require(!active_holder || expected_pid == held_worker_pid,
        "active fixture worker differs from the retained holder");
    // The original mode occupies an empty endpoint. The active-holder mode
    // borrows an independently retained installer; it must never open the
    // fixture's first connection or send another installer request here.
    // PID/birth facts alone do not establish native installation ownership.
    // The hosted controller must separately retain that ownership observation.
    Handle connection(INVALID_HANDLE_VALUE);
    if (!active_holder) {
        connection.value = connect_publisher_request_endpoint(service_name, 30000);
        ULONG server_pid = 0;
        require(GetNamedPipeServerProcessId(connection.value, &server_pid) && server_pid == expected_pid,
            "fixture connection is not the held SCM worker endpoint");
    }
    Handle worker(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, expected_pid));
    require(worker.value != nullptr && WaitForSingleObject(worker.value, 0) == WAIT_TIMEOUT,
        "fixture worker is unavailable");
    const auto worker_birth = birth(worker.value);
    require(!active_holder || std::to_string(worker_birth) == held_worker_birth,
        "active fixture worker birth differs from the retained holder");
    std::wstring image(32768, L'\0');
    DWORD image_size = static_cast<DWORD>(image.size());
    require(QueryFullProcessImageNameW(worker.value, 0, image.data(), &image_size) && image_size,
        "fixture worker image is unavailable");
    image.resize(image_size);
    const auto reference = publisher_request_inspection_reference(service_name);
    Value::Array cases;
    cases.push_back(outcome_case("fail_fast", request, service_name, {}, reference, "operation_conflict"));
    PublisherRequestOptions timed;
    timed.conflict_wait_milliseconds = 75;
    cases.push_back(outcome_case("deadline", request, service_name, timed, reference, "operation_conflict"));
    require(cases.back().at("elapsed_milliseconds").as_unsigned() >= 75,
        "registered contention deadline was not exercised");
    Handle cancel(CreateEventW(nullptr, TRUE, TRUE, nullptr));
    require(cancel.value != nullptr, "fixture cancellation event is unavailable");
    PublisherRequestOptions cancelled;
    cancelled.cancel_event = cancel.value;
    cancelled.conflict_wait_milliseconds = 1000;
    cases.push_back(outcome_case("ready_cancel", request, service_name, cancelled, reference, "operation_cancelled"));
    require(ResetEvent(cancel.value) != FALSE, "fixture cancellation reset failed");
    CallTiming timing;
    std::atomic<bool> finished{false};
    std::exception_ptr failure;
    Value asynchronous;
    std::thread contender([&] {
        try {
            asynchronous = outcome_case("async_cancel", request, service_name, cancelled, reference,
                "operation_cancelled", &timing);
        } catch (...) { failure = std::current_exception(); }
        finished.store(true);
    });
    JoinThread join{contender};
    const auto start_deadline = GetTickCount64() + 5000;
    while (!timing.started.load() && !finished.load() && GetTickCount64() < start_deadline) Sleep(1);
    Sleep(25);
    const auto signal_counter = counter();
    const bool active_at_signal = timing.started.load() != 0 && timing.completed.load() == 0 && !finished.load();
    const bool signalled = SetEvent(cancel.value) != FALSE;
    contender.join();
    require(signalled, "fixture cancellation signal failed");
    if (failure) std::rethrow_exception(failure);
    const auto call_started = timing.started.load();
    const auto call_completed = timing.completed.load();
    require(active_at_signal && call_started < signal_counter && signal_counter < call_completed &&
        asynchronous.at("elapsed_milliseconds").as_unsigned() > 0,
        "fixture cancellation did not interrupt an active registered call");
    asynchronous.as_object().emplace("cancellation_order", Value(Value::Object{
        {"call_started_qpc", Value(call_started)}, {"cancellation_signalled_qpc", Value(signal_counter)},
        {"call_completed_qpc", Value(call_completed)}, {"call_active_at_signal", Value(active_at_signal)}}));
    cases.push_back(asynchronous);
    require(worker_pid(service.value) == expected_pid && birth(worker.value) == worker_birth &&
        WaitForSingleObject(worker.value, 0) == WAIT_TIMEOUT,
        "endpoint contention replaced or ended its existing worker");
    input.verify_unchanged();
    const std::string service_ascii = utf8(service_name);
    const auto observation = Value(Value::Object{
        {"schema", Value("usk.publisher_registered_contention_observation.v1")}, {"status", Value("pass")},
        {"scope", Value(active_holder ? "active_install_holder_endpoint_before_effect_request_bytes" :
            "registered_endpoint_before_effect_request_bytes")}, {"profile_qualified", Value(false)},
        {"service_name", Value(service_ascii)}, {"inspection_reference", Value(reference)},
        {"worker_process_id", Value(static_cast<std::uint64_t>(expected_pid))},
        {"worker_process_creation_time", Value(worker_birth)}, {"worker_alive_after_cases", Value(true)},
        // The ordinary client observes the held process path; it does not
        // read the private protected executable or measure mapped image bytes.
        {"worker_process_image_path", Value(utf8(image))},
        {"worker_expected_image_sha256", Value(expected_image_sha256)}, {"request_sha256", Value(input.sha256_hex())},
        {"caller_process_id", Value(static_cast<std::uint64_t>(GetCurrentProcessId()))},
        {"caller_process_creation_time", Value(birth(GetCurrentProcess()))}, {"cases", Value(cases)}});
    // Only the original mode owns a first connection. The active installer
    // remains under the hosted controller's checked process custody.
    if (!active_holder) {
        require(CloseHandle(connection.value) != FALSE, "fixture connection closure failed");
        connection.value = INVALID_HANDLE_VALUE;
    }
    std::cout << usk::json::canonical(observation) << '\n';
    return std::cout ? 0 : 1;
}
}
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 4 && argc != 6) return 2;
        const std::wstring digest(argv[3]);
        require(digest.size() == 64 && digest.find_first_not_of(L"0123456789abcdef") == std::wstring::npos,
            "fixture image digest differs");
        DWORD holder_pid = 0;
        std::string holder_birth;
        if (argc == 6) {
            const std::wstring pid_text(argv[4]), birth_text(argv[5]);
            require(!pid_text.empty() && pid_text.size() <= 10 && pid_text[0] != L'0' &&
                pid_text.find_first_not_of(L"0123456789") == std::wstring::npos &&
                !birth_text.empty() && birth_text.size() <= 20 && birth_text[0] != L'0' &&
                birth_text.find_first_not_of(L"0123456789") == std::wstring::npos,
                "active fixture holder identity is not canonical");
            const auto parsed = std::stoull(pid_text);
            require(parsed <= MAXDWORD, "active fixture holder PID exceeds its bound");
            holder_pid = static_cast<DWORD>(parsed);
            // Exact comparison with independently read FILETIME below also
            // rejects overflow without narrowing or accepting a PID alone.
            holder_birth = utf8(birth_text);
        }
        return run(argv[1], std::filesystem::path(argv[2]), utf8(digest), holder_pid, holder_birth);
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
#endif
