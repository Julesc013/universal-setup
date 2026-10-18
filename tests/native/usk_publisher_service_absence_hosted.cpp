// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_service_absence_internal.h"
#include <objbase.h>
#include <array>
#include <chrono>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
namespace native = usk::platform::windows::detail;
void require(bool okay, const char* reason) { if (!okay) throw std::runtime_error(reason); }
bool environment_is(const char* key, const char* expected) {
    std::array<char, 64> value{};
    const auto length = GetEnvironmentVariableA(key, value.data(), static_cast<DWORD>(value.size()));
    return length && length < value.size() && std::string(value.data()) == expected;
}
struct ScmHandle {
    SC_HANDLE value = nullptr;
    explicit ScmHandle(SC_HANDLE handle) : value(handle) {}
    ~ScmHandle() { if (value) CloseServiceHandle(value); }
    ScmHandle(const ScmHandle&) = delete;
    ScmHandle& operator=(const ScmHandle&) = delete;
    void close_confirmed() {
        const auto closing = value;
        value = nullptr;
        require(closing && CloseServiceHandle(closing), "fixture SCM handle close unconfirmed");
    }
};
struct OwnedService {
    std::wstring name;
    ScmHandle original;
    explicit OwnedService(SC_HANDLE manager) : name(unique_name()), original(create(manager, name)) {}
    ~OwnedService() { if (original.value) DeleteService(original.value); }
    static std::wstring unique_name() {
        GUID guid{};
        require(SUCCEEDED(CoCreateGuid(&guid)), "fixture service identity unavailable");
        std::array<wchar_t, 40> text{};
        require(StringFromGUID2(guid, text.data(), static_cast<int>(text.size())) != 0,
            "fixture service identity conversion failed");
        return std::wstring(L"USK_ABSENCE_") + text.data();
    }
    static SC_HANDLE create(SC_HANDLE manager, const std::wstring& name) {
        std::array<wchar_t, 32768> image{};
        const auto length = GetModuleFileNameW(nullptr, image.data(), static_cast<DWORD>(image.size()));
        require(length && length < image.size(), "fixture image unavailable");
        const auto command = std::wstring(L"\"") + image.data() + L"\"";
        const auto service = CreateServiceW(manager, name.c_str(), name.c_str(),
            DELETE | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS, SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        require(service != nullptr, "fixture owned service creation failed; no existing service is reused");
        return service;
    }
    void mark_and_close() {
        SERVICE_STATUS_PROCESS status{};
        DWORD needed = 0;
        require(QueryServiceStatusEx(original.value, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<BYTE*>(&status), sizeof(status), &needed) &&
            status.dwCurrentState == SERVICE_STOPPED && status.dwProcessId == 0,
            "fixture service is not stopped");
        require(DeleteService(original.value) != FALSE, "fixture service delete unconfirmed");
        // This is the API that documents the already-marked error. A later
        // read-only OpenService may still open the record while it is held.
        require(DeleteService(original.value) == FALSE && GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE,
            "fixture original service deletion mark was not independently observed");
        original.close_confirmed();
    }
};

template<typename Function>
std::string refused(const char* phase, Function&& function, const char* expected) {
    std::string diagnostic;
    try { function(); }
    catch (const std::exception& error) { diagnostic = error.what(); }
    if (diagnostic.empty() || diagnostic.find(expected) == std::string::npos) {
        constexpr std::size_t diagnostic_limit = 2048;
        if (diagnostic.size() > diagnostic_limit) diagnostic.resize(diagnostic_limit);
        throw std::runtime_error(std::string("fixture phase ") + phase +
            ": expected refusal containing [" + expected + "]; observed [" +
            (diagnostic.empty() ? "operation returned without a refusal" : diagnostic) + "]");
    }
    return diagnostic;
}

void qualify(SC_HANDLE manager) {
    OwnedService service(manager);
    refused("strict present", [&] { native::require_publisher_service_absence(manager, service.name); }, "service is present");
    refused("wait present", [&] { (void)native::wait_for_deleted_publisher_service_absence(manager, service.name); },
        "service is present");
    // A native error other than 1060/1072 must refuse immediately.
    refused("invalid name", [&] { (void)native::wait_for_deleted_publisher_service_absence(manager, L"invalid/name"); },
        "Win32 123; probes 1; pending-deletion observations 0");

    ScmHandle observer(OpenServiceW(manager, service.name.c_str(), SERVICE_QUERY_CONFIG));
    require(observer.value != nullptr, "fixture query-only handle unavailable");
    service.mark_and_close();
    const auto strict = refused("strict held deletion", [&] {
        native::require_publisher_service_absence(manager, service.name);
    }, "owned retirement strict SCM revalidation: ");
    const bool pending_error = strict == "owned retirement strict SCM revalidation: SCM absence is unconfirmed; "
        "Win32 1072; probes 1; pending-deletion observations 1";
    require(pending_error || strict == "owned retirement strict SCM revalidation: service is present",
        "held service refusal did not establish presence or the exact pending error");

    if (!pending_error) {
        // The stopped record remains in SCM until its last handle closes.
        // Presence is a valid strict refusal, never permission to retry it as
        // absent. Do not manufacture 1072 coverage from DeleteService's error.
        refused("wait held presence", [&] {
            (void)native::wait_for_deleted_publisher_service_absence(manager, service.name);
        }, "owned retirement post-delete-and-close SCM completion: service is present");
        refused("strict held presence unchanged", [&] {
            native::require_publisher_service_absence(manager, service.name);
        }, "owned retirement strict SCM revalidation: service is present");
        observer.close_confirmed();
        std::cout << "held-query-handle presence refused; native OpenService 1072 retry route not observed\n";
    } else {
        const auto waiting = refused("wait held deletion", [&] {
            (void)native::wait_for_deleted_publisher_service_absence(manager, service.name);
        }, "post-delete-and-close SCM completion: SCM absence is unconfirmed; Win32 1072");
        std::cout << "held-query-handle timeout: " << waiting << '\n';
        // It remains pending after timeout; no fallback is projected as absence.
        refused("strict after deadline", [&] { native::require_publisher_service_absence(manager, service.name); }, "Win32 1072");

        // Execute the exact product helper while the original query-only handle
        // still exists. The returned count must positively establish entry through
        // 1072; a scheduler that never enters that route cannot pass this control.
        auto completion = std::async(std::launch::async, [&] {
            return native::wait_for_deleted_publisher_service_absence(manager, service.name);
        });
        require(completion.wait_for(std::chrono::milliseconds(200)) == std::future_status::timeout,
            "pending fixture completed before the observer closed");
        observer.close_confirmed();
        const auto result = completion.get();
        require(result.pending_deletion_observations > 0 && result.probes <= 81 &&
            result.probes == result.pending_deletion_observations + 1,
            "pending completion did not positively cover the bounded native route");
        std::cout << "held-query-handle completion: probes " << result.probes <<
            "; pending-deletion observations " << result.pending_deletion_observations << '\n';
    }
    // Both native observations must converge only after the original observer
    // was explicitly closed. Only a fresh 1060 may establish actual absence.
    native::require_publisher_service_absence(manager, service.name);
    const auto absent = native::wait_for_deleted_publisher_service_absence(manager, service.name);
    require(absent.probes == 1 && absent.pending_deletion_observations == 0,
        "already absent fixture did not use one fresh observation");
    std::cout << "strict native absence confirmed after observer closure\n";
}
} // namespace

int main(int argc, char** argv) {
    try {
        // This fixture creates only its own stopped service, never starts it,
        // and is not registered with ordinary local/core CTest.
        require(argc == 2 && std::string(argv[1]) == "--trusted-hosted-scm-fixture" &&
            environment_is("GITHUB_ACTIONS", "true") &&
            environment_is("RUNNER_ENVIRONMENT", "github-hosted") &&
            environment_is("USK_TRUSTED_HOSTED_LAB", "true"),
            "SCM fixture requires the admitted disposable hosted lab");
        ScmHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE));
        require(manager.value != nullptr, "fixture SCM manager unavailable");
        qualify(manager.value);
        manager.close_confirmed();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "usk_publisher_service_absence_hosted: " << error.what() << '\n';
        return 1;
    }
}
