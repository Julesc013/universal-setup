// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_service_absence_internal.h"
#include "usk_publisher_fixture_scm_wait.h"
#include "usk_publisher_service_absence_fixture_checks.h"
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
    // A live/unmarked service cannot become successful absence. The bounded
    // owner-only wait refuses it; the single fresh strict check stays immediate.
    const auto present_wait = refused("wait present", [&] {
        (void)native::wait_for_deleted_publisher_service_absence(manager, service.name);
    }, "SCM absence is unconfirmed (completion bound reached)");
    require(usk::test::bounded_service_absence_refusal(present_wait, false),
        "live service did not reach the completion bound while still present");
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
    require(usk::test::strict_service_absence_refusal(strict),
        "held service refusal did not establish presence or the exact pending error");

    const auto waiting = refused("wait held deletion", [&] {
        (void)native::wait_for_deleted_publisher_service_absence(manager, service.name);
    }, "SCM absence is unconfirmed (completion bound reached)");
    require(usk::test::bounded_service_absence_refusal(waiting, true),
        "held service did not reach the completion bound while present or pending");
    std::cout << "held-query-handle timeout: " << waiting << '\n';
    const auto after_timeout = refused("strict after held timeout", [&] {
        native::require_publisher_service_absence(manager, service.name);
    }, "owned retirement strict SCM revalidation: ");
    require(usk::test::strict_service_absence_refusal(after_timeout),
        "fresh strict held-service probe did not establish presence or the exact pending error");

    // Exercise the actual product waiter while the exact query handle remains
    // held. A thread that never observes presence/pending cannot pass this case.
    auto completion = std::async(std::launch::async, [&] {
        return native::wait_for_deleted_publisher_service_absence(manager, service.name);
    });
    require(completion.wait_for(std::chrono::milliseconds(200)) == std::future_status::timeout,
        "held fixture completed before the observer closed");
    observer.close_confirmed();
    const auto result = completion.get();
    require(result.present_observations + result.pending_deletion_observations > 0 &&
        result.probes <= 81 &&
        result.probes == result.present_observations + result.pending_deletion_observations + 1,
        "native deletion completion did not positively enter the bounded wait");
    std::cout << "held-query-handle completion: probes " << result.probes <<
        "; present observations " << result.present_observations <<
        "; pending-deletion observations " << result.pending_deletion_observations <<
        "; initial strict1072 " << pending_error << '\n';
    // CloseServiceHandle may return before SCM finishes deleting the stopped
    // fixture record. Keep this independent fixture-only completion check;
    // the actual product wait above already required its own timely native1060.
    const auto fixture_completion = usk::test::wait_for_fixture_service_deletion(
        [&] {
            ScmHandle probe(OpenServiceW(manager, service.name.c_str(), SERVICE_QUERY_CONFIG));
            if (probe.value) {
                probe.close_confirmed();
                return usk::test::FixtureScmState::present;
            }
            const auto error = GetLastError();
            if (error == ERROR_SERVICE_DOES_NOT_EXIST) return usk::test::FixtureScmState::absent;
            if (error == ERROR_SERVICE_MARKED_FOR_DELETE) return usk::test::FixtureScmState::pending_deletion;
            throw std::runtime_error("fixture SCM deletion observation failed; Win32 " + std::to_string(error));
        }, [] { return GetTickCount64(); },
        [](std::uint64_t duration) { Sleep(static_cast<DWORD>(duration)); });
    std::cout << "fixture post-close completion: probes " << fixture_completion.probes <<
        "; present " << fixture_completion.present << "; pending " << fixture_completion.pending << '\n';
    // Both product helpers now make their own fresh, strict native1060 probes.
    native::require_publisher_service_absence(manager, service.name);
    const auto absent = native::wait_for_deleted_publisher_service_absence(manager, service.name);
    require(absent.probes == 1 && absent.pending_deletion_observations == 0 && absent.present_observations == 0,
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
