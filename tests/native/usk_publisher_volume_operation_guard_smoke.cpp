// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_volume_operation_guard.h"
#include "usk_publisher_installation_lease.h"

#if defined(_WIN32)
#include <objbase.h>

#include <atomic>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

std::wstring fresh_root()
{
    GUID guid{};
    wchar_t spelling[40]{};
    if (CoCreateGuid(&guid) != S_OK || StringFromGUID2(guid, spelling, 40) != 39) {
        throw std::runtime_error("cannot make an isolated volume-guard test name");
    }
    return L"\\\\?\\Volume" + std::wstring(spelling) + L"\\";
}

bool rejects(const std::wstring& root)
{
    try {
        (void)usk::platform::windows::publisher_volume_operation_guard_name(root);
    } catch (const std::invalid_argument&) {
        return true;
    }
    return false;
}

struct TestEvent {
    TestEvent() : handle(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
        if (!handle) throw std::runtime_error("cannot create owned guard-test event");
    }
    ~TestEvent() { CloseHandle(handle); }
    HANDLE handle;
};

template<class Busy, class Acquire>
bool bounded_acquisition_cases(const char* scope, Acquire acquire)
{
    using usk::platform::windows::PublisherOperationCancelled;
    using usk::platform::windows::publisher_guard_max_wait_milliseconds;
    TestEvent cancelled;
    if (!SetEvent(cancelled.handle)) return false;
    bool cancelled_before_acquisition = false;
    try { auto guard = acquire(cancelled.handle, 0); }
    catch (const PublisherOperationCancelled&) { cancelled_before_acquisition = true; }
    if (!cancelled_before_acquisition || !ResetEvent(cancelled.handle)) {
        std::cerr << scope << ": ready cancellation or event reset failed\n";
        return false;
    }
    bool refused_unbounded = false;
    try { auto guard = acquire(nullptr, publisher_guard_max_wait_milliseconds + 1); }
    catch (const std::invalid_argument&) { refused_unbounded = true; }
    if (!refused_unbounded) {
        std::cerr << scope << ": unbounded wait was accepted\n";
        return false;
    }

    {
        auto holder = acquire(nullptr, 0);
        std::atomic<int> deadline_result{0};
        ULONGLONG deadline_elapsed = 0;
        std::thread deadline_contender([&] {
            const ULONGLONG started = GetTickCount64();
            try { auto guard = acquire(nullptr, 50); deadline_result = 2; }
            catch (const Busy&) {
                const ULONGLONG elapsed = GetTickCount64() - started;
                deadline_elapsed = elapsed;
                deadline_result = elapsed >= 30 && elapsed < 5000 ? 1 : 3;
            } catch (...) { deadline_result = 4; }
        });
        deadline_contender.join();
        if (deadline_result != 1) {
            std::cerr << scope << ": busy deadline result=" << deadline_result.load()
                      << " elapsed_ms=" << deadline_elapsed << '\n';
            return false;
        }

        TestEvent contender_started;
        std::atomic<int> cancellation_result{0};
        std::thread cancelled_contender([&] {
            if (!SetEvent(contender_started.handle)) { cancellation_result = 4; return; }
            try { auto guard = acquire(cancelled.handle, 5000); cancellation_result = 2; }
            catch (const PublisherOperationCancelled&) { cancellation_result = 1; }
            catch (...) { cancellation_result = 3; }
        });
        const DWORD started_wait = WaitForSingleObject(contender_started.handle, 5000);
        const BOOL cancellation_set = SetEvent(cancelled.handle);
        cancelled_contender.join();
        if (started_wait != WAIT_OBJECT_0 || !cancellation_set || cancellation_result != 1) {
            std::cerr << scope << ": asynchronous cancellation wait=" << started_wait
                      << " signal=" << cancellation_set << " result=" << cancellation_result.load() << '\n';
            return false;
        }
    }
    if (!ResetEvent(cancelled.handle)) return false;
    // A separate thread must acquire after both refused attempts. This also
    // checks that cancellation did not leave a recursive mutex acquisition.
    std::atomic<int> successor_result{0};
    std::thread successor([&] {
        try { auto guard = acquire(nullptr, 0); successor_result = 1; }
        catch (...) { successor_result = 2; }
    });
    successor.join();
    if (successor_result != 1) {
        std::cerr << scope << ": successor acquisition result=" << successor_result.load() << '\n';
        return false;
    }

    TestEvent held;
    TestEvent release;
    std::atomic<int> holder_result{0};
    const ULONGLONG release_case_started = GetTickCount64();
    ULONGLONG holder_scope_exit_ms = 0;
    ULONGLONG release_signal_ms = 0;
    DWORD release_signal_error = ERROR_SUCCESS;
    std::thread releasing_holder([&] {
        try {
            {
                auto guard = acquire(nullptr, 0);
                if (!SetEvent(held.handle)) { holder_result = 3; return; }
                holder_result = WaitForSingleObject(release.handle, 5000) == WAIT_OBJECT_0 ? 1 : 4;
            }
            holder_scope_exit_ms = GetTickCount64() - release_case_started;
        } catch (...) { holder_result = 2; SetEvent(held.handle); }
    });
    const DWORD held_wait = WaitForSingleObject(held.handle, 5000);
    std::thread release_signal([&] {
        Sleep(50);
        release_signal_ms = GetTickCount64() - release_case_started;
        if (!SetEvent(release.handle)) release_signal_error = GetLastError();
    });
    bool acquired_after_release = false;
    bool observed_abandonment = false;
    std::string acquisition_error;
    const ULONGLONG acquisition_started = GetTickCount64();
    try {
        auto guard = acquire(nullptr, 2000);
        observed_abandonment = guard.previous_owner_abandoned();
        acquired_after_release = !observed_abandonment;
    } catch (const std::exception& error) { acquisition_error = error.what(); }
    catch (...) { acquisition_error = "non-standard exception"; }
    const ULONGLONG acquisition_elapsed = GetTickCount64() - acquisition_started;
    release_signal.join();
    releasing_holder.join();
    const bool passed = held_wait == WAIT_OBJECT_0 && holder_result == 1 && acquired_after_release;
    if (!passed) {
        std::cerr << scope << ": release-before-deadline wait=" << held_wait
                  << " holder_result=" << holder_result.load()
                  << " acquired=" << acquired_after_release
                  << " abandoned=" << observed_abandonment
                  << " acquisition_elapsed_ms=" << acquisition_elapsed
                  << " release_signal_ms=" << release_signal_ms
                  << " release_signal_error=" << release_signal_error
                  << " holder_scope_exit_ms=" << holder_scope_exit_ms
                  << " acquisition_error=" << acquisition_error << '\n';
    }
    return passed;
}

int child_guard_result(const std::wstring& mode, const std::wstring& root,
    const std::wstring& install_id = L"")
{
    std::wstring executable(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, executable.data(),
        static_cast<DWORD>(executable.size()));
    if (!length || length >= executable.size()) return -1;
    executable.resize(length);
    std::wstring command = L"\"" + executable + L"\" " + mode + L" " + root;
    if (!install_id.empty()) command += L" " + install_id;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr,
            FALSE, 0, nullptr, nullptr, &startup, &child)) return -2;
    const DWORD waited = WaitForSingleObject(child.hProcess, 10000);
    DWORD code = 0;
    if (waited != WAIT_OBJECT_0 || !GetExitCodeProcess(child.hProcess, &code)) {
        TerminateProcess(child.hProcess, 99);
        WaitForSingleObject(child.hProcess, 10000);
        code = 99;
    }
    FILETIME birth{}, exit{}, kernel{}, user{};
    if (waited == WAIT_OBJECT_0 && GetProcessTimes(child.hProcess, &birth, &exit, &kernel, &user)) {
        std::ostringstream creation;
        creation << std::hex << std::setfill('0') << std::setw(16) <<
            ((static_cast<std::uint64_t>(birth.dwHighDateTime) << 32) | birth.dwLowDateTime);
        const usk::json::Value holder(usk::json::Value::Object{
            {"process_id", usk::json::Value(static_cast<std::uint64_t>(child.dwProcessId))},
            {"process_creation_time", usk::json::Value(creation.str())}});
        if (usk::platform::windows::observe_publisher_previous_lease_holder(holder) !=
            usk::transaction::InstallLeasePreviousHolder::ended) code = 98;
    } else code = 97;
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return static_cast<int>(code);
}

} // namespace

int run_guard_smoke(int argc, wchar_t** argv)
{
    using usk::platform::windows::PublisherVolumeBusy;
    using usk::platform::windows::PublisherVolumeOperationGuard;
    using usk::platform::windows::PublisherInstallBusy;
    using usk::platform::windows::PublisherInstallOperationGuard;
    using usk::platform::windows::publisher_install_operation_guard_name;
    using usk::platform::windows::publisher_volume_operation_guard_name;

    if (argc == 3 && std::wstring(argv[1]) == L"--contend-volume") {
        try { PublisherVolumeOperationGuard guard(argv[2]); return 2; }
        catch (const PublisherVolumeBusy&) { return 0; }
        catch (...) { return 3; }
    }
    if (argc == 3 && std::wstring(argv[1]) == L"--abandon-volume") {
        try {
            PublisherVolumeOperationGuard guard(argv[2]);
            ExitProcess(0); // Deliberately skip guard destruction in the child.
        } catch (...) { return 3; }
    }
    if (argc == 4 && std::wstring(argv[1]) == L"--contend-install") {
        try {
            const std::wstring id(argv[3]);
            if (id != L"org.example.setup" && id != L"org.example.other") return 3;
            std::string ascii_id;
            for (const wchar_t ch : id) ascii_id.push_back(static_cast<char>(ch));
            PublisherInstallOperationGuard guard(argv[2],
                ascii_id);
            return 2;
        } catch (const PublisherInstallBusy&) { return 0; }
        catch (...) { return 3; }
    }
    if (argc != 1) return 16;

    const auto live_holder = usk::platform::windows::observe_publisher_lease_holder();
    if (live_holder.at("process_id").as_unsigned() != GetCurrentProcessId() ||
        usk::platform::windows::observe_publisher_previous_lease_holder(live_holder) !=
            usk::transaction::InstallLeasePreviousHolder::live) return 31;
    auto old_birth = live_holder;
    old_birth.as_object().at("process_creation_time") = usk::json::Value("0000000000000001");
    // A recorded old birth time cannot identify this real live process. This
    // tests the OS observation/classification, not an actual forced PID reuse.
    if (usk::platform::windows::observe_publisher_previous_lease_holder(old_birth) !=
        usk::transaction::InstallLeasePreviousHolder::identity_reused) return 32;
    HANDLE actual_root = CreateFileW(std::filesystem::current_path().c_str(),
        FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (actual_root == INVALID_HANDLE_VALUE) return 34;
    const auto actual_identity = usk::platform::windows::observe_publisher_lease_root_identity(actual_root);
    CloseHandle(actual_root);
    // Real native observations can enter the data protocol. This ordinary
    // test directory supplies no protected-service or mutation authority.
    const std::string revision(64, 'a');
    const auto observed_protocol = usk::transaction::derive_install_lease_ownership({},
        {"org.example.setup", "install_local", "test.operation", "test.attempt", revision, false, std::string(64, 'd')},
        actual_identity, live_holder, revision);
    usk::transaction::require_install_lease_record(observed_protocol);

    const std::wstring root = fresh_root();
    if (!rejects(L"E:\\") || !rejects(root + L"child") ||
        !rejects(L"\\\\?\\Volume{12345678-1234-1234-1234-12345678901z}\\")) {
        return 1;
    }
    std::wstring lower = root;
    for (wchar_t& ch : lower) {
        if (ch >= L'A' && ch <= L'F') ch = ch - L'A' + L'a';
    }
    if (publisher_volume_operation_guard_name(root) !=
        publisher_volume_operation_guard_name(lower)) return 2;
    if (publisher_install_operation_guard_name(root, "org.example.setup") !=
            publisher_install_operation_guard_name(lower, "org.example.setup") ||
        publisher_install_operation_guard_name(root, "org.example.setup") ==
            publisher_install_operation_guard_name(root, "Org.example.setup")) return 10;
    for (const std::string& invalid : {std::string{}, std::string("../other"),
            std::string(129, 'a')}) {
        bool refused = false;
        try { (void)publisher_install_operation_guard_name(root, invalid); }
        catch (const std::invalid_argument&) { refused = true; }
        if (!refused) return 11;
    }
    {
        PublisherInstallOperationGuard owner(root, "org.example.setup");
        const auto inspection_reference =
            usk::platform::windows::publisher_install_operation_inspection_reference(root, "org.example.setup");
        if (inspection_reference.size() != std::string("usk.operation-inspection.v1:").size() + 64 ||
            inspection_reference != usk::platform::windows::publisher_install_operation_inspection_reference(
                lower, "org.example.setup") ||
            inspection_reference == usk::platform::windows::publisher_install_operation_inspection_reference(
                root, "org.example.other") ||
            inspection_reference == usk::platform::windows::publisher_volume_operation_inspection_reference(root))
            return 42;
        if (owner.previous_owner_abandoned()) return 12;
        owner.require_owned(root, "org.example.setup");
        bool wrong_install_refused = false;
        try { owner.require_owned(root, "org.example.other"); }
        catch (const PublisherInstallBusy&) { wrong_install_refused = true; }
        if (!wrong_install_refused) return 33;
        std::atomic<int> contender_result{0};
        std::thread contender([&] {
            try { owner.require_owned(root, "org.example.setup"); }
            catch (const PublisherInstallBusy&) { contender_result = 4; }
            if (contender_result != 4) { contender_result = 5; return; }
            try {
                PublisherInstallOperationGuard second(lower, "org.example.setup");
                contender_result = 2;
            } catch (const PublisherInstallBusy& busy) {
                contender_result = busy.inspection_reference() == inspection_reference ? 1 : 6;
            } catch (...) {
                contender_result = 3;
            }
        });
        contender.join();
        if (contender_result != 1) return 13;
        PublisherInstallOperationGuard independent(root, "org.example.other");
        if (independent.previous_owner_abandoned()) return 14;
        if (child_guard_result(L"--contend-install", root,
                L"org.example.setup") != 0 ||
            child_guard_result(L"--contend-install", root,
                L"org.example.other") != 0) return 17;
    }
    {
        PublisherInstallOperationGuard successor(root, "org.example.setup");
        if (successor.previous_owner_abandoned()) return 15;
    }
    if (child_guard_result(L"--contend-install", root,
            L"org.example.setup") != 2) return 19;

    {
        PublisherVolumeOperationGuard owner(root);
        if (owner.previous_owner_abandoned()) return 3;
        if (child_guard_result(L"--contend-volume", root) != 0) return 18;
        std::atomic<int> contender_result{0};
        std::thread contender([&] {
            try {
                PublisherVolumeOperationGuard second(lower);
                contender_result = 2;
            } catch (const PublisherVolumeBusy&) {
                contender_result = 1;
            } catch (...) {
                contender_result = 3;
            }
        });
        contender.join();
        if (contender_result != 1) return 4;
    }
    {
        PublisherVolumeOperationGuard successor(root);
        if (successor.previous_owner_abandoned()) return 5;
    }
    if (child_guard_result(L"--contend-volume", root) != 2) return 20;

    const std::wstring abandoned_root = fresh_root();
    const std::wstring abandoned_name = publisher_volume_operation_guard_name(abandoned_root);
    HANDLE retained_name = CreateMutexW(nullptr, FALSE, abandoned_name.c_str());
    if (!retained_name) return 21;
    if (child_guard_result(L"--abandon-volume", abandoned_root) != 0) {
        CloseHandle(retained_name);
        return 22;
    }
    {
        PublisherVolumeOperationGuard recovery(abandoned_root);
        if (!recovery.previous_owner_abandoned()) {
            CloseHandle(retained_name);
            return 23;
        }
    }
    CloseHandle(retained_name);

    HANDLE raw = nullptr;
    DWORD first_wait = WAIT_FAILED;
    const std::wstring name = publisher_volume_operation_guard_name(root);
    std::thread interrupted([&] {
        raw = CreateMutexW(nullptr, FALSE, name.c_str());
        if (raw) first_wait = WaitForSingleObject(raw, 0);
        // Simulate an owner thread ending without releasing its mutex.
    });
    interrupted.join();
    if (!raw || first_wait != WAIT_OBJECT_0) {
        if (raw) CloseHandle(raw);
        return 6;
    }
    {
        PublisherVolumeOperationGuard recovery(root);
        if (!recovery.previous_owner_abandoned()) {
            CloseHandle(raw);
            return 7;
        }
    }
    CloseHandle(raw);

    const std::wstring occupied_root = fresh_root();
    const std::wstring occupied_name = publisher_volume_operation_guard_name(occupied_root);
    HANDLE wrong_type = CreateEventW(nullptr, FALSE, FALSE, occupied_name.c_str());
    if (!wrong_type) return 8;
    bool refused_wrong_type = false;
    try {
        PublisherVolumeOperationGuard conflict(occupied_root);
    } catch (const std::runtime_error&) {
        refused_wrong_type = true;
    }
    CloseHandle(wrong_type);
    if (!refused_wrong_type) return 9;

    const std::wstring wait_root = fresh_root();
    if (!bounded_acquisition_cases<PublisherVolumeBusy>("volume", [&](HANDLE cancel, DWORD budget) {
            return PublisherVolumeOperationGuard(wait_root, cancel, budget);
        })) return 24;
    if (!bounded_acquisition_cases<PublisherInstallBusy>("installation", [&](HANDLE cancel, DWORD budget) {
            return PublisherInstallOperationGuard(wait_root, "org.example.setup", cancel, budget);
        })) return 25;
    return 0;
}

int wmain(int argc, wchar_t** argv)
{
    const int result = run_guard_smoke(argc, argv);
    if (argc == 1 && result != 0)
        std::cerr << "usk_publisher_volume_operation_guard_smoke: exit_code=" << result << '\n';
    return result;
}
#endif
