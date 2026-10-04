// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_volume_operation_guard.h"

#if defined(_WIN32)
#include <objbase.h>

#include <atomic>
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
bool bounded_acquisition_cases(Acquire acquire)
{
    using usk::platform::windows::PublisherOperationCancelled;
    using usk::platform::windows::publisher_guard_max_wait_milliseconds;
    TestEvent cancelled;
    if (!SetEvent(cancelled.handle)) return false;
    bool cancelled_before_acquisition = false;
    try { auto guard = acquire(cancelled.handle, 0); }
    catch (const PublisherOperationCancelled&) { cancelled_before_acquisition = true; }
    if (!cancelled_before_acquisition || !ResetEvent(cancelled.handle)) return false;
    bool refused_unbounded = false;
    try { auto guard = acquire(nullptr, publisher_guard_max_wait_milliseconds + 1); }
    catch (const std::invalid_argument&) { refused_unbounded = true; }
    if (!refused_unbounded) return false;

    {
        auto holder = acquire(nullptr, 0);
        std::atomic<int> deadline_result{0};
        std::thread deadline_contender([&] {
            const ULONGLONG started = GetTickCount64();
            try { auto guard = acquire(nullptr, 50); deadline_result = 2; }
            catch (const Busy&) {
                const ULONGLONG elapsed = GetTickCount64() - started;
                deadline_result = elapsed >= 30 && elapsed < 5000 ? 1 : 3;
            } catch (...) { deadline_result = 4; }
        });
        deadline_contender.join();
        if (deadline_result != 1) return false;

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
        if (started_wait != WAIT_OBJECT_0 || !cancellation_set || cancellation_result != 1)
            return false;
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
    if (successor_result != 1) return false;

    TestEvent held;
    TestEvent release;
    std::atomic<int> holder_result{0};
    std::thread releasing_holder([&] {
        try {
            auto guard = acquire(nullptr, 0);
            if (!SetEvent(held.handle)) { holder_result = 3; return; }
            holder_result = WaitForSingleObject(release.handle, 5000) == WAIT_OBJECT_0 ? 1 : 4;
        } catch (...) { holder_result = 2; SetEvent(held.handle); }
    });
    const DWORD held_wait = WaitForSingleObject(held.handle, 5000);
    std::thread release_signal([&] { Sleep(50); SetEvent(release.handle); });
    bool acquired_after_release = false;
    try {
        auto guard = acquire(nullptr, 2000);
        acquired_after_release = !guard.previous_owner_abandoned();
    } catch (...) { }
    release_signal.join();
    releasing_holder.join();
    return held_wait == WAIT_OBJECT_0 && holder_result == 1 && acquired_after_release;
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
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return static_cast<int>(code);
}

} // namespace

int wmain(int argc, wchar_t** argv)
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
        if (owner.previous_owner_abandoned()) return 12;
        std::atomic<int> contender_result{0};
        std::thread contender([&] {
            try {
                PublisherInstallOperationGuard second(lower, "org.example.setup");
                contender_result = 2;
            } catch (const PublisherInstallBusy&) {
                contender_result = 1;
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
    if (!bounded_acquisition_cases<PublisherVolumeBusy>([&](HANDLE cancel, DWORD budget) {
            return PublisherVolumeOperationGuard(wait_root, cancel, budget);
        })) return 24;
    if (!bounded_acquisition_cases<PublisherInstallBusy>([&](HANDLE cancel, DWORD budget) {
            return PublisherInstallOperationGuard(wait_root, "org.example.setup", cancel, budget);
        })) return 25;
    return 0;
}
#endif
