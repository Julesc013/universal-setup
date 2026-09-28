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

} // namespace

int main()
{
    using usk::platform::windows::PublisherVolumeBusy;
    using usk::platform::windows::PublisherVolumeOperationGuard;
    using usk::platform::windows::PublisherInstallBusy;
    using usk::platform::windows::PublisherInstallOperationGuard;
    using usk::platform::windows::PublisherServiceControlBusy;
    using usk::platform::windows::PublisherServiceControlGuard;
    using usk::platform::windows::publisher_install_operation_guard_name;
    using usk::platform::windows::publisher_service_control_guard_name;
    using usk::platform::windows::publisher_volume_operation_guard_name;

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
    const std::wstring service_name = L"USK_PUB_0123456789abcdef0123456789abcdef";
    if (publisher_service_control_guard_name(root, service_name) !=
            publisher_service_control_guard_name(lower, service_name) ||
        publisher_service_control_guard_name(root, service_name) ==
            publisher_volume_operation_guard_name(root)) return 16;
    bool malformed_service_refused = false;
    try { (void)publisher_service_control_guard_name(root, L"USK_PUB_not_generated"); }
    catch (const std::invalid_argument&) { malformed_service_refused = true; }
    if (!malformed_service_refused) return 17;
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
    }
    {
        PublisherInstallOperationGuard successor(root, "org.example.setup");
        if (successor.previous_owner_abandoned()) return 15;
    }

    {
        PublisherServiceControlGuard owner(root, service_name);
        // A service is allowed to acquire its volume guard while the control
        // process is still returning from StartServiceW.
        PublisherVolumeOperationGuard service(root);
        std::atomic<int> contender_result{0};
        std::thread contender([&] {
            try {
                PublisherServiceControlGuard second(lower, service_name);
                contender_result = 2;
            } catch (const PublisherServiceControlBusy&) {
                contender_result = 1;
            } catch (...) {
                contender_result = 3;
            }
        });
        contender.join();
        if (contender_result != 1) return 18;
    }
    { PublisherServiceControlGuard successor(root, service_name); }

    {
        PublisherVolumeOperationGuard owner(root);
        if (owner.previous_owner_abandoned()) return 3;
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
    return 0;
}
#endif
