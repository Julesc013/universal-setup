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
