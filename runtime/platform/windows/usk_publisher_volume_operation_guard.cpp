// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_volume_operation_guard.h"

#if defined(_WIN32)
#include <cstddef>
#include <stdexcept>

namespace usk::platform::windows {

namespace {

template<class Busy>
bool acquire_guard(HANDLE mutex, HANDLE cancel_event, DWORD wait_milliseconds)
{
    const DWORD mutex_index = cancel_event ? 1u : 0u;
    HANDLE handles[] = {cancel_event, mutex};
    // Cancellation comes first when both objects are signalled. It never
    // acquires the mutex or permits a timed takeover of a live holder.
    const DWORD outcome = cancel_event ?
        WaitForMultipleObjects(2, handles, FALSE, wait_milliseconds) :
        WaitForSingleObject(mutex, wait_milliseconds);
    if (outcome == WAIT_OBJECT_0 + mutex_index) return false;
    if (outcome == WAIT_ABANDONED_0 + mutex_index) return true;
    if (cancel_event && outcome == WAIT_OBJECT_0) throw PublisherOperationCancelled();
    if (outcome == WAIT_TIMEOUT) throw Busy();
    throw std::runtime_error("publisher operation guard wait failed; Win32 " +
        std::to_string(GetLastError()));
}

void require_bounded_wait(DWORD wait_milliseconds)
{
    if (wait_milliseconds > publisher_guard_max_wait_milliseconds)
        throw std::invalid_argument("publisher operation guard deadline exceeds its bound");
}

} // namespace

std::wstring publisher_volume_operation_guard_name(const std::wstring& root)
{
    const std::wstring prefix = L"\\\\?\\Volume{";
    if (root.size() != prefix.size() + 38u || root.rfind(prefix, 0) != 0 ||
        root[root.size() - 2u] != L'}' || root.back() != L'\\') {
        throw std::invalid_argument("publisher volume guard requires an exact volume GUID root");
    }
    std::wstring guid = root.substr(prefix.size(), 36u);
    for (std::size_t index = 0; index < guid.size(); ++index) {
        const bool hyphen = index == 8u || index == 13u || index == 18u || index == 23u;
        const wchar_t ch = guid[index];
        if (hyphen ? ch != L'-' :
            !((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ||
                (ch >= L'A' && ch <= L'F'))) {
            throw std::invalid_argument("publisher volume guard GUID is malformed");
        }
        if (ch >= L'A' && ch <= L'F') guid[index] = ch - L'A' + L'a';
    }
    return L"Global\\USK.Publisher.Volume." + guid;
}

std::wstring publisher_install_operation_guard_name(const std::wstring& root,
    const std::string& install_id)
{
    const std::wstring volume_name = publisher_volume_operation_guard_name(root);
    if (install_id.empty() || install_id.size() > 128u) {
        throw std::invalid_argument("publisher install guard requires a bounded install ID");
    }
    constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring name = L"Global\\USK.Publisher.Install." +
        volume_name.substr(std::wstring(L"Global\\USK.Publisher.Volume.").size()) + L".";
    for (const unsigned char ch : install_id) {
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
              (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-')) {
            throw std::invalid_argument("publisher install guard ID is not canonical ASCII");
        }
        name.push_back(hex[ch >> 4u]);
        name.push_back(hex[ch & 0x0fu]);
    }
    return name;
}

PublisherVolumeOperationGuard::PublisherVolumeOperationGuard(const std::wstring& root,
    HANDLE cancel_event, DWORD wait_milliseconds)
{
    require_bounded_wait(wait_milliseconds);
    const std::wstring name = publisher_volume_operation_guard_name(root);
    mutex_ = CreateMutexW(nullptr, FALSE, name.c_str());
    if (!mutex_) {
        throw std::runtime_error("publisher volume guard cannot open its named mutex");
    }
    try {
        previous_owner_abandoned_ = acquire_guard<PublisherVolumeBusy>(
            mutex_, cancel_event, wait_milliseconds);
    } catch (...) {
        CloseHandle(mutex_);
        mutex_ = nullptr;
        throw;
    }
}

PublisherVolumeOperationGuard::~PublisherVolumeOperationGuard()
{
    if (mutex_) {
        ReleaseMutex(mutex_);
        CloseHandle(mutex_);
    }
}

PublisherInstallOperationGuard::PublisherInstallOperationGuard(const std::wstring& root,
    const std::string& install_id, HANDLE cancel_event, DWORD wait_milliseconds)
{
    require_bounded_wait(wait_milliseconds);
    const std::wstring name = publisher_install_operation_guard_name(root, install_id);
    mutex_ = CreateMutexW(nullptr, FALSE, name.c_str());
    if (!mutex_) {
        throw std::runtime_error("publisher install guard cannot open its named mutex");
    }
    try {
        previous_owner_abandoned_ = acquire_guard<PublisherInstallBusy>(
            mutex_, cancel_event, wait_milliseconds);
    } catch (...) {
        CloseHandle(mutex_);
        mutex_ = nullptr;
        throw;
    }
}

PublisherInstallOperationGuard::~PublisherInstallOperationGuard()
{
    if (mutex_) {
        ReleaseMutex(mutex_);
        CloseHandle(mutex_);
    }
}

} // namespace usk::platform::windows
#endif
