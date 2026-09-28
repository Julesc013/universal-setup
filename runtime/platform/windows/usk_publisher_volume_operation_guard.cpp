// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_volume_operation_guard.h"

#if defined(_WIN32)
#include <cstddef>
#include <stdexcept>

namespace usk::platform::windows {

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

std::wstring publisher_service_control_guard_name(const std::wstring& root,
    const std::wstring& service_name)
{
    const std::wstring volume_name = publisher_volume_operation_guard_name(root);
    if (service_name.size() != 40u || service_name.rfind(L"USK_PUB_", 0) != 0) {
        throw std::invalid_argument("publisher service control guard requires a generated service name");
    }
    for (std::size_t index = 8u; index < service_name.size(); ++index) {
        const wchar_t ch = service_name[index];
        if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) {
            throw std::invalid_argument("publisher service control guard name is malformed");
        }
    }
    return L"Global\\USK.Publisher.ServiceControl." +
        volume_name.substr(std::wstring(L"Global\\USK.Publisher.Volume.").size()) +
        L"." + service_name;
}

PublisherVolumeOperationGuard::PublisherVolumeOperationGuard(const std::wstring& root)
{
    const std::wstring name = publisher_volume_operation_guard_name(root);
    mutex_ = CreateMutexW(nullptr, FALSE, name.c_str());
    if (!mutex_) {
        throw std::runtime_error("publisher volume guard cannot open its named mutex");
    }
    const DWORD outcome = WaitForSingleObject(mutex_, 0);
    if (outcome == WAIT_OBJECT_0 || outcome == WAIT_ABANDONED) {
        previous_owner_abandoned_ = outcome == WAIT_ABANDONED;
        return;
    }
    CloseHandle(mutex_);
    mutex_ = nullptr;
    if (outcome == WAIT_TIMEOUT) throw PublisherVolumeBusy();
    throw std::runtime_error("publisher volume guard wait failed");
}

PublisherVolumeOperationGuard::~PublisherVolumeOperationGuard()
{
    if (mutex_) {
        ReleaseMutex(mutex_);
        CloseHandle(mutex_);
    }
}

PublisherInstallOperationGuard::PublisherInstallOperationGuard(const std::wstring& root,
    const std::string& install_id)
{
    const std::wstring name = publisher_install_operation_guard_name(root, install_id);
    mutex_ = CreateMutexW(nullptr, FALSE, name.c_str());
    if (!mutex_) {
        throw std::runtime_error("publisher install guard cannot open its named mutex");
    }
    const DWORD outcome = WaitForSingleObject(mutex_, 0);
    if (outcome == WAIT_OBJECT_0 || outcome == WAIT_ABANDONED) {
        previous_owner_abandoned_ = outcome == WAIT_ABANDONED;
        return;
    }
    CloseHandle(mutex_);
    mutex_ = nullptr;
    if (outcome == WAIT_TIMEOUT) throw PublisherInstallBusy();
    throw std::runtime_error("publisher install guard wait failed");
}

PublisherInstallOperationGuard::~PublisherInstallOperationGuard()
{
    if (mutex_) {
        ReleaseMutex(mutex_);
        CloseHandle(mutex_);
    }
}

PublisherServiceControlGuard::PublisherServiceControlGuard(const std::wstring& root,
    const std::wstring& service_name)
{
    const std::wstring name = publisher_service_control_guard_name(root, service_name);
    mutex_ = CreateMutexW(nullptr, FALSE, name.c_str());
    if (!mutex_) {
        throw std::runtime_error("publisher service control guard cannot open its named mutex");
    }
    const DWORD outcome = WaitForSingleObject(mutex_, 0);
    if (outcome == WAIT_OBJECT_0 || outcome == WAIT_ABANDONED) return;
    CloseHandle(mutex_);
    mutex_ = nullptr;
    if (outcome == WAIT_TIMEOUT) throw PublisherServiceControlBusy();
    throw std::runtime_error("publisher service control guard wait failed");
}

PublisherServiceControlGuard::~PublisherServiceControlGuard()
{
    if (mutex_) {
        ReleaseMutex(mutex_);
        CloseHandle(mutex_);
    }
}

} // namespace usk::platform::windows
#endif
