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

} // namespace usk::platform::windows
#endif
