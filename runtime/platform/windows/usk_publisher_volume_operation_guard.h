// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_VOLUME_OPERATION_GUARD_H
#define USK_PUBLISHER_VOLUME_OPERATION_GUARD_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>

#include <stdexcept>
#include <string>

namespace usk::platform::windows {

// A conservative volume-wide guard for the lab service. It prevents a second
// service instance from changing the same volume while the first is working.
// It does not replace the per-install lease and revision fencing contract.
class PublisherVolumeBusy final : public std::runtime_error {
public:
    PublisherVolumeBusy() : std::runtime_error("publisher volume operation is active") {}
};

std::wstring publisher_volume_operation_guard_name(const std::wstring& volume_guid_root);

class PublisherVolumeOperationGuard final {
public:
    explicit PublisherVolumeOperationGuard(const std::wstring& volume_guid_root);
    ~PublisherVolumeOperationGuard();

    PublisherVolumeOperationGuard(const PublisherVolumeOperationGuard&) = delete;
    PublisherVolumeOperationGuard& operator=(const PublisherVolumeOperationGuard&) = delete;
    bool previous_owner_abandoned() const noexcept { return previous_owner_abandoned_; }

private:
    HANDLE mutex_ = nullptr;
    bool previous_owner_abandoned_ = false;
};

} // namespace usk::platform::windows
#endif
#endif
