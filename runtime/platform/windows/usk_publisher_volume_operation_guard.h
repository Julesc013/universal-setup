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

class PublisherInstallBusy final : public std::runtime_error {
public:
    PublisherInstallBusy() : std::runtime_error("publisher installation operation is active") {}
};

class PublisherServiceControlBusy final : public std::runtime_error {
public:
    PublisherServiceControlBusy() : std::runtime_error("publisher service control is active") {}
};

std::wstring publisher_volume_operation_guard_name(const std::wstring& volume_guid_root);
std::wstring publisher_install_operation_guard_name(const std::wstring& volume_guid_root,
    const std::string& install_id);
std::wstring publisher_service_control_guard_name(const std::wstring& volume_guid_root,
    const std::wstring& service_name);

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

// The volume guard is acquired first because this candidate has one protected
// publication namespace per volume. An authenticated install request then
// holds this installation-specific mutex until its state transition ends.
// Neither mutex grants timed automatic takeover of a live worker.
class PublisherInstallOperationGuard final {
public:
    PublisherInstallOperationGuard(const std::wstring& volume_guid_root,
        const std::string& install_id);
    ~PublisherInstallOperationGuard();

    PublisherInstallOperationGuard(const PublisherInstallOperationGuard&) = delete;
    PublisherInstallOperationGuard& operator=(const PublisherInstallOperationGuard&) = delete;
    bool previous_owner_abandoned() const noexcept { return previous_owner_abandoned_; }

private:
    HANDLE mutex_ = nullptr;
    bool previous_owner_abandoned_ = false;
};

// Serializes this product's SCM configuration, start and removal requests for
// one generated service. It is separate from the volume guard held by the
// service itself, so a fast-starting service cannot fail on its own guard.
class PublisherServiceControlGuard final {
public:
    PublisherServiceControlGuard(const std::wstring& volume_guid_root,
        const std::wstring& service_name);
    ~PublisherServiceControlGuard();

    PublisherServiceControlGuard(const PublisherServiceControlGuard&) = delete;
    PublisherServiceControlGuard& operator=(const PublisherServiceControlGuard&) = delete;

private:
    HANDLE mutex_ = nullptr;
};

} // namespace usk::platform::windows
#endif
#endif
