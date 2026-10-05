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
#include <utility>

namespace usk::platform::windows {

// A conservative volume-wide guard for the lab service. It prevents a second
// service instance from changing the same volume while the first is working.
// It does not replace the per-install lease and revision fencing contract.
class PublisherVolumeBusy final : public std::runtime_error {
public:
    explicit PublisherVolumeBusy(std::string inspection_reference = {}) :
        std::runtime_error("publisher volume operation is active"),
        inspection_reference_(std::move(inspection_reference)) {}
    const std::string& inspection_reference() const noexcept { return inspection_reference_; }
private:
    std::string inspection_reference_;
};

class PublisherInstallBusy final : public std::runtime_error {
public:
    explicit PublisherInstallBusy(std::string inspection_reference = {}) :
        std::runtime_error("publisher installation operation is active"),
        inspection_reference_(std::move(inspection_reference)) {}
    const std::string& inspection_reference() const noexcept { return inspection_reference_; }
private:
    std::string inspection_reference_;
};

class PublisherOperationCancelled final : public std::runtime_error {
public:
    explicit PublisherOperationCancelled(std::string inspection_reference = {}) :
        std::runtime_error("publisher operation acquisition cancelled"),
        inspection_reference_(std::move(inspection_reference)) {}
    const std::string& inspection_reference() const noexcept { return inspection_reference_; }
private:
    std::string inspection_reference_;
};

inline constexpr DWORD publisher_guard_max_wait_milliseconds = 30000;

std::wstring publisher_volume_operation_guard_name(const std::wstring& volume_guid_root);
std::wstring publisher_install_operation_guard_name(const std::wstring& volume_guid_root,
    const std::string& install_id);
// Opaque diagnostic references to these exact coordination scopes. They do
// not identify a current holder or grant inspection/publication authority.
std::string publisher_volume_operation_inspection_reference(const std::wstring& volume_guid_root);
std::string publisher_install_operation_inspection_reference(const std::wstring& volume_guid_root,
    const std::string& install_id);

class PublisherVolumeOperationGuard final {
public:
    explicit PublisherVolumeOperationGuard(const std::wstring& volume_guid_root,
        HANDLE cancel_event = nullptr, DWORD wait_milliseconds = 0);
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
        const std::string& install_id, HANDLE cancel_event = nullptr,
        DWORD wait_milliseconds = 0);
    ~PublisherInstallOperationGuard();

    PublisherInstallOperationGuard(const PublisherInstallOperationGuard&) = delete;
    PublisherInstallOperationGuard& operator=(const PublisherInstallOperationGuard&) = delete;
    bool previous_owner_abandoned() const noexcept { return previous_owner_abandoned_; }
    void require_owned(const std::wstring& volume_guid_root, const std::string& install_id) const;

private:
    HANDLE mutex_ = nullptr;
    bool previous_owner_abandoned_ = false;
    DWORD owner_thread_ = 0;
    std::wstring name_;
};

} // namespace usk::platform::windows
#endif
#endif
