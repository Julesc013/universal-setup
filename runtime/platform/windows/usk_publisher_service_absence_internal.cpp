// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#if defined(_WIN32)
#include "usk_publisher_service_absence_internal.h"
#include <algorithm>
#include <stdexcept>

namespace usk::platform::windows::detail {
namespace {
DWORD observe_absence(SC_HANDLE manager, const std::wstring& name, const char* phase) {
    const auto probe = OpenServiceW(manager, name.c_str(), SERVICE_QUERY_CONFIG);
    if (probe) {
        // GetLastError is unspecified after success. Presence is a refusal,
        // including a newly created service with the old name.
        if (!CloseServiceHandle(probe)) {
            const auto error = GetLastError();
            throw std::runtime_error(std::string(phase) +
                ": presence probe close is unconfirmed; Win32 " + std::to_string(error));
        }
        throw std::runtime_error(std::string(phase) + ": service is present");
    }
    return GetLastError();
}

[[noreturn]] void refuse(const char* phase, DWORD error,
        const PublisherServiceAbsenceObservation& observation) {
    throw std::runtime_error(std::string(phase) + ": SCM absence is unconfirmed; Win32 " +
        std::to_string(error) + "; probes " + std::to_string(observation.probes) +
        "; pending-deletion observations " + std::to_string(observation.pending_deletion_observations));
}
} // namespace

void require_publisher_service_absence(SC_HANDLE manager, const std::wstring& name) {
    constexpr auto phase = "owned retirement strict SCM revalidation";
    const auto error = observe_absence(manager, name, phase);
    if (error != ERROR_SERVICE_DOES_NOT_EXIST)
        refuse(phase, error, PublisherServiceAbsenceObservation{
            1, error == ERROR_SERVICE_MARKED_FOR_DELETE ? 1u : 0u});
}

PublisherServiceAbsenceObservation wait_for_deleted_publisher_service_absence(
        SC_HANDLE manager, const std::wstring& name) {
    constexpr auto phase = "owned retirement post-delete-and-close SCM completion";
    constexpr unsigned max_probes = 81;
    constexpr ULONGLONG retry_window_ms = 2000;
    constexpr ULONGLONG sleep_ms = 25;
    const auto started = GetTickCount64();
    PublisherServiceAbsenceObservation observation;
    for (;;) {
        ++observation.probes;
        const auto error = observe_absence(manager, name, phase);
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) return observation;
        if (error != ERROR_SERVICE_MARKED_FOR_DELETE) refuse(phase, error, observation);
        ++observation.pending_deletion_observations;
        const auto elapsed = GetTickCount64() - started;
        if (observation.probes == max_probes || elapsed >= retry_window_ms)
            refuse(phase, error, observation);
        Sleep(static_cast<DWORD>((std::min)(sleep_ms, retry_window_ms - elapsed)));
        if (GetTickCount64() - started >= retry_window_ms) refuse(phase, error, observation);
    }
}
} // namespace usk::platform::windows::detail
#endif
