// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#if defined(_WIN32)
#include "usk_publisher_service_absence_internal.h"
#include <algorithm>
#include <stdexcept>

namespace usk::platform::windows::detail {
namespace {
PublisherServiceOpenError observe_absence(SC_HANDLE manager, const std::wstring& name, const char* phase) {
    const auto probe = OpenServiceW(manager, name.c_str(), SERVICE_QUERY_CONFIG);
    if (probe) {
        // GetLastError is unspecified after success. Close this exact query
        // handle before reporting presence; it supplies no absence or authority.
        if (!CloseServiceHandle(probe)) {
            const auto error = GetLastError();
            throw std::runtime_error(std::string(phase) +
                ": presence probe close is unconfirmed; Win32 " + std::to_string(error));
        }
        return std::nullopt;
    }
    return GetLastError();
}

} // namespace

void require_publisher_service_absence(SC_HANDLE manager, const std::wstring& name) {
    constexpr auto phase = "owned retirement strict SCM revalidation";
    const auto error = observe_absence(manager, name, phase);
    if (!error) throw std::runtime_error(std::string(phase) + ": service is present");
    if (*error != ERROR_SERVICE_DOES_NOT_EXIST)
        refuse_publisher_service_absence(phase, error, PublisherServiceAbsenceObservation{
            1, *error == ERROR_SERVICE_MARKED_FOR_DELETE ? 1u : 0u});
}

PublisherServiceAbsenceObservation wait_for_deleted_publisher_service_absence(
        SC_HANDLE manager, const std::wstring& name) {
    constexpr auto phase = "owned retirement post-delete-and-close SCM completion";
    return wait_for_deleted_publisher_service_absence_observed(
        [&] { return observe_absence(manager, name, phase); },
        [] { return GetTickCount64(); },
        [](ULONGLONG duration) { Sleep(static_cast<DWORD>(duration)); });
}
} // namespace usk::platform::windows::detail
#endif
