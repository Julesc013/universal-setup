// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_REGISTERED_CLIENT_INTERNAL_H
#define USK_PUBLISHER_REGISTERED_CLIENT_INTERNAL_H
#if defined(_WIN32)
#include "usk_publisher_request_channel.h"
namespace usk::platform::windows {
// Only the administrator-owned service-admitted registration is eligible.
// There is no privileged legacy/controller fallback. Dispatch uncertainty from
// the authenticated pipe remains with the caller, including allocation failure.
std::string submit_service_admitted_publisher_request(const std::wstring& service_name,
    const std::string& request, const PublisherRequestOptions& options = {});
}
#endif
#endif
