// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_SERVICE_ACCESS_H
#define USK_PUBLISHER_SERVICE_ACCESS_H
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "usk_json.h"
#include <string>
namespace usk::platform::windows {
// Stored SCM owner/DACL observation. The held service handle and separately
// validated configuration bind the object; this does not prove handle history.
usk::json::Value observe_publisher_service_access(SC_HANDLE service,
    const std::string& authorized_client_sid);
void require_publisher_service_access(const usk::json::Value& value,
    const std::string& authorized_client_sid);
// Administrative registration only. Preserve existing owner/ACEs and add
// start/config-query/status-query/security-query for exactly the bound client.
// Read back the complete expected policy; an uncertain update is not success.
void grant_publisher_service_client_start(SC_HANDLE service,
    const std::string& authorized_client_sid);
}
#endif
#endif
