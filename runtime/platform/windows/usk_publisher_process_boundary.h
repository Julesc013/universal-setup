// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_PROCESS_BOUNDARY_H
#define USK_PUBLISHER_PROCESS_BOUNDARY_H

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "usk_json.h"
#include "usk_publisher_token_observation.h"
#include <cstdint>
#include <string>
#include <vector>

namespace usk::platform::windows {
// Read-only stored owner/DACL facts for this process. This does not admit the
// process as a publisher or describe capabilities already outside it.
usk::json::Value observe_current_publisher_process_boundary();

// The caller supplies independently validated SCM/process-token bindings.
// Owners capable of rewriting the process DACL must be excluded privileged
// principals or the publisher's own service/logon identity. Other allow ACEs
// may grant process/security identity queries only.
void require_publisher_process_boundary(const usk::json::Value& value,
    std::uint32_t process_id, const std::string& service_sid,
    const std::vector<ObservedTokenGroup>& process_groups);
} // namespace usk::platform::windows
#endif
#endif
