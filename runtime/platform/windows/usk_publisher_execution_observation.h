// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_EXECUTION_OBSERVATION_H
#define USK_PUBLISHER_EXECUTION_OBSERVATION_H

#if defined(_WIN32)
#include "usk_json.h"
#include "usk_publisher_token_observation.h"
#include <windows.h>
#include <string>
#include <vector>

namespace usk::platform::windows {
class PublisherRequestChannel;
struct PublisherPhaseHandle {
    std::string role;
    HANDLE handle;
    std::string expected_file_id;
};

// Read-only runtime/compiled SDK facts, also usable by ordinary test processes.
// An observation is not admission of that process as a service.
usk::json::Value observe_publisher_execution_platform();
void require_publisher_execution_platform(const usk::json::Value& value);

// Fresh SCM/process-token, runtime platform, actual held-handle and process
// owner/DACL facts. Token/thread security, object creation history and already
// exported capabilities are separate predicates, not inferred here.
usk::json::Value observe_publisher_execution_phase(
    const std::wstring& service_name, const std::string& phase,
    const std::vector<PublisherPhaseHandle>& handles,
    const PublisherRequestChannel* authenticated_request = nullptr);

// Closed retained evidence, bound to the shared client and stored object facts.
// Descriptor bytes are the GetSecurityInfo representation, not an assertion
// that its control flags equal GetKernelObjectSecurity protection flags.
void require_publisher_authenticated_object_access(const usk::json::Value& access,
    const usk::json::Value& client, const usk::json::Value& object);

// Closed retained evidence validation. The supplied bindings come from the
// independently validated native anchor/tree record, never from this object.
// A restart may have a new process/token identity; stable service and object
// bindings remain mandatory. Within one worker require phase identity match.
void require_publisher_execution_phase(
    const usk::json::Value& value, const std::wstring& service_name,
    const std::string& service_sid, const std::string& phase,
    const std::vector<std::pair<std::string, std::string>>& object_bindings);

void require_publisher_execution_worker_match(
    const usk::json::Value& earlier, const usk::json::Value& later);

// Both phases must already be independently validated. A retained prepared
// and visible record from the same observed process/primary-token identity
// must retain the complete worker binding; restart identities are separate.
void require_publisher_execution_record_continuity(
    const usk::json::Value& earlier, const usk::json::Value& later);
} // namespace usk::platform::windows
#endif
#endif
