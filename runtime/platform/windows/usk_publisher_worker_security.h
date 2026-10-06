// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_WORKER_SECURITY_H
#define USK_PUBLISHER_WORKER_SECURITY_H
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "usk_json.h"
#include "usk_publisher_token_observation.h"

namespace usk::platform::windows {
// Reads only this process's primary token and its observed thread population.
// Handles are non-inheritable, retained during readback, and never exported.
// This is a bracketed observation, not an atomic population or handle census.
usk::json::Value observe_current_publisher_worker_security();
// The SCM/process/primary-token context must already have been validated.
void require_publisher_worker_security(const usk::json::Value& value,
    const PublisherServiceObservation& service);
// Read-only startup ordering, before freezing a creation baseline or starting
// durable operation effects. Every observation must pass the complete native
// policy; no expected thread count, thread control or post-effect refresh.
// Refuses cancellation, observation failure or an8s unsettled deadline.
usk::json::Value observe_settled_publisher_worker_security(
    const PublisherServiceObservation& service, HANDLE cancel_event = nullptr);
} // namespace usk::platform::windows
#endif
#endif
