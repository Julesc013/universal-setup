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
} // namespace usk::platform::windows
#endif
#endif
