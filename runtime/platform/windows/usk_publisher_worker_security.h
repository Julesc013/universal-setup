// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_WORKER_SECURITY_H
#define USK_PUBLISHER_WORKER_SECURITY_H
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <functional>
#include <memory>
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
// Read-only lifetime proof, established before this owner's maintenance effects.
// The supplied baseline must equal actual native observations around pinning
// all original query-only thread handles. It grants no effect authority.
// Only signaled retirement of an original non-execution thread is allowed;
// every surviving fact and non-thread field stays frozen. The original JSON
// is never refreshed, and creation/execution observation equality is unchanged.
// Continuity readback uses only already-pinned originals. At most four samples
// account for positively proven non-execution retirement; unavailable reads,
// added threads and changed security refuse without retry. This remains a
// bracketed observation, not an atomic population or continuous census.
class PublisherWorkerSecurityContinuity;
namespace detail {
// Private deterministic ordinary-thread control seam. The production owner
// supplies no callback; this neither constructs authority nor changes facts.
usk::json::Value observe_publisher_worker_continuity_for_test(
    const PublisherWorkerSecurityContinuity& continuity,
    const std::function<void(const char*)>& checkpoint);
}
class PublisherWorkerSecurityContinuity {
public:
    explicit PublisherWorkerSecurityContinuity(const usk::json::Value& baseline);
    ~PublisherWorkerSecurityContinuity();
    PublisherWorkerSecurityContinuity(const PublisherWorkerSecurityContinuity&) = delete;
    PublisherWorkerSecurityContinuity& operator=(const PublisherWorkerSecurityContinuity&) = delete;
    usk::json::Value observe_current() const;
private:
    friend usk::json::Value detail::observe_publisher_worker_continuity_for_test(
        const PublisherWorkerSecurityContinuity&, const std::function<void(const char*)>&);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace usk::platform::windows
#endif
#endif
