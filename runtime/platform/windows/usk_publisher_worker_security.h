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
#include <string>
#include "usk_json.h"
#include "usk_publisher_token_observation.h"

namespace usk::platform::windows {
// The actual effect process and its primary token are a distinct context
// from the original SCM broker. This read-only policy binding supplies no
// service status, effect admission, frozen-thread or creator provenance.
struct PublisherWorkerTokenContext {
    std::uint32_t process_id;
    std::string service_sid;
    PublisherTokenObservation token;
};
// Reads only this process's primary token and its observed thread population.
// Handles are non-inheritable, retained during readback, and never exported.
// This is a bracketed observation, not an atomic population or handle census.
usk::json::Value observe_current_publisher_worker_security();
// The read-only SCM broker permits a changing current population, separately
// from the child's immutable original-held continuity. Acquire native thread
// objects before reading their facts, bracket acquisition with independent
// complete independent censuses, and require complete coverage before admission.
// The FIRST acquisition retains native objects before its first independent
// census; every acquired ID must survive that census and every census ID stays
// mandatory. It does not claim an earlier pre-handle snapshot. Subsequent walks
// retain prior mandatory AFTER subset BEFORE subset native subset AFTER.
// Census-only additions require another existing full-policy read round,
// retaining all first handles/facts within the same four-round bound,
// and bind the same full v1 policy to the actual restricted service. Retirement
// during sampling still refuses; no original baseline is installed/refreshed.
// Optional first-probe/missing-original lifetime diagnostics grant no authority.
// A signaled first probe means ended by that sample, not before native return;
// it cannot exempt an acquired ID from the first or subsequent census gates.
usk::json::Value observe_current_publisher_broker_worker_security(const PublisherServiceObservation& service);
// Distinct prospective SCM observer. It transfers the SAME original native
// handles from a completed service-bound policy read, before the first reply.
// Later additions remain pending until the whole read passes. Only completely
// admitted, continuously held non-execution objects can positively retire.
// No JSON/reopened-ID baseline, eviction, child continuity or effect authority.
class PublisherBrokerWorkerSecurity final {
public:
    explicit PublisherBrokerWorkerSecurity(const PublisherServiceObservation&);
    ~PublisherBrokerWorkerSecurity();
    PublisherBrokerWorkerSecurity(const PublisherBrokerWorkerSecurity&) = delete;
    PublisherBrokerWorkerSecurity& operator=(const PublisherBrokerWorkerSecurity&) = delete;
    usk::json::Value observe_current(const PublisherServiceObservation&);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
// Closed data checks only; they cannot establish native lifetime custody.
void require_publisher_broker_worker_security(const usk::json::Value&, const PublisherWorkerTokenContext&);
void require_publisher_broker_worker_security_continuity(const usk::json::Value& earlier,
    const usk::json::Value& later);
// The SCM/process/primary-token context must already have been validated.
void require_publisher_worker_security(const usk::json::Value& value,
    const PublisherServiceObservation& service);
// Use this distinct binding for a child only after the genuine broker/child
// relationship and the child's actual primary token have been established.
// The complete stored token/default/process-thread policy stays identical.
void require_publisher_worker_security(const usk::json::Value& value,
    const PublisherWorkerTokenContext& worker);
// Both records must already pass their bound native policy. Version1 retains
// complete equality. Version2 additionally requires the same frozen original
// baseline and monotonic, immutable positive retirement evidence.
void require_publisher_worker_security_continuity(const usk::json::Value& earlier,
    const usk::json::Value& later);
// Read-only startup ordering, before freezing a creation baseline or starting
// durable operation effects. Every observation must pass the complete native
// policy; no expected thread count, thread control or post-effect refresh.
// Refuses cancellation, observation failure or an8s unsettled deadline.
usk::json::Value observe_settled_publisher_worker_security(
    const PublisherServiceObservation& service, HANDLE cancel_event = nullptr);
usk::json::Value observe_settled_publisher_worker_security(
    const PublisherWorkerTokenContext& worker, HANDLE cancel_event = nullptr);
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
// Actual ordinary owned-thread controls; no service/effect authorization.
struct BrokerWorkerSecurityTestOwner;
std::shared_ptr<BrokerWorkerSecurityTestOwner> pin_broker_worker_security_for_test();
usk::json::Value observe_broker_worker_security_for_test(BrokerWorkerSecurityTestOwner&,
    const std::function<void(const char*)>& checkpoint);
// Numerical census control with actual held objects; never native census proof.
void require_broker_retired_census_binding_for_test(BrokerWorkerSecurityTestOwner&,
    DWORD census_id, HANDLE observed_object = nullptr);
// Ordinary owned-thread controls only; this reads facts and grants no authority.
usk::json::Value observe_publisher_broker_worker_security_for_test(
    const std::function<void(const char*)>& checkpoint);
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
    // Optional bounded failure context supplies diagnostics only. It cannot
    // change the native baseline, observations or refusal predicates.
    usk::json::Value observe_current(const std::string& failure_context = {}) const;
    // Version2 reports the actual live partition and original-held native exit
    // facts separately from the immutable baseline. Omission proves nothing.
    // It grants no effect authority and does not alter the version1 API.
    usk::json::Value observe_current_with_retirement(const std::string& failure_context = {}) const;
private:
    friend usk::json::Value detail::observe_publisher_worker_continuity_for_test(
        const PublisherWorkerSecurityContinuity&, const std::function<void(const char*)>&);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace usk::platform::windows
#endif
#endif
