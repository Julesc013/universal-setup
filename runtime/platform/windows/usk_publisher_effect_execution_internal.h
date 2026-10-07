// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_EFFECT_EXECUTION_INTERNAL_H
#define USK_PUBLISHER_EFFECT_EXECUTION_INTERNAL_H
#if defined(_WIN32)
#include "usk_publisher_effect_broker_internal.h"
#include <memory>

namespace usk::platform::windows {
struct CandidatePublisherConfiguration;
std::string execute_candidate_restricted_publisher(
    const CandidatePublisherConfiguration&, bool& effects_may_exist);

// Distinct native identities. service is always the actual SCM owner; worker
// is the actual current effect process. They coincide only on the old service
// execution path. This read-only result cannot activate a child route.
struct PublisherNativeExecutionObservation {
    PublisherServiceObservation service;
    PublisherWorkerTokenContext worker;
};
PublisherNativeExecutionObservation observe_current_publisher_native_execution_owner(
    const std::wstring& service_name);

// Private actual-child observation owner. Only the original connected native
// peer can construct it. It owns fresh broker readback and the original pinned
// child-security lifetime; supplied JSON, callbacks and cached observations
// cannot install this route. The peer must outlive this owner on the original
// execution thread. This grants no operation, creator or filesystem authority:
// the engine must still admit the exact original request, target and operation.
// One construction attempt is permitted in this child process. A failed
// attempt, another thread, expired owner or completed owner refuses without
// an SCM fallback or a new pinned security baseline.
class PublisherEffectExecutionOwner final {
public:
    PublisherEffectExecutionOwner(PublisherEffectWorkerPeer&, const std::wstring& service_name);
    ~PublisherEffectExecutionOwner();
    PublisherEffectExecutionOwner(const PublisherEffectExecutionOwner&) = delete;
    PublisherEffectExecutionOwner& operator=(const PublisherEffectExecutionOwner&) = delete;
    PublisherEffectExecutionOwner(PublisherEffectExecutionOwner&&) = delete;
    PublisherEffectExecutionOwner& operator=(PublisherEffectExecutionOwner&&) = delete;
    PublisherNativeExecutionObservation observe_current();
    usk::json::Value service_admission();
    usk::json::Value selected_reviewed_operation();
    usk::json::Value authenticated_object_access(HANDLE original_child_handle);
    const std::string& canonical_request() const;
    // Borrowed concrete owners for the native v7/v4 observers. Their lifetime
    // remains this owner, on its original thread; no native handle is exported.
    PublisherEffectWorkerReadback& readback();
    PublisherEffectWorkerNativeSecurity& security();
private:
    friend PublisherNativeExecutionObservation observe_current_publisher_native_execution_owner(
        const std::wstring& service_name);
    friend std::string execute_candidate_restricted_publisher(
        const CandidatePublisherConfiguration&, bool& effects_may_exist);
    // Only the concrete engine may borrow the existing synchronize-only event
    // for its native waits. It cannot modify, duplicate or serialize the event.
    HANDLE cancellation_observer() const;
    // Before the engine publishes its own TLS or acquires effect resources,
    // join its configured origin to this exact original native route.
    static void require_engine_origin(const PublisherEffectExecutionOwner*,
        const std::wstring& service_name);
    struct State;
    struct Routing;
    static Routing& current_routing();
    static void require_available();
    void require_current() const;
    std::shared_ptr<State> state_;
};
}
#endif
#endif
