// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_EFFECT_EXECUTION_INTERNAL_H
#define USK_PUBLISHER_EFFECT_EXECUTION_INTERNAL_H
#if defined(_WIN32)
#include "usk_publisher_effect_broker_internal.h"
#include <memory>
#include <utility>

namespace usk::lifecycle::detail { class NativeMaintenanceContext; }
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
// Independently owned read-only results from one completed original-owner
// bracket. Only that native owner can produce them. These values export no
// handle, install no route and cannot authorize another fence or effect.
class PublisherEffectSecurityObservation final {
public:
    const usk::json::Value& broker() const { return broker_; }
    const usk::json::Value& native() const { return native_; }
private:
    friend class PublisherEffectExecutionOwner;
    PublisherEffectSecurityObservation(usk::json::Value broker, usk::json::Value native) :
        broker_(std::move(broker)), native_(std::move(native)) {}
    usk::json::Value broker_, native_;
};
// Producer-only completed selection, admission and local-security bracket.
// Read-only facts cannot survive as authorization for a subsequent fence.
class PublisherEffectSelectedSecurityObservation final {
public:
    const usk::json::Value& broker() const { return security_.broker(); }
    const usk::json::Value& native() const { return security_.native(); }
    const usk::json::Value& selection() const { return selection_; }
private:
    friend class PublisherEffectExecutionOwner;
    PublisherEffectSelectedSecurityObservation(PublisherEffectSecurityObservation security,
        usk::json::Value selection) : security_(std::move(security)), selection_(std::move(selection)) {}
    PublisherEffectSecurityObservation security_;
    usk::json::Value selection_;
};
// One completed read-only selection/security and ordered access bracket.
// Its producer is the original native owner; it cannot authorize a later fence.
class PublisherEffectSelectedAccessObservation final {
public:
    const PublisherEffectSelectedSecurityObservation& selected() const { return selected_; }
    usk::json::Value take_access() { return std::move(access_); }
private:
    friend class PublisherEffectExecutionOwner;
    PublisherEffectSelectedAccessObservation(PublisherEffectSelectedSecurityObservation selected,
        usk::json::Value access) : selected_(std::move(selected)), access_(std::move(access)) {}
    PublisherEffectSelectedSecurityObservation selected_;
    usk::json::Value access_;
};
PublisherNativeExecutionObservation observe_current_publisher_native_execution_owner(
    const std::wstring& service_name);
// Retained-data validation only. A closed child original-custody record must
// join its actual worker/birth/token to the original lease, request, caller
// and distinct SCM broker. Parsing this record cannot install a native route.
void require_publisher_effect_maintenance_original_record(const usk::json::Value&,
    const usk::json::Value& original_apply_request, const std::wstring& original_service_name);

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
    PublisherEffectSecurityObservation observe_security(const std::string& failure_context = {});
    PublisherEffectSelectedSecurityObservation observe_selected_security(PublisherEffectSelectionKind,
        const std::string& failure_context = {});
    usk::json::Value selected_reviewed_operation();
    usk::json::Value selected_original_maintenance_recovery();
    usk::json::Value selected_original_installation_recovery();
    usk::json::Value authenticated_object_access(HANDLE original_child_handle);
    // Ordered actual handles, including repeated objects. Whole-batch parent
    // and child native brackets are read-only evidence, never effect authority.
    usk::json::Value authenticated_object_access_batch(const std::vector<HANDLE>& original_child_handles);
    PublisherEffectSelectedAccessObservation observe_selected_security_and_access_batch(
        PublisherEffectSelectionKind, const std::vector<HANDLE>& original_child_handles,
        const std::string& failure_context = {});
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
    friend class usk::lifecycle::detail::NativeMaintenanceContext;
    friend class usk::lifecycle::detail::NativeMaintenanceRecordByteRead;
    friend class PublisherEffectWorkerReadback;
    void require_authority_record_selection(
        usk::lifecycle::detail::NativeMaintenanceRecordByteRead&,
        const usk::json::Value& profile, const usk::json::Value& selection,
        const usk::json::Value& native);
    void verify_original_maintenance_record_bytes(
        usk::lifecycle::detail::NativeMaintenanceRecordByteRead&);
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
