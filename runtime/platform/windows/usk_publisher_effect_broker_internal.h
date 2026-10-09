// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_EFFECT_BROKER_INTERNAL_H
#define USK_PUBLISHER_EFFECT_BROKER_INTERNAL_H
#if defined(_WIN32)
#include "usk_publisher_effect_worker_custody_internal.h"
#include "usk_publisher_handle_observation.h"
#include "usk_publisher_worker_security.h"
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace usk::platform::windows {
// Read-only transport bound. Each occurrence has its own native query and
// checked closure; the existing packet byte/value limits also remain in force.
inline constexpr std::size_t publisher_object_access_batch_limit = 8u;
// Closed selectors for read-only original selection. They do not select an
// operation, admit a worker, or grant recovery/effect authority.
enum class PublisherEffectSelectionKind {
    reviewed_operation, original_maintenance_recovery, original_installation_recovery
};
class RegisteredPublisherAdmission;
class PublisherRequestChannel;
class PublisherEffectBrokerReadback;
// Closed retained-record parsing only. These functions do not authenticate
// transport, corroborate live SCM, activate a scope or grant effect authority.
void require_publisher_effect_broker_readback_record(const usk::json::Value&);
usk::json::Value publisher_effect_broker_immutable_record(const usk::json::Value&);
// Both closed records are validated first. Prospective broker originals and
// retirement facts must accumulate without loss, revival or security changes.
void require_publisher_effect_broker_readback_continuity(const usk::json::Value& earlier,
    const usk::json::Value& later);
PublisherWorkerTokenContext publisher_effect_worker_record_context(const usk::json::Value&);
PublisherServiceObservation publisher_effect_broker_service_record(const usk::json::Value&);
void require_publisher_effect_original_maintenance_selection(const usk::json::Value& selection,
    const usk::json::Value& minimal_request, const usk::json::Value& broker_record);
void require_publisher_effect_original_installation_selection(const usk::json::Value& selection,
    const usk::json::Value& minimal_request, const usk::json::Value& broker_record);
// Closed v5 retained-data validation of the selected operation against BOTH
// actual broker endpoints. Parsing cannot create an execution route or proof.
void require_publisher_effect_selection_readback(const usk::json::Value& reply,
    const usk::json::Value& actual_request);
// Closed v6 retained-data validation; all ordered occurrences and selection
// join both actual endpoints. Parsing supplies no native owner or authority.
void require_publisher_effect_selected_object_access_batch_readback(const usk::json::Value& reply,
    const usk::json::Value& actual_request, const usk::json::Value& expected_native_objects);
// Closed data validation only. A marker is not completed proof, a result,
// selection, native custody, worker admission or permission for an effect.
void require_publisher_effect_queries_closed_marker(const usk::json::Value& marker,
    const std::string& kind, const usk::json::Value& expected_native_objects);
void require_publisher_effect_terminal_record(const usk::json::Value&, const usk::json::Value& broker_record);
// Bounded original-peer error data, never a terminal or definite preflight
// result. It cannot narrow retained effects or grant an execution scope.
void require_publisher_effect_failure_diagnostic(const usk::json::Value&);
class PublisherBrokerQueryClosureUnknown final : public std::runtime_error {
public:
    PublisherBrokerQueryClosureUnknown(DWORD error, std::exception_ptr primary);
    DWORD close_error() const noexcept { return error_; }
    const std::exception_ptr& primary_failure() const noexcept { return primary_; }
private:
    DWORD error_;
    std::exception_ptr primary_;
};

// Read-only native object observer. The ID is only a query selector under the
// held NTFS root, never a path, creation certificate or operation authority.
// No effect/creator handle is duplicated, inherited or returned. An actual
// query-rights-only reopen must match the complete requested native facts.
// Close is one checked attempt. Unknown closure retains one bounded owner and
// permanently refuses another query in this process, including constructor
// failure; a successful broker reply must follow confirmed closure.
class PublisherBrokerObjectQuery final {
public:
    PublisherBrokerObjectQuery(HANDLE original_volume_root,
        const usk::json::Value& expected_native_object);
    ~PublisherBrokerObjectQuery();
    PublisherBrokerObjectQuery(const PublisherBrokerObjectQuery&) = delete;
    PublisherBrokerObjectQuery& operator=(const PublisherBrokerObjectQuery&) = delete;
    usk::json::Value observation() const;
    DWORD granted_access() const;
    bool close() noexcept;
private:
    friend class PublisherEffectBrokerReadback;
    usk::json::Value authenticated_access(const PublisherRequestChannel&) const;
    struct State;
    std::unique_ptr<State> state_;
};

// Finite protected-original lookup. IDs and operation come only from the
// actual authenticated minimal request; no caller-supplied path/apply/record
// can select an intent. Owns four read-only native observers under the original
// query-only volume. No install mutex, pending record, lease or effect exists
// here. Checked closure shares the broker's one-query/retained-unknown gate.
class PublisherOriginalRecoveryIntentQuery final {
public:
    PublisherOriginalRecoveryIntentQuery(const RegisteredPublisherAdmission&,
        const PublisherRequestChannel&, HANDLE original_volume_root);
    ~PublisherOriginalRecoveryIntentQuery();
    PublisherOriginalRecoveryIntentQuery(const PublisherOriginalRecoveryIntentQuery&) = delete;
    PublisherOriginalRecoveryIntentQuery& operator=(const PublisherOriginalRecoveryIntentQuery&) = delete;
    usk::json::Value observation() const;
    bool close() noexcept;
    DWORD close_error() const noexcept;
private:
    struct State;
    std::unique_ptr<State> state_;
};

// Parent-side finite READ-ONLY mediation. Original admission, channel, volume
// and custody are borrowed from the concrete SCM owner and must outlive this
// instance on their original execution thread. The channel supplies its real
// received request; supplied text/JSON cannot replace that binding. Fresh SCM,
// registration, actual peer token/image/job and target/caller facts bracket
// each reply. There is no dispatch, mutation, arbitrary path, token export,
// selected-plan setter or effect-admission API here.
class PublisherEffectBrokerReadback final {
public:
    PublisherEffectBrokerReadback(const RegisteredPublisherAdmission&,
        const PublisherRequestChannel&, HANDLE original_volume_root,
        PublisherEffectWorkerCustody&);
    ~PublisherEffectBrokerReadback();
    PublisherEffectBrokerReadback(const PublisherEffectBrokerReadback&) = delete;
    PublisherEffectBrokerReadback& operator=(const PublisherEffectBrokerReadback&) = delete;
    void respond_to_one_readback(DWORD timeout_ms = 120000);
    // Receives one actual private packet. Readbacks are answered here; a
    // terminal is returned only after live original native custody fences.
    // The caller must confirm custody shutdown before public delivery.
    std::optional<usk::json::Value> respond_to_one_packet(DWORD timeout_ms = 120000);
private:
    struct State;
    std::unique_ptr<State> state_;
};

// Child-side readback client. It fences its own held object before/after the
// broker's independent reopen and validates fresh actual parent/child tokens
// and custody locally. These observations do NOT install an execution scope,
// select a reviewed operation or establish child-thread/creator provenance.
class PublisherEffectWorkerReadback final {
public:
    explicit PublisherEffectWorkerReadback(PublisherEffectWorkerPeer&);
    ~PublisherEffectWorkerReadback();
    PublisherEffectWorkerReadback(const PublisherEffectWorkerReadback&) = delete;
    PublisherEffectWorkerReadback& operator=(const PublisherEffectWorkerReadback&) = delete;
    usk::json::Value service_admission(DWORD timeout_ms = 120000);
    // Separate actual local effect PID/token; the original SCM PID is never
    // rewritten into this context. The result remains a read-only binding.
    PublisherWorkerTokenContext worker_token_context(DWORD timeout_ms = 120000);
    // Read only the parent's original native-held exact-request selection.
    // Absence is explicit; this cannot select a request or authorize replay.
    usk::json::Value selected_reviewed_operation(DWORD timeout_ms = 120000);
    // A separate finite original-intent/enrollment relation for the actual
    // minimal maintenance recovery request. Never relaxes fresh selection.
    usk::json::Value selected_original_maintenance_recovery(DWORD timeout_ms = 120000);
    usk::json::Value selected_original_installation_recovery(DWORD timeout_ms = 120000);
    usk::json::Value authenticated_object_access(HANDLE, DWORD timeout_ms = 120000);
private:
    friend class PublisherEffectWorkerNativeSecurity;
    friend class PublisherEffectExecutionOwner;
    // One closed read-only exchange returns the parent's actual native brackets
    // of this query. Only the original execution owner may use this alongside
    // its original child's complete local security observations.
    struct ObjectAccessObservation {
        usk::json::Value before;
        usk::json::Value after;
        usk::json::Value access;
    };
    ObjectAccessObservation authenticated_object_access_bracket(HANDLE, DWORD timeout = 120000);
    ObjectAccessObservation authenticated_object_access_batch_bracket(const std::vector<HANDLE>&,
        DWORD timeout = 120000, const std::function<void()>& after_queries_closed = {});
    struct AdmissionObservation {
        usk::json::Value before;
        usk::json::Value after;
    };
    AdmissionObservation service_admission_bracket(DWORD timeout = 120000);
    struct SelectionObservation {
        usk::json::Value before;
        usk::json::Value after;
        usk::json::Value selection;
    };
    SelectionObservation selected_operation_bracket(PublisherEffectSelectionKind,
        DWORD timeout = 120000);
    struct SelectedObjectAccessObservation {
        SelectionObservation selected;
        usk::json::Value access;
    };
    SelectedObjectAccessObservation selected_object_access_batch_bracket(PublisherEffectSelectionKind,
        const std::vector<HANDLE>&, DWORD timeout = 120000,
        const std::function<void()>& after_queries_closed = {});
    // Only actual completed observations from the original execution owner
    // reach this private retention step, after all of its native joins.
    // Sticky refusal also covers a later execution-owner join/deadline
    // failure, including an already-borrowed public readback reference.
    void poison() noexcept;
    void retain_readback_bracket(const usk::json::Value& before, const usk::json::Value& after);
    void retain_selection_bracket(const SelectionObservation&, PublisherEffectSelectionKind);
    // Both facts originate from the SAME actual validated wire read. This is
    // private to the original native security owner, never a JSON input API.
    struct CurrentWorkerObservation {
        usk::json::Value broker;
        PublisherWorkerTokenContext worker;
    };
    CurrentWorkerObservation observe_current_worker(DWORD timeout = 120000);
    usk::json::Value settled_worker_security(const PublisherWorkerTokenContext&);
    struct State;
    std::unique_ptr<State> state_;
};
// Read-only native child-security owner established before effects. It keeps
// the child's actual token/process boundary and original query-only threads
// pinned; the broker retains its separate SCM identity. New/changed/unknown
// threads refuse under the unchanged continuity policy, with no refresh.
// The borrowed readback must outlive this owner on its original execution
// thread. This installs no execution scope and grants no effect authority.
class PublisherEffectWorkerNativeSecurity final {
public:
    explicit PublisherEffectWorkerNativeSecurity(PublisherEffectWorkerReadback&);
    ~PublisherEffectWorkerNativeSecurity();
    PublisherEffectWorkerNativeSecurity(const PublisherEffectWorkerNativeSecurity&) = delete;
    PublisherEffectWorkerNativeSecurity& operator=(const PublisherEffectWorkerNativeSecurity&) = delete;
    // Bounded diagnostics are forwarded to the original continuity owner;
    // they cannot admit threads or replace its frozen native baseline.
    usk::json::Value observe_current(const std::string& failure_context = {});
private:
    friend class PublisherEffectExecutionOwner;
    // Obtained only from this owner's original readback, with every actual
    // local token/process/thread check between the two wire observations.
    // The execution owner reuses this completed bracket; it cannot supply
    // profiles, refresh provenance, activate a scope or gain effect rights.
    struct BrokeredObservation {
        usk::json::Value before;
        usk::json::Value after;
        usk::json::Value native;
    };
    BrokeredObservation observe_brokered(const std::string& failure_context = {});
    // Complete actual local checks from the same pinned native owner. No wire
    // profile, caller context or replacement baseline is accepted here.
    usk::json::Value observe_local_current(const std::string& failure_context = {});
    struct State;
    std::unique_ptr<State> state_;
};
}
#endif
#endif
