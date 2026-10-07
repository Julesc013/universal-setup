// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_EFFECT_BROKER_INTERNAL_H
#define USK_PUBLISHER_EFFECT_BROKER_INTERNAL_H
#if defined(_WIN32)
#include "usk_publisher_effect_worker_custody_internal.h"
#include "usk_publisher_handle_observation.h"
#include <memory>

namespace usk::platform::windows {
class RegisteredPublisherAdmission;
class PublisherRequestChannel;
class PublisherEffectBrokerReadback;
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
    usk::json::Value authenticated_object_access(HANDLE, DWORD timeout_ms = 120000);
private:
    struct State;
    std::unique_ptr<State> state_;
};
}
#endif
#endif
