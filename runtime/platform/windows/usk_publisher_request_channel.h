// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_REQUEST_CHANNEL_H
#define USK_PUBLISHER_REQUEST_CHANNEL_H
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "usk_json.h"
#include <memory>
#include <string>
#include <stdexcept>
namespace usk::platform::windows {
struct PublisherRequestOptions {
    // Borrowed manual-reset event. Cancellation before the first write is a
    // known non-dispatch; after a write is attempted the outcome stays unknown.
    HANDLE cancel_event = nullptr;
    // Zero is fail-fast on an occupied endpoint. Optional waiting is bounded
    // to 30 seconds and never transfers publication or installation ownership.
    DWORD conflict_wait_milliseconds = 0;
};
inline constexpr DWORD publisher_request_max_conflict_wait_milliseconds = 30000;
class PublisherRequestOutcomeUnknown final : public std::runtime_error {
public:
    explicit PublisherRequestOutcomeUnknown(const std::string& reason) :
        std::runtime_error("publisher response unavailable; outcome unknown: " + reason) {}
};
// Private transport only. This grants no filesystem or publisher authority.
// The service supplies the admitted caller SID; message fields cannot choose it.
class PublisherRequestChannel final {
public:
    PublisherRequestChannel(const std::wstring& service_name,
        const std::wstring& service_sid, const std::wstring& caller_sid,
        HANDLE stop_event, DWORD timeout_ms = 30000);
    ~PublisherRequestChannel();
    PublisherRequestChannel(const PublisherRequestChannel&) = delete;
    PublisherRequestChannel& operator=(const PublisherRequestChannel&) = delete;
    std::string receive();
    // Immutable canonical bytes actually received on this channel, available
    // only while its original authenticated token is unchanged and unreplied.
    // A caller cannot replace this binding with supplied request text.
    std::string authenticated_canonical_request() const;
    // Actual authenticated identification token and current held file-object
    // descriptor only. This is read-only evidence, not publication admission.
    // The token stays private to this one-request channel and is never exported.
    usk::json::Value observe_authenticated_object_access(HANDLE object) const;
    void reply(const std::string& response);
    // One-request service: after the terminal reply, retain the pipe until
    // the client closes it or the bounded wait ends. No second request runs.
    void wait_for_client_disconnect() noexcept;
private:
    struct State;
    std::unique_ptr<State> state_;
};
// Verifies the held pipe's server against the live own-process restricted SCM
// service before sending bytes. The caller never impersonates as the service.
std::string submit_publisher_request(const std::wstring& service_name,
    const std::string& request, DWORD timeout_ms = 30000,
    const std::wstring& expected_process_image = {},
    const PublisherRequestOptions& options = {});
// Internal connection stage only; sends no bytes and grants no authority.
// Caller owns the returned handle and must independently authenticate SCM,
// held process/image and pipe server before writing any effect request.
HANDLE connect_publisher_request_endpoint(const std::wstring& service_name,
    DWORD timeout_ms, const PublisherRequestOptions& options = {});
std::string publisher_request_inspection_reference(const std::wstring& service_name);
// A terminal success must identify the submitted install or verification.
// Service observations bind their separate envelope to the request nonce and,
// when supplied, the independently held pipe-server/SCM process identity.
// Failure and recovery-required replies may omit install IDs, but must retain
// their exact response schema and status. A mismatch after dispatch is unknown.
void require_publisher_response_binding(const std::wstring& service_name,
    const std::string& request, const std::string& response,
    DWORD expected_process_id = 0);
std::wstring publisher_request_pipe_name(const std::wstring& service_name);
// Current restricted SYSTEM service only: grant the admitted consumer enough
// process rights to hold/query our identity, preserving every existing ACE.
void admit_current_publisher_client_observer(const std::wstring& service_name,
    const std::wstring& consumer_sid);
}
#endif
#endif
