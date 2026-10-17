// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_REQUEST_CHANNEL_H
#define USK_PUBLISHER_REQUEST_CHANNEL_H
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <array>
#include <cstddef>
#include <vector>
#include <exception>
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
// Message construction/copy must not allocate: this exception can be thrown
// while handling allocation failure after the first possible request write.
// A lost diagnostic suffix never changes the outcome or authorizes a retry.
class PublisherRequestOutcomeUnknown final : public std::exception {
public:
    explicit PublisherRequestOutcomeUnknown(const char* reason) noexcept {
        append("publisher response unavailable; outcome unknown: ");
        append(reason);
    }
    explicit PublisherRequestOutcomeUnknown(const std::string& reason) noexcept :
        PublisherRequestOutcomeUnknown(reason.c_str()) {}
    PublisherRequestOutcomeUnknown(const char* context, const char* reason) noexcept :
        PublisherRequestOutcomeUnknown(context) { append(reason); }
    PublisherRequestOutcomeUnknown(const char* context, DWORD error) noexcept :
        PublisherRequestOutcomeUnknown(context) {
        // DWORD's complete decimal range fits in ten digits plus the terminator.
        char digits[11]{};
        auto* cursor = digits + sizeof(digits) - 1u;
        do {
            *--cursor = static_cast<char>('0' + error % 10u);
            error /= 10u;
        } while (error != 0);
        append(cursor);
    }
    const char* what() const noexcept override { return message_.data(); }
private:
    std::array<char, 512> message_{};
    void append(const char* text) noexcept {
        if (!text) return;
        std::size_t used = 0;
        while (message_[used]) ++used;
        while (*text && used + 1u < message_.size()) message_[used++] = *text++;
        if (*text) {
            message_[used - 3u] = '.';
            message_[used - 2u] = '.';
            message_[used - 1u] = '.';
        }
        message_[used] = '\0';
    }
};
namespace detail {
// One freshly returned token-information value, not a token or authority cache.
// TokenUser/Groups contain pointers into their own returned buffer. C++17
// prvalue construction and deleted moves keep that storage at a fixed address.
class PublisherClientTokenBytes final {
public:
    PublisherClientTokenBytes(HANDLE token, TOKEN_INFORMATION_CLASS kind);
    PublisherClientTokenBytes(const PublisherClientTokenBytes&) = delete;
    PublisherClientTokenBytes& operator=(const PublisherClientTokenBytes&) = delete;
    PublisherClientTokenBytes(PublisherClientTokenBytes&&) = delete;
    PublisherClientTokenBytes& operator=(PublisherClientTokenBytes&&) = delete;
    const unsigned char* data() const noexcept {
        return expanded_.empty() ? inline_bytes_.data() : expanded_.data();
    }
    std::size_t size() const noexcept { return size_; }
private:
    alignas(std::max_align_t) std::array<unsigned char, 1024> inline_bytes_{};
    std::vector<unsigned char> expanded_;
    DWORD size_ = 0;
};
}
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
