// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_REQUEST_CHANNEL_H
#define USK_PUBLISHER_REQUEST_CHANNEL_H
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <memory>
#include <string>
#include <stdexcept>
namespace usk::platform::windows {
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
    const std::string& request, DWORD timeout_ms = 30000);
std::wstring publisher_request_pipe_name(const std::wstring& service_name);
// Current restricted SYSTEM service only: grant the admitted consumer enough
// process rights to hold/query our identity, preserving every existing ACE.
void admit_current_publisher_client_observer(const std::wstring& service_name,
    const std::wstring& consumer_sid);
}
#endif
#endif
