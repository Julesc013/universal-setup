// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_TOKEN_OBSERVATION_H
#define USK_PUBLISHER_TOKEN_OBSERVATION_H

#if defined(_WIN32)
#include <cstdint>
#include <string>
#include <vector>

namespace usk::platform::windows {

struct ObservedTokenGroup {
    std::string sid;
    std::uint32_t attributes;
};

struct PublisherTokenObservation {
    std::string process_user_sid;
    std::vector<ObservedTokenGroup> process_groups;
    std::vector<ObservedTokenGroup> process_restricted_sids;
    bool current_thread_impersonating;
};

struct PublisherServiceObservation {
    std::wstring service_name;
    std::string service_sid;
    std::uint32_t service_sid_type;
    std::uint32_t service_type;
    std::uint32_t service_state;
    std::uint32_t process_id;
    PublisherTokenObservation token;
};

// Read-only current-token facts. The process token is observed separately
// from the current thread's impersonation state. These facts alone do not
// prove SCM service configuration, handle provenance, or profile eligibility.
PublisherTokenObservation observe_current_publisher_token();

// A necessary token predicate only; it does not admit a publisher profile.
bool has_restricted_publisher_token_facts(
    const PublisherTokenObservation& observation, const std::string& service_sid);

// Read-only SCM and process-token corroboration for a named, running,
// own-process restricted service. It refuses a CLI process or an absent
// service. Configuration can change later; this does not establish handle
// provenance, protected filesystem rights, or production eligibility.
PublisherServiceObservation observe_current_restricted_publisher_service(
    const std::wstring& service_name);

} // namespace usk::platform::windows
#endif

#endif
