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

struct PublisherTokenIdentity {
    std::uint64_t token_id = 0;
    std::uint64_t authentication_id = 0;
    std::uint64_t modified_id = 0;
    std::uint32_t token_type = 0;
};

struct PublisherTokenObservation {
    std::string process_user_sid;
    std::vector<ObservedTokenGroup> process_groups;
    std::vector<ObservedTokenGroup> process_restricted_sids;
    bool current_thread_impersonating;
    PublisherTokenIdentity identity{};
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

// Documented Windows name mapping for the bounded ASCII service names used
// by this profile. Derivation works before SCM creation and proves neither
// registration existence nor service-token or filesystem authority.
std::vector<unsigned char> derive_ascii_publisher_service_sid(const std::wstring& name);

// Read-only current-token facts. The process token is observed separately
// from the current thread's impersonation state. These facts alone do not
// prove SCM service configuration, handle provenance, or profile eligibility.
PublisherTokenObservation observe_current_publisher_token();
// Read-only primary token of the supplied held native process. The caller
// retains and independently fences that process's PID/birth/image/liveness.
// current_thread_impersonating describes this observing thread; it does not
// describe a remote process's threads. No token handle or authority is exported.
PublisherTokenObservation observe_held_publisher_process_token(void* process_handle);

// A necessary token predicate only; it does not admit a publisher profile.
bool has_restricted_publisher_token_facts(
    const PublisherTokenObservation& observation, const std::string& service_sid);

// Read-only SCM and process-token corroboration for a named, running,
// own-process restricted service. It refuses a CLI process or an absent
// service. Configuration can change later; this does not establish handle
// provenance, protected filesystem rights, or production eligibility.
// Within the original admission's private scope, readbacks reuse its held
// native service object and fresh native facts join its captured/derived
// name/SID. That route does not claim another named-account lookup occurred.
PublisherServiceObservation observe_current_restricted_publisher_service(
    const std::wstring& service_name);

} // namespace usk::platform::windows
#endif

#endif
