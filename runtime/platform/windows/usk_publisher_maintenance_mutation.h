// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_MAINTENANCE_MUTATION_H
#define USK_PUBLISHER_MAINTENANCE_MUTATION_H
#if defined(_WIN32)
#include "usk_publisher_handle_observation.h"
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

namespace usk::platform::windows {
struct PublisherBoundFileRenameObservation {
    std::string file_id, sha256, source_parent_file_id, destination_parent_file_id;
    std::uint64_t size_bytes;
    std::wstring former_name, visible_name;
    std::int64_t native_call_start_tick, native_call_end_tick, clock_frequency;
    std::uint32_t native_status, io_status, source_granted_access,
        destination_parent_granted_access;
};

// Private maintenance mechanism, not an ownership or commit grant. Requires
// the live operation effect fence, original durable intent, and independently
// admitted parent/descriptor custody in the caller. Reopens the exact listed
// regular file relative to its source parent, binds bytes/size/security/streams,
// then uses the held file and destination parent for a no-replace rename.
// The supplied file handle is dedicated and synchronous; its position resets.
// Any failure after the native call is PublisherRenameUnconfirmed; the caller
// retains the original intent and enters recovery without retrying the call.
PublisherBoundFileRenameObservation rename_publisher_bound_file_no_replace(
    HANDLE file, HANDLE source_parent, const std::wstring& source_component,
    HANDLE destination_parent, const std::wstring& destination_component,
    const PublisherHandleObservation& expected_file,
    const PublisherHandleObservation& expected_source_parent,
    const PublisherHandleObservation& expected_destination_parent,
    std::uint64_t expected_size, const std::string& expected_sha256);

namespace detail { struct PublisherRemovalOwner; }
class PublisherRemovalUnconfirmed final : public std::runtime_error {
public:
    PublisherRemovalUnconfirmed(const std::string& message,
        std::shared_ptr<detail::PublisherRemovalOwner> owner);
private:
    // A failed close is quarantined, not an open/reusable-handle assertion.
    // The state follows the typed failure; no destructor retries the close.
    std::shared_ptr<detail::PublisherRemovalOwner> retained_owner_;
};
struct PublisherBoundRemovalObservation {
    std::string object_file_id, parent_file_id;
    std::wstring component;
    bool native_call_attempted, absence_confirmed;
    std::int64_t native_call_start_tick, native_call_end_tick, clock_frequency;
    std::uint32_t native_status, io_status, source_granted_access;
};

// Open/mark/close only this exact listed object under the mandatory live fence.
// Success requires actual parent-relative absence after close. An uncertain
// call or pending external handle retains recovery; no path deletion fallback.
PublisherBoundRemovalObservation remove_publisher_bound_file(
    HANDLE parent, const std::wstring& component,
    const PublisherHandleObservation& expected_file,
    const PublisherHandleObservation& expected_parent,
    std::uint64_t expected_size, const std::string& expected_sha256);

// A bound nonempty directory returns no-call retained. The caller must decide
// whether its original journal permits that result. Never deletes descendants.
PublisherBoundRemovalObservation remove_publisher_bound_empty_directory(
    HANDLE parent, const std::wstring& component,
    const PublisherHandleObservation& expected_directory,
    const PublisherHandleObservation& expected_parent);
}
#endif
#endif
