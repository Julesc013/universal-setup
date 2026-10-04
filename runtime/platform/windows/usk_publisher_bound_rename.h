// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_BOUND_RENAME_H
#define USK_PUBLISHER_BOUND_RENAME_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>

#include "usk_publisher_handle_observation.h"

#include <functional>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace usk::platform::windows {

// A failed or unconfirmed native call may already have changed the namespace.
// Its caller must retain both handles and enter recovery, never retry blindly.
class PublisherRenameUnconfirmed final : public std::runtime_error {
public:
    explicit PublisherRenameUnconfirmed(const std::string& message)
        : std::runtime_error(message) {}
};

// Returned only after native success and held-identity/visible-child checks.
// Failed or ambiguous calls keep their conservative exception outcome.
struct PublisherBoundRenameObservation {
    std::string root_file_id;
    std::wstring former_name;
    std::wstring visible_name;
    std::int64_t native_call_start_tick;
    std::int64_t native_call_end_tick;
    std::int64_t clock_frequency;
    std::string destination_parent_file_id;
    std::wstring destination_component;
    std::uint32_t destination_absence_status;
    std::uint32_t information_class;
    std::uint32_t information_bytes;
    std::uint32_t file_name_bytes;
    bool replace_if_exists;
    std::uint32_t native_status;
    std::uint32_t io_status;
};

// Handle-bound no-replace mechanism. A publication caller must retain a durable
// publish_prepared record and a sealed complete protected tree before
// invocation. This primitive neither creates that journal nor grants authority.
PublisherBoundRenameObservation probe_publisher_bound_rename_no_replace(
    HANDLE staged_root, HANDLE destination_parent,
    const std::wstring& destination_component,
    const PublisherHandleObservation& expected_staged_root,
    const PublisherHandleObservation& expected_destination_parent,
    const std::function<void()>& after_absence_check = {});

} // namespace usk::platform::windows
#endif
#endif
