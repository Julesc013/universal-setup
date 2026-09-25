// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_VOLUME_STREAM_OBSERVATION_H
#define USK_PUBLISHER_VOLUME_STREAM_OBSERVATION_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace usk::platform::windows {

struct PublisherVolumeObservation {
    std::wstring volume_label;
    std::uint32_t volume_information_serial;
    std::uint64_t file_id_volume_serial;
    std::wstring filesystem_name;
    std::uint32_t maximum_component_length;
    std::uint32_t filesystem_flags;
    std::uint32_t remote_protocol_error;
};

struct PublisherStreamObservation {
    std::wstring name;
    std::int64_t size;
    std::int64_t allocation_size;
};

// Read-only facts from a held handle. The volume observer is a necessary
// local-NTFS filter, not a dedicated-volume or publisher admission decision.
PublisherVolumeObservation observe_local_ntfs_volume_handle(HANDLE handle);

// Bounded enumeration of streams on one file/directory handle. Callers must
// reject every named stream for the WU-006 publication profile and reobserve
// complete closure at each required phase.
std::vector<PublisherStreamObservation> observe_publisher_handle_streams(HANDLE handle);

// Apply the candidate's exact stream shape to one held object. This does not
// replace complete closure enumeration or the other publisher predicates.
void require_publisher_stream_shape(HANDLE handle);

// Validate a retained observation without silently querying a later phase.
void require_publisher_stream_shape(
    const std::vector<PublisherStreamObservation>& streams, bool directory);

} // namespace usk::platform::windows
#endif

#endif
