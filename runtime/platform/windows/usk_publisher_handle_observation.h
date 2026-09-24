// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_HANDLE_OBSERVATION_H
#define USK_PUBLISHER_HANDLE_OBSERVATION_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace usk::platform::windows {

struct ObservedAce {
    std::uint8_t type;
    std::uint8_t flags;
    std::uint32_t access_mask;
    std::string sid;
};

struct PublisherHandleObservation {
    std::string file_id;
    std::wstring native_name;
    std::uint32_t attributes;
    std::uint32_t reparse_tag;
    std::uint32_t link_count;
    bool case_sensitive;
    std::string owner_sid;
    bool dacl_protected;
    std::vector<ObservedAce> dacl_aces;
};

// Read-only facts from one already-opened directory handle. This is an
// observation primitive, not a profile-admission or publication capability.
// The caller must retain and independently revalidate the handle and its
// namespace chain across all publication phases.
PublisherHandleObservation observe_publisher_directory_handle(HANDLE handle);

} // namespace usk::platform::windows
#endif

#endif
