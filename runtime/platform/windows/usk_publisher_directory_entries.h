// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_DIRECTORY_ENTRIES_H
#define USK_PUBLISHER_DIRECTORY_ENTRIES_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace usk::platform::windows {

struct PublisherDirectoryEntry {
    std::wstring name;
    std::array<std::uint8_t, 16> file_id;
    std::uint32_t attributes;
    std::uint32_t reparse_tag;
    std::int64_t listing_size;
};

// Exact canonical component rule used for both live names and recorded
// assertions. A true result alone does not establish that the child exists.
bool is_publisher_canonical_component(const std::wstring& name);

// Read-only enumeration from one held directory handle. The returned 128-bit
// IDs and listing attributes are untrusted observations until each child is
// independently reopened relative to this parent and verified on that handle.
std::vector<PublisherDirectoryEntry> observe_publisher_directory_entries(
    HANDLE directory, std::size_t byte_budget = 64 * 1024 * 1024);

// Open one listed child relative to the retained parent handle without
// following a reparse point. The caller owns and must CloseHandle the result.
// Listing size is provisional; the returned handle must supply content facts.
HANDLE open_publisher_listed_child(HANDLE parent,
    const PublisherDirectoryEntry& listed);

} // namespace usk::platform::windows
#endif

#endif
