// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_TREE_OBSERVATION_H
#define USK_PUBLISHER_TREE_OBSERVATION_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace usk::platform::windows {

struct PublisherTreeEntry {
    std::wstring relative_path;
    std::array<std::uint8_t, 16> file_id;
    std::uint32_t attributes;
    bool directory;
    std::uint64_t size;
    std::string sha256;
};

struct PublisherTreeObservation {
    std::uint64_t volume_serial;
    std::array<std::uint8_t, 16> root_file_id;
    std::vector<PublisherTreeEntry> descendants;
};

// Read-only candidate closure of namespace, identity, streams, and file bytes.
// Security/anchor facts and phase equality are separate admission obligations.
PublisherTreeObservation observe_publisher_tree(HANDLE root);

} // namespace usk::platform::windows
#endif

#endif
