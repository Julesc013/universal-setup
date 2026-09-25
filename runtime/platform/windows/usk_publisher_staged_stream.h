// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_STAGED_STREAM_H
#define USK_PUBLISHER_STAGED_STREAM_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace usk::platform::windows {

struct PublisherStagedStream {
    HANDLE file; // Caller owns this non-inheritable handle.
    std::uint64_t bytes_written;
    std::string sha256;
};

// Candidate primitive for an already-qualified protected parent. The source
// must be a dedicated seekable regular-file handle; its position is reset.
// The destination is created only after source preflight, exclusively relative
// to the held parent, and is retained on every post-creation failure. Caller
// must verify parent provenance, source trust, complete tree closure, durable
// intent and recovery. This does not enable the production publisher.
PublisherStagedStream stream_verified_source_to_staged_file(
    HANDLE protected_parent, const std::wstring& canonical_name,
    const std::vector<unsigned char>& creation_descriptor, HANDLE source,
    std::uint64_t expected_size, const std::string& expected_sha256);

using PublisherPayloadReader = std::function<std::size_t(
    std::uint64_t offset, unsigned char* output, std::size_t capacity)>;

// A verified archive entry can stream directly into protected staging without
// retaining its complete payload. The caller must hold and validate the archive
// source, bind the selected entry to the reviewed plan, and protect the parent.
// A post-creation failure retains the staged child for recovery.
PublisherStagedStream stream_verified_reader_to_staged_file(
    HANDLE protected_parent, const std::wstring& canonical_name,
    const std::vector<unsigned char>& creation_descriptor,
    std::uint64_t expected_size, const std::string& expected_sha256,
    const PublisherPayloadReader& reader,
    const std::function<void()>& validate_source);

} // namespace usk::platform::windows
#endif
#endif
