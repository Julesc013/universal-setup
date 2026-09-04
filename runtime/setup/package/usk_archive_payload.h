// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_ARCHIVE_PAYLOAD_H
#define USK_ARCHIVE_PAYLOAD_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace usk::archive {

inline constexpr std::size_t streaming_payload_buffer_bytes = 64u * 1024u;

using CancellationCheck = std::function<bool()>;

struct PayloadFile {
    std::string relative_path;
    std::vector<unsigned char> bytes;
    std::string sha256;
};

struct StoredArchivePayload {
    std::string source_sha256;
    std::string source_identity_digest;
    std::string entry_set_digest;
    std::uint64_t archive_size_bytes = 0;
    std::uint64_t uncompressed_bytes = 0;
    std::vector<PayloadFile> files;
};

struct PayloadMemoryObservation {
    std::uint64_t materialization_ceiling_bytes = 0;
    std::uint64_t final_payload_size_bytes = 0;
    std::uint64_t final_payload_capacity_bytes = 0;
    std::uint64_t peak_payload_capacity_bytes = 0;
    std::uint64_t largest_entry_bytes = 0;
    std::uint64_t file_count = 0;
    bool complete_payload_retained = false;
};

using PayloadReader = std::function<std::size_t(
    std::uint64_t offset,
    unsigned char* output,
    std::size_t capacity)>;

struct StreamingPayloadFile {
    std::string relative_path;
    std::string sha256;
    std::uint32_t crc32 = 0;
    std::uint64_t size_bytes = 0;
    PayloadReader reader;
    std::string compression_method;
};

struct StreamingStoredArchivePayload {
    std::string source_sha256;
    std::string source_identity_digest;
    std::string entry_set_digest;
    std::uint64_t archive_size_bytes = 0;
    std::uint64_t uncompressed_bytes = 0;
    std::size_t payload_buffer_bytes = 0;
    std::vector<StreamingPayloadFile> files;
};

struct StreamingPayloadMemoryObservation {
    std::uint64_t logical_payload_bytes = 0;
    std::uint64_t peak_payload_buffer_bytes = 0;
    std::uint64_t peak_compressed_input_buffer_bytes = 0;
    std::uint64_t peak_total_stream_buffer_bytes = 0;
    std::uint64_t file_count = 0;
    bool complete_payload_retained = false;
};

StoredArchivePayload inspect_stored_payload(
    const std::string& archive_inspection_request_json,
    const std::string& strip_prefix,
    PayloadMemoryObservation* memory_observation = nullptr);

StreamingStoredArchivePayload inspect_streaming_stored_payload(
    const std::string& archive_inspection_request_json,
    const std::string& strip_prefix,
    std::size_t payload_buffer_bytes = streaming_payload_buffer_bytes,
    StreamingPayloadMemoryObservation* memory_observation = nullptr);

StreamingStoredArchivePayload inspect_streaming_stored_payload(
    const std::string& archive_inspection_request_json,
    const std::string& strip_prefix,
    std::size_t payload_buffer_bytes,
    StreamingPayloadMemoryObservation* memory_observation,
    CancellationCheck cancellation);

StreamingStoredArchivePayload inspect_streaming_payload(
    const std::string& archive_inspection_request_json,
    const std::string& strip_prefix,
    std::size_t payload_buffer_bytes = streaming_payload_buffer_bytes,
    StreamingPayloadMemoryObservation* memory_observation = nullptr);

StreamingStoredArchivePayload inspect_streaming_payload(
    const std::string& archive_inspection_request_json,
    const std::string& strip_prefix,
    std::size_t payload_buffer_bytes,
    StreamingPayloadMemoryObservation* memory_observation,
    CancellationCheck cancellation);

} // namespace usk::archive

#endif
