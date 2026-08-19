// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_ARCHIVE_PAYLOAD_H
#define USK_ARCHIVE_PAYLOAD_H

#include <cstdint>
#include <string>
#include <vector>

namespace usk::archive {

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

StoredArchivePayload inspect_stored_payload(
    const std::string& archive_inspection_request_json,
    const std::string& strip_prefix,
    PayloadMemoryObservation* memory_observation = nullptr);

} // namespace usk::archive

#endif
