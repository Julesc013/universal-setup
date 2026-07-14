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
    std::uint64_t uncompressed_bytes = 0;
    std::vector<PayloadFile> files;
};

StoredArchivePayload inspect_stored_payload(
    const std::string& archive_inspection_request_json,
    const std::string& strip_prefix);

} // namespace usk::archive

#endif
