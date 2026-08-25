// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_STREAMING_SOURCE_TARGET_H
#define USK_STREAMING_SOURCE_TARGET_H

#include "usk_transaction_session.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace usk::streaming {

struct ResourceBudget {
    std::size_t payload_buffer_bytes = 64u * 1024u;
    std::size_t maximum_entries = 100000u;
};

struct PayloadEntryDescriptor {
    std::filesystem::path source_path;
    std::string relative_path;
    std::string source_identity_digest;
    std::string sha256;
    std::uint32_t crc32 = 0;
    std::uint64_t size_bytes = 0;
};

struct DirectorySource {
    std::filesystem::path root;
    std::string entry_set_digest;
    std::vector<PayloadEntryDescriptor> entries;
    std::uint64_t total_bytes = 0;
};

class CancellationView {
public:
    virtual ~CancellationView() = default;
    virtual bool cancelled() const noexcept = 0;
};

class ProgressSink {
public:
    virtual ~ProgressSink() = default;
    virtual void advanced(
        const std::string& relative_path,
        std::uint64_t entry_bytes,
        std::uint64_t total_bytes) = 0;
};

using FaultInjector = std::function<void(
    const std::string& point,
    const std::string& relative_path,
    std::uint64_t offset)>;

struct StreamRequest {
    DirectorySource source;
    transaction::TransactionSpec transaction;
    std::string audit_chain_id;
    std::string recorded_at;
    ResourceBudget budget;
    CancellationView* cancellation = nullptr;
    ProgressSink* progress = nullptr;
    FaultInjector fault;
};

struct StreamResult {
    bool completed = false;
    std::string disposition;
    std::string error_code;
    std::string detail;
    std::string entry_set_digest;
    std::string audit_event_digest;
    std::uint64_t entries_completed = 0;
    std::uint64_t bytes_completed = 0;
    std::uint64_t peak_payload_buffer_bytes = 0;
    bool public_abi_changed = false;
};

DirectorySource inspect_directory_source(
    const std::filesystem::path& source_root,
    ResourceBudget budget = {});

StreamResult stream_directory_to_target(StreamRequest request) noexcept;

std::uint64_t measure_generated_payload_buffer(
    std::uint64_t logical_bytes,
    ResourceBudget budget = {});

} // namespace usk::streaming

#endif
