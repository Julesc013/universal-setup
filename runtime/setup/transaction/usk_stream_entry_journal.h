// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_STREAM_ENTRY_JOURNAL_H
#define USK_STREAM_ENTRY_JOURNAL_H

#include "usk_json.h"
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace usk::transaction {
struct StreamEntryObservation {
    std::string relative_path;
    std::string sha256;
    std::uint64_t expected_size = 0;
    std::string source_identity_digest;
    std::string phase = "intent";
    std::string output_identity;
};
struct StreamJournal {
    std::string source_digest;
    std::string source_context;
    std::string origin_transaction_id;
    std::string origin_snapshot_sha256;
    std::vector<StreamEntryObservation> entries;
    bool present = false;
};
json::Value render_stream_journal(const StreamJournal& journal);
StreamJournal read_stream_journal(
    const json::Value& document,
    const std::function<bool(const std::filesystem::path&)>& valid_path);
// Identity observation from the original open creation handle, never cleanup authority.
std::string stream_output_identity(std::intptr_t handle);
} // namespace usk::transaction
#endif
