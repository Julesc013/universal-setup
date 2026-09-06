// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_stream_entry_journal.h"
#include "usk_record_io.h"
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace {
using usk::json::Value;
bool digest(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
std::string optional_string(const Value& value) {
    return value.type() == Value::Type::null_value ? std::string{} : value.as_string();
}
Value nullable(const std::string& value) { return value.empty() ? Value{} : Value(value); }
void exact_keys(const Value& value, const std::set<std::string>& expected) {
    std::set<std::string> actual;
    for (const auto& item : value.as_object()) actual.insert(item.first);
    if (actual != expected) throw std::runtime_error("stream journal fields are invalid");
}
std::string hex_id(std::uint64_t value) {
    std::ostringstream out; out << std::hex << std::setfill('0') << std::setw(16) << value;
    return out.str();
}
}
namespace usk::transaction {
json::Value render_stream_journal(const StreamJournal& journal) {
    Value::Array entries;
    for (const auto& entry : journal.entries) {
        entries.emplace_back(Value::Object{
            {"relative_path", Value(entry.relative_path)}, {"sha256", Value(entry.sha256)},
            {"expected_size", Value(entry.expected_size)},
            {"source_identity_digest", Value(entry.source_identity_digest)},
            {"phase", Value(entry.phase)}, {"output_identity", nullable(entry.output_identity)}});
    }
    Value origin;
    if (!journal.origin_transaction_id.empty()) origin = Value(Value::Object{
        {"transaction_id", Value(journal.origin_transaction_id)},
        {"snapshot_sha256", Value(journal.origin_snapshot_sha256)}});
    Value result(Value::Object{{"version", Value(std::uint64_t{1})},
        {"source_digest", nullable(journal.source_digest)}, {"restart_origin", origin},
        {"entries", Value(std::move(entries))}});
    if (!journal.source_context.empty()) result.as_object().emplace("source_context", Value(journal.source_context));
    const auto hash = json::sha256_canonical(result);
    result.as_object().emplace("digest", Value(hash));
    return result;
}
StreamJournal read_stream_journal(const Value& document,
    const std::function<bool(const std::filesystem::path&)>& valid_path) {
    StreamJournal result;
    if (!document.contains("recovery_metadata")) return result;
    const auto& metadata = document.at("recovery_metadata");
    if (!metadata.contains("stream_journal")) return result;
    if (!metadata.contains("stream_cleanup_policy") ||
        metadata.at("stream_cleanup_policy").as_string() != "retain_only" ||
        metadata.at("staging_identity").type() != Value::Type::null_value) {
        throw std::runtime_error("stream journal cannot grant rollback authority");
    }
    const auto& value = metadata.at("stream_journal");
    if (value.contains("source_context")) {
        exact_keys(value, {"version", "source_digest", "source_context", "restart_origin", "entries", "digest"});
    } else {
        exact_keys(value, {"version", "source_digest", "restart_origin", "entries", "digest"});
    }
    auto body = value;
    const auto hash = body.at("digest").as_string(); body.as_object().erase("digest");
    if (value.at("version").as_unsigned() != 1 || !digest(hash) ||
        json::sha256_canonical(body) != hash) throw std::runtime_error("stream journal digest/version is invalid");
    result.source_digest = optional_string(value.at("source_digest"));
    if (value.at("source_digest").type() != Value::Type::null_value && !digest(result.source_digest))
        throw std::runtime_error("stream source digest is invalid");
    if (value.contains("source_context")) {
        result.source_context = value.at("source_context").as_string();
        if (result.source_context.empty() || result.source_context.size() > 16384u) {
            throw std::runtime_error("stream source context exceeds its bound");
        }
        const auto context = json::parse(result.source_context);
        if (json::canonical(context) != result.source_context ||
            json::sha256_canonical(context) != result.source_digest) {
            throw std::runtime_error("stream source context is not bound by its source digest");
        }
    }
    const auto& origin = value.at("restart_origin");
    if (origin.type() != Value::Type::null_value) {
        exact_keys(origin, {"transaction_id", "snapshot_sha256"});
        result.origin_transaction_id = origin.at("transaction_id").as_string();
        result.origin_snapshot_sha256 = origin.at("snapshot_sha256").as_string();
        if (!record_io::valid_identifier(result.origin_transaction_id) ||
            result.origin_transaction_id == document.at("transaction_id").as_string() ||
            !digest(result.origin_snapshot_sha256) || result.source_digest.empty())
            throw std::runtime_error("stream restart lineage is invalid");
    }
    std::map<std::string, const Value*> staged_files;
    for (const auto& staged : metadata.at("staged_files").as_array()) {
        if (!staged_files.emplace(staged.at("relative_path").as_string(), &staged).second)
            throw std::runtime_error("stream journal has duplicate staged closure paths");
    }
    std::set<std::string> paths;
    bool incomplete = false;
    const auto& entries = value.at("entries").as_array();
    if (entries.size() > 100000) throw std::runtime_error("stream journal entry bound exceeded");
    for (const auto& entry : entries) {
        exact_keys(entry, {"relative_path", "sha256", "expected_size", "source_identity_digest", "phase", "output_identity"});
        StreamEntryObservation observation{entry.at("relative_path").as_string(),
            entry.at("sha256").as_string(), entry.at("expected_size").as_unsigned(),
            entry.at("source_identity_digest").as_string(), entry.at("phase").as_string(),
            optional_string(entry.at("output_identity"))};
        auto folded = observation.relative_path;
        std::transform(folded.begin(), folded.end(), folded.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        const bool identity_valid = observation.output_identity.size() == 33 &&
            observation.output_identity[16] == ':' &&
            std::count(observation.output_identity.begin(), observation.output_identity.end(), ':') == 1 &&
            std::all_of(observation.output_identity.begin(), observation.output_identity.end(), [](unsigned char c) {
                return c == ':' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            });
        if (incomplete || !valid_path(std::filesystem::path(observation.relative_path)) ||
            !paths.insert(folded).second || !digest(observation.sha256) ||
            !digest(observation.source_identity_digest) ||
            (observation.phase != "intent" && observation.phase != "writing" && observation.phase != "complete") ||
            (observation.phase == "intent" ? entry.at("output_identity").type() != Value::Type::null_value : !identity_valid))
            throw std::runtime_error("stream entry observation is invalid");
        const auto staged = staged_files.find(observation.relative_path);
        if (staged != staged_files.end() &&
            (staged->second->at("sha256").as_string() != observation.sha256 ||
             staged->second->at("size_bytes").as_unsigned() != observation.expected_size))
            throw std::runtime_error("stream completion differs from staged closure");
        if ((staged != staged_files.end()) != (observation.phase == "complete"))
            throw std::runtime_error("stream phase differs from staged closure");
        incomplete = observation.phase != "complete";
        result.entries.push_back(std::move(observation));
    }
    result.present = true;
    return result;
}
std::string stream_output_identity(std::intptr_t handle) {
#if defined(_WIN32)
    BY_HANDLE_FILE_INFORMATION info{};
    const HANDLE file = reinterpret_cast<HANDLE>(handle);
    if (!GetFileInformationByHandle(file, &info) || GetFileType(file) != FILE_TYPE_DISK ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        info.nNumberOfLinks != 1) throw std::runtime_error("stream output handle identity is invalid");
    return hex_id(info.dwVolumeSerialNumber) + ":" + hex_id(
        (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow);
#else
    struct stat info{};
    if (::fstat(static_cast<int>(handle), &info) != 0 || !S_ISREG(info.st_mode) || info.st_nlink != 1)
        throw std::runtime_error("stream output descriptor identity is invalid");
    return hex_id(static_cast<std::uint64_t>(info.st_dev)) + ":" + hex_id(static_cast<std::uint64_t>(info.st_ino));
#endif
}
} // namespace usk::transaction
