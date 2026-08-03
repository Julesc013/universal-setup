// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_archive_inspect.h"
#include "usk_archive_payload.h"

#include "usk/usk_result.h"
#include "usk_json.h"
#include "usk_sha256.h"
#include "usk_stable_file.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <initializer_list>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr std::size_t max_request_bytes = 64u * 1024u;
constexpr std::size_t max_request_string_bytes = 32768u;
constexpr std::size_t max_request_values = 32u;
constexpr std::size_t max_name_bytes = 4096u;
constexpr std::size_t max_central_directory_bytes = 64u * 1024u * 1024u;
constexpr std::uint64_t classic_zip_max = 0xffffffffull;
constexpr std::uint64_t max_archive_bytes = 1ull << 40;
constexpr std::uint64_t max_materialized_payload_bytes = 512ull * 1024ull * 1024ull;
constexpr std::uint64_t max_inspection_elapsed_ms = 10ull * 60ull * 1000ull;
constexpr std::uint64_t max_request_entries = 100000u;
constexpr std::uint64_t max_request_uncompressed_bytes = 1ull << 40;
constexpr std::uint64_t max_request_entry_bytes = 1ull << 38;
constexpr std::uint64_t max_request_depth = 256u;
constexpr std::uint64_t max_request_ratio = 100000u;

struct Budgets {
    std::uint64_t max_entries = 10000;
    std::uint64_t max_uncompressed_bytes = 64ull * 1024ull * 1024ull * 1024ull;
    std::uint64_t max_entry_bytes = 16ull * 1024ull * 1024ull * 1024ull;
    std::uint64_t max_depth = 64;
    std::uint64_t max_ratio = 1000;
    std::uint64_t max_elapsed_ms = 30000;
};

struct ArchiveRequest {
    std::string archive_path;
    Budgets budgets;
};

struct Entry {
    std::string normalized_path;
    bool directory = false;
    std::uint64_t compressed_size = 0;
    std::uint64_t uncompressed_size = 0;
    std::uint16_t compression_method = 0;
    std::uint32_t crc32 = 0;
    std::uint64_t local_header_offset = 0;
    std::uint64_t data_offset = 0;
    std::uint64_t data_end = 0;
};

struct Inspection {
    fs::path path;
    usk::base::StableFileIdentity identity;
    std::string source_sha256;
    std::string entry_set_digest;
    std::string inspected_at;
    Budgets budgets;
    std::vector<Entry> entries;
    std::uint64_t file_count = 0;
    std::uint64_t directory_count = 0;
    std::uint64_t compressed_bytes = 0;
    std::uint64_t uncompressed_bytes = 0;
};

std::string json_escape(const std::string& value)
{
    std::ostringstream out;
    for (unsigned char ch : value) {
        switch (ch) {
        case '\\': out << "\\\\"; break;
        case '"': out << "\\\""; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (ch < 0x20u) {
                out << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<unsigned int>(ch) << std::dec;
            } else {
                out << static_cast<char>(ch);
            }
        }
    }
    return out.str();
}

std::string quote(const std::string& value)
{
    return "\"" + json_escape(value) + "\"";
}

void require_exact_members(
    const usk::json::Value& value,
    std::initializer_list<const char*> names,
    const std::string& object_name)
{
    if (value.type() != usk::json::Value::Type::object) {
        throw std::runtime_error(object_name + " must be a JSON object");
    }
    std::set<std::string> expected;
    for (const char* name : names) expected.emplace(name);
    for (const auto& member : value.as_object()) {
        if (expected.count(member.first) == 0) {
            throw std::runtime_error(
                object_name + " has an unexpected member: " + member.first);
        }
    }
    for (const std::string& name : expected) {
        if (!value.contains(name)) {
            throw std::runtime_error(
                object_name + " is missing required member: " + name);
        }
    }
}

std::string require_string(
    const usk::json::Value& object,
    const std::string& key)
{
    const usk::json::Value& value = object.at(key);
    if (value.type() != usk::json::Value::Type::string) {
        throw std::runtime_error(
            "archive inspection request field must be a string: " + key);
    }
    return value.as_string();
}

std::uint64_t require_bounded_unsigned(
    const usk::json::Value& object,
    const std::string& key,
    std::uint64_t maximum)
{
    const usk::json::Value& value = object.at(key);
    if (value.type() != usk::json::Value::Type::unsigned_integer) {
        throw std::runtime_error(
            "numeric request field must be an unsigned integer: " + key);
    }
    const std::uint64_t result = value.as_unsigned();
    if (result > maximum) {
        throw std::runtime_error(
            "numeric request field exceeds its hard limit: " + key);
    }
    if (result == 0) {
        throw std::runtime_error(
            "numeric request field is outside its allowed range: " + key);
    }
    return result;
}

ArchiveRequest parse_archive_request(const std::string& text)
{
    usk::json::ParseLimits limits;
    limits.max_bytes = max_request_bytes;
    limits.max_depth = 2;
    limits.max_values = max_request_values;
    limits.max_string_bytes = max_request_string_bytes;
    const usk::json::Value request = usk::json::parse(text, limits);
    require_exact_members(
        request,
        {"schema", "archive_path", "archive_format", "budgets"},
        "archive inspection request");

    if (require_string(request, "schema") != "usk.archive_inspect_request.v1") {
        throw std::runtime_error("unsupported archive inspection request schema");
    }
    if (require_string(request, "archive_format") != "zip") {
        throw std::runtime_error(
            "WU3 supports only explicitly declared ZIP archives");
    }

    ArchiveRequest result;
    result.archive_path = require_string(request, "archive_path");
    if (result.archive_path.empty()) {
        throw std::runtime_error("archive_path is required");
    }
    if (result.archive_path.find('\0') != std::string::npos) {
        throw std::runtime_error("archive_path contains an embedded NUL");
    }
    if (result.archive_path.size() > max_request_string_bytes) {
        throw std::runtime_error("archive_path exceeds its hard length limit");
    }

    const usk::json::Value& budgets = request.at("budgets");
    require_exact_members(
        budgets,
        {"max_entries", "max_uncompressed_bytes", "max_entry_bytes",
         "max_depth", "max_ratio", "max_elapsed_ms"},
        "archive inspection request budgets");
    result.budgets.max_entries = require_bounded_unsigned(
        budgets, "max_entries", max_request_entries);
    result.budgets.max_uncompressed_bytes = require_bounded_unsigned(
        budgets, "max_uncompressed_bytes", max_request_uncompressed_bytes);
    result.budgets.max_entry_bytes = require_bounded_unsigned(
        budgets, "max_entry_bytes", max_request_entry_bytes);
    result.budgets.max_depth = require_bounded_unsigned(
        budgets, "max_depth", max_request_depth);
    result.budgets.max_ratio = require_bounded_unsigned(
        budgets, "max_ratio", max_request_ratio);
    result.budgets.max_elapsed_ms = require_bounded_unsigned(
        budgets, "max_elapsed_ms", max_inspection_elapsed_ms);
    return result;
}

std::uint16_t little16(const std::vector<unsigned char>& data, std::size_t offset)
{
    if (offset > data.size() || data.size() - offset < 2) {
        throw std::runtime_error("ZIP structure is truncated");
    }
    return static_cast<std::uint16_t>(data[offset]) |
        (static_cast<std::uint16_t>(data[offset + 1]) << 8);
}

std::uint32_t little32(const std::vector<unsigned char>& data, std::size_t offset)
{
    if (offset > data.size() || data.size() - offset < 4) {
        throw std::runtime_error("ZIP structure is truncated");
    }
    return static_cast<std::uint32_t>(data[offset]) |
        (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
        (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
        (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

std::uint64_t little64(const std::vector<unsigned char>& data, std::size_t offset)
{
    if (offset > data.size() || data.size() - offset < 8) {
        throw std::runtime_error("ZIP structure is truncated");
    }
    return static_cast<std::uint64_t>(little32(data, offset)) |
        (static_cast<std::uint64_t>(little32(data, offset + 4)) << 32);
}

std::string lowercase_ascii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool windows_reserved_name(const std::string& segment)
{
    const std::size_t dot = segment.find('.');
    const std::string base = lowercase_ascii(segment.substr(0, dot));
    if (base == "con" || base == "prn" || base == "aux" || base == "nul") {
        return true;
    }
    if (base.size() == 4 &&
        (base.rfind("com", 0) == 0 || base.rfind("lpt", 0) == 0) &&
        base[3] >= '1' && base[3] <= '9') {
        return true;
    }
    return false;
}

std::string normalize_path(
    const std::string& raw,
    bool& trailing_separator,
    const Budgets& budgets)
{
    if (raw.empty() || raw.size() > max_name_bytes) {
        throw std::runtime_error("archive entry path is empty or exceeds the name budget");
    }
    for (unsigned char ch : raw) {
        if (ch < 0x20u || ch >= 0x7fu) {
            throw std::runtime_error(
                "archive entry path requires unsupported Unicode normalization");
        }
    }
    if (raw.front() == '/' || raw.front() == '\\' ||
        (raw.size() >= 2 && std::isalpha(static_cast<unsigned char>(raw[0])) && raw[1] == ':')) {
        throw std::runtime_error("archive entry path is absolute, drive-qualified, or UNC-like");
    }
    trailing_separator = raw.back() == '/' || raw.back() == '\\';
    std::vector<std::string> segments;
    std::string segment;
    for (std::size_t index = 0; index <= raw.size(); ++index) {
        const bool separator = index == raw.size() || raw[index] == '/' || raw[index] == '\\';
        if (!separator) {
            if (raw[index] == ':') {
                throw std::runtime_error("archive entry path contains an alternate-data-stream separator");
            }
            segment.push_back(raw[index]);
            continue;
        }
        if (segment.empty()) {
            if (index == raw.size() && trailing_separator && !segments.empty()) {
                break;
            }
            throw std::runtime_error("archive entry path contains an empty or ambiguous segment");
        }
        if (segment == "." || segment == "..") {
            throw std::runtime_error("archive entry path contains traversal or dot segments");
        }
        if (segment.back() == '.' || segment.back() == ' ' || windows_reserved_name(segment)) {
            throw std::runtime_error("archive entry path contains a reserved or ambiguous Windows name");
        }
        segments.push_back(segment);
        segment.clear();
    }
    if (segments.empty() || segments.size() > budgets.max_depth) {
        throw std::runtime_error("archive entry path exceeds the depth budget");
    }
    std::ostringstream normalized;
    for (std::size_t index = 0; index < segments.size(); ++index) {
        if (index != 0) normalized << '/';
        normalized << segments[index];
    }
    return normalized.str();
}

struct Zip64Extra {
    bool present = false;
    std::uint64_t uncompressed_size = 0;
    std::uint64_t compressed_size = 0;
    std::uint64_t local_header_offset = 0;
    std::uint32_t disk_start = 0;
};

Zip64Extra parse_extra_fields(
    const std::vector<unsigned char>& data,
    std::size_t offset,
    std::size_t size,
    bool needs_uncompressed_size,
    bool needs_compressed_size,
    bool needs_local_header_offset,
    bool needs_disk_start)
{
    if (offset > data.size() || size > data.size() - offset) {
        throw std::runtime_error("ZIP extra field range is truncated");
    }
    const std::size_t end = offset + size;
    std::set<std::uint16_t> identifiers;
    Zip64Extra zip64;
    while (offset < end) {
        if (end - offset < 4) {
            throw std::runtime_error("ZIP extra field header is truncated");
        }
        const std::uint16_t identifier = little16(data, offset);
        const std::uint16_t field_size = little16(data, offset + 2);
        offset += 4;
        if (field_size > end - offset || !identifiers.insert(identifier).second) {
            throw std::runtime_error("ZIP extra fields are truncated or duplicated");
        }
        const std::size_t field_end = offset + field_size;
        if (identifier == 0x0001u) {
            if (!needs_uncompressed_size && !needs_compressed_size &&
                !needs_local_header_offset && !needs_disk_start) {
                throw std::runtime_error(
                    "ZIP64 extra field is present when no sentinel requires it");
            }
            zip64.present = true;
            if (needs_uncompressed_size) {
                if (field_end - offset < 8) {
                    throw std::runtime_error(
                        "ZIP64 extra field is missing uncompressed size");
                }
                zip64.uncompressed_size = little64(data, offset);
                offset += 8;
            }
            if (needs_compressed_size) {
                if (field_end - offset < 8) {
                    throw std::runtime_error(
                        "ZIP64 extra field is missing compressed size");
                }
                zip64.compressed_size = little64(data, offset);
                offset += 8;
            }
            if (needs_local_header_offset) {
                if (field_end - offset < 8) {
                    throw std::runtime_error(
                        "ZIP64 extra field is missing local-header offset");
                }
                zip64.local_header_offset = little64(data, offset);
                offset += 8;
            }
            if (needs_disk_start) {
                if (field_end - offset < 4) {
                    throw std::runtime_error(
                        "ZIP64 extra field is missing disk number");
                }
                zip64.disk_start = little32(data, offset);
                offset += 4;
            }
            if (offset != field_end) {
                throw std::runtime_error(
                    "ZIP64 extra field contains ambiguous trailing values");
            }
        } else if (identifier == 0x7075u || identifier == 0x9901u) {
            throw std::runtime_error(
                "alternate Unicode paths and AES metadata are unsupported");
        } else {
            offset = field_end;
        }
    }
    if ((needs_uncompressed_size || needs_compressed_size ||
         needs_local_header_offset || needs_disk_start) &&
        !zip64.present) {
        throw std::runtime_error(
            "ZIP64 sentinel has no ZIP64 extra field");
    }
    return zip64;
}

void add_checked(std::uint64_t& total, std::uint64_t value, std::uint64_t maximum, const char* name)
{
    if (value > maximum || total > maximum - value) {
        throw std::runtime_error(std::string(name) + " exceeds its archive inspection budget");
    }
    total += value;
}

std::string iso8601_now()
{
    const std::time_t now = std::time(nullptr);
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    std::ostringstream out;
    out << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

std::string hash_source_until(
    const usk::base::StableFile& source,
    std::chrono::steady_clock::time_point deadline)
{
    usk::base::Sha256 hash;
    std::uint64_t offset = 0;
    while (offset < source.identity().size_bytes) {
        if (std::chrono::steady_clock::now() > deadline) {
            throw std::runtime_error("archive inspection exceeded the elapsed-time budget while hashing");
        }
        const std::size_t count = static_cast<std::size_t>(std::min<std::uint64_t>(
            64u * 1024u,
            source.identity().size_bytes - offset));
        const auto bytes = source.read(offset, count);
        hash.update(bytes.data(), bytes.size());
        offset += count;
    }
    return hash.finish();
}

std::string entry_set_digest(const std::vector<Entry>& entries)
{
    usk::base::Sha256 hash;
    for (const Entry& entry : entries) {
        const std::string line =
            std::string(entry.directory ? "directory\0" : "file\0", entry.directory ? 10 : 5) +
            entry.normalized_path + "\0" + std::to_string(entry.uncompressed_size) + "\0" +
            std::to_string(entry.compressed_size) + "\0" + std::to_string(entry.crc32) + "\0" +
            std::to_string(entry.compression_method) + "\n";
        hash.update(reinterpret_cast<const unsigned char*>(line.data()), line.size());
    }
    return hash.finish();
}

void validate_path_collision(
    std::map<std::string, bool>& paths,
    const std::string& normalized,
    bool directory)
{
    const std::string key = lowercase_ascii(normalized);
    if (!paths.emplace(key, directory).second) {
        throw std::runtime_error("archive contains duplicate or case-insensitive-colliding paths");
    }
    std::size_t separator = key.find('/');
    while (separator != std::string::npos) {
        const auto ancestor = paths.find(key.substr(0, separator));
        if (ancestor != paths.end() && !ancestor->second) {
            throw std::runtime_error("archive path descends through an entry declared as a file");
        }
        separator = key.find('/', separator + 1);
    }
    if (!directory) {
        const std::string prefix = key + "/";
        const auto child = paths.lower_bound(prefix);
        if (child != paths.end() && child->first.rfind(prefix, 0) == 0) {
            throw std::runtime_error("archive file path collides with an existing directory subtree");
        }
    }
}

Inspection inspect_zip(const std::string& request)
{
    const ArchiveRequest parsed = parse_archive_request(request);
    const Budgets& budgets = parsed.budgets;

    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(budgets.max_elapsed_ms);
    usk::base::StableFile source(parsed.archive_path);
    if (source.identity().size_bytes < 22 ||
        source.identity().size_bytes > max_archive_bytes) {
        throw std::runtime_error("source is not a bounded ZIP archive");
    }

    Inspection inspection;
    inspection.path = source.path();
    inspection.identity = source.identity();
    inspection.budgets = budgets;
    inspection.source_sha256 = hash_source_until(source, deadline);

    const std::size_t tail_size = static_cast<std::size_t>(std::min<std::uint64_t>(
        source.identity().size_bytes,
        22u + 65535u));
    const std::uint64_t tail_offset = source.identity().size_bytes - tail_size;
    const auto tail = source.read(tail_offset, tail_size);
    std::size_t eocd = std::string::npos;
    if (tail.size() >= 22) {
        for (std::size_t position = tail.size() - 22 + 1; position-- > 0;) {
            if (little32(tail, position) == 0x06054b50u) {
                const std::uint16_t comment_length = little16(tail, position + 20);
                if (position + 22u + comment_length == tail.size()) {
                    eocd = position;
                    break;
                }
            }
        }
    }
    if (eocd == std::string::npos) {
        throw std::runtime_error(
            "ZIP end-of-central-directory record is missing or ambiguous");
    }
    if (little16(tail, eocd + 4) != 0 || little16(tail, eocd + 6) != 0) {
        throw std::runtime_error("multi-disk ZIP archives are unsupported");
    }
    const std::uint16_t classic_entries_on_disk = little16(tail, eocd + 8);
    const std::uint16_t classic_entry_count = little16(tail, eocd + 10);
    const std::uint32_t classic_central_size = little32(tail, eocd + 12);
    const std::uint32_t classic_central_offset = little32(tail, eocd + 16);
    std::uint64_t entries_on_disk = classic_entries_on_disk;
    std::uint64_t entry_count = classic_entry_count;
    std::uint64_t central_size = classic_central_size;
    std::uint64_t central_offset = classic_central_offset;
    const std::uint64_t eocd_offset = tail_offset + eocd;
    bool has_zip64_locator = false;
    std::vector<unsigned char> locator;
    if (eocd_offset >= 20) {
        locator = source.read(eocd_offset - 20, 20);
        has_zip64_locator = little32(locator, 0) == 0x07064b50u;
    }
    const bool needs_zip64 =
        classic_entries_on_disk == 0xffffu ||
        classic_entry_count == 0xffffu ||
        classic_central_size == 0xffffffffu ||
        classic_central_offset == 0xffffffffu;
    std::uint64_t central_end = eocd_offset;
    if (needs_zip64 || has_zip64_locator) {
        if (!has_zip64_locator) {
            throw std::runtime_error("ZIP64 locator is missing");
        }
        if (little32(locator, 4) != 0 || little32(locator, 16) != 1) {
            throw std::runtime_error(
                "ZIP64 locator declares a multi-disk archive");
        }
        const std::uint64_t zip64_offset = little64(locator, 8);
        if (zip64_offset > eocd_offset - 20 ||
            eocd_offset - 20 - zip64_offset < 56) {
            throw std::runtime_error("ZIP64 end record offset is invalid");
        }
        const auto zip64 = source.read(zip64_offset, 56);
        const std::uint64_t zip64_record_size = little64(zip64, 4);
        if (little32(zip64, 0) != 0x06064b50u ||
            zip64_record_size != 44 ||
            zip64_offset + 12 + zip64_record_size != eocd_offset - 20) {
            throw std::runtime_error(
                "ZIP64 end-of-central-directory record is malformed");
        }
        if (little32(zip64, 16) != 0 || little32(zip64, 20) != 0) {
            throw std::runtime_error(
                "ZIP64 end record declares a multi-disk archive");
        }
        entries_on_disk = little64(zip64, 24);
        entry_count = little64(zip64, 32);
        central_size = little64(zip64, 40);
        central_offset = little64(zip64, 48);
        if (entries_on_disk != entry_count) {
            throw std::runtime_error(
                "ZIP64 central-directory entry counts disagree");
        }
        if ((classic_entries_on_disk != 0xffffu &&
             classic_entries_on_disk != entries_on_disk) ||
            (classic_entry_count != 0xffffu &&
             classic_entry_count != entry_count) ||
            (classic_central_size != 0xffffffffu &&
             classic_central_size != central_size) ||
            (classic_central_offset != 0xffffffffu &&
             classic_central_offset != central_offset)) {
            throw std::runtime_error(
                "classic and ZIP64 end records disagree");
        }
        central_end = zip64_offset;
    }
    if (entry_count == 0 || entry_count > budgets.max_entries ||
        central_size > max_central_directory_bytes ||
        central_offset > central_end ||
        central_size > central_end - central_offset ||
        central_offset + central_size != central_end ||
        entries_on_disk != entry_count) {
        throw std::runtime_error("ZIP central-directory count, size, or bounds are invalid");
    }
    const auto central = source.read(
        central_offset, static_cast<std::size_t>(central_size));
    std::size_t position = 0;
    std::map<std::string, bool> normalized_paths;
    inspection.entries.reserve(static_cast<std::size_t>(entry_count));

    for (std::uint64_t index = 0; index < entry_count; ++index) {
        if (std::chrono::steady_clock::now() > deadline) {
            throw std::runtime_error("archive inspection exceeded the elapsed-time budget");
        }
        if (little32(central, position) != 0x02014b50u || central.size() - position < 46) {
            throw std::runtime_error("ZIP central-directory entry is truncated or malformed");
        }
        const std::uint16_t version_made = little16(central, position + 4);
        const std::uint16_t flags = little16(central, position + 8);
        const std::uint16_t method = little16(central, position + 10);
        const std::uint32_t crc32 = little32(central, position + 16);
        const std::uint32_t compressed32 = little32(central, position + 20);
        const std::uint32_t uncompressed32 = little32(central, position + 24);
        const std::uint16_t name_size = little16(central, position + 28);
        const std::uint16_t extra_size = little16(central, position + 30);
        const std::uint16_t comment_size = little16(central, position + 32);
        const std::uint16_t disk_start16 = little16(central, position + 34);
        const std::uint32_t external_attributes = little32(central, position + 38);
        const std::uint32_t local_offset32 = little32(central, position + 42);
        const std::size_t record_size = 46u + name_size + extra_size + comment_size;
        if (record_size > central.size() - position || name_size == 0) {
            throw std::runtime_error("ZIP central-directory variable fields are truncated");
        }
        if ((flags & (0x0001u | 0x0008u | 0x0020u | 0x0040u | 0x2000u)) != 0) {
            throw std::runtime_error("encrypted, streamed, patched, masked, or multi-disk ZIP entries are unsupported");
        }
        if (method != 0 && method != 8) {
            throw std::runtime_error("ZIP entry uses an unsupported compression method");
        }
        const std::string raw_name(
            reinterpret_cast<const char*>(central.data() + position + 46),
            name_size);
        const bool needs_uncompressed = uncompressed32 == 0xffffffffu;
        const bool needs_compressed = compressed32 == 0xffffffffu;
        const bool needs_local_offset = local_offset32 == 0xffffffffu;
        const bool needs_disk_start = disk_start16 == 0xffffu;
        const Zip64Extra central_zip64 = parse_extra_fields(
            central,
            position + 46 + name_size,
            extra_size,
            needs_uncompressed,
            needs_compressed,
            needs_local_offset,
            needs_disk_start);
        const std::uint64_t compressed = needs_compressed
            ? central_zip64.compressed_size
            : compressed32;
        const std::uint64_t uncompressed = needs_uncompressed
            ? central_zip64.uncompressed_size
            : uncompressed32;
        const std::uint64_t local_offset = needs_local_offset
            ? central_zip64.local_header_offset
            : local_offset32;
        const std::uint32_t disk_start = needs_disk_start
            ? central_zip64.disk_start
            : disk_start16;
        if (disk_start != 0) {
            throw std::runtime_error(
                "ZIP entry declares a nonzero or multi-disk start");
        }

        const std::uint16_t unix_mode = static_cast<std::uint16_t>(external_attributes >> 16);
        const std::uint16_t unix_type = unix_mode & 0170000u;
        const bool unix_directory = unix_type == 0040000u;
        const bool unix_regular = unix_type == 0100000u || unix_type == 0;
        if (!unix_directory && !unix_regular) {
            throw std::runtime_error("ZIP entry is a link, device, socket, or unsupported Unix file type");
        }
        if ((external_attributes & 0x00000440u) != 0) {
            throw std::runtime_error("ZIP entry declares reparse-like or device attributes");
        }
        bool trailing_separator = false;
        const std::string normalized = normalize_path(raw_name, trailing_separator, budgets);
        const bool dos_directory = (external_attributes & 0x10u) != 0;
        const bool directory = trailing_separator || unix_directory || dos_directory;
        if ((unix_type == 0100000u && directory) ||
            (directory && (compressed != 0 || uncompressed != 0 || method != 0))) {
            throw std::runtime_error("ZIP directory and file metadata disagree");
        }
        if (!directory) {
            if (uncompressed > budgets.max_entry_bytes ||
                compressed > max_archive_bytes) {
                throw std::runtime_error("ZIP entry exceeds the per-entry size budget");
            }
            if (uncompressed != 0 && compressed == 0) {
                throw std::runtime_error("ZIP entry declares an unbounded compression ratio");
            }
            if (compressed != 0 &&
                static_cast<std::uint64_t>(uncompressed) >
                    static_cast<std::uint64_t>(compressed) * budgets.max_ratio) {
                throw std::runtime_error("ZIP entry exceeds the compression-ratio budget");
            }
            add_checked(
                inspection.uncompressed_bytes,
                uncompressed,
                budgets.max_uncompressed_bytes,
                "total uncompressed size");
            add_checked(
                inspection.compressed_bytes,
                compressed,
                max_archive_bytes,
                "total compressed size");
            ++inspection.file_count;
        } else {
            ++inspection.directory_count;
        }
        validate_path_collision(normalized_paths, normalized, directory);

        if (local_offset >= central_offset ||
            central_offset - local_offset < 30u) {
            throw std::runtime_error("ZIP local header offset overlaps the central directory");
        }
        const auto local_header = source.read(local_offset, 30);
        const std::uint32_t local_compressed32 =
            little32(local_header, 18);
        const std::uint32_t local_uncompressed32 =
            little32(local_header, 22);
        if (little32(local_header, 0) != 0x04034b50u ||
            little16(local_header, 6) != flags ||
            little16(local_header, 8) != method ||
            little32(local_header, 14) != crc32 ||
            little16(local_header, 26) != name_size) {
            throw std::runtime_error("ZIP local and central headers disagree");
        }
        const std::uint16_t local_extra_size = little16(local_header, 28);
        const std::uint64_t variable_size =
            static_cast<std::uint64_t>(name_size) + local_extra_size;
        if (variable_size > central_offset - local_offset - 30u) {
            throw std::runtime_error("ZIP local header variable fields overlap the central directory");
        }
        const auto local_variables = source.read(
            local_offset + 30u,
            static_cast<std::size_t>(name_size) + local_extra_size);
        if (std::memcmp(local_variables.data(), raw_name.data(), name_size) != 0) {
            throw std::runtime_error("ZIP local and central entry names disagree");
        }
        const bool local_needs_uncompressed =
            local_uncompressed32 == 0xffffffffu;
        const bool local_needs_compressed =
            local_compressed32 == 0xffffffffu;
        const Zip64Extra local_zip64 = parse_extra_fields(
            local_variables,
            name_size,
            local_extra_size,
            local_needs_uncompressed,
            local_needs_compressed,
            false,
            false);
        const std::uint64_t local_compressed = local_needs_compressed
            ? local_zip64.compressed_size
            : local_compressed32;
        const std::uint64_t local_uncompressed = local_needs_uncompressed
            ? local_zip64.uncompressed_size
            : local_uncompressed32;
        if (local_compressed != compressed ||
            local_uncompressed != uncompressed) {
            throw std::runtime_error(
                "ZIP local and central sizes disagree");
        }
        const std::uint64_t data_offset =
            local_offset + 30u + variable_size;
        if (data_offset > central_offset ||
            compressed > central_offset - data_offset) {
            throw std::runtime_error(
                "ZIP entry payload overlaps the central directory");
        }
        const std::uint64_t data_end = data_offset + compressed;

        inspection.entries.push_back(Entry{
            normalized,
            directory,
            compressed,
            uncompressed,
            method,
            crc32,
            local_offset,
            data_offset,
            data_end});
        position += record_size;
    }
    if (position != central.size()) {
        throw std::runtime_error("ZIP central directory contains trailing or uncounted records");
    }
    std::vector<Entry> physical_entries = inspection.entries;
    std::sort(physical_entries.begin(), physical_entries.end(), [](const Entry& left, const Entry& right) {
        return left.local_header_offset < right.local_header_offset;
    });
    if (physical_entries.empty() || physical_entries.front().local_header_offset != 0) {
        throw std::runtime_error("ZIP archive contains a preamble or has no entry at offset zero");
    }
    for (std::size_t index = 1; index < physical_entries.size(); ++index) {
        if (physical_entries[index - 1].data_end != physical_entries[index].local_header_offset) {
            throw std::runtime_error("ZIP entry ranges overlap or contain ambiguous unclaimed bytes");
        }
    }
    if (physical_entries.back().data_end != central_offset) {
        throw std::runtime_error("ZIP local entries leave ambiguous bytes before the central directory");
    }
    std::sort(inspection.entries.begin(), inspection.entries.end(), [](const Entry& left, const Entry& right) {
        return left.normalized_path < right.normalized_path;
    });
    inspection.entry_set_digest = entry_set_digest(inspection.entries);
    inspection.inspected_at = iso8601_now();
    source.verify_unchanged();
    return inspection;
}

std::string inspection_json(const Inspection& inspection)
{
    std::ostringstream out;
    out << "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\",\"payload\":{";
    out << "\"schema\":\"usk.archive_inspection.v1\",";
    out << "\"inspection_id\":" << quote("inspection." + inspection.entry_set_digest.substr(0, 24)) << ',';
    out << "\"entry_set_digest\":" << quote(inspection.entry_set_digest) << ',';
    out << "\"status\":\"pass\",\"inspected_at\":" << quote(inspection.inspected_at) << ',';
    out << "\"normalization_policy\":\"ascii_case_insensitive_v1\",";
    out << "\"source\":{";
    out << "\"schema\":\"usk.source.v1\",";
    out << "\"source_id\":" << quote("source." + inspection.source_sha256.substr(0, 24)) << ',';
    out << "\"kind\":\"local_archive\",\"path\":" << quote(inspection.path.string()) << ',';
    out << "\"archive_format\":\"zip\",\"size_bytes\":" << inspection.identity.size_bytes << ',';
    out << "\"sha256\":" << quote(inspection.source_sha256) << ',';
    out << "\"filesystem_identity\":{";
    out << "\"volume_id\":" << quote(inspection.identity.volume_id) << ',';
    out << "\"file_id\":" << quote(inspection.identity.file_id) << ',';
    out << "\"size_bytes\":" << inspection.identity.size_bytes << ',';
    out << "\"modified_time_ns\":" << inspection.identity.modified_time_ns << "},";
    out << "\"inspected_at\":" << quote(inspection.inspected_at) << ",\"stable_read\":true,";
    out << "\"budgets\":{";
    out << "\"max_entries\":" << inspection.budgets.max_entries << ',';
    out << "\"max_uncompressed_bytes\":" << inspection.budgets.max_uncompressed_bytes << ',';
    out << "\"max_entry_bytes\":" << inspection.budgets.max_entry_bytes << ',';
    out << "\"max_depth\":" << inspection.budgets.max_depth << ',';
    out << "\"max_ratio\":" << inspection.budgets.max_ratio << ',';
    out << "\"max_elapsed_ms\":" << inspection.budgets.max_elapsed_ms << "}},";
    out << "\"entries\":[";
    for (std::size_t index = 0; index < inspection.entries.size(); ++index) {
        const Entry& entry = inspection.entries[index];
        if (index != 0) out << ',';
        out << "{\"normalized_path\":" << quote(entry.normalized_path) << ',';
        out << "\"entry_type\":" << quote(entry.directory ? "directory" : "file") << ',';
        out << "\"compressed_size\":" << entry.compressed_size << ',';
        out << "\"uncompressed_size\":" << entry.uncompressed_size << ',';
        out << "\"compression_method\":" << quote(entry.compression_method == 0 ? "stored" : "deflate") << ',';
        out << "\"local_header_offset\":" << entry.local_header_offset << '}';
    }
    out << "],\"totals\":{";
    out << "\"file_count\":" << inspection.file_count << ',';
    out << "\"directory_count\":" << inspection.directory_count << ',';
    out << "\"compressed_bytes\":" << inspection.compressed_bytes << ',';
    out << "\"uncompressed_bytes\":" << inspection.uncompressed_bytes;
    out << "},\"problems\":[]},\"error\":null}";
    return out.str();
}

std::string refused_json(const std::string& problem)
{
    return "{\"schema\":\"usk.command_response.v1\",\"status\":\"refused\","
        "\"payload\":null,\"error\":{\"code\":\"archive_inspection_refused\",\"message\":" +
        quote(problem) + "}}";
}

} // namespace

namespace usk::archive {

namespace {

std::uint32_t payload_crc32(const std::vector<unsigned char>& bytes)
{
    std::uint32_t crc = 0xffffffffu;
    for (unsigned char value : bytes) {
        crc ^= value;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

std::string source_identity_digest(const usk::base::StableFileIdentity& identity)
{
    const std::string text = identity.volume_id + "\n" + identity.file_id + "\n" +
        std::to_string(identity.size_bytes) + "\n" + std::to_string(identity.modified_time_ns);
    usk::base::Sha256 digest;
    digest.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
    return digest.finish();
}

std::string strip_entry_path(
    const std::string& entry,
    const std::string& prefix,
    bool directory)
{
    if (prefix.empty()) return entry;
    if (entry == prefix) {
        if (!directory) throw std::runtime_error("strip prefix resolves to a file entry");
        return {};
    }
    const std::string required = prefix + "/";
    if (entry.rfind(required, 0) != 0) {
        throw std::runtime_error("archive entry is outside the reviewed strip prefix");
    }
    return entry.substr(required.size());
}

} // namespace

StoredArchivePayload inspect_stored_payload(
    const std::string& archive_inspection_request_json,
    const std::string& strip_prefix)
{
    Inspection inspection = inspect_zip(archive_inspection_request_json);
    if (inspection.uncompressed_bytes > max_materialized_payload_bytes) {
        throw std::runtime_error("archive payload exceeds the public lifecycle materialization budget");
    }
    std::string normalized_prefix;
    if (!strip_prefix.empty()) {
        bool trailing = false;
        normalized_prefix = normalize_path(strip_prefix, trailing, inspection.budgets);
        if (trailing) throw std::runtime_error("strip prefix must not have a trailing separator");
    }

    usk::base::StableFile source(inspection.path);
    if (source.identity().volume_id != inspection.identity.volume_id ||
        source.identity().file_id != inspection.identity.file_id ||
        source.identity().size_bytes != inspection.identity.size_bytes ||
        source.identity().modified_time_ns != inspection.identity.modified_time_ns) {
        throw std::runtime_error("source archive identity changed after inspection");
    }
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(inspection.budgets.max_elapsed_ms);
    if (hash_source_until(source, deadline) != inspection.source_sha256) {
        throw std::runtime_error("source archive digest changed after inspection");
    }

    StoredArchivePayload result;
    result.source_sha256 = inspection.source_sha256;
    result.source_identity_digest = source_identity_digest(inspection.identity);
    result.entry_set_digest = inspection.entry_set_digest;
    result.archive_size_bytes = inspection.identity.size_bytes;
    std::set<std::string> paths;
    for (const Entry& entry : inspection.entries) {
        const std::string path = strip_entry_path(
            entry.normalized_path, normalized_prefix, entry.directory);
        if (entry.directory || path.empty()) continue;
        if (entry.compression_method != 0 || entry.compressed_size != entry.uncompressed_size) {
            throw std::runtime_error(
                "public lifecycle materialization currently requires stored ZIP file entries");
        }
        if (!paths.insert(lowercase_ascii(path)).second) {
            throw std::runtime_error("strip prefix creates a payload path collision");
        }
        std::vector<unsigned char> bytes = source.read(entry.data_offset, entry.compressed_size);
        if (payload_crc32(bytes) != entry.crc32) {
            throw std::runtime_error("stored ZIP payload CRC does not match reviewed metadata");
        }
        usk::base::Sha256 digest;
        digest.update(bytes.data(), bytes.size());
        result.files.push_back(PayloadFile{path, std::move(bytes), digest.finish()});
        result.uncompressed_bytes += entry.uncompressed_size;
    }
    if (result.files.empty()) throw std::runtime_error("archive payload has no files after strip prefix");
    source.verify_unchanged();
    return result;
}

} // namespace usk::archive

extern "C" char* usk_archive_inspect_command_json(
    const char* request_json,
    size_t request_size,
    int* out_command_status)
{
    if (out_command_status == nullptr) return nullptr;
    std::string response;
    try {
        if (request_json == nullptr || request_size == 0 || request_size > max_request_bytes) {
            throw std::runtime_error("bounded archive inspection request is required");
        }
        response = inspection_json(inspect_zip(std::string(request_json, request_size)));
        *out_command_status = USK_STATUS_OK;
    } catch (const std::exception& error) {
        response = refused_json(error.what());
        *out_command_status = USK_STATUS_ERROR;
    }
    char* result = static_cast<char*>(std::malloc(response.size() + 1));
    if (result == nullptr) {
        *out_command_status = USK_STATUS_ERROR;
        return nullptr;
    }
    std::memcpy(result, response.c_str(), response.size() + 1);
    return result;
}

extern "C" void usk_archive_inspect_command_free(char* value)
{
    std::free(value);
}
