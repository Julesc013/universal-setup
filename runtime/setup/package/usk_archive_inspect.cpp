// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_archive_inspect.h"

#include "usk/usk_result.h"
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
constexpr std::size_t max_name_bytes = 4096u;
constexpr std::size_t max_central_directory_bytes = 64u * 1024u * 1024u;
constexpr std::uint64_t classic_zip_max = 0xffffffffull;

struct Budgets {
    std::uint64_t max_entries = 10000;
    std::uint64_t max_uncompressed_bytes = 64ull * 1024ull * 1024ull * 1024ull;
    std::uint64_t max_entry_bytes = 16ull * 1024ull * 1024ull * 1024ull;
    std::uint64_t max_depth = 64;
    std::uint64_t max_ratio = 1000;
    std::uint64_t max_elapsed_ms = 30000;
};

struct Entry {
    std::string normalized_path;
    bool directory = false;
    std::uint32_t compressed_size = 0;
    std::uint32_t uncompressed_size = 0;
    std::uint16_t compression_method = 0;
    std::uint32_t local_header_offset = 0;
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

std::string json_string(const std::string& text, const std::string& key)
{
    const std::string marker = "\"" + key + "\"";
    std::size_t position = text.find(marker);
    if (position == std::string::npos) return {};
    position = text.find(':', position + marker.size());
    if (position == std::string::npos) return {};
    position = text.find('"', position + 1);
    if (position == std::string::npos) return {};
    std::string value;
    for (++position; position < text.size(); ++position) {
        const char ch = text[position];
        if (ch == '"') return value;
        if (ch != '\\') {
            value.push_back(ch);
            continue;
        }
        if (++position >= text.size()) return {};
        switch (text[position]) {
        case '"': value.push_back('"'); break;
        case '\\': value.push_back('\\'); break;
        case '/': value.push_back('/'); break;
        case 'n': value.push_back('\n'); break;
        case 'r': value.push_back('\r'); break;
        case 't': value.push_back('\t'); break;
        default: return {};
        }
    }
    return {};
}

std::uint64_t json_unsigned(
    const std::string& text,
    const std::string& key,
    std::uint64_t maximum)
{
    const std::string marker = "\"" + key + "\"";
    std::size_t position = text.find(marker);
    if (position == std::string::npos) {
        throw std::runtime_error("required numeric request field is missing: " + key);
    }
    position = text.find(':', position + marker.size());
    if (position == std::string::npos) {
        throw std::runtime_error("malformed numeric request field: " + key);
    }
    ++position;
    while (position < text.size() &&
           std::isspace(static_cast<unsigned char>(text[position]))) {
        ++position;
    }
    if (position >= text.size() || !std::isdigit(static_cast<unsigned char>(text[position]))) {
        throw std::runtime_error("numeric request field must be an unsigned integer: " + key);
    }
    std::uint64_t value = 0;
    while (position < text.size() && std::isdigit(static_cast<unsigned char>(text[position]))) {
        const unsigned int digit = static_cast<unsigned int>(text[position] - '0');
        if (value > (maximum - digit) / 10u) {
            throw std::runtime_error("numeric request field exceeds its hard limit: " + key);
        }
        value = value * 10u + digit;
        ++position;
    }
    if (value == 0 || value > maximum) {
        throw std::runtime_error("numeric request field is outside its allowed range: " + key);
    }
    return value;
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

void validate_extra_fields(
    const std::vector<unsigned char>& data,
    std::size_t offset,
    std::size_t size)
{
    if (offset > data.size() || size > data.size() - offset) {
        throw std::runtime_error("ZIP extra field range is truncated");
    }
    const std::size_t end = offset + size;
    std::set<std::uint16_t> identifiers;
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
        if (identifier == 0x0001u || identifier == 0x7075u || identifier == 0x9901u) {
            throw std::runtime_error("ZIP64, alternate Unicode paths, and AES metadata are unsupported");
        }
        offset += field_size;
    }
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
            std::to_string(entry.compressed_size) + "\0" +
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
    if (json_string(request, "schema") != "usk.archive_inspect_request.v1") {
        throw std::runtime_error("unsupported or missing archive inspection request schema");
    }
    if (json_string(request, "archive_format") != "zip") {
        throw std::runtime_error("WU3 supports only explicitly declared classic ZIP archives");
    }
    const std::string archive_path = json_string(request, "archive_path");
    if (archive_path.empty()) {
        throw std::runtime_error("archive_path is required");
    }

    Budgets budgets;
    budgets.max_entries = json_unsigned(request, "max_entries", 100000);
    budgets.max_uncompressed_bytes = json_unsigned(
        request, "max_uncompressed_bytes", 1ull << 40);
    budgets.max_entry_bytes = json_unsigned(
        request, "max_entry_bytes", 1ull << 38);
    budgets.max_depth = json_unsigned(request, "max_depth", 256);
    budgets.max_ratio = json_unsigned(request, "max_ratio", 100000);
    budgets.max_elapsed_ms = json_unsigned(
        request, "max_elapsed_ms", 120000);

    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(budgets.max_elapsed_ms);
    usk::base::StableFile source(archive_path);
    if (source.identity().size_bytes < 22 || source.identity().size_bytes > classic_zip_max) {
        throw std::runtime_error("source is not a bounded classic ZIP archive");
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
        throw std::runtime_error("classic ZIP end-of-central-directory record is missing or ambiguous");
    }
    if (little16(tail, eocd + 4) != 0 || little16(tail, eocd + 6) != 0) {
        throw std::runtime_error("multi-disk ZIP archives are unsupported");
    }
    const std::uint16_t entries_on_disk = little16(tail, eocd + 8);
    const std::uint16_t entry_count = little16(tail, eocd + 10);
    const std::uint32_t central_size = little32(tail, eocd + 12);
    const std::uint32_t central_offset = little32(tail, eocd + 16);
    if (entries_on_disk == 0xffffu || entry_count == 0xffffu ||
        central_size == 0xffffffffu || central_offset == 0xffffffffu) {
        throw std::runtime_error("ZIP64 archives are unsupported in WU3");
    }
    if (entry_count == 0 || entry_count > budgets.max_entries ||
        central_size > max_central_directory_bytes ||
        static_cast<std::uint64_t>(central_offset) + central_size != tail_offset + eocd ||
        entries_on_disk != entry_count) {
        throw std::runtime_error("ZIP central-directory count, size, or bounds are invalid");
    }
    const auto central = source.read(central_offset, central_size);
    std::size_t position = 0;
    std::map<std::string, bool> normalized_paths;
    inspection.entries.reserve(entry_count);

    for (std::uint32_t index = 0; index < entry_count; ++index) {
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
        const std::uint32_t compressed = little32(central, position + 20);
        const std::uint32_t uncompressed = little32(central, position + 24);
        const std::uint16_t name_size = little16(central, position + 28);
        const std::uint16_t extra_size = little16(central, position + 30);
        const std::uint16_t comment_size = little16(central, position + 32);
        const std::uint16_t disk_start = little16(central, position + 34);
        const std::uint32_t external_attributes = little32(central, position + 38);
        const std::uint32_t local_offset = little32(central, position + 42);
        const std::size_t record_size = 46u + name_size + extra_size + comment_size;
        if (record_size > central.size() - position || name_size == 0) {
            throw std::runtime_error("ZIP central-directory variable fields are truncated");
        }
        if (compressed == 0xffffffffu || uncompressed == 0xffffffffu ||
            local_offset == 0xffffffffu) {
            throw std::runtime_error("ZIP64 entry metadata is unsupported in WU3");
        }
        if (disk_start != 0 || (flags & (0x0001u | 0x0008u | 0x0020u | 0x0040u | 0x2000u)) != 0) {
            throw std::runtime_error("encrypted, streamed, patched, masked, or multi-disk ZIP entries are unsupported");
        }
        if (method != 0 && method != 8) {
            throw std::runtime_error("ZIP entry uses an unsupported compression method");
        }
        const std::string raw_name(
            reinterpret_cast<const char*>(central.data() + position + 46),
            name_size);
        validate_extra_fields(central, position + 46 + name_size, extra_size);

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
            if (uncompressed > budgets.max_entry_bytes) {
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
                classic_zip_max,
                "total compressed size");
            ++inspection.file_count;
        } else {
            ++inspection.directory_count;
        }
        validate_path_collision(normalized_paths, normalized, directory);

        if (local_offset >= central_offset ||
            static_cast<std::uint64_t>(local_offset) + 30u > central_offset) {
            throw std::runtime_error("ZIP local header offset overlaps the central directory");
        }
        const auto local_header = source.read(local_offset, 30);
        if (little32(local_header, 0) != 0x04034b50u ||
            little16(local_header, 6) != flags ||
            little16(local_header, 8) != method ||
            little32(local_header, 14) != crc32 ||
            little32(local_header, 18) != compressed ||
            little32(local_header, 22) != uncompressed ||
            little16(local_header, 26) != name_size) {
            throw std::runtime_error("ZIP local and central headers disagree");
        }
        const std::uint16_t local_extra_size = little16(local_header, 28);
        const std::uint64_t data_offset =
            static_cast<std::uint64_t>(local_offset) + 30u + name_size + local_extra_size;
        const std::uint64_t data_end = data_offset + compressed;
        if (data_offset > central_offset || data_end > central_offset) {
            throw std::runtime_error("ZIP local header variable fields overlap the central directory");
        }
        const auto local_variables = source.read(
            static_cast<std::uint64_t>(local_offset) + 30u,
            static_cast<std::size_t>(name_size) + local_extra_size);
        if (std::memcmp(local_variables.data(), raw_name.data(), name_size) != 0) {
            throw std::runtime_error("ZIP local and central entry names disagree");
        }
        validate_extra_fields(local_variables, name_size, local_extra_size);

        inspection.entries.push_back(Entry{
            normalized,
            directory,
            compressed,
            uncompressed,
            method,
            local_offset,
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
