// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk/usk_api.h"
#include "usk_archive_payload.h"
#include "usk_sha256.h"
#include "usk_utf8_path.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace {

struct ZipEntry {
    std::string name;
    std::string data;
    std::uint32_t external_attributes = (0100644u << 16);
    std::uint16_t flags = 0;
    std::uint16_t method = 0;
    std::optional<std::uint32_t> compressed_size;
    std::optional<std::uint32_t> uncompressed_size;
    std::string local_name;
    std::vector<unsigned char> local_extra;
    std::vector<unsigned char> central_extra;
    std::optional<std::string> uncompressed_data;
    std::optional<std::uint32_t> crc32_value;
    bool zip64_sizes = false;
};

struct WrittenEntry {
    ZipEntry entry;
    std::uint32_t local_offset = 0;
};

std::uint32_t crc32(const std::string& data)
{
    std::uint32_t crc = 0xffffffffu;
    for (unsigned char value : data) {
        crc ^= value;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

const std::string& logical_data(const ZipEntry& entry)
{
    return entry.uncompressed_data.has_value()
        ? *entry.uncompressed_data
        : entry.data;
}

std::string bytes_from_hex(const std::string& value)
{
    if (value.size() % 2u != 0u) {
        throw std::runtime_error("hex fixture length is invalid");
    }
    std::string result;
    result.reserve(value.size() / 2u);
    for (std::size_t index = 0; index < value.size(); index += 2u) {
        result.push_back(static_cast<char>(std::stoul(value.substr(index, 2u), nullptr, 16)));
    }
    return result;
}

ZipEntry deflate_entry(
    std::string name,
    const std::string& compressed_hex,
    std::string plain)
{
    ZipEntry result;
    result.name = std::move(name);
    result.data = bytes_from_hex(compressed_hex);
    result.method = 8;
    result.uncompressed_data = std::move(plain);
    return result;
}

std::string read_streaming_file(const usk::archive::StreamingPayloadFile& file)
{
    std::string result;
    result.resize(static_cast<std::size_t>(file.size_bytes));
    std::uint64_t offset = 0;
    while (offset < file.size_bytes) {
        const std::size_t capacity = static_cast<std::size_t>(
            std::min<std::uint64_t>(37u, file.size_bytes - offset));
        const std::size_t count = file.reader(
            offset,
            reinterpret_cast<unsigned char*>(result.data()) + offset,
            capacity);
        if (count == 0u || count > capacity) {
            throw std::runtime_error("streaming fixture reader returned an invalid count");
        }
        offset += count;
    }
    unsigned char probe = 0;
    if (file.reader(offset, &probe, 1u) != 0u) {
        throw std::runtime_error("streaming fixture exceeded its reviewed size");
    }
    return result;
}

void append16(std::vector<unsigned char>& output, std::uint16_t value)
{
    output.push_back(static_cast<unsigned char>(value & 0xffu));
    output.push_back(static_cast<unsigned char>((value >> 8) & 0xffu));
}

void append32(std::vector<unsigned char>& output, std::uint32_t value)
{
    append16(output, static_cast<std::uint16_t>(value & 0xffffu));
    append16(output, static_cast<std::uint16_t>((value >> 16) & 0xffffu));
}

void append64(std::vector<unsigned char>& output, std::uint64_t value)
{
    append32(output, static_cast<std::uint32_t>(value & 0xffffffffu));
    append32(output, static_cast<std::uint32_t>(value >> 32));
}

void append_text(std::vector<unsigned char>& output, const std::string& value)
{
    output.insert(output.end(), value.begin(), value.end());
}

void append_bytes(
    std::vector<unsigned char>& output,
    const std::vector<unsigned char>& value)
{
    output.insert(output.end(), value.begin(), value.end());
}

void write16(std::ostream& output, std::uint16_t value)
{
    const std::array<unsigned char, 2> bytes = {
        static_cast<unsigned char>(value & 0xffu),
        static_cast<unsigned char>((value >> 8) & 0xffu)};
    output.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
}

void write32(std::ostream& output, std::uint32_t value)
{
    write16(output, static_cast<std::uint16_t>(value & 0xffffu));
    write16(output, static_cast<std::uint16_t>((value >> 16) & 0xffffu));
}

const std::array<std::uint32_t, 256>& crc32_table()
{
    static const std::array<std::uint32_t, 256> table = [] {
        std::array<std::uint32_t, 256> values{};
        for (std::uint32_t index = 0; index < values.size(); ++index) {
            std::uint32_t value = index;
            for (int bit = 0; bit < 8; ++bit) {
                value = (value >> 1) ^
                    (0xedb88320u & (0u - (value & 1u)));
            }
            values[index] = value;
        }
        return values;
    }();
    return table;
}

void write_repeated_stored_zip(
    const fs::path& path,
    const std::string& name,
    unsigned char value,
    std::uint32_t size)
{
    std::fstream output(
        path,
        std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
    if (!output) throw std::runtime_error("could not create large ZIP fixture");

    write32(output, 0x04034b50u);
    write16(output, 20);
    write16(output, 0);
    write16(output, 0);
    write16(output, 0);
    write16(output, 0);
    const std::streampos local_crc_offset = output.tellp();
    write32(output, 0);
    write32(output, size);
    write32(output, size);
    write16(output, static_cast<std::uint16_t>(name.size()));
    write16(output, 0);
    output.write(name.data(), static_cast<std::streamsize>(name.size()));

    constexpr std::size_t fixture_buffer_bytes = 1024u * 1024u;
    const std::array<std::uint32_t, 256>& table = crc32_table();
    std::vector<unsigned char> buffer(fixture_buffer_bytes, value);
    std::uint32_t crc = 0xffffffffu;
    std::uint64_t remaining = size;
    while (remaining != 0u) {
        const std::size_t count = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, buffer.size()));
        output.write(
            reinterpret_cast<const char*>(buffer.data()),
            static_cast<std::streamsize>(count));
        for (std::size_t index = 0; index < count; ++index) {
            crc = (crc >> 8) ^ table[(crc ^ buffer[index]) & 0xffu];
        }
        remaining -= count;
    }
    crc = ~crc;
    const std::streampos central_offset = output.tellp();

    output.seekp(local_crc_offset);
    write32(output, crc);
    output.seekp(central_offset);
    write32(output, 0x02014b50u);
    write16(output, static_cast<std::uint16_t>((3u << 8) | 20u));
    write16(output, 20);
    write16(output, 0);
    write16(output, 0);
    write16(output, 0);
    write16(output, 0);
    write32(output, crc);
    write32(output, size);
    write32(output, size);
    write16(output, static_cast<std::uint16_t>(name.size()));
    write16(output, 0);
    write16(output, 0);
    write16(output, 0);
    write16(output, 0);
    write32(output, 0100644u << 16);
    write32(output, 0);
    output.write(name.data(), static_cast<std::streamsize>(name.size()));
    const std::uint32_t central_size = static_cast<std::uint32_t>(
        output.tellp() - central_offset);
    write32(output, 0x06054b50u);
    write16(output, 0);
    write16(output, 0);
    write16(output, 1);
    write16(output, 1);
    write32(output, central_size);
    write32(output, static_cast<std::uint32_t>(central_offset));
    write16(output, 0);
    if (!output) throw std::runtime_error("could not write large ZIP fixture");
}

void write_repeated_deflate_zip(
    const fs::path& path,
    const std::string& name,
    unsigned char value,
    std::uint32_t size)
{
    constexpr std::uint32_t max_block = 65535u;
    const std::uint32_t block_count =
        size == 0u ? 1u : (size + max_block - 1u) / max_block;
    const std::uint32_t compressed_size = size + block_count * 5u;
    std::fstream output(
        path,
        std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
    if (!output) throw std::runtime_error("could not create large Deflate ZIP fixture");

    write32(output, 0x04034b50u);
    write16(output, 20);
    write16(output, 0);
    write16(output, 8);
    write16(output, 0);
    write16(output, 0);
    const std::streampos local_crc_offset = output.tellp();
    write32(output, 0);
    write32(output, compressed_size);
    write32(output, size);
    write16(output, static_cast<std::uint16_t>(name.size()));
    write16(output, 0);
    output.write(name.data(), static_cast<std::streamsize>(name.size()));

    constexpr std::size_t fixture_buffer_bytes = 1024u * 1024u;
    const std::array<std::uint32_t, 256>& table = crc32_table();
    std::vector<unsigned char> buffer(fixture_buffer_bytes, value);
    std::uint32_t crc = 0xffffffffu;
    std::uint64_t remaining = size;
    for (std::uint32_t block = 0; block < block_count; ++block) {
        const std::uint16_t count = static_cast<std::uint16_t>(
            std::min<std::uint64_t>(remaining, max_block));
        output.put(static_cast<char>(block + 1u == block_count ? 0x01 : 0x00));
        write16(output, count);
        write16(output, static_cast<std::uint16_t>(~count));
        std::uint32_t block_remaining = count;
        while (block_remaining != 0u) {
            const std::size_t chunk = std::min<std::size_t>(
                block_remaining, buffer.size());
            output.write(
                reinterpret_cast<const char*>(buffer.data()),
                static_cast<std::streamsize>(chunk));
            for (std::size_t index = 0; index < chunk; ++index) {
                crc = (crc >> 8) ^ table[(crc ^ buffer[index]) & 0xffu];
            }
            block_remaining -= static_cast<std::uint32_t>(chunk);
            remaining -= chunk;
        }
    }
    crc = ~crc;
    const std::streampos central_offset = output.tellp();
    output.seekp(local_crc_offset);
    write32(output, crc);
    output.seekp(central_offset);
    write32(output, 0x02014b50u);
    write16(output, static_cast<std::uint16_t>((3u << 8) | 20u));
    write16(output, 20);
    write16(output, 0);
    write16(output, 8);
    write16(output, 0);
    write16(output, 0);
    write32(output, crc);
    write32(output, compressed_size);
    write32(output, size);
    write16(output, static_cast<std::uint16_t>(name.size()));
    write16(output, 0);
    write16(output, 0);
    write16(output, 0);
    write16(output, 0);
    write32(output, 0100644u << 16);
    write32(output, 0);
    output.write(name.data(), static_cast<std::streamsize>(name.size()));
    const std::uint32_t central_size = static_cast<std::uint32_t>(
        output.tellp() - central_offset);
    write32(output, 0x06054b50u);
    write16(output, 0);
    write16(output, 0);
    write16(output, 1);
    write16(output, 1);
    write32(output, central_size);
    write32(output, static_cast<std::uint32_t>(central_offset));
    write16(output, 0);
    if (!output || remaining != 0u) {
        throw std::runtime_error("could not write large Deflate ZIP fixture");
    }
}

void write_zip(const fs::path& path, const std::vector<ZipEntry>& specs)
{
    std::vector<unsigned char> bytes;
    std::vector<WrittenEntry> entries;
    for (const ZipEntry& spec : specs) {
        WrittenEntry written;
        written.entry = spec;
        written.local_offset = static_cast<std::uint32_t>(bytes.size());
        entries.push_back(written);
        const std::string& local_name = spec.local_name.empty() ? spec.name : spec.local_name;
        const std::uint32_t compressed = spec.compressed_size.value_or(
            static_cast<std::uint32_t>(spec.data.size()));
        const std::uint32_t uncompressed = spec.uncompressed_size.value_or(
            static_cast<std::uint32_t>(logical_data(spec).size()));
        append32(bytes, 0x04034b50u);
        append16(bytes, 20);
        append16(bytes, spec.flags);
        append16(bytes, spec.method);
        append16(bytes, 0);
        append16(bytes, 0);
        append32(bytes, spec.crc32_value.value_or(crc32(logical_data(spec))));
        append32(bytes, compressed);
        append32(bytes, uncompressed);
        append16(bytes, static_cast<std::uint16_t>(local_name.size()));
        append16(bytes, static_cast<std::uint16_t>(spec.local_extra.size()));
        append_text(bytes, local_name);
        append_bytes(bytes, spec.local_extra);
        append_text(bytes, spec.data);
    }

    const std::uint32_t central_offset = static_cast<std::uint32_t>(bytes.size());
    for (const WrittenEntry& written : entries) {
        const ZipEntry& spec = written.entry;
        const std::uint32_t compressed = spec.compressed_size.value_or(
            static_cast<std::uint32_t>(spec.data.size()));
        const std::uint32_t uncompressed = spec.uncompressed_size.value_or(
            static_cast<std::uint32_t>(logical_data(spec).size()));
        append32(bytes, 0x02014b50u);
        append16(bytes, static_cast<std::uint16_t>((3u << 8) | 20u));
        append16(bytes, 20);
        append16(bytes, spec.flags);
        append16(bytes, spec.method);
        append16(bytes, 0);
        append16(bytes, 0);
        append32(bytes, spec.crc32_value.value_or(crc32(logical_data(spec))));
        append32(bytes, compressed);
        append32(bytes, uncompressed);
        append16(bytes, static_cast<std::uint16_t>(spec.name.size()));
        append16(bytes, static_cast<std::uint16_t>(spec.central_extra.size()));
        append16(bytes, 0);
        append16(bytes, 0);
        append16(bytes, 0);
        append32(bytes, spec.external_attributes);
        append32(bytes, written.local_offset);
        append_text(bytes, spec.name);
        append_bytes(bytes, spec.central_extra);
    }
    const std::uint32_t central_size =
        static_cast<std::uint32_t>(bytes.size()) - central_offset;
    append32(bytes, 0x06054b50u);
    append16(bytes, 0);
    append16(bytes, 0);
    append16(bytes, static_cast<std::uint16_t>(entries.size()));
    append16(bytes, static_cast<std::uint16_t>(entries.size()));
    append32(bytes, central_size);
    append32(bytes, central_offset);
    append16(bytes, 0);

    std::ofstream output(path, std::ios::binary);
    output.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
}

void write_zip64(const fs::path& path, const std::vector<ZipEntry>& specs)
{
    std::vector<unsigned char> bytes;
    std::vector<WrittenEntry> entries;
    for (const ZipEntry& spec : specs) {
        WrittenEntry written;
        written.entry = spec;
        written.local_offset = static_cast<std::uint32_t>(bytes.size());
        entries.push_back(written);
        const std::string& local_name =
            spec.local_name.empty() ? spec.name : spec.local_name;
        const std::uint32_t compressed = spec.compressed_size.value_or(
            static_cast<std::uint32_t>(spec.data.size()));
        const std::uint32_t uncompressed = spec.uncompressed_size.value_or(
            static_cast<std::uint32_t>(logical_data(spec).size()));
        append32(bytes, 0x04034b50u);
        append16(bytes, 45);
        append16(bytes, spec.flags);
        append16(bytes, spec.method);
        append16(bytes, 0);
        append16(bytes, 0);
        append32(bytes, spec.crc32_value.value_or(crc32(logical_data(spec))));
        append32(bytes, spec.zip64_sizes ? 0xffffffffu : compressed);
        append32(bytes, spec.zip64_sizes ? 0xffffffffu : uncompressed);
        append16(bytes, static_cast<std::uint16_t>(local_name.size()));
        std::vector<unsigned char> local_extra = spec.local_extra;
        if (spec.zip64_sizes) {
            append16(local_extra, 0x0001u);
            append16(local_extra, 16u);
            append64(local_extra, uncompressed);
            append64(local_extra, compressed);
        }
        append16(bytes, static_cast<std::uint16_t>(local_extra.size()));
        append_text(bytes, local_name);
        append_bytes(bytes, local_extra);
        append_text(bytes, spec.data);
    }

    const std::uint64_t central_offset = bytes.size();
    for (const WrittenEntry& written : entries) {
        const ZipEntry& spec = written.entry;
        const std::uint32_t compressed = spec.compressed_size.value_or(
            static_cast<std::uint32_t>(spec.data.size()));
        const std::uint32_t uncompressed = spec.uncompressed_size.value_or(
            static_cast<std::uint32_t>(logical_data(spec).size()));
        std::vector<unsigned char> central_extra = spec.central_extra;
        append16(central_extra, 0x0001u);
        append16(central_extra, spec.zip64_sizes ? 24u : 8u);
        if (spec.zip64_sizes) {
            append64(central_extra, uncompressed);
            append64(central_extra, compressed);
        }
        append64(central_extra, written.local_offset);
        append32(bytes, 0x02014b50u);
        append16(bytes, static_cast<std::uint16_t>((3u << 8) | 45u));
        append16(bytes, 45);
        append16(bytes, spec.flags);
        append16(bytes, spec.method);
        append16(bytes, 0);
        append16(bytes, 0);
        append32(bytes, spec.crc32_value.value_or(crc32(logical_data(spec))));
        append32(bytes, spec.zip64_sizes ? 0xffffffffu : compressed);
        append32(bytes, spec.zip64_sizes ? 0xffffffffu : uncompressed);
        append16(bytes, static_cast<std::uint16_t>(spec.name.size()));
        append16(bytes, static_cast<std::uint16_t>(central_extra.size()));
        append16(bytes, 0);
        append16(bytes, 0);
        append16(bytes, 0);
        append32(bytes, spec.external_attributes);
        append32(bytes, 0xffffffffu);
        append_text(bytes, spec.name);
        append_bytes(bytes, central_extra);
    }
    const std::uint64_t central_size = bytes.size() - central_offset;
    const std::uint64_t zip64_offset = bytes.size();
    append32(bytes, 0x06064b50u);
    append64(bytes, 44u);
    append16(bytes, 45);
    append16(bytes, 45);
    append32(bytes, 0);
    append32(bytes, 0);
    append64(bytes, entries.size());
    append64(bytes, entries.size());
    append64(bytes, central_size);
    append64(bytes, central_offset);
    append32(bytes, 0x07064b50u);
    append32(bytes, 0);
    append64(bytes, zip64_offset);
    append32(bytes, 1);
    append32(bytes, 0x06054b50u);
    append16(bytes, 0);
    append16(bytes, 0);
    append16(bytes, 0xffffu);
    append16(bytes, 0xffffu);
    append32(bytes, 0xffffffffu);
    append32(bytes, 0xffffffffu);
    append16(bytes, 0);

    std::ofstream output(path, std::ios::binary);
    output.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
}

std::string json_escape(const std::string& value)
{
    std::string result;
    for (char ch : value) {
        if (ch == '\\' || ch == '"') result.push_back('\\');
        result.push_back(ch);
    }
    return result;
}

std::string request_json_from_utf8_path(
    const std::string& archive_path,
    int max_entries = 100,
    int max_depth = 32,
    int max_ratio = 100,
    std::uint64_t max_uncompressed_bytes = 1048576,
    std::uint64_t max_entry_bytes = 524288,
    std::uint64_t max_elapsed_ms = 30000)
{
    return "{\"schema\":\"usk.archive_inspect_request.v1\","
        "\"archive_path\":\"" + json_escape(archive_path) + "\","
        "\"archive_format\":\"zip\",\"budgets\":{"
        "\"max_entries\":" + std::to_string(max_entries) + ","
        "\"max_uncompressed_bytes\":" +
        std::to_string(max_uncompressed_bytes) +
        ",\"max_entry_bytes\":" + std::to_string(max_entry_bytes) + ","
        "\"max_depth\":" + std::to_string(max_depth) + ","
        "\"max_ratio\":" + std::to_string(max_ratio) + ","
        "\"max_elapsed_ms\":" + std::to_string(max_elapsed_ms) + "}}";
}

std::string request_json(
    const fs::path& archive,
    int max_entries = 100,
    int max_depth = 32,
    int max_ratio = 100,
    std::uint64_t max_uncompressed_bytes = 1048576,
    std::uint64_t max_entry_bytes = 524288,
    std::uint64_t max_elapsed_ms = 30000)
{
    return request_json_from_utf8_path(
        archive.u8string(),
        max_entries,
        max_depth,
        max_ratio,
        max_uncompressed_bytes,
        max_entry_bytes,
        max_elapsed_ms);
}

std::string reordered_request_json(const fs::path& archive)
{
    return "{\n  \"budgets\": {"
        "\"max_elapsed_ms\":30000,\"max_ratio\":100,\"max_depth\":32,"
        "\"max_entry_bytes\":524288,\"max_uncompressed_bytes\":1048576,"
        "\"max_entries\":100},\n"
        "  \"archive_format\": \"zip\",\n"
        "  \"archive_path\": \"" + json_escape(archive.u8string()) + "\",\n"
        "  \"schema\": \"usk.archive_inspect_request.v1\"\n}";
}

std::string replace_once(
    std::string value,
    const std::string& from,
    const std::string& to)
{
    const std::size_t position = value.find(from);
    if (position == std::string::npos) {
        throw std::runtime_error("test request mutation target is missing: " + from);
    }
    value.replace(position, from.size(), to);
    return value;
}

std::string execute_raw(
    usk_context* context,
    const std::string& payload,
    int& status)
{
    usk_command_request_v1 request{};
    usk_command_response_v1 response{};
    request.struct_size = sizeof(request);
    request.command_name = {"install_local.inspect", 21};
    request.json_payload = {payload.data(), static_cast<usk_size>(payload.size())};
    request.dry_run = 1;
    response.struct_size = sizeof(response);
    status = usk_command_execute_v1(context, &request, &response);
    return response.json_payload.data == nullptr
        ? std::string()
        : std::string(response.json_payload.data, response.json_payload.size);
}

std::string execute(
    usk_context* context,
    const fs::path& archive,
    int& status,
    int max_entries = 100,
    int max_depth = 32,
    int max_ratio = 100)
{
    return execute_raw(
        context,
        request_json(archive, max_entries, max_depth, max_ratio),
        status);
}

bool contains(const std::string& value, const std::string& expected)
{
    return value.find(expected) != std::string::npos;
}

std::string field(const std::string& value, const std::string& name)
{
    const std::string marker = "\"" + name + "\":\"";
    const std::size_t begin = value.find(marker);
    if (begin == std::string::npos) return {};
    const std::size_t start = begin + marker.size();
    const std::size_t end = value.find('"', start);
    return end == std::string::npos ? std::string() : value.substr(start, end - start);
}

bool refused(
    usk_context* context,
    const fs::path& path,
    const std::string& reason,
    int max_entries = 100,
    int max_depth = 32,
    int max_ratio = 100)
{
    int status = 0;
    const std::string response = execute(
        context, path, status, max_entries, max_depth, max_ratio);
    return status == USK_STATUS_ERROR &&
        contains(response, "\"status\":\"refused\"") &&
        contains(response, "\"code\":\"archive_inspection_refused\"") &&
        contains(response, reason);
}

bool request_refused(
    usk_context* context,
    const std::string& request,
    const std::string& reason)
{
    int status = 0;
    const std::string response = execute_raw(context, request, status);
    return status == USK_STATUS_ERROR &&
        contains(response, "\"status\":\"refused\"") &&
        contains(response, "\"code\":\"archive_inspection_refused\"") &&
        contains(response, reason);
}

} // namespace

int main()
{
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path root = fs::temp_directory_path() /
        ("usk-archive-inspect-" + std::to_string(nonce));
    std::error_code error;
    fs::create_directories(root, error);
    if (error) return 1;

    usk_context* context = nullptr;
    if (usk_context_create_v1(nullptr, &context) != USK_STATUS_OK) return 2;

    const fs::path valid = root / "valid.zip";
    write_zip(valid, {
        {"app/", "", (0040755u << 16) | 0x10u},
        {"app/bin/tool.exe", "binary"},
        {"app/data/config.ini", "config"}
    });
    int status = 0;
    const std::string valid_response = execute(context, valid, status);
    if (status != USK_STATUS_OK ||
        !contains(valid_response, "\"schema\":\"usk.archive_inspection.v1\"") ||
        !contains(valid_response, "\"stable_read\":true") ||
        !contains(valid_response, "\"file_count\":2") ||
        !contains(valid_response, "\"directory_count\":1") ||
        !contains(valid_response, "\"normalized_path\":\"app/bin/tool.exe\"") ||
        field(valid_response, "entry_set_digest").size() != 64 ||
        field(valid_response, "sha256").size() != 64) {
        return 3;
    }
    const std::string preferred_separator(1, fs::path::preferred_separator);
    const std::string valid_parent = valid.parent_path().u8string();
    const std::string valid_name = valid.filename().u8string();
    struct SourcePathRefusalCase {
        std::string path;
        const char* reason;
    };
    const std::vector<SourcePathRefusalCase> source_path_refusals = {
        {valid_name, "absolute local filesystem path"},
        {valid_parent + preferred_separator + "." + preferred_separator + valid_name,
         "lexically normalized"},
        {valid_parent + preferred_separator + "unused" + preferred_separator + ".." +
             preferred_separator + valid_name,
         "lexically normalized"},
        {valid_parent + preferred_separator + preferred_separator + valid_name,
         "lexically normalized"},
        {"C:valid.zip", "absolute local filesystem path"},
        {"\\\\server\\share\\archive.zip", "UNC or device namespace"},
        {"//server/share/archive.zip", "UNC or device namespace"}
    };
    for (std::size_t index = 0; index < source_path_refusals.size(); ++index) {
        const SourcePathRefusalCase& refusal = source_path_refusals[index];
        if (!request_refused(
                context,
                request_json_from_utf8_path(refusal.path),
                refusal.reason)) {
            return static_cast<int>(110 + index);
        }
    }

    const fs::path utf8_path = root / fs::u8path("valid-\xc3\xa9.zip");
    write_zip(utf8_path, {{"payload.txt", "utf8"}});
    const std::string utf8_response = execute(context, utf8_path, status);
    if (status != USK_STATUS_OK ||
        !contains(
            utf8_response,
            "\"path\":\"" + json_escape(utf8_path.u8string()) + "\"") ||
        field(utf8_response, "sha256").size() != 64) {
        return 19;
    }
    const std::string utf8_path_identity = utf8_path.u8string();
    const fs::path rebuilt_utf8_path =
        usk::base::require_normalized_absolute_local_path_utf8(
            utf8_path_identity, "archive_path");
    if (usk::base::path_to_utf8(rebuilt_utf8_path) != utf8_path_identity) {
        return 20;
    }
#if defined(_WIN32)
    if (rebuilt_utf8_path.native() != utf8_path.native() ||
        rebuilt_utf8_path.native().find(L'\u00e9') == std::wstring::npos) {
        return 118;
    }
#endif
    const std::string reordered_request_response = execute_raw(
        context, reordered_request_json(valid), status);
    if (status != USK_STATUS_OK ||
        field(reordered_request_response, "entry_set_digest") !=
            field(valid_response, "entry_set_digest")) {
        return 15;
    }
    const usk::archive::StoredArchivePayload payload =
        usk::archive::inspect_stored_payload(request_json(valid), "app");
    if (payload.source_sha256 != field(valid_response, "sha256") ||
        payload.source_identity_digest.size() != 64 ||
        payload.entry_set_digest != field(valid_response, "entry_set_digest") ||
        payload.archive_size_bytes != fs::file_size(valid) ||
        payload.uncompressed_bytes != 12 ||
        payload.files.size() != 2 ||
        payload.files[0].relative_path != "bin/tool.exe" ||
        std::string(payload.files[0].bytes.begin(), payload.files[0].bytes.end()) != "binary" ||
        payload.files[0].sha256.size() != 64 ||
        payload.files[1].relative_path != "data/config.ini" ||
        std::string(payload.files[1].bytes.begin(), payload.files[1].bytes.end()) != "config" ||
        payload.files[1].sha256.size() != 64) {
        return 8;
    }

    const fs::path small_memory_zip = root / "memory-small.zip";
    write_zip(small_memory_zip, {
        {"payload/a.bin", std::string(64u * 1024u, 'a')},
        {"payload/b.bin", std::string(64u * 1024u, 'b')}
    });
    usk::archive::PayloadMemoryObservation small_memory;
    const auto small_payload = usk::archive::inspect_stored_payload(
        request_json(small_memory_zip), "payload", &small_memory);

    const fs::path large_memory_zip = root / "memory-large.zip";
    write_zip(large_memory_zip, {
        {"payload/a.bin", std::string(4u * 1024u * 1024u, 'a')},
        {"payload/b.bin", std::string(2u * 1024u * 1024u, 'b')}
    });
    usk::archive::PayloadMemoryObservation large_memory;
    const auto large_payload = usk::archive::inspect_stored_payload(
        request_json(
            large_memory_zip,
            100,
            32,
            100,
            8u * 1024u * 1024u,
            4u * 1024u * 1024u),
        "payload",
        &large_memory);
    if (!small_memory.complete_payload_retained ||
        !large_memory.complete_payload_retained ||
        small_memory.file_count != 2 || large_memory.file_count != 2 ||
        small_memory.final_payload_size_bytes != small_payload.uncompressed_bytes ||
        large_memory.final_payload_size_bytes != large_payload.uncompressed_bytes ||
        small_memory.final_payload_capacity_bytes < small_payload.uncompressed_bytes ||
        large_memory.final_payload_capacity_bytes < large_payload.uncompressed_bytes ||
        small_memory.peak_payload_capacity_bytes <
            small_memory.final_payload_capacity_bytes ||
        large_memory.peak_payload_capacity_bytes <
            large_memory.final_payload_capacity_bytes ||
        large_memory.peak_payload_capacity_bytes <=
            small_memory.peak_payload_capacity_bytes ||
        large_memory.peak_payload_capacity_bytes >
            large_memory.materialization_ceiling_bytes ||
        large_memory.materialization_ceiling_bytes != 512ull * 1024ull * 1024ull ||
        large_memory.largest_entry_bytes != 4ull * 1024ull * 1024ull) {
        return 121;
    }
    std::cout
        << "payload-memory-characterization: {\"schema\":\"usk.payload_memory_characterization.v1\""
        << ",\"materialization_ceiling_bytes\":"
        << large_memory.materialization_ceiling_bytes
        << ",\"small_logical_bytes\":" << small_memory.final_payload_size_bytes
        << ",\"small_peak_capacity_bytes\":"
        << small_memory.peak_payload_capacity_bytes
        << ",\"large_logical_bytes\":" << large_memory.final_payload_size_bytes
        << ",\"large_peak_capacity_bytes\":"
        << large_memory.peak_payload_capacity_bytes
        << ",\"complete_payload_retained\":true}\n";

    {
    constexpr std::size_t streaming_buffer_bytes = 64u * 1024u;
    usk::archive::StreamingPayloadMemoryObservation small_streaming_memory;
    const auto small_streaming = usk::archive::inspect_streaming_stored_payload(
        request_json(small_memory_zip),
        "payload",
        streaming_buffer_bytes,
        &small_streaming_memory);
    usk::archive::StreamingPayloadMemoryObservation large_streaming_memory;
    const auto large_streaming = usk::archive::inspect_streaming_stored_payload(
        request_json(
            large_memory_zip,
            100,
            32,
            100,
            8u * 1024u * 1024u,
            4u * 1024u * 1024u),
        "payload",
        streaming_buffer_bytes,
        &large_streaming_memory);
    if (small_streaming_memory.complete_payload_retained ||
        large_streaming_memory.complete_payload_retained ||
        small_streaming_memory.file_count != 2 ||
        large_streaming_memory.file_count != 2 ||
        small_streaming_memory.logical_payload_bytes !=
            small_streaming.uncompressed_bytes ||
        large_streaming_memory.logical_payload_bytes !=
            large_streaming.uncompressed_bytes ||
        small_streaming_memory.peak_payload_buffer_bytes !=
            streaming_buffer_bytes ||
        large_streaming_memory.peak_payload_buffer_bytes !=
            streaming_buffer_bytes ||
        small_streaming.files.front().size_bytes != 64u * 1024u ||
        !small_streaming.files.front().reader) {
        return 122;
    }
    usk::base::Sha256 streamed_digest;
    std::vector<unsigned char> stream_buffer(4096u);
    std::uint64_t streamed_offset = 0;
    while (streamed_offset < small_streaming.files.front().size_bytes) {
        const std::size_t count = small_streaming.files.front().reader(
            streamed_offset, stream_buffer.data(), stream_buffer.size());
        if (count == 0u || count > stream_buffer.size()) return 123;
        streamed_digest.update(stream_buffer.data(), count);
        streamed_offset += count;
    }
    if (small_streaming.files.front().reader(
            streamed_offset, stream_buffer.data(), 1u) != 0u ||
        streamed_digest.finish() != small_streaming.files.front().sha256) {
        return 124;
    }
    for (const std::size_t invalid_budget : {
             4095u,
             4u * 1024u * 1024u}) {
        bool invalid_streaming_budget_refused = false;
        try {
            (void)usk::archive::inspect_streaming_stored_payload(
                request_json(small_memory_zip), "payload", invalid_budget);
        } catch (const std::exception& exception) {
            invalid_streaming_budget_refused =
                contains(exception.what(), "buffer budget");
        }
        if (!invalid_streaming_budget_refused) return 125;
    }
    std::size_t cancellation_checks = 0;
    bool streaming_cancellation_refused = false;
    try {
        (void)usk::archive::inspect_streaming_stored_payload(
            request_json(small_memory_zip),
            "payload",
            streaming_buffer_bytes,
            nullptr,
            [&]() { return ++cancellation_checks >= 3u; });
    } catch (const std::exception& exception) {
        streaming_cancellation_refused = contains(exception.what(), "cancelled");
    }
    if (!streaming_cancellation_refused) return 126;
    std::cout
        << "payload-streaming-characterization: {\"schema\":"
           "\"usk.payload_streaming_characterization.v1\""
        << ",\"small_logical_bytes\":"
        << small_streaming_memory.logical_payload_bytes
        << ",\"large_logical_bytes\":"
        << large_streaming_memory.logical_payload_bytes
        << ",\"peak_payload_buffer_bytes\":"
        << large_streaming_memory.peak_payload_buffer_bytes
        << ",\"complete_payload_retained\":false}\n";
    }

    {
    const std::string fixed_plain = std::string("hello deflate world\n") +
        std::string("hello deflate world\n") +
        std::string("hello deflate world\n") +
        std::string("hello deflate world\n");
    std::string fixed_plain_32;
    for (int index = 0; index < 8; ++index) fixed_plain_32 += fixed_plain;
    std::string dynamic_plain;
    for (int index = 0; index < 256; ++index) {
        dynamic_plain += "alpha beta gamma delta ";
    }
    std::string multiple_blocks;
    for (int index = 0; index < 50; ++index) multiple_blocks += "block-one-";
    for (int index = 0; index < 50; ++index) multiple_blocks += "block-two-";
    const std::string raw_stored_plain = "raw stored deflate block";

    const ZipEntry fixed = deflate_entry(
        "payload/fixed.txt",
        "cb48cdc9c95748494dcb492c495528cf2fca49e1ca18151b15cba18f1800",
        fixed_plain_32);
    const ZipEntry dynamic = deflate_entry(
        "payload/dynamic.txt",
        "edc8c109c0201405b055fe6a4f143d28f4d0fd69d710720bc97e56aa8d3735734eaa8ffd3b5a6badb5d65a6badb5d65a6badf5cdfd01",
        dynamic_plain);
    const ZipEntry multiple = deflate_entry(
        "payload/multiple.txt",
        "4acac94fced6cdcf4bd54d1a65e98e0c16000000ffff83f8b2a43c7f94553e525800",
        multiple_blocks);
    const ZipEntry raw_stored = deflate_entry(
        "payload/raw-stored.txt",
        "011800e7ff7261772073746f726564206465666c61746520626c6f636b",
        raw_stored_plain);
    const ZipEntry empty = deflate_entry("payload/empty.txt", "0300", "");
    const fs::path deflate_zip = root / "deflate-mixed.zip";
    write_zip(deflate_zip, {
        {"payload/", "", (0040755u << 16) | 0x10u},
        {"payload/stored.txt", "stored"},
        fixed,
        dynamic,
        multiple,
        raw_stored,
        empty,
    });
    usk::archive::StreamingPayloadMemoryObservation deflate_memory;
    const auto deflate_payload = usk::archive::inspect_streaming_payload(
        request_json(deflate_zip, 100, 32, 200),
        "payload",
        64u * 1024u,
        &deflate_memory);
    if (deflate_payload.files.size() != 6u ||
        deflate_memory.complete_payload_retained ||
        deflate_memory.peak_payload_buffer_bytes != 64u * 1024u ||
        deflate_memory.peak_compressed_input_buffer_bytes != 64u * 1024u ||
        deflate_memory.peak_total_stream_buffer_bytes != 128u * 1024u) {
        return 138;
    }
    const std::map<std::string, std::pair<std::string, std::string>> expected = {
        {"stored.txt", {"stored", "stored"}},
        {"fixed.txt", {"deflate", fixed_plain_32}},
        {"dynamic.txt", {"deflate", dynamic_plain}},
        {"multiple.txt", {"deflate", multiple_blocks}},
        {"raw-stored.txt", {"deflate", raw_stored_plain}},
        {"empty.txt", {"deflate", ""}},
    };
    for (const auto& file : deflate_payload.files) {
        const auto found = expected.find(file.relative_path);
        if (found == expected.end() ||
            file.compression_method != found->second.first ||
            read_streaming_file(file) != found->second.second) {
            return 139;
        }
    }
    bool late_reader_cancellation = false;
    const auto late_cancel_payload = usk::archive::inspect_streaming_payload(
        request_json(deflate_zip, 100, 32, 200),
        "payload",
        64u * 1024u,
        nullptr,
        [&]() { return late_reader_cancellation; });
    const auto late_cancel_file = std::find_if(
        late_cancel_payload.files.begin(),
        late_cancel_payload.files.end(),
        [](const usk::archive::StreamingPayloadFile& file) {
            return file.relative_path == "fixed.txt";
        });
    if (late_cancel_file == late_cancel_payload.files.end()) return 172;
    std::vector<unsigned char> late_cancel_buffer(
        static_cast<std::size_t>(late_cancel_file->size_bytes));
    const std::size_t late_cancel_count = late_cancel_file->reader(
        0u, late_cancel_buffer.data(), late_cancel_buffer.size());
    if (late_cancel_count != late_cancel_buffer.size()) return 172;
    late_reader_cancellation = true;
    bool late_eof_cancellation_refused = false;
    try {
        unsigned char probe = 0;
        (void)late_cancel_file->reader(
            late_cancel_file->size_bytes, &probe, 1u);
    } catch (const std::exception& exception) {
        late_eof_cancellation_refused = contains(exception.what(), "cancelled");
    }
    if (!late_eof_cancellation_refused) return 172;
    bool stored_only_refused = false;
    try {
        (void)usk::archive::inspect_streaming_stored_payload(
            request_json(deflate_zip, 100, 32, 200), "payload");
    } catch (const std::exception& exception) {
        stored_only_refused = contains(exception.what(), "requires stored");
    }
    if (!stored_only_refused) return 140;

    const fs::path exact_ratio_zip = root / "deflate-exact-ratio.zip";
    write_zip(exact_ratio_zip, {fixed});
    (void)usk::archive::inspect_streaming_payload(
        request_json(exact_ratio_zip, 100, 32, 22), "payload");
    bool ratio_over_refused = false;
    try {
        (void)usk::archive::inspect_streaming_payload(
            request_json(exact_ratio_zip, 100, 32, 21), "payload");
    } catch (const std::exception& exception) {
        ratio_over_refused = contains(exception.what(), "compression-ratio");
    }
    if (!ratio_over_refused) return 149;

    const fs::path deflate_zip64 = root / "deflate-zip64.zip";
    write_zip64(deflate_zip64, {fixed, empty});
    const auto zip64_deflate_payload = usk::archive::inspect_streaming_payload(
        request_json(deflate_zip64, 100, 32, 200), "payload");
    if (zip64_deflate_payload.files.size() != 2u) return 141;
    for (const auto& file : zip64_deflate_payload.files) {
        const std::string expected_value =
            file.relative_path == "fixed.txt" ? fixed_plain_32 : "";
        if ((file.relative_path != "fixed.txt" &&
             file.relative_path != "empty.txt") ||
            read_streaming_file(file) != expected_value) {
            return 141;
        }
    }

    std::vector<ZipEntry> malformed;
    ZipEntry truncated = fixed;
    truncated.name = "payload/truncated.txt";
    truncated.data.pop_back();
    malformed.push_back(truncated);
    ZipEntry trailing = fixed;
    trailing.name = "payload/trailing.txt";
    trailing.data.push_back('\0');
    malformed.push_back(trailing);
    ZipEntry corrupt = dynamic;
    corrupt.name = "payload/corrupt.txt";
    corrupt.data[corrupt.data.size() / 2u] ^= 0x20;
    malformed.push_back(corrupt);
    ZipEntry forged_short = fixed;
    forged_short.name = "payload/forged-short.txt";
    forged_short.uncompressed_size =
        static_cast<std::uint32_t>(fixed_plain_32.size() - 1u);
    malformed.push_back(forged_short);
    ZipEntry forged_long = fixed;
    forged_long.name = "payload/forged-long.txt";
    forged_long.uncompressed_size =
        static_cast<std::uint32_t>(fixed_plain_32.size() + 1u);
    malformed.push_back(forged_long);
    ZipEntry wrong_crc = fixed;
    wrong_crc.name = "payload/wrong-crc.txt";
    wrong_crc.crc32_value = crc32(fixed_plain_32) ^ 1u;
    malformed.push_back(wrong_crc);
    for (std::size_t index = 0; index < malformed.size(); ++index) {
        const fs::path malformed_zip =
            root / ("deflate-malformed-" + std::to_string(index) + ".zip");
        write_zip(malformed_zip, {malformed[index]});
        bool rejected = false;
        try {
            (void)usk::archive::inspect_streaming_payload(
                request_json(malformed_zip, 100, 32, 200), "payload");
        } catch (const std::exception&) {
            rejected = true;
        }
        if (!rejected) return static_cast<int>(142 + index);
    }

    std::size_t mutation_refusals = 0;
    for (std::size_t byte_index = 0; byte_index < fixed.data.size(); ++byte_index) {
        for (unsigned bit = 0; bit < 8u; ++bit) {
            ZipEntry mutated = fixed;
            mutated.name = "payload/mutated.txt";
            mutated.data[byte_index] ^= static_cast<char>(1u << bit);
            const fs::path mutation_zip = root /
                ("deflate-mutation-" + std::to_string(byte_index) + "-" +
                 std::to_string(bit) + ".zip");
            write_zip(mutation_zip, {mutated});
            try {
                const auto mutation_payload =
                    usk::archive::inspect_streaming_payload(
                        request_json(mutation_zip, 100, 32, 200), "payload");
                if (mutation_payload.files.size() != 1u ||
                    read_streaming_file(mutation_payload.files.front()) !=
                        fixed_plain_32) {
                    return 150;
                }
            } catch (const std::exception&) {
                ++mutation_refusals;
            }
        }
    }
    if (mutation_refusals == 0u) return 151;
    }

    const char* large_streaming_proof =
        std::getenv("USK_LARGE_STREAMING_MEMORY_PROOF");
    if (large_streaming_proof != nullptr &&
        std::string(large_streaming_proof) == "1") {
        struct LargeStreamingCase {
            std::uint32_t size_bytes;
            unsigned char value;
        };
        const std::array<LargeStreamingCase, 3> large_streaming_cases = {{
            {1u * 1024u * 1024u, static_cast<unsigned char>('1')},
            {64u * 1024u * 1024u, static_cast<unsigned char>('6')},
            {512u * 1024u * 1024u, static_cast<unsigned char>('5')}
        }};
        constexpr std::size_t streaming_buffer_bytes = 64u * 1024u;
        for (std::size_t index = 0; index < large_streaming_cases.size(); ++index) {
            const LargeStreamingCase& proof_case = large_streaming_cases[index];
            const fs::path proof_zip =
                root / ("memory-streaming-" + std::to_string(proof_case.size_bytes) + ".zip");
            write_repeated_stored_zip(
                proof_zip,
                "payload/blob.bin",
                proof_case.value,
                proof_case.size_bytes);
            {
                usk::archive::StreamingPayloadMemoryObservation observation;
                const auto proof_payload =
                    usk::archive::inspect_streaming_stored_payload(
                        request_json(
                            proof_zip,
                            100,
                            32,
                            100,
                            proof_case.size_bytes,
                            proof_case.size_bytes,
                            600000),
                        "payload",
                        streaming_buffer_bytes,
                        &observation);
                if (observation.complete_payload_retained ||
                    observation.file_count != 1 ||
                    observation.logical_payload_bytes != proof_case.size_bytes ||
                    observation.peak_payload_buffer_bytes != streaming_buffer_bytes ||
                    proof_payload.uncompressed_bytes != proof_case.size_bytes ||
                    proof_payload.files.size() != 1 ||
                    proof_payload.files.front().size_bytes != proof_case.size_bytes ||
                    !proof_payload.files.front().reader) {
                    return static_cast<int>(126 + index);
                }
                std::vector<unsigned char> boundary_buffer(4096u);
                const auto matches_value = [&boundary_buffer, &proof_case]() {
                    return std::all_of(
                        boundary_buffer.begin(),
                        boundary_buffer.end(),
                        [&proof_case](unsigned char byte) {
                            return byte == proof_case.value;
                        });
                };
                if (proof_payload.files.front().reader(
                        0,
                        boundary_buffer.data(),
                        boundary_buffer.size()) != boundary_buffer.size() ||
                    !matches_value() ||
                    proof_payload.files.front().reader(
                        proof_case.size_bytes - boundary_buffer.size(),
                        boundary_buffer.data(),
                        boundary_buffer.size()) != boundary_buffer.size() ||
                    !matches_value() ||
                    proof_payload.files.front().reader(
                        proof_case.size_bytes,
                        boundary_buffer.data(),
                        1u) != 0u) {
                    return static_cast<int>(130 + index);
                }
            }
            error.clear();
            fs::remove(proof_zip, error);
            if (error) return static_cast<int>(134 + index);

            const fs::path deflate_proof_zip = root /
                ("memory-deflate-streaming-" +
                 std::to_string(proof_case.size_bytes) + ".zip");
            write_repeated_deflate_zip(
                deflate_proof_zip,
                "payload/blob.bin",
                proof_case.value,
                proof_case.size_bytes);
            {
            usk::archive::StreamingPayloadMemoryObservation deflate_observation;
            const auto deflate_proof = usk::archive::inspect_streaming_payload(
                request_json(
                    deflate_proof_zip,
                    100,
                    32,
                    100,
                    proof_case.size_bytes,
                    proof_case.size_bytes,
                    600000),
                "payload",
                streaming_buffer_bytes,
                &deflate_observation);
            if (deflate_proof.files.size() != 1u ||
                deflate_proof.files.front().compression_method != "deflate" ||
                deflate_observation.complete_payload_retained ||
                deflate_observation.peak_payload_buffer_bytes !=
                    streaming_buffer_bytes ||
                deflate_observation.peak_compressed_input_buffer_bytes !=
                    streaming_buffer_bytes ||
                deflate_observation.peak_total_stream_buffer_bytes !=
                    2u * streaming_buffer_bytes) {
                return static_cast<int>(154 + index);
            }
            std::vector<unsigned char> streamed(streaming_buffer_bytes);
            std::uint64_t streamed_offset = 0;
            while (streamed_offset < proof_case.size_bytes) {
                const std::size_t capacity = static_cast<std::size_t>(
                    std::min<std::uint64_t>(
                        streamed.size(), proof_case.size_bytes - streamed_offset));
                const std::size_t count = deflate_proof.files.front().reader(
                    streamed_offset, streamed.data(), capacity);
                if (count == 0u || count > capacity ||
                    !std::all_of(
                        streamed.data(),
                        streamed.data() + count,
                        [&](unsigned char byte) {
                            return byte == proof_case.value;
                        })) {
                    return static_cast<int>(158 + index);
                }
                streamed_offset += count;
            }
            unsigned char deflate_probe = 0;
            if (deflate_proof.files.front().reader(
                    streamed_offset, &deflate_probe, 1u) != 0u) {
                return static_cast<int>(162 + index);
            }
            }
            error.clear();
            fs::remove(deflate_proof_zip, error);
            if (error) return static_cast<int>(166 + index);
        }
        std::cout
            << "payload-large-streaming-characterization: {\"schema\":"
               "\"usk.payload_large_streaming_characterization.v1\""
            << ",\"logical_payload_bytes\":[1048576,67108864,536870912]"
            << ",\"peak_payload_buffer_bytes\":" << streaming_buffer_bytes
            << ",\"peak_deflate_stream_buffers_bytes\":"
            << 2u * streaming_buffer_bytes
            << ",\"complete_payload_retained\":false}\n";
    }

    const fs::path valid_zip64 = root / "valid-zip64.zip";
    write_zip64(valid_zip64, {
        {"app/", "", (0040755u << 16) | 0x10u},
        {"app/bin/tool.exe", "binary"},
        {"app/data/config.ini", "config"}
    });
    const std::string zip64_response =
        execute(context, valid_zip64, status);
    if (status != USK_STATUS_OK ||
        !contains(zip64_response, "\"file_count\":2") ||
        !contains(zip64_response, "\"directory_count\":1") ||
        field(zip64_response, "entry_set_digest") !=
            field(valid_response, "entry_set_digest")) {
        return 10;
    }
    const usk::archive::StoredArchivePayload zip64_payload =
        usk::archive::inspect_stored_payload(
            request_json(valid_zip64), "app");
    if (zip64_payload.entry_set_digest !=
            field(valid_response, "entry_set_digest") ||
        zip64_payload.files.size() != 2 ||
        zip64_payload.uncompressed_bytes != 12) {
        return 11;
    }
    {
        const auto zip64_streaming_payload =
            usk::archive::inspect_streaming_stored_payload(
                request_json(valid_zip64), "app");
        if (zip64_streaming_payload.entry_set_digest !=
                zip64_payload.entry_set_digest ||
            zip64_streaming_payload.files.size() != 2 ||
            zip64_streaming_payload.uncompressed_bytes != 12) {
            return 11;
        }
    }
    {
    ZipEntry zip64_size_deflate = deflate_entry(
        "payload.txt", "cb48cdc9c90700", "hello");
    zip64_size_deflate.zip64_sizes = true;
    const fs::path zip64_size_sentinels =
        root / "zip64-size-sentinels-deflate.zip";
    write_zip64(zip64_size_sentinels, {zip64_size_deflate});
    const auto zip64_size_payload = usk::archive::inspect_streaming_payload(
        request_json(zip64_size_sentinels), "");
    if (zip64_size_payload.files.size() != 1u ||
        zip64_size_payload.files.front().compression_method != "deflate" ||
        zip64_size_payload.files.front().size_bytes != 5u ||
        read_streaming_file(zip64_size_payload.files.front()) != "hello") {
        return 170;
    }
    const fs::path zip64_size_order_mismatch =
        root / "zip64-size-order-mismatch.zip";
    fs::copy_file(zip64_size_sentinels, zip64_size_order_mismatch);
    {
        std::fstream stream(
            zip64_size_order_mismatch,
            std::ios::in | std::ios::out | std::ios::binary);
        stream.seekp(static_cast<std::streamoff>(
            30u + zip64_size_deflate.name.size() + 4u));
        stream.put(static_cast<char>(zip64_size_deflate.data.size()));
    }
    if (!refused(
            context,
            zip64_size_order_mismatch,
            "local and central sizes disagree")) {
        return 171;
    }
    }
    const fs::path missing_zip64_locator =
        root / "missing-zip64-locator.zip";
    fs::copy_file(valid_zip64, missing_zip64_locator);
    {
        std::fstream stream(
            missing_zip64_locator,
            std::ios::in | std::ios::out | std::ios::binary);
        stream.seekp(-42, std::ios::end);
        stream.put('\0');
    }
    if (!refused(
            context,
            missing_zip64_locator,
            "ZIP64 locator")) {
        return 12;
    }

    const fs::path bad_crc = root / "bad-crc.zip";
    write_zip(bad_crc, {{"payload.txt", "original"}});
    {
        std::fstream stream(bad_crc, std::ios::in | std::ios::out | std::ios::binary);
        stream.seekp(static_cast<std::streamoff>(30 + std::string("payload.txt").size()));
        stream.put('X');
    }
    bool rejected_bad_crc = false;
    try {
        (void)usk::archive::inspect_stored_payload(request_json(bad_crc), "");
    } catch (const std::exception& exception) {
        rejected_bad_crc = contains(exception.what(), "CRC");
    }
    if (!rejected_bad_crc) return 9;
    const std::string valid_request = request_json(valid);
    std::string missing_budget = valid_request;
    const std::string budget_field = "\"max_depth\":32,";
    missing_budget.erase(missing_budget.find(budget_field), budget_field.size());
    const std::string missing_budget_response = execute_raw(context, missing_budget, status);
    if (status != USK_STATUS_ERROR ||
        !contains(missing_budget_response, "missing required member: max_depth")) {
        return 6;
    }
    std::string wrong_format = valid_request;
    wrong_format.replace(wrong_format.find("\"zip\""), 5, "\"tar\"");
    const std::string wrong_format_response = execute_raw(context, wrong_format, status);
    if (status != USK_STATUS_ERROR ||
        !contains(wrong_format_response, "declared ZIP")) {
        return 7;
    }
    std::string maximum_elapsed_budget = valid_request;
    maximum_elapsed_budget.replace(
        maximum_elapsed_budget.find("\"max_elapsed_ms\":30000"),
        std::string("\"max_elapsed_ms\":30000").size(),
        "\"max_elapsed_ms\":600000");
    const std::string maximum_elapsed_response =
        execute_raw(context, maximum_elapsed_budget, status);
    if (status != USK_STATUS_OK ||
        !contains(maximum_elapsed_response, "\"max_elapsed_ms\":600000")) {
        return 13;
    }
    std::string excessive_elapsed_budget = valid_request;
    excessive_elapsed_budget.replace(
        excessive_elapsed_budget.find("\"max_elapsed_ms\":30000"),
        std::string("\"max_elapsed_ms\":30000").size(),
        "\"max_elapsed_ms\":600001");
    const std::string excessive_elapsed_response =
        execute_raw(context, excessive_elapsed_budget, status);
    if (status != USK_STATUS_ERROR ||
        !contains(
            excessive_elapsed_response,
            "numeric request field exceeds its hard limit: max_elapsed_ms")) {
        return 14;
    }

    constexpr std::size_t request_byte_limit = 64u * 1024u;
    if (valid_request.size() >= request_byte_limit) return 16;
    std::string maximum_sized_request = valid_request;
    maximum_sized_request.append(
        request_byte_limit - maximum_sized_request.size(), ' ');
    const std::string maximum_sized_response =
        execute_raw(context, maximum_sized_request, status);
    if (status != USK_STATUS_OK ||
        field(maximum_sized_response, "entry_set_digest") !=
            field(valid_response, "entry_set_digest")) {
        return 16;
    }
    std::string excessive_sized_request = maximum_sized_request;
    excessive_sized_request.push_back(' ');
    if (!request_refused(
            context,
            excessive_sized_request,
            "bounded archive inspection request is required")) {
        return 17;
    }

    std::string maximum_budget_request = valid_request;
    for (const auto& replacement :
         std::vector<std::pair<std::string, std::string>>{
             {"\"max_entries\":100", "\"max_entries\":100000"},
             {"\"max_uncompressed_bytes\":1048576",
              "\"max_uncompressed_bytes\":1099511627776"},
             {"\"max_entry_bytes\":524288", "\"max_entry_bytes\":274877906944"},
             {"\"max_depth\":32", "\"max_depth\":256"},
             {"\"max_ratio\":100", "\"max_ratio\":100000"},
             {"\"max_elapsed_ms\":30000", "\"max_elapsed_ms\":600000"}}) {
        maximum_budget_request = replace_once(
            std::move(maximum_budget_request), replacement.first, replacement.second);
    }
    const std::string maximum_budget_response =
        execute_raw(context, maximum_budget_request, status);
    if (status != USK_STATUS_OK ||
        field(maximum_budget_response, "entry_set_digest") !=
            field(valid_response, "entry_set_digest")) {
        return 18;
    }

    struct NumericBoundaryCase {
        const char* field;
        const char* current_value;
        const char* excessive_value;
    };
    const std::vector<NumericBoundaryCase> numeric_boundaries = {
        {"max_entries", "100", "100001"},
        {"max_uncompressed_bytes", "1048576", "1099511627777"},
        {"max_entry_bytes", "524288", "274877906945"},
        {"max_depth", "32", "257"},
        {"max_ratio", "100", "100001"},
        {"max_elapsed_ms", "30000", "600001"}
    };
    for (std::size_t index = 0; index < numeric_boundaries.size(); ++index) {
        const NumericBoundaryCase& boundary = numeric_boundaries[index];
        const std::string marker = std::string("\"") + boundary.field + "\":" +
            boundary.current_value;
        const std::string excessive = std::string("\"") + boundary.field + "\":" +
            boundary.excessive_value;
        if (!request_refused(
                context,
                replace_once(valid_request, marker, excessive),
                std::string("exceeds its hard limit: ") + boundary.field)) {
            return static_cast<int>(90 + index);
        }
        const std::string zero = std::string("\"") + boundary.field + "\":0";
        if (!request_refused(
                context,
                replace_once(valid_request, marker, zero),
                std::string("outside its allowed range: ") + boundary.field)) {
            return static_cast<int>(100 + index);
        }
    }

    struct RequestRefusalCase {
        std::string request;
        const char* reason;
    };
    const std::string encoded_valid_path = json_escape(valid.u8string());
    const std::string budgets_array =
        "{\"schema\":\"usk.archive_inspect_request.v1\","
        "\"archive_path\":\"" + encoded_valid_path + "\","
        "\"archive_format\":\"zip\",\"budgets\":[]}";
    const std::string invalid_utf8_path =
        std::string("invalid-") + "\xc0\xaf" + ".zip";
    const std::vector<RequestRefusalCase> request_refusals = {
        {
            replace_once(
                valid_request,
                "\"schema\":\"usk.archive_inspect_request.v1\"",
                "\"schema\":\"usk.archive_inspect_request.v1\","
                "\"schema\":\"usk.archive_inspect_request.v1\""),
            "duplicate key"
        },
        {
            replace_once(
                valid_request,
                "\"max_depth\":32",
                "\"max_depth\":32,\"max_depth\":32"),
            "duplicate key"
        },
        {
            replace_once(
                valid_request,
                "\"budgets\":{",
                "\"unexpected\":true,\"budgets\":{"),
            "unexpected member: unexpected"
        },
        {
            replace_once(
                valid_request,
                "\"max_entries\":100",
                "\"max_entries\":100,\"unexpected\":1"),
            "unexpected member: unexpected"
        },
        {
            replace_once(valid_request, "\"archive_format\":\"zip\",", ""),
            "missing required member: archive_format"
        },
        {
            replace_once(
                missing_budget,
                "\"budgets\":{",
                "\"max_depth\":32,\"budgets\":{"),
            "unexpected member: max_depth"
        },
        {
            replace_once(missing_budget, encoded_valid_path, "max_depth"),
            "missing required member: max_depth"
        },
        {"[]", "must be a JSON object"},
        {budgets_array, "budgets must be a JSON object"},
        {
            replace_once(
                valid_request,
                "\"schema\":\"usk.archive_inspect_request.v1\"",
                "\"schema\":1"),
            "field must be a string: schema"
        },
        {
            replace_once(valid_request, "\"archive_format\":\"zip\"", "\"archive_format\":true"),
            "field must be a string: archive_format"
        },
        {
            replace_once(
                valid_request,
                "\"schema\":\"usk.archive_inspect_request.v1\"",
                "\"schema\":\"usk.archive_inspect_request.v2\""),
            "unsupported archive inspection request schema"
        },
        {
            replace_once(
                valid_request,
                "\"archive_path\":\"" + encoded_valid_path + "\"",
                "\"archive_path\":true"),
            "field must be a string: archive_path"
        },
        {
            replace_once(valid_request, encoded_valid_path, ""),
            "archive_path is required"
        },
        {
            replace_once(valid_request, "\"max_depth\":32", "\"max_depth\":\"32\""),
            "must be an unsigned integer: max_depth"
        },
        {
            replace_once(valid_request, "\"max_depth\":32", "\"max_depth\":true"),
            "must be an unsigned integer: max_depth"
        },
        {
            replace_once(valid_request, "\"max_depth\":32", "\"max_depth\":null"),
            "must be an unsigned integer: max_depth"
        },
        {
            replace_once(valid_request, "\"max_depth\":32", "\"max_depth\":{}"),
            "must be an unsigned integer: max_depth"
        },
        {
            replace_once(valid_request, "\"max_depth\":32", "\"max_depth\":{\"nested\":1}"),
            "depth budget"
        },
        {
            replace_once(valid_request, "\"max_depth\":32", "\"max_depth\":1.5"),
            "floating point numbers are forbidden"
        },
        {
            replace_once(valid_request, "\"max_depth\":32", "\"max_depth\":-1"),
            "unsupported value token"
        },
        {
            replace_once(valid_request, "\"max_depth\":32", "\"max_depth\":1e2"),
            "floating point numbers are forbidden"
        },
        {
            replace_once(
                valid_request,
                "\"max_depth\":32",
                "\"max_depth\":18446744073709551616"),
            "overflows uint64"
        },
        {
            replace_once(valid_request, "\"max_depth\":32", "\"max_depth\":032"),
            "leading zero"
        },
        {
            replace_once(valid_request, "\"max_depth\":32", "\"max_depth\":0"),
            "outside its allowed range: max_depth"
        },
        {
            replace_once(valid_request, "\"max_depth\":32", "\"max_depth\":257"),
            "exceeds its hard limit: max_depth"
        },
        {valid_request + " trailing", "trailing content"},
        {
            replace_once(valid_request, encoded_valid_path, invalid_utf8_path),
            "not valid UTF-8"
        },
        {
            replace_once(
                valid_request,
                encoded_valid_path,
                "prefix\\u0000suffix.zip"),
            "archive_path contains an embedded NUL"
        },
        {
            replace_once(valid_request, encoded_valid_path, std::string(32769u, 'a')),
            "string exceeds budget"
        },
        {
            replace_once(
                valid_request,
                "\",\"archive_format\"",
                "\"archive_format\""),
            "punctuation is invalid"
        }
    };
    for (std::size_t index = 0; index < request_refusals.size(); ++index) {
        const RequestRefusalCase& refusal = request_refusals[index];
        if (!request_refused(context, refusal.request, refusal.reason)) {
            return static_cast<int>(60 + index);
        }
    }
    error.clear();
    fs::permissions(
        valid,
        fs::perms::owner_read | fs::perms::group_read | fs::perms::others_read,
        fs::perm_options::replace,
        error);
    if (!error) {
        const std::string read_only_response = execute(context, valid, status);
        if (status != USK_STATUS_OK ||
            field(read_only_response, "entry_set_digest") != field(valid_response, "entry_set_digest")) {
            return 5;
        }
    }

    const fs::path reordered = root / "reordered.zip";
    write_zip(reordered, {
        {"app/data/config.ini", "config"},
        {"app/bin/tool.exe", "binary"},
        {"app/", "", (0040755u << 16) | 0x10u}
    });
    const std::string reordered_response = execute(context, reordered, status);
    if (status != USK_STATUS_OK ||
        field(valid_response, "entry_set_digest") != field(reordered_response, "entry_set_digest")) {
        return 4;
    }

    struct RefusalCase {
        const char* filename;
        std::vector<ZipEntry> entries;
        const char* reason;
        int max_entries = 100;
        int max_depth = 32;
        int max_ratio = 100;
    };
    const std::vector<unsigned char> unicode_extra = {0x75, 0x70, 0x00, 0x00};
    const std::vector<RefusalCase> cases = {
        {"traversal.zip", {{"../escape", "x"}}, "traversal"},
        {"absolute.zip", {{"/absolute", "x"}}, "absolute"},
        {"drive.zip", {{"C:/escape", "x"}}, "drive-qualified"},
        {"unc.zip", {{"\\\\server\\share", "x"}}, "absolute"},
        {"ads.zip", {{"safe:stream", "x"}}, "alternate-data-stream"},
        {"segments.zip", {{"a//b", "x"}}, "empty or ambiguous"},
        {"dot.zip", {{"a/./b", "x"}}, "dot segments"},
        {"trailing.zip", {{"a/name. ", "x"}}, "reserved or ambiguous"},
        {"reserved.zip", {{"folder/CON.txt", "x"}}, "reserved or ambiguous"},
        {"clock-device.zip", {{"folder/CLOCK$.txt", "x"}}, "reserved or ambiguous"},
        {"case.zip", {{"Data/File.txt", "x"}, {"data/file.TXT", "y"}}, "case-insensitive-colliding"},
        {"file-parent.zip", {{"a", "x"}, {"a/b", "y"}}, "declared as a file"},
        {"file-after-child.zip", {{"a/b", "y"}, {"a", "x"}}, "directory subtree"},
        {"symlink.zip", {{"link", "", (0120777u << 16)}}, "link, device"},
        {"device.zip", {{"device", "", (0020666u << 16)}}, "link, device"},
        {"reparse.zip", {{"reparse", "x", (0100644u << 16) | 0x400u}}, "reparse-like"},
        {"encrypted.zip", {{"secret", "x", (0100644u << 16), 0x0001u}}, "encrypted"},
        {"streamed.zip", {{"streamed", "x", (0100644u << 16), 0x0008u}}, "streamed"},
        {"unknown-flags.zip", {{"unknown", "x", (0100644u << 16), 0x0010u}}, "unsupported flags"},
        {"method.zip", {{"method", "x", (0100644u << 16), 0, 99}}, "compression method"},
        {"unicode.zip", {{std::string("nonascii-\xc3\xa9"), "x"}}, "Unicode normalization"},
        {"unicode-normalization-collision.zip",
            {{std::string("data/caf\xc3\xa9.txt"), "nfc"},
             {std::string("data/cafe\xcc\x81.txt"), "nfd"}},
            "Unicode normalization"},
        {"unicode-extra.zip", {{"ascii", "x", (0100644u << 16), 0, 0, {}, {}, {}, {}, unicode_extra}}, "alternate Unicode"},
        {"ratio.zip", {{"bomb", "x", (0100644u << 16), 0, 8, 1u, 1000u}}, "compression-ratio", 100, 32, 10},
        {"entry-size.zip", {{"large", "x", (0100644u << 16), 0, 8, 1u, 600000u}}, "per-entry size"},
        {"count.zip", {{"one", "1"}, {"two", "2"}}, "count", 1},
        {"depth.zip", {{"a/b/c/d", "x"}}, "depth", 100, 3},
        {"local-name.zip", {{"central", "x", (0100644u << 16), 0, 0, {}, {}, "differx"}}, "names disagree"},
        {"unclaimed.zip", {{"zero", "x", (0100644u << 16), 0, 0, 0u, 0u}}, "ambiguous bytes"},
        {"zip64-entry.zip", {{"zip64", "x", (0100644u << 16), 0, 0, 0xffffffffu, 0xffffffffu}}, "ZIP64 extra"}
    };

    for (std::size_t index = 0; index < cases.size(); ++index) {
        const RefusalCase& refusal_case = cases[index];
        const fs::path path = root / refusal_case.filename;
        write_zip(path, refusal_case.entries);
        if (!refused(
                context,
                path,
                refusal_case.reason,
                refusal_case.max_entries,
                refusal_case.max_depth,
                refusal_case.max_ratio)) {
            return static_cast<int>(20 + index);
        }
    }

    usk_context_destroy_v1(context);
    error.clear();
    fs::permissions(valid, fs::perms::owner_all, fs::perm_options::add, error);
    error.clear();
    fs::remove_all(root, error);
    return error ? 50 : 0;
}
