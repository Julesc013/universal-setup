// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk/usk_api.h"
#include "usk_archive_payload.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
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
            static_cast<std::uint32_t>(spec.data.size()));
        append32(bytes, 0x04034b50u);
        append16(bytes, 20);
        append16(bytes, spec.flags);
        append16(bytes, spec.method);
        append16(bytes, 0);
        append16(bytes, 0);
        append32(bytes, crc32(spec.data));
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
            static_cast<std::uint32_t>(spec.data.size()));
        append32(bytes, 0x02014b50u);
        append16(bytes, static_cast<std::uint16_t>((3u << 8) | 20u));
        append16(bytes, 20);
        append16(bytes, spec.flags);
        append16(bytes, spec.method);
        append16(bytes, 0);
        append16(bytes, 0);
        append32(bytes, crc32(spec.data));
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

std::string json_escape(const std::string& value)
{
    std::string result;
    for (char ch : value) {
        if (ch == '\\' || ch == '"') result.push_back('\\');
        result.push_back(ch);
    }
    return result;
}

std::string request_json(
    const fs::path& archive,
    int max_entries = 100,
    int max_depth = 32,
    int max_ratio = 100)
{
    return "{\"schema\":\"usk.archive_inspect_request.v1\","
        "\"archive_path\":\"" + json_escape(archive.string()) + "\","
        "\"archive_format\":\"zip\",\"budgets\":{"
        "\"max_entries\":" + std::to_string(max_entries) + ","
        "\"max_uncompressed_bytes\":1048576,\"max_entry_bytes\":524288,"
        "\"max_depth\":" + std::to_string(max_depth) + ","
        "\"max_ratio\":" + std::to_string(max_ratio) + ","
        "\"max_elapsed_ms\":30000}}";
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
    const usk::archive::StoredArchivePayload payload =
        usk::archive::inspect_stored_payload(request_json(valid), "app");
    if (payload.source_sha256 != field(valid_response, "sha256") ||
        payload.source_identity_digest.size() != 64 ||
        payload.entry_set_digest != field(valid_response, "entry_set_digest") ||
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
    std::string missing_budget = request_json(valid);
    const std::string budget_field = "\"max_depth\":32,";
    missing_budget.erase(missing_budget.find(budget_field), budget_field.size());
    const std::string missing_budget_response = execute_raw(context, missing_budget, status);
    if (status != USK_STATUS_ERROR ||
        !contains(missing_budget_response, "required numeric request field is missing: max_depth")) {
        return 6;
    }
    std::string wrong_format = request_json(valid);
    wrong_format.replace(wrong_format.find("\"zip\""), 5, "\"tar\"");
    const std::string wrong_format_response = execute_raw(context, wrong_format, status);
    if (status != USK_STATUS_ERROR ||
        !contains(wrong_format_response, "classic ZIP")) {
        return 7;
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
        {"ads.zip", {{"safe:stream", "x"}}, "alternate-data-stream"},
        {"segments.zip", {{"a//b", "x"}}, "empty or ambiguous"},
        {"dot.zip", {{"a/./b", "x"}}, "dot segments"},
        {"trailing.zip", {{"a/name. ", "x"}}, "reserved or ambiguous"},
        {"reserved.zip", {{"folder/CON.txt", "x"}}, "reserved or ambiguous"},
        {"case.zip", {{"Data/File.txt", "x"}, {"data/file.TXT", "y"}}, "case-insensitive-colliding"},
        {"file-parent.zip", {{"a", "x"}, {"a/b", "y"}}, "declared as a file"},
        {"file-after-child.zip", {{"a/b", "y"}, {"a", "x"}}, "directory subtree"},
        {"symlink.zip", {{"link", "", (0120777u << 16)}}, "link, device"},
        {"device.zip", {{"device", "", (0020666u << 16)}}, "link, device"},
        {"reparse.zip", {{"reparse", "x", (0100644u << 16) | 0x400u}}, "reparse-like"},
        {"encrypted.zip", {{"secret", "x", (0100644u << 16), 0x0001u}}, "encrypted"},
        {"streamed.zip", {{"streamed", "x", (0100644u << 16), 0x0008u}}, "streamed"},
        {"method.zip", {{"method", "x", (0100644u << 16), 0, 99}}, "compression method"},
        {"unicode.zip", {{std::string("nonascii-\xc3\xa9"), "x"}}, "Unicode normalization"},
        {"unicode-extra.zip", {{"ascii", "x", (0100644u << 16), 0, 0, {}, {}, {}, {}, unicode_extra}}, "alternate Unicode"},
        {"ratio.zip", {{"bomb", "x", (0100644u << 16), 0, 8, 1u, 1000u}}, "compression-ratio", 100, 32, 10},
        {"entry-size.zip", {{"large", "x", (0100644u << 16), 0, 8, 1u, 600000u}}, "per-entry size"},
        {"count.zip", {{"one", "1"}, {"two", "2"}}, "count", 1},
        {"depth.zip", {{"a/b/c/d", "x"}}, "depth", 100, 3},
        {"local-name.zip", {{"central", "x", (0100644u << 16), 0, 0, {}, {}, "differx"}}, "names disagree"},
        {"unclaimed.zip", {{"zero", "x", (0100644u << 16), 0, 0, 0u, 0u}}, "ambiguous bytes"},
        {"zip64-entry.zip", {{"zip64", "x", (0100644u << 16), 0, 0, 0xffffffffu, 0xffffffffu}}, "ZIP64 entry"}
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
