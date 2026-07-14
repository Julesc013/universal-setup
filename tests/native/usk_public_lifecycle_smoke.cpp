// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk/usk_api.h"
#include "usk_json.h"
#include "usk_sha256.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using usk::json::Value;

namespace {

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

void write_zip(const fs::path& path)
{
    struct Entry { std::string name; std::string data; std::uint32_t offset; };
    std::vector<Entry> entries = {{"product/bin/probe.txt", "synthetic-version-1\n", 0},
                                  {"product/data/config.ini", "enabled=true\n", 0}};
    std::vector<unsigned char> bytes;
    for (Entry& entry : entries) {
        entry.offset = static_cast<std::uint32_t>(bytes.size());
        append32(bytes, 0x04034b50u); append16(bytes, 20); append16(bytes, 0); append16(bytes, 0);
        append16(bytes, 0); append16(bytes, 0); append32(bytes, crc32(entry.data));
        append32(bytes, static_cast<std::uint32_t>(entry.data.size()));
        append32(bytes, static_cast<std::uint32_t>(entry.data.size()));
        append16(bytes, static_cast<std::uint16_t>(entry.name.size())); append16(bytes, 0);
        bytes.insert(bytes.end(), entry.name.begin(), entry.name.end());
        bytes.insert(bytes.end(), entry.data.begin(), entry.data.end());
    }
    const std::uint32_t central_offset = static_cast<std::uint32_t>(bytes.size());
    for (const Entry& entry : entries) {
        append32(bytes, 0x02014b50u); append16(bytes, 0x0314u); append16(bytes, 20);
        append16(bytes, 0); append16(bytes, 0); append16(bytes, 0); append16(bytes, 0);
        append32(bytes, crc32(entry.data)); append32(bytes, static_cast<std::uint32_t>(entry.data.size()));
        append32(bytes, static_cast<std::uint32_t>(entry.data.size()));
        append16(bytes, static_cast<std::uint16_t>(entry.name.size())); append16(bytes, 0);
        append16(bytes, 0); append16(bytes, 0); append16(bytes, 0); append32(bytes, (0100644u << 16));
        append32(bytes, entry.offset); bytes.insert(bytes.end(), entry.name.begin(), entry.name.end());
    }
    const std::uint32_t central_size = static_cast<std::uint32_t>(bytes.size()) - central_offset;
    append32(bytes, 0x06054b50u); append16(bytes, 0); append16(bytes, 0);
    append16(bytes, static_cast<std::uint16_t>(entries.size()));
    append16(bytes, static_cast<std::uint16_t>(entries.size()));
    append32(bytes, central_size); append32(bytes, central_offset); append16(bytes, 0);
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

std::string execute(usk_context* context, const char* command, const Value& payload, int dry_run, int& status)
{
    const std::string json = usk::json::canonical(payload);
    usk_command_request_v1 request{};
    usk_command_response_v1 response{};
    request.struct_size = sizeof(request);
    request.command_name = {command, static_cast<usk_size>(std::char_traits<char>::length(command))};
    request.json_payload = {json.data(), static_cast<usk_size>(json.size())};
    request.dry_run = dry_run;
    response.struct_size = sizeof(response);
    status = usk_command_execute_v1(context, &request, &response);
    return response.json_payload.data == nullptr ? std::string() :
        std::string(response.json_payload.data, response.json_payload.size);
}

Value plan_request(const fs::path& archive, const fs::path& target, const std::string& source_hash)
{
    return Value(Value::Object{
        {"archive", Value(Value::Object{
            {"budgets", Value(Value::Object{{"max_depth", Value(std::uint64_t{32})},
                {"max_elapsed_ms", Value(std::uint64_t{30000})}, {"max_entries", Value(std::uint64_t{100})},
                {"max_entry_bytes", Value(std::uint64_t{1048576})}, {"max_ratio", Value(std::uint64_t{100})},
                {"max_uncompressed_bytes", Value(std::uint64_t{10485760})}})},
            {"expected_sha256", Value(source_hash)}, {"format", Value("zip")},
            {"path", Value(archive.generic_u8string())}, {"strip_prefix", Value("product")}})},
        {"created_at", Value("2026-07-14T01:00:00Z")}, {"install_id", Value("synthetic.install.1")},
        {"recipe", Value(Value::Object{
            {"components", Value(Value::Array{Value("base")})},
            {"entrypoints", Value(Value::Array{Value(Value::Object{
                {"entrypoint_id", Value("probe")}, {"kind", Value("tool")},
                {"relative_path", Value("bin/probe.txt")}})})},
            {"product_id", Value("synthetic.product")}, {"product_version", Value("1.0.0")},
            {"provider_revision", Value("test.provider.1")}, {"recipe_digest", Value(std::string(64, 'a'))}})},
        {"request_id", Value("plan.install.1")}, {"schema", Value("usk.install_local_plan_request.v1")},
        {"target", Value(Value::Object{{"class", Value("operator_acceptance")},
            {"root", Value(target.generic_u8string())}})}});
}

} // namespace

int main()
{
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path root = fs::temp_directory_path() / ("usk-public-lifecycle-" + std::to_string(nonce));
    const fs::path archive = root / "synthetic.zip";
    const fs::path setup_root = root / "setup-owned";
    const fs::path target = root / "managed-product";
    std::error_code error;
    fs::create_directories(root, error);
    if (error) return 1;
    write_zip(archive);

    usk_context* unavailable = nullptr;
    if (usk_context_create_v1(nullptr, &unavailable) != USK_STATUS_OK) return 2;
    int status = 0;
    const Value planned = plan_request(archive, target, usk::base::sha256_hex_file(archive));
    std::string response = execute(unavailable, "install_local.plan", planned, 1, status);
    if (status != USK_STATUS_ERROR || response.find("live_target_acceptance_required") == std::string::npos) return 3;
    usk_context_destroy_v1(unavailable);

    const std::string setup = setup_root.string();
    const std::string acceptance = root.string();
    usk_config_v1 config{};
    config.struct_size = sizeof(config);
    config.state_root = setup.c_str();
    config.authorized_acceptance_root = acceptance.c_str();
    config.target_policy_activation = "operator_acceptance_candidate";
    usk_context* context = nullptr;
    if (usk_context_create_v1(&config, &context) != USK_STATUS_OK) return 4;

    response = execute(context, "install_local.plan", planned, 1, status);
    if (status != USK_STATUS_OK || fs::exists(setup_root) || fs::exists(target)) return 5;
    const Value plan_response = usk::json::parse(response);
    const std::string plan_digest = plan_response.at("payload").at("plan_digest").as_string();
    if (plan_digest.size() != 64 ||
        plan_response.at("payload").at("totals").at("file_count").as_unsigned() != 2) return 6;

    Value stale(Value::Object{{"applied_at", Value("2026-07-14T01:01:00Z")},
        {"confirmation", Value("APPLY")}, {"plan_request", planned},
        {"reviewed_plan_digest", Value(std::string(64, '0'))}, {"reviewed_plan_id", Value("plan.install.1")},
        {"schema", Value("usk.install_local_apply_request.v1")}, {"transaction_id", Value("tx.install.1")}});
    response = execute(context, "install_local.apply", stale, 0, status);
    if (status != USK_STATUS_ERROR || response.find("stale_plan") == std::string::npos ||
        fs::exists(setup_root) || fs::exists(target)) return 7;

    stale.as_object()["reviewed_plan_digest"] = Value(plan_digest);
    response = execute(context, "install_local.apply", stale, 0, status);
    if (status != USK_STATUS_OK || !fs::is_regular_file(target / "bin/probe.txt") ||
        !fs::is_regular_file(target / "data/config.ini") || !fs::is_directory(setup_root / "state")) return 8;

    const Value inspect(Value::Object{{"install_id", Value("synthetic.install.1")},
        {"request_id", Value("inspect.1")}, {"schema", Value("usk.installed_inspect_request.v1")}});
    response = execute(context, "installed.inspect", inspect, 1, status);
    if (status != USK_STATUS_OK || response.find("\"lifecycle_status\":\"installed\"") == std::string::npos) return 9;

    const Value verify(Value::Object{{"install_id", Value("synthetic.install.1")},
        {"report_id", Value("verify.public.1")}, {"request_id", Value("verify.request.1")},
        {"schema", Value("usk.installed_verify_request.v1")}, {"verified_at", Value("2026-07-14T01:02:00Z")}});
    response = execute(context, "installed.verify", verify, 1, status);
    if (status != USK_STATUS_OK || response.find("\"status\":\"pass\"") == std::string::npos) return 10;

    usk_context_destroy_v1(context);
    fs::remove_all(root, error);
    return error ? 11 : 0;
}
