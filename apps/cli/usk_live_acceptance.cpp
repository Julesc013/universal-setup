// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk/usk_api.h"
#include "usk_json.h"
#include "usk_live_evidence.h"
#include "usk_record_io.h"
#include "usk_sha256.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using usk::json::Value;

namespace {

struct Options {
    fs::path root;
    std::string run_id;
    std::string setup_revision;
    std::string consumer_revision;
    bool test_mode = false;
};

struct CommandResult {
    int status = USK_STATUS_ERROR;
    Value envelope;
};

bool hex_value(const std::string& value, std::size_t size)
{
    return value.size() == size && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isdigit(ch) || (ch >= 'a' && ch <= 'f');
    });
}

std::string lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string normalized(const fs::path& path)
{
    return fs::absolute(path).lexically_normal().generic_u8string();
}

bool same_or_below(const fs::path& root, const fs::path& candidate)
{
    const fs::path base = fs::absolute(root).lexically_normal();
    const fs::path value = fs::absolute(candidate).lexically_normal();
#if defined(_WIN32)
    if (lower(base.generic_u8string()) == lower(value.generic_u8string())) return true;
#else
    if (base == value) return true;
#endif
    const fs::path relative = value.lexically_relative(base);
    if (relative.empty() || relative.is_absolute()) return false;
    for (const fs::path& part : relative) if (part == "..") return false;
    return true;
}

std::string digest_text(const std::string& text)
{
    usk::base::Sha256 digest;
    digest.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
    return digest.finish();
}

std::string timestamp()
{
    const std::time_t observed = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    static std::time_t last = 0;
    const std::time_t now = observed > last ? observed : last + 1;
    last = now;
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    char buffer[32]{};
    if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utc) == 0) {
        throw std::runtime_error("cannot format acceptance timestamp");
    }
    return buffer;
}

void append16(std::string& output, std::uint16_t value)
{
    output.push_back(static_cast<char>(value & 0xffu));
    output.push_back(static_cast<char>((value >> 8) & 0xffu));
}

void append32(std::string& output, std::uint32_t value)
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

std::string synthetic_zip()
{
    struct Entry { std::string name; std::string data; std::uint32_t offset = 0; };
    std::vector<Entry> entries{
        {"product/README.txt", "Harmless Universal Setup M2 acceptance fixture.\n"},
        {"product/config/settings.ini", "enabled=true\nmode=acceptance\n"},
        {"product/data/payload.dat", "synthetic-data-v1\n"},
    };
    std::string bytes;
    for (Entry& entry : entries) {
        entry.offset = static_cast<std::uint32_t>(bytes.size());
        append32(bytes, 0x04034b50u); append16(bytes, 20); append16(bytes, 0); append16(bytes, 0);
        append16(bytes, 0); append16(bytes, 0); append32(bytes, crc32(entry.data));
        append32(bytes, static_cast<std::uint32_t>(entry.data.size()));
        append32(bytes, static_cast<std::uint32_t>(entry.data.size()));
        append16(bytes, static_cast<std::uint16_t>(entry.name.size())); append16(bytes, 0);
        bytes.append(entry.name); bytes.append(entry.data);
    }
    const std::uint32_t central_offset = static_cast<std::uint32_t>(bytes.size());
    for (const Entry& entry : entries) {
        append32(bytes, 0x02014b50u); append16(bytes, 0x0314u); append16(bytes, 20);
        append16(bytes, 0); append16(bytes, 0); append16(bytes, 0); append16(bytes, 0);
        append32(bytes, crc32(entry.data)); append32(bytes, static_cast<std::uint32_t>(entry.data.size()));
        append32(bytes, static_cast<std::uint32_t>(entry.data.size()));
        append16(bytes, static_cast<std::uint16_t>(entry.name.size())); append16(bytes, 0);
        append16(bytes, 0); append16(bytes, 0); append16(bytes, 0); append32(bytes, (0100644u << 16));
        append32(bytes, entry.offset); bytes.append(entry.name);
    }
    const std::uint32_t central_size = static_cast<std::uint32_t>(bytes.size()) - central_offset;
    append32(bytes, 0x06054b50u); append16(bytes, 0); append16(bytes, 0);
    append16(bytes, static_cast<std::uint16_t>(entries.size()));
    append16(bytes, static_cast<std::uint16_t>(entries.size()));
    append32(bytes, central_size); append32(bytes, central_offset); append16(bytes, 0);
    return bytes;
}

Options parse_options(int argc, char** argv)
{
    Options options;
    std::string confirmation;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        auto value = [&]() -> std::string {
            if (++index >= argc) throw std::runtime_error("missing value after " + argument);
            return argv[index];
        };
        if (argument == "--root") options.root = fs::path(value());
        else if (argument == "--run-id") options.run_id = value();
        else if (argument == "--setup-revision") options.setup_revision = value();
        else if (argument == "--consumer-revision") options.consumer_revision = value();
        else if (argument == "--confirm") confirmation = value();
        else if (argument == "--test-mode") options.test_mode = true;
        else throw std::runtime_error("unknown argument: " + argument);
    }
    if (confirmation != "APPLY") throw std::runtime_error("explicit --confirm APPLY is required");
    if (options.root.empty() || !options.root.is_absolute()) throw std::runtime_error("--root must be absolute");
    if (!usk::record_io::valid_identifier(options.run_id)) throw std::runtime_error("--run-id is invalid");
    if (!hex_value(options.setup_revision, 40) || !hex_value(options.consumer_revision, 40)) {
        throw std::runtime_error("source revisions must be exact lowercase 40-character Git SHAs");
    }
    const fs::path absolute = fs::absolute(options.root).lexically_normal();
    if (options.test_mode) {
        if (!same_or_below(fs::temp_directory_path(), absolute) ||
            absolute.filename().generic_u8string().rfind("usk-live-acceptance-test-", 0) != 0) {
            throw std::runtime_error("test-mode roots must be named usk-live-acceptance-test-* below the temporary root");
        }
    } else {
#if defined(_WIN32)
        if (lower(absolute.generic_u8string()) != lower(fs::path("D:/FacMan-Live-Acceptance/M2").generic_u8string())) {
            throw std::runtime_error("live acceptance is restricted to D:/FacMan-Live-Acceptance/M2");
        }
#else
        throw std::runtime_error("non-Windows live roots require a future platform-specific operator authorization");
#endif
    }
    options.root = absolute;
    return options;
}

CommandResult execute(usk_context* context, const std::string& command, const Value& request, bool dry_run)
{
    const std::string json = usk::json::canonical(request);
    usk_command_request_v1 input{};
    usk_command_response_v1 output{};
    input.struct_size = sizeof(input);
    input.command_name = {command.data(), static_cast<usk_size>(command.size())};
    input.json_payload = {json.data(), static_cast<usk_size>(json.size())};
    input.dry_run = dry_run ? 1 : 0;
    output.struct_size = sizeof(output);
    CommandResult result;
    result.status = usk_command_execute_v1(context, &input, &output);
    if (output.json_payload.data == nullptr) throw std::runtime_error(command + " returned no JSON envelope");
    result.envelope = usk::json::parse(std::string(output.json_payload.data, output.json_payload.size));
    return result;
}

Value payload(usk_context* context, const std::string& command, const Value& request, bool dry_run)
{
    CommandResult result = execute(context, command, request, dry_run);
    if (result.status != USK_STATUS_OK || result.envelope.at("status").as_string() != "ok") {
        throw std::runtime_error(command + " refused: " + usk::json::canonical(result.envelope));
    }
    return result.envelope.at("payload");
}

Value apply_request(const std::string& schema, const Value& plan_request, const Value& plan,
                    const std::string& transaction_id)
{
    return Value(Value::Object{
        {"applied_at", Value(timestamp())}, {"confirmation", Value("APPLY")},
        {"plan_request", plan_request}, {"reviewed_plan_digest", plan.at("plan_digest")},
        {"reviewed_plan_id", plan.at("plan_id")}, {"schema", Value(schema)},
        {"transaction_id", Value(transaction_id)},
    });
}

Value finding(const std::string& code, const std::string& classification, const std::string& detail)
{
    return Value(Value::Object{{"classification", Value(classification)}, {"code", Value(code)},
        {"details_digest", Value(digest_text(detail))},
        {"severity", Value(classification == "failed_check" ? "error" : "info")}});
}

Value derived_target(const fs::path& root, const Value& original_target)
{
    const std::string path_digest = digest_text(normalized(root));
    const Value& filesystem = original_target.at("filesystem");
    return Value(Value::Object{
        {"class", Value("operator_acceptance")},
        {"filesystem", filesystem},
        {"identity_digest", Value(digest_text(path_digest + "\n" +
            filesystem.at("identity_digest").as_string()))},
        {"path_identity_digest", Value(path_digest)},
        {"persistent_effects", Value(Value::Array{
            Value("create or mutate exact setup-owned target"),
            Value("write setup-owned state and transaction journal"),
            Value("append setup-owned audit and evidence records")})},
    });
}

Value capture(usk_context* context, const Options& options, const Value& install_plan,
              const std::string& install_id, const std::string& packet_id,
              const std::string& operation, const std::string& plan_id,
              const std::string& plan_digest, const std::string& transaction_id,
              const fs::path& staging_parent, const fs::path& observed_target_root,
              const fs::path& transaction_target_root,
              const std::string& pre_snapshot, std::uint64_t file_count,
              std::uint64_t byte_count, Value::Array findings)
{
    const Value& source = install_plan.at("source");
    const Value target = derived_target(observed_target_root, install_plan.at("target"));
    const std::string post_snapshot = usk::evidence::snapshot_target(observed_target_root).snapshot_digest;
    const Value request(Value::Object{
        {"archive", Value(Value::Object{
            {"filesystem_identity_digest", source.at("filesystem_identity_digest")},
            {"path_identity_digest", source.at("path_identity_digest")},
            {"sha256", source.at("sha256")}, {"size_bytes", source.at("size_bytes")},
            {"source_id", source.at("source_id")}})},
        {"automated_findings", Value(std::move(findings))}, {"captured_at", Value(timestamp())},
        {"contract_versions", Value(Value::Array{
            Value(Value::Object{{"contract_id", Value("install_plan")}, {"schema_version", Value("usk.install_plan.v1")}}),
            Value(Value::Object{{"contract_id", Value("installed_state")}, {"schema_version", Value("usk.installed_state.v1")}}),
            Value(Value::Object{{"contract_id", Value("live_evidence")}, {"schema_version", Value("usk.live_target_evidence_packet.v1")}})})},
        {"install_id", Value(install_id)}, {"packet_id", Value(packet_id)},
        {"plan", Value(Value::Object{{"expected_byte_count", Value(byte_count)},
            {"expected_file_count", Value(file_count)}, {"operation", Value(operation)},
            {"plan_digest", Value(plan_digest)}, {"plan_id", Value(plan_id)}})},
        {"recipe_id", Value("recipe.synthetic.m2.v1")},
        {"request_id", Value("capture." + packet_id)},
        {"schema", Value("usk.live_target_evidence_capture_request.v1")},
        {"snapshots", Value(Value::Object{{"post_target_digest", Value(post_snapshot)},
            {"pre_target_digest", Value(pre_snapshot)}})},
        {"source_revisions", Value(Value::Array{
            Value(Value::Object{{"repository_id", Value("universal_setup")}, {"revision", Value(options.setup_revision)}}),
            Value(Value::Object{{"repository_id", Value("product_consumer")}, {"revision", Value(options.consumer_revision)}})})},
        {"target", target},
        {"transaction", Value(Value::Object{{"staging_parent", Value(normalized(staging_parent))},
            {"target_root", Value(normalized(transaction_target_root))}, {"transaction_id", Value(transaction_id)}})},
    });
    return payload(context, "live_evidence.capture", request, false);
}

void add_step(Value::Array& steps, const std::string& name, const std::string& status,
              const std::string& identity = {})
{
    Value::Object step{{"name", Value(name)}, {"status", Value(status)}};
    if (!identity.empty()) step.emplace("identity", Value(identity));
    steps.emplace_back(std::move(step));
}

int run(const Options& options)
{
    usk::record_io::require_safe_directory(options.root);
    usk::record_io::create_directory_exclusive(options.root, options.run_id);
    const fs::path run_root = options.root / options.run_id;
    const fs::path archive = run_root / "synthetic-product.zip";
    const fs::path setup_root = run_root / "setup-state";
    const fs::path installed_root = run_root / "installed-product";
    const fs::path moved_root = run_root / "moved-product";
    const fs::path summary_path = run_root / "acceptance-summary.json";
    usk::record_io::write_new_durable_text(archive, synthetic_zip());

    const std::string setup = setup_root.string();
    const std::string acceptance = options.root.string();
    usk_config_v1 config{};
    config.struct_size = sizeof(config);
    config.state_root = setup.c_str();
    config.authorized_acceptance_root = acceptance.c_str();
    config.target_policy_activation = "operator_acceptance_candidate";
    usk_context* context = nullptr;
    if (usk_context_create_v1(&config, &context) != USK_STATUS_OK || context == nullptr) {
        throw std::runtime_error("cannot create configured setup context");
    }

    Value::Array steps;
    Value::Array packets;
    try {
        const std::string install_id = "synthetic.m2." + options.run_id;
        const std::string archive_digest = usk::base::sha256_hex_file(archive);
        const std::string recipe_digest = digest_text("recipe.synthetic.m2.v1\nnon-executable\n3-files");
        const Value archive_binding(Value::Object{
            {"budgets", Value(Value::Object{{"max_depth", Value(std::uint64_t{32})},
                {"max_elapsed_ms", Value(std::uint64_t{30000})}, {"max_entries", Value(std::uint64_t{100})},
                {"max_entry_bytes", Value(std::uint64_t{1048576})}, {"max_ratio", Value(std::uint64_t{100})},
                {"max_uncompressed_bytes", Value(std::uint64_t{10485760})}})},
            {"expected_sha256", Value(archive_digest)}, {"format", Value("zip")},
            {"path", Value(normalized(archive))}, {"strip_prefix", Value("product")},
        });
        const Value install_request(Value::Object{
            {"archive", archive_binding}, {"created_at", Value(timestamp())}, {"install_id", Value(install_id)},
            {"recipe", Value(Value::Object{
                {"components", Value(Value::Array{Value("base")})},
                {"entrypoints", Value(Value::Array{Value(Value::Object{{"entrypoint_id", Value("readme")},
                    {"kind", Value("tool")}, {"relative_path", Value("README.txt")}})})},
                {"product_id", Value("synthetic.product")}, {"product_version", Value("1.0.0")},
                {"provider_revision", Value(options.setup_revision)}, {"recipe_digest", Value(recipe_digest)}})},
            {"request_id", Value("plan.install." + options.run_id)},
            {"schema", Value("usk.install_local_plan_request.v1")},
            {"target", Value(Value::Object{{"class", Value("operator_acceptance")},
                {"root", Value(normalized(installed_root))}})},
        });
        const Value install_plan = payload(context, "install_local.plan", install_request, true);
        const std::uint64_t file_count = install_plan.at("totals").at("file_count").as_unsigned();
        const std::uint64_t byte_count = install_plan.at("totals").at("uncompressed_bytes").as_unsigned();
        add_step(steps, "install_plan", "reviewed", install_plan.at("plan_digest").as_string());
        payload(context, "install_local.apply", apply_request("usk.install_local_apply_request.v1",
            install_request, install_plan, "tx.install." + options.run_id), false);
        add_step(steps, "install_apply", "completed");

        const Value verify_install(Value::Object{{"install_id", Value(install_id)},
            {"report_id", Value("verify.install." + options.run_id)},
            {"request_id", Value("request.verify.install." + options.run_id)},
            {"schema", Value("usk.installed_verify_request.v1")}, {"verified_at", Value(timestamp())}});
        const Value install_verification = payload(context, "installed.verify", verify_install, true);
        if (install_verification.at("status").as_string() != "pass") throw std::runtime_error("installed closure did not verify");
        add_step(steps, "install_verify", "pass", install_verification.at("report_digest").as_string());
        Value install_packet = capture(context, options, install_plan, install_id,
            "evidence.install." + options.run_id, "install_local", install_plan.at("plan_id").as_string(),
            install_plan.at("plan_digest").as_string(), "tx.install." + options.run_id,
            setup_root / "staging", installed_root, installed_root,
            install_plan.at("target").at("pre_snapshot_digest").as_string(), file_count, byte_count,
            Value::Array{finding("install_closure_verified", "passed_check", "three harmless files verified")});
        packets.emplace_back(Value::Object{{"packet_id", install_packet.at("packet_id")},
            {"packet_digest", install_packet.at("packet_digest")}});

        {
            std::ofstream damage(installed_root / "config/settings.ini", std::ios::binary | std::ios::trunc);
            damage << "damaged=true\n";
            if (!damage) throw std::runtime_error("cannot create deliberate owned-file damage");
        }
        const Value verify_damage(Value::Object{{"install_id", Value(install_id)},
            {"report_id", Value("verify.damage." + options.run_id)},
            {"request_id", Value("request.verify.damage." + options.run_id)},
            {"schema", Value("usk.installed_verify_request.v1")}, {"verified_at", Value(timestamp())}});
        const Value damage_report = payload(context, "installed.verify", verify_damage, true);
        if (damage_report.at("status").as_string() != "fail" ||
            damage_report.at("summary").at("modified_files").as_unsigned() == 0) {
            throw std::runtime_error("deliberate owned-file damage was not detected");
        }
        add_step(steps, "damage_verify", "expected_fail", damage_report.at("report_digest").as_string());

        const Value repair_request(Value::Object{{"archive", Value(Value::Object{
                {"expected_sha256", Value(archive_digest)}, {"format", Value("zip")},
                {"path", Value(normalized(archive))}, {"strip_prefix", Value("product")}})},
            {"created_at", Value(timestamp())}, {"install_id", Value(install_id)},
            {"plan_id", Value("plan.repair." + options.run_id)}, {"request_id", Value("request.repair." + options.run_id)},
            {"schema", Value("usk.repair_plan_request.v1")}});
        const Value repair_plan = payload(context, "repair.plan", repair_request, true);
        payload(context, "repair.apply", apply_request("usk.repair_apply_request.v1", repair_request,
            repair_plan, "tx.repair." + options.run_id), false);
        const Value verify_repair(Value::Object{{"install_id", Value(install_id)},
            {"report_id", Value("verify.repair." + options.run_id)},
            {"request_id", Value("request.verify.repair." + options.run_id)},
            {"schema", Value("usk.installed_verify_request.v1")}, {"verified_at", Value(timestamp())}});
        const Value repair_verification = payload(context, "installed.verify", verify_repair, true);
        if (repair_verification.at("status").as_string() != "pass") throw std::runtime_error("repair did not restore closure");
        add_step(steps, "repair", "pass", repair_plan.at("plan_digest").as_string());
        Value repair_packet = capture(context, options, install_plan, install_id,
            "evidence.repair." + options.run_id, "repair", repair_plan.at("plan_id").as_string(),
            repair_plan.at("plan_digest").as_string(), "tx.repair." + options.run_id,
            setup_root / "staging", installed_root,
            installed_root.parent_path() / (".usk-repair-tx.repair." + options.run_id),
            repair_plan.at("pre_target_snapshot_digest").as_string(),
            file_count, byte_count, Value::Array{
                finding("owned_damage_detected", "passed_check", "modified owned file detected"),
                finding("owned_damage_repaired", "passed_check", "exact source restored closure")});
        packets.emplace_back(Value::Object{{"packet_id", repair_packet.at("packet_id")},
            {"packet_digest", repair_packet.at("packet_digest")}});

        const Value move_request(Value::Object{{"created_at", Value(timestamp())}, {"install_id", Value(install_id)},
            {"new_target", Value(Value::Object{{"class", Value("operator_acceptance")},
                {"root", Value(normalized(moved_root))}})}, {"plan_id", Value("plan.move." + options.run_id)},
            {"request_id", Value("request.move." + options.run_id)}, {"schema", Value("usk.move_plan_request.v1")}});
        const Value move_plan = payload(context, "move.plan", move_request, true);
        const Value move_report = payload(context, "move.apply", apply_request("usk.move_apply_request.v1",
            move_request, move_plan, "tx.move." + options.run_id), false);
        if (move_report.at("status").as_string() != "new_committed_old_retained") {
            throw std::runtime_error("move did not preserve staged acceptance semantics");
        }
        const Value verify_move(Value::Object{{"install_id", Value(install_id)},
            {"report_id", Value("verify.move." + options.run_id)},
            {"request_id", Value("request.verify.move." + options.run_id)},
            {"schema", Value("usk.installed_verify_request.v1")}, {"verified_at", Value(timestamp())}});
        const Value move_verification = payload(context, "installed.verify", verify_move, true);
        if (move_verification.at("status").as_string() != "pass") throw std::runtime_error("moved closure did not verify");
        add_step(steps, "same_volume_move", "pass_old_root_retained", move_plan.at("plan_digest").as_string());
        Value move_packet = capture(context, options, install_plan, install_id,
            "evidence.move." + options.run_id, "move", move_plan.at("plan_id").as_string(),
            move_plan.at("plan_digest").as_string(), "tx.move." + options.run_id,
            moved_root.parent_path(), moved_root, moved_root,
            move_plan.at("target_snapshots").at("pre_target_digest").as_string(), file_count, byte_count,
            Value::Array{finding("moved_closure_verified", "passed_check", "new root verified; old root retained")});
        packets.emplace_back(Value::Object{{"packet_id", move_packet.at("packet_id")},
            {"packet_digest", move_packet.at("packet_digest")}});
        add_step(steps, "cross_volume_move", "not_attempted_no_second_authorized_volume");

        const fs::path foreign_file = moved_root / "operator-note.txt";
        usk::record_io::write_new_durable_text(foreign_file, "foreign acceptance content\n");
        const Value uninstall_review(Value::Object{{"created_at", Value(timestamp())}, {"install_id", Value(install_id)},
            {"plan_id", Value("plan.uninstall.review." + options.run_id)},
            {"request_id", Value("request.uninstall.review." + options.run_id)},
            {"schema", Value("usk.uninstall_plan_request.v1")}});
        const Value review_plan = payload(context, "uninstall.plan", uninstall_review, true);
        const CommandResult refused = execute(context, "uninstall.apply",
            apply_request("usk.uninstall_apply_request.v1", uninstall_review, review_plan,
                "tx.uninstall.refused." + options.run_id), false);
        if (refused.status == USK_STATUS_OK || usk::json::canonical(refused.envelope).find(
                "foreign_content_review_required") == std::string::npos || !fs::exists(foreign_file)) {
            throw std::runtime_error("uninstall did not retain and report foreign content");
        }
        add_step(steps, "uninstall_with_foreign_content", "refused_and_retained");

        std::error_code remove_error;
        if (!fs::remove(foreign_file, remove_error) || remove_error) {
            throw std::runtime_error("authorized exact foreign-file removal failed");
        }
        add_step(steps, "operator_exact_foreign_file_removal", "completed_by_runner_not_setup");
        const Value uninstall_request(Value::Object{{"created_at", Value(timestamp())}, {"install_id", Value(install_id)},
            {"plan_id", Value("plan.uninstall.clean." + options.run_id)},
            {"request_id", Value("request.uninstall.clean." + options.run_id)},
            {"schema", Value("usk.uninstall_plan_request.v1")}});
        const Value uninstall_plan = payload(context, "uninstall.plan", uninstall_request, true);
        const Value uninstall_report = payload(context, "uninstall.apply",
            apply_request("usk.uninstall_apply_request.v1", uninstall_request, uninstall_plan,
                "tx.uninstall.clean." + options.run_id), false);
        if (uninstall_report.at("status").as_string() != "completed" || fs::exists(moved_root)) {
            throw std::runtime_error("clean uninstall did not remove the current owned root");
        }
        add_step(steps, "clean_uninstall", "pass", uninstall_plan.at("plan_digest").as_string());
        Value uninstall_packet = capture(context, options, install_plan, install_id,
            "evidence.uninstall." + options.run_id, "uninstall", uninstall_plan.at("plan_id").as_string(),
            uninstall_plan.at("plan_digest").as_string(), "tx.uninstall.clean." + options.run_id,
            setup_root / "staging", moved_root,
            moved_root.parent_path() / (".usk-uninstall-tx.uninstall.clean." + options.run_id),
            uninstall_plan.at("target_snapshots").at("pre_target_digest").as_string(), file_count, byte_count,
            Value::Array{
                finding("foreign_content_refusal", "passed_check", "unknown file retained and apply refused"),
                finding("clean_uninstall_completed", "passed_check", "current owned root removed")});
        packets.emplace_back(Value::Object{{"packet_id", uninstall_packet.at("packet_id")},
            {"packet_digest", uninstall_packet.at("packet_digest")}});

        const Value summary(Value::Object{
            {"archive", Value(Value::Object{{"path", Value(normalized(archive))},
                {"sha256", Value(archive_digest)}, {"contains_executable_code", Value(false)}})},
            {"authority", Value(Value::Object{{"acceptance_root", Value(normalized(options.root))},
                {"ordinary_live_apply_promoted", Value(false)}, {"operator_verdict", Value("pending")},
                {"run_execute_authorized", Value(false)}})},
            {"completed_at", Value(timestamp())}, {"evidence_packets", Value(std::move(packets))},
            {"run_id", Value(options.run_id)}, {"run_root", Value(normalized(run_root))},
            {"schema", Value("usk.m2_live_acceptance_summary.v1")},
            {"source_revisions", Value(Value::Object{{"consumer", Value(options.consumer_revision)},
                {"universal_setup", Value(options.setup_revision)}})},
            {"status", Value("automated_findings_complete_pending_operator_verdict")},
            {"steps", Value(std::move(steps))},
        });
        usk::record_io::write_new_durable_text(summary_path, usk::json::canonical(summary) + "\n");
        std::cout << usk::json::canonical(Value(Value::Object{{"status", Value("ok")},
            {"summary", Value(normalized(summary_path))}})) << '\n';
        usk_context_destroy_v1(context);
        return 0;
    } catch (...) {
        usk_context_destroy_v1(context);
        throw;
    }
}

} // namespace

int main(int argc, char** argv)
{
    try {
        return run(parse_options(argc, argv));
    } catch (const std::exception& error) {
        std::cerr << "usk_live_acceptance: " << error.what() << '\n';
        return 1;
    }
}
