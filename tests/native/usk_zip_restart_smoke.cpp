// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk/usk_api.h"
#include "usk_public_lifecycle.h"
#include "usk_install_restart.h"
#include "usk_archive_payload.h"
#include "usk_audit_repository.h"
#include "usk_json.h"
#include "usk_lifecycle.h"
#include "usk_sha256.h"
#include "usk_transaction_session.h"

#include <algorithm>
#include <cstdlib>
#include <map>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif
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

std::string bytes_from_hex(const std::string& value)
{
    if (value.size() % 2u != 0u) throw std::runtime_error("invalid fixture hex");
    std::string result;
    result.reserve(value.size() / 2u);
    for (std::size_t index = 0; index < value.size(); index += 2u) {
        result.push_back(static_cast<char>(
            std::stoul(value.substr(index, 2u), nullptr, 16)));
    }
    return result;
}

std::string probe_content() { return std::string(2u * 65536u + 17u, 'p'); }

void write_zip(const fs::path& path, bool deflated = false)
{
    struct Entry {
        std::string name;
        std::string data;
        std::string archive_data;
        std::uint16_t method;
        std::uint32_t offset;
    };
    std::vector<Entry> entries = {
        {"product/bin/probe.txt", probe_content(),
         deflated ? bytes_from_hex("edc13101000000c2a0caeb7f99c00640010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c03") : probe_content(),
         static_cast<std::uint16_t>(deflated ? 8 : 0), 0},
        {"product/data/config.ini", "enabled=true\n",
         deflated ? bytes_from_hex("4bcd4b4cca494db12d292a4de50200") : "enabled=true\n",
         static_cast<std::uint16_t>(deflated ? 8 : 0), 0}};
    std::vector<unsigned char> bytes;
    for (Entry& entry : entries) {
        entry.offset = static_cast<std::uint32_t>(bytes.size());
        append32(bytes, 0x04034b50u); append16(bytes, 20); append16(bytes, 0); append16(bytes, entry.method);
        append16(bytes, 0); append16(bytes, 0); append32(bytes, crc32(entry.data));
        append32(bytes, static_cast<std::uint32_t>(entry.archive_data.size()));
        append32(bytes, static_cast<std::uint32_t>(entry.data.size()));
        append16(bytes, static_cast<std::uint16_t>(entry.name.size())); append16(bytes, 0);
        bytes.insert(bytes.end(), entry.name.begin(), entry.name.end());
        bytes.insert(bytes.end(), entry.archive_data.begin(), entry.archive_data.end());
    }
    const std::uint32_t central_offset = static_cast<std::uint32_t>(bytes.size());
    for (const Entry& entry : entries) {
        append32(bytes, 0x02014b50u); append16(bytes, 0x0314u); append16(bytes, 20);
        append16(bytes, 0); append16(bytes, entry.method); append16(bytes, 0); append16(bytes, 0);
        append32(bytes, crc32(entry.data)); append32(bytes, static_cast<std::uint32_t>(entry.archive_data.size()));
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


std::string read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
struct Fixture {
    fs::path root = fs::temp_directory_path() /
        ("usk-zr-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    usk::lifecycle::LifecycleRoots roots{root / "u/staging", root / "u/state", root / "u/audit"};
    explicit Fixture(bool native = true) {
        fs::create_directories(root);
        if (!native) return;
        fs::create_directories(roots.staging_parent);
        fs::create_directories(roots.state_root);
        fs::create_directories(roots.audit_root);
        usk::state::StateRepository::initialize_layout(roots.state_root);
        fs::create_directory(roots.state_root / "transactions");
        usk::audit::AuditRepository::initialize_layout(roots.audit_root);
    }
    ~Fixture() { std::error_code ignored; fs::remove_all(root, ignored); }
};
usk::lifecycle::InstallPlan plan(Fixture& fixture, bool deflate) {
    const fs::path archive = fixture.root / "source.zip";
    if (!fs::exists(archive)) write_zip(archive, deflate);
    const Value request(Value::Object{
        {"schema", Value("usk.archive_inspect_request.v1")},
        {"archive_path", Value(archive.u8string())},
        {"archive_format", Value("zip")},
        {"budgets", Value(Value::Object{
        {"max_entries", Value(std::uint64_t{100})},
        {"max_uncompressed_bytes", Value(std::uint64_t{10485760})},
        {"max_entry_bytes", Value(std::uint64_t{1048576})},
        {"max_ratio", Value(std::uint64_t{10000})},
        {"max_depth", Value(std::uint64_t{32})},
        {"max_elapsed_ms", Value(std::uint64_t{30000})}})}});
    auto archive_payload = usk::archive::inspect_streaming_payload(usk::json::canonical(request), "product");
    usk::lifecycle::RecipeBinding recipe{"product", "1", std::string(64, 'a'),
        archive_payload.source_sha256, std::string(64, 'b'), "provider", {"base"},
        {{"probe", "bin/probe.txt", "tool"}}};
    recipe.source_identity_digest = archive_payload.source_identity_digest;
    recipe.entry_set_digest = archive_payload.entry_set_digest;
    std::vector<usk::lifecycle::PayloadFile> files;
    for (auto& entry : archive_payload.files) {
        files.push_back({entry.relative_path, {}, entry.sha256, entry.size_bytes,
                         std::move(entry.reader), archive_payload.payload_buffer_bytes});
    }
    return usk::lifecycle::plan_install("plan", "i", "2026-09-07T00:00:00Z",
        fixture.root / "target", fixture.roots, std::move(recipe), std::move(files), std::move(archive_payload.validate_source));
}
int pending_source_binding() {
    for (bool deflate : {false, true}) {
        Fixture fixture;
        const auto planned = plan(fixture, deflate);
        bool interrupted = false;
        try {
            (void)usk::lifecycle::apply_install(planned, planned.plan_digest, "old",
                "2026-09-07T00:00:01Z", [&](const std::string&, const std::string& point) {
                    if (point == "transaction.staging.before_stream_read") {
                        interrupted = true;
                        throw std::runtime_error("entry interruption");
                    }
                });
        } catch (const std::runtime_error&) {}
        if (!interrupted) return 200;
        const auto journal = usk::json::parse(read(fixture.roots.state_root / "transactions/old.journal.json"));
        if (journal.at("recovery_metadata").at("stream_journal").at("source_digest").type() !=
                Value::Type::string) return 201;
    }
    return 0;
}
Value public_plan_request(const fs::path& archive, const fs::path& target, const std::string& source_hash)
{
    return Value(Value::Object{
        {"archive", Value(Value::Object{
            {"budgets", Value(Value::Object{{"max_depth", Value(std::uint64_t{32})},
                {"max_elapsed_ms", Value(std::uint64_t{30000})}, {"max_entries", Value(std::uint64_t{100})},
                {"max_entry_bytes", Value(std::uint64_t{1048576})}, {"max_ratio", Value(std::uint64_t{10000})},
                {"max_uncompressed_bytes", Value(std::uint64_t{10485760})}})},
            {"expected_sha256", Value(source_hash)}, {"format", Value("zip")},
            {"path", Value(archive.u8string())}, {"strip_prefix", Value("product")}})},
        {"created_at", Value("2026-07-14T01:00:00Z")}, {"install_id", Value("i")},
        {"recipe", Value(Value::Object{
            {"components", Value(Value::Array{Value("base")})},
            {"entrypoints", Value(Value::Array{Value(Value::Object{
                {"entrypoint_id", Value("probe")}, {"kind", Value("tool")},
                {"relative_path", Value("bin/probe.txt")}})})},
            {"product_id", Value("synthetic.product")}, {"product_version", Value("1.0.0")},
            {"provider_revision", Value("test.provider.1")}, {"recipe_digest", Value(std::string(64, 'a'))}})},
        {"request_id", Value("plan")}, {"schema", Value("usk.install_local_plan_request.v1")},
        {"target", Value(Value::Object{{"class", Value("operator_acceptance")},
            {"root", Value(target.generic_u8string())}})}});
}

Value apply_request(
    const char* schema,
    const Value& plan,
    const std::string& plan_id,
    const std::string& plan_digest,
    const std::string& transaction_id,
    const std::string& applied_at)
{
    return Value(Value::Object{{"applied_at", Value(applied_at)}, {"confirmation", Value("APPLY")},
        {"plan_request", plan}, {"reviewed_plan_digest", Value(plan_digest)},
        {"reviewed_plan_id", Value(plan_id)}, {"schema", Value(schema)},
        {"transaction_id", Value(transaction_id)}});
}


void write(const fs::path& path, const std::string& text) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc); output << text;
    if (!output) throw std::runtime_error("fixture write failed");
}
using Snapshot = std::map<std::string, std::string>;
Snapshot snapshot(const fs::path& root) {
    Snapshot result;
    if (!fs::exists(root)) return result;
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        result.emplace(entry.path().lexically_relative(root).generic_string(),
            entry.is_directory() ? "directory" : read(entry.path()));
    }
    return result;
}
struct PublicResult { int status; Value document; };
PublicResult command(const fs::path& root, const std::string& name, const Value& request,
    usk::lifecycle::LifecycleFaultInjector fault = {}) {
    const auto setup = (root / "u").string(); const auto acceptance = root.string();
    const auto text = usk::json::canonical(request); int status = USK_STATUS_ERROR;
    std::string response;
    if (fault) {
        char* raw = usk::lifecycle::public_command_json(name.c_str(), text.data(), text.size(),
            setup.c_str(), acceptance.c_str(), "operator_acceptance_candidate", &status, fault);
        if (raw == nullptr) throw std::runtime_error("private dispatcher allocation failed");
        response = raw; usk_public_lifecycle_command_free(raw);
    } else {
        usk_config_v1 config{}; config.struct_size = sizeof(config);
        config.state_root = setup.c_str(); config.authorized_acceptance_root = acceptance.c_str();
        config.target_policy_activation = "operator_acceptance_candidate";
        usk_context* context = nullptr;
        if (usk_context_create_v1(&config, &context) != USK_STATUS_OK) throw std::runtime_error("public context failed");
        usk_command_request_v1 input{}; input.struct_size = sizeof(input);
        input.command_name = {name.data(), static_cast<usk_size>(name.size())};
        input.json_payload = {text.data(), static_cast<usk_size>(text.size())};
        input.dry_run = name == "install_local.plan" || name == "recovery.inspect";
        usk_command_response_v1 output{}; output.struct_size = sizeof(output);
        status = usk_command_execute_v1(context, &input, &output);
        response = output.json_payload.data == nullptr ? "" : std::string(output.json_payload.data, output.json_payload.size);
        usk_context_destroy_v1(context);
    }
    return {status, usk::json::parse(response)};
}
Value reviewed_apply(const fs::path& root, const std::string& transaction_id) {
    const auto request = usk::json::parse(read(root / "request.json"));
    const auto reviewed = usk::json::parse(read(root / "planned.json"));
    return apply_request("usk.install_local_apply_request.v1", request,
        reviewed.at("plan_id").as_string(), reviewed.at("plan_digest").as_string(),
        transaction_id, "2026-09-07T00:00:01Z");
}
PublicResult inspect(const fs::path& root, const std::string& transaction_id) {
    const auto reviewed = usk::json::parse(read(root / "planned.json"));
    return command(root, "recovery.inspect", Value(Value::Object{
        {"schema", Value("usk.recovery_inspect_request.v1")}, {"request_id", Value("inspect")},
        {"install_id", Value("i")}, {"transaction_id", Value(transaction_id)},
        {"plan_id", reviewed.at("plan_id")}, {"plan_digest", reviewed.at("plan_digest")},
        {"operation", Value("install_local")}, {"target_root", Value((root / "target").generic_u8string())}}));
}
Value replay_request(const fs::path& root, const std::string& prior, const std::string& next) {
    const auto observation = inspect(root, prior);
    if (observation.status != USK_STATUS_OK) throw std::runtime_error(usk::json::canonical(observation.document));
    auto request = reviewed_apply(root, next);
    const auto& report = observation.document.at("payload");
    request.as_object().emplace("restart_from", Value(Value::Object{
        {"transaction_id", Value(prior)}, {"journal_snapshot_sha256", report.at("journal_snapshot_sha256")},
        {"audit_chain_digest", report.at("audit_chain_digest")}}));
    return request;
}
void prepare_public(Fixture& fixture, bool deflate) {
    write_zip(fixture.root / "source.zip", deflate);
    auto request = public_plan_request(fixture.root / "source.zip", fixture.root / "target",
        usk::base::sha256_hex_file(fixture.root / "source.zip"));
    const auto result = command(fixture.root, "install_local.plan", request);
    if (result.status != USK_STATUS_OK) throw std::runtime_error(usk::json::canonical(result.document));
    write(fixture.root / "request.json", usk::json::canonical(request));
    write(fixture.root / "planned.json", usk::json::canonical(result.document.at("payload")));
    if (fs::exists(fixture.root / "u")) throw std::runtime_error("plan initialized setup state");
}
int public_audit_observation_bound() {
    Fixture fixture(false); prepare_public(fixture, false);
    const auto stopped = command(fixture.root, "install_local.apply", reviewed_apply(fixture.root, "old"),
        [](const std::string&, const std::string& point) {
            if (point == "transaction.staging.after_stream_intent") throw std::runtime_error("retained audit inspection fixture");
        });
    if (stopped.status != USK_STATUS_ERROR) return 140;
    const usk::audit::AuditRepository repository(fixture.roots.audit_root);
    const std::string chain_id = "audit.i";
    const auto original = repository.read_and_validate_chain_bounded(chain_id, 1);
    if (original.size() != 1) return 141;
    const usk::audit::AuditInput input{"2026-09-07T00:00:02Z", "recovery", "recovery", "warn",
        "journal", "old", std::string(64, 'a'), "old", "", "bounded inspection fixture"};
    for (std::size_t index = original.size(); index < 32; ++index) repository.append(chain_id, input);
    const auto at_limit = repository.read_and_validate_chain_bounded(chain_id, 32);
    if (at_limit.size() != 32) return 142;
    const auto before_limit_inspection = snapshot(fixture.root);
    const auto admitted = inspect(fixture.root, "old");
    if (admitted.status != USK_STATUS_OK ||
        admitted.document.at("payload").at("audit_chain_digest").as_string() != at_limit.back().event_digest ||
        snapshot(fixture.root) != before_limit_inspection) return 143;
    repository.append(chain_id, input);
    // This is a valid chain beyond the public observation cap, not malformed audit data.
    const auto over_limit = repository.read_and_validate_chain_bounded(chain_id, 33);
    if (over_limit.size() != 33 || over_limit.back().previous_event_digest != at_limit.back().event_digest) return 144;
    const auto before_over_limit_inspection = snapshot(fixture.root);
    const auto unavailable = inspect(fixture.root, "old");
    if (unavailable.status != USK_STATUS_OK ||
        unavailable.document.at("payload").at("audit_chain_digest").type() != Value::Type::null_value ||
        unavailable.document.at("payload").at("journal_snapshot_sha256").as_string() !=
            admitted.document.at("payload").at("journal_snapshot_sha256").as_string() ||
        snapshot(fixture.root) != before_over_limit_inspection) return 145;
    return 0;
}
int run_child(const fs::path& executable, const fs::path& root, const std::string& point) {
#if defined(_WIN32)
    const auto quote = [](const std::wstring& value) {
        if (value.find(L'"') != std::wstring::npos) throw std::runtime_error("invalid fixture argument");
        return L"\"" + value + L"\"";
    };
    std::wstring command = quote(executable.wstring()) + L" child " + quote(root.wstring()) +
        L" " + quote(std::wstring(point.begin(), point.end()));
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) throw std::runtime_error("child launch failed");
    const DWORD waited = WaitForSingleObject(process.hProcess, 30000);
    DWORD code = 255;
    if (waited != WAIT_OBJECT_0) { TerminateProcess(process.hProcess, 255); WaitForSingleObject(process.hProcess, 5000); }
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    return static_cast<int>(code);
#else
    const auto path = executable.string(); const auto directory = root.string();
    const pid_t child = fork();
    if (child < 0) throw std::runtime_error("child fork failed");
    if (child == 0) {
        execl(path.c_str(), path.c_str(), "child", directory.c_str(), point.c_str(), static_cast<char*>(nullptr));
        std::_Exit(254);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 255;
    return WEXITSTATUS(status);
#endif
}

int child(const fs::path& root, const std::string& point) {
    const bool replay = point.rfind("replay:", 0) == 0;
    const std::string observed_point = replay ? point.substr(7) : point;
    const auto request = replay ? replay_request(root, "old", "new") : reviewed_apply(root, "old");
    const auto result = command(root, "install_local.apply", request,
        [&](const std::string&, const std::string& actual) { if (actual == observed_point) std::_Exit(77); });
    std::cerr << usk::json::canonical(result.document) << '\n';
    return 249;
}
int public_process_boundaries(const fs::path& executable) {
    const std::vector<std::string> points{
        "transaction.staging.after_stream_intent", "transaction.staging.after_stream_open",
        "transaction.staging.after_stream_write", "transaction.staging.after_stage_stream",
        "transaction.staged.after_journal", "transaction.verified.after_journal",
        "transaction.committing.after_journal", "transaction.committing.after_commit_effect",
        "transaction.committed.after_journal"};
    for (bool deflate : {false, true}) {
        for (std::size_t i = 0; i < points.size(); ++i) {
            Fixture fixture(false); prepare_public(fixture, deflate);
            if (run_child(executable, fixture.root, points[i]) != 77) return 20 + static_cast<int>(i);
            const auto inspected = inspect(fixture.root, "old");
            if (inspected.status != USK_STATUS_OK) return 30;
            const auto prior_journal = read(fixture.roots.state_root / "transactions/old.journal.json");
            const auto old_audit = snapshot(fixture.roots.audit_root / "chains/audit.i");
            const auto staging = fixture.roots.staging_parent / ".usk-stage-old";
            if (i == 3) {
                fs::rename(staging / "bin/probe.txt", fixture.root / "original.txt");
                write(staging / "bin/probe.txt", probe_content());
            }
            const auto old_stage = snapshot(staging);
            const auto request = replay_request(fixture.root, "old", "new");
            const auto before = snapshot(fixture.root);
            const auto result = command(fixture.root, "install_local.apply", request);
            if (i < 6) {
                if (result.status != USK_STATUS_OK) {
                    std::cerr << points[i] << " replay: " << usk::json::canonical(result.document) << '\n'; return 40;
                }
                if (read(fixture.root / "target/bin/probe.txt") != probe_content() ||
                    snapshot(staging) != old_stage || snapshot(fixture.roots.audit_root / "chains/audit.i") != old_audit ||
                    read(fixture.roots.state_root / "transactions/old.journal.json") != prior_journal) return 41;
                const auto new_chain = usk::lifecycle::install_audit_chain_id("i", "new", true);
                const auto events = usk::audit::AuditRepository(fixture.roots.audit_root).read_and_validate_chain(new_chain);
                if (events.size() != 2 || events.front().operation != "recovery" || events.back().phase != "completed") return 42;
                const auto genesis = usk::json::parse(events.front().message);
                if (genesis.at("prior_journal_snapshot_sha256").as_string() !=
                    inspected.document.at("payload").at("journal_snapshot_sha256").as_string() ||
                    genesis.at("prior_audit_chain_digest").as_string() !=
                    inspected.document.at("payload").at("audit_chain_digest").as_string()) return 43;
            } else if (result.status == USK_STATUS_OK || snapshot(fixture.root) != before) {
                return 50 + static_cast<int>(i);
            }
        }
    }
    return 0;
}

int admission_and_custody(const fs::path& executable) {
    for (bool deflate : {false, true}) {
        for (int which = 0; which < 7; ++which) {
            Fixture fixture(false); prepare_public(fixture, deflate);
            if (run_child(executable, fixture.root, "transaction.staging.after_stream_write") != 77) return 60;
            auto request = replay_request(fixture.root, "old", "new");
            if (which == 0) {
                request.as_object()["restart_from"].as_object()["journal_snapshot_sha256"] = Value(std::string(64, '0'));
            } else if (which == 1) {
                request.as_object()["restart_from"].as_object()["audit_chain_digest"] = Value(std::string(64, '0'));
            } else if (which == 2) {
                fs::rename(fixture.root / "source.zip", fixture.root / "original.zip");
                fs::copy_file(fixture.root / "original.zip", fixture.root / "source.zip");
            } else if (which == 3) {
                fs::rename(fixture.root / "u", fixture.root / "original-u");
                fs::copy(fixture.root / "original-u", fixture.root / "u", fs::copy_options::recursive);
            } else if (which == 4) {
                const auto journal_path = fixture.roots.state_root / "transactions/old.journal.json";
                auto journal = usk::json::parse(read(journal_path));
                auto& stream = journal.as_object()["recovery_metadata"].as_object()["stream_journal"];
                auto context = usk::json::parse(stream.at("source_context").as_string());
                auto policy_context = usk::json::parse(context.at("policy_context").as_string());
                policy_context.as_object()["policy"].as_object()["setup_binding_digest"] = Value(std::string(64, 'f'));
                context.as_object()["policy_context"] = Value(usk::json::canonical(policy_context));
                context.as_object()["policy_digest"] = Value(usk::json::sha256_canonical(policy_context.at("policy")));
                stream.as_object()["source_context"] = Value(usk::json::canonical(context));
                stream.as_object()["source_digest"] = Value(usk::json::sha256_canonical(context));
                stream.as_object().erase("digest");
                stream.as_object()["digest"] = Value(usk::json::sha256_canonical(stream));
                write(journal_path, usk::json::canonical(journal) + "\n");
                request.as_object()["restart_from"].as_object()["journal_snapshot_sha256"] =
                    Value(usk::base::sha256_hex_file(journal_path));
            } else if (which == 5) {
                const auto chain = fixture.roots.audit_root / "chains" /
                    usk::lifecycle::install_audit_chain_id("i", "new", true);
                fs::create_directory(chain); write(chain / "foreign.txt", "foreign chain survives");
            } else {
                // A fresh ID whose journal already exists must not change old or new audit records.
                write(fixture.roots.state_root / "transactions/new.journal.json", "foreign journal");
            }
            const auto before = snapshot(fixture.root);
            const auto result = command(fixture.root, "install_local.apply", request);
            if (result.status == USK_STATUS_OK) return 61 + which;
            if (which == 5) {
                if (result.document.at("error").at("code").as_string() != "restart_effects_retained" ||
                    !fs::exists(fixture.roots.state_root / "transactions/new.journal.json") ||
                    inspect(fixture.root, "new").status != USK_STATUS_OK) return 70;
                for (const auto& [name, bytes] : before) {
                    if (bytes != "directory" && read(fixture.root / name) != bytes) return 71;
                }
                if (fs::exists(fixture.root / "target")) return 72;
            } else if (snapshot(fixture.root) != before) return 73 + which;
        }
    }
    return 0;
}
int replay_creation_boundaries(const fs::path& executable) {
    const std::vector<std::string> points{
        "transaction.created.after_journal", "before_replay_audit_create",
        "after_replay_audit_directory_create", "after_replay_audit_create"};
    for (bool deflate : {false, true}) {
        for (std::size_t index = 0; index < points.size(); ++index) {
            Fixture fixture(false); prepare_public(fixture, deflate);
            if (run_child(executable, fixture.root, "transaction.staging.after_stream_write") != 77) return 90;
            const auto old_stage = snapshot(fixture.roots.staging_parent / ".usk-stage-old");
            const auto old_chain = snapshot(fixture.roots.audit_root / "chains/audit.i");
            const auto old_journal = read(fixture.roots.state_root / "transactions/old.journal.json");
            if (run_child(executable, fixture.root, "replay:" + points[index]) != 77) return 91;
            const auto result = inspect(fixture.root, "new");
            if (result.status != USK_STATUS_OK || fs::exists(fixture.root / "target") ||
                snapshot(fixture.roots.staging_parent / ".usk-stage-old") != old_stage ||
                snapshot(fixture.roots.audit_root / "chains/audit.i") != old_chain ||
                read(fixture.roots.state_root / "transactions/old.journal.json") != old_journal) return 92;
            const auto new_journal = usk::json::parse(read(fixture.roots.state_root / "transactions/new.journal.json"));
            const auto& metadata = new_journal.at("recovery_metadata");
            if (metadata.at("stream_cleanup_policy").as_string() != "retain_only" ||
                metadata.at("staging_identity").type() != Value::Type::null_value ||
                metadata.at("stream_journal").at("restart_origin").at("transaction_id").as_string() != "old") return 93;
            if (index < 3) {
                if (result.document.at("payload").at("audit_chain_digest").type() != Value::Type::null_value) return 94;
            } else {
                const auto replay = command(fixture.root, "install_local.apply", replay_request(fixture.root, "new", "third"));
                if (replay.status != USK_STATUS_OK || read(fixture.root / "target/bin/probe.txt") != probe_content()) {
                    std::cerr << "replay lineage: " << usk::json::canonical(replay.document) << '\n'; return 95;
                }
            }
        }
    }
    return 0;
}
int absent_target_commit_uncertainty(const fs::path& executable) {
    for (bool deflate : {false, true}) {
        Fixture fixture(false); prepare_public(fixture, deflate);
        if (run_child(executable, fixture.root, "transaction.committing.after_commit_effect") != 77) return 100;
        fs::rename(fixture.root / "target", fixture.root / "original-target");
        const auto request = replay_request(fixture.root, "old", "new");
        const auto before = snapshot(fixture.root);
        const auto result = command(fixture.root, "install_local.apply", request);
        if (result.status == USK_STATUS_OK || snapshot(fixture.root) != before ||
            read(fixture.root / "original-target/bin/probe.txt") != probe_content()) return 101;
    }
    return 0;
}

usk::lifecycle::InstallRestartRequest native_restart_request(const Fixture& fixture,
    const usk::lifecycle::InstallPlan& planned, const std::string& prior) {
    const usk::transaction::TransactionSpec spec{prior, planned.plan_id, planned.plan_digest, "install_local",
        fixture.roots.staging_parent, planned.target_root, fixture.roots.state_root, fixture.roots.audit_root};
    const auto observation = usk::transaction::TransactionSession::inspect_recovery(spec);
    const auto chain = usk::lifecycle::install_audit_chain_id(planned.install_id, prior,
        !observation.restart_origin_transaction_id.empty());
    return {prior, observation.snapshot_sha256,
        usk::audit::AuditRepository(fixture.roots.audit_root).read_and_validate_chain(chain).back().event_digest};
}
int native_replay_finalization() {
    for (bool deflate : {false, true}) {
        Fixture fixture; auto original = plan(fixture, deflate);
        bool interrupted = false;
        try {
            (void)usk::lifecycle::apply_install(original, original.plan_digest, "old", "2026-09-07T00:00:01Z",
                [&](const std::string&, const std::string& point) {
                    if (point == "transaction.staging.after_stream_write") { interrupted = true; throw std::runtime_error("interrupted"); }
                });
        } catch (const std::runtime_error&) {}
        if (!interrupted) return 110;
        const auto retained = snapshot(fixture.roots.staging_parent / ".usk-stage-old");
        auto fresh = plan(fixture, deflate);
        const auto restart = native_restart_request(fixture, fresh, "old");
        bool retained_error = false;
        try {
            (void)usk::lifecycle::restart_install(fresh, fresh.plan_digest, "new", "2026-09-07T00:00:02Z", restart,
                [](const std::string&, const std::string& point) {
                    if (point == "after_target_commit") throw std::runtime_error("after replay target visibility");
                });
        } catch (const usk::lifecycle::RestartEffectsRetained&) { retained_error = true; }
        if (!retained_error || !fs::exists(fixture.root / "target")) return 111;
        const auto result = usk::lifecycle::recover_install_finalization(fresh, "new", "2026-09-07T00:00:03Z");
        if (result.verification.status != "pass" || result.installed_state.transaction_id != "new" ||
            result.installed_state.audit_chain_id != usk::lifecycle::install_audit_chain_id("i", "new", true) ||
            snapshot(fixture.roots.staging_parent / ".usk-stage-old") != retained ||
            read(fixture.root / "target/bin/probe.txt") != probe_content()) return 112;
    }
    return 0;
}
int concurrent_original_and_replay() {
    for (bool deflate : {false, true}) {
        Fixture fixture; auto original = plan(fixture, deflate);
        std::mutex mutex; std::condition_variable ready; int verified = 0; bool release = false;
        std::atomic<int> completed{0};
        const auto barrier = [&](const std::string&, const std::string& point) {
            if (point != "transaction.verified.after_journal") return;
            std::unique_lock<std::mutex> lock(mutex); ++verified; ready.notify_all();
            if (!ready.wait_for(lock, std::chrono::seconds(20), [&] { return release; })) {
                throw std::runtime_error("bounded commit rendezvous expired");
            }
        };
        std::thread first([&] {
            try { (void)usk::lifecycle::apply_install(original, original.plan_digest, "old", "2026-09-07T00:00:01Z", barrier); ++completed; }
            catch (const std::exception&) {}
        });
        bool first_ready = false;
        { std::unique_lock<std::mutex> lock(mutex); first_ready = ready.wait_for(lock, std::chrono::seconds(20), [&] { return verified == 1; }); }
        if (!first_ready) { { std::lock_guard<std::mutex> lock(mutex); release = true; } ready.notify_all(); first.join(); return 120; }
        auto fresh = plan(fixture, deflate);
        const auto restart = native_restart_request(fixture, fresh, "old");
        std::thread second([&] {
            try { (void)usk::lifecycle::restart_install(fresh, fresh.plan_digest, "new", "2026-09-07T00:00:02Z", restart, barrier); ++completed; }
            catch (const std::exception&) {}
        });
        bool both_ready = false;
        { std::unique_lock<std::mutex> lock(mutex); both_ready = ready.wait_for(lock, std::chrono::seconds(20), [&] { return verified == 2; }); release = true; }
        ready.notify_all(); first.join(); second.join();
        if (!both_ready || completed.load() != 1 || read(fixture.root / "target/bin/probe.txt") != probe_content()) return 121;
        int completed_journals = 0, retained_journals = 0;
        for (const auto* id : {"old", "new"}) {
            const usk::transaction::TransactionSpec spec{id, fresh.plan_id, fresh.plan_digest, "install_local",
                fixture.roots.staging_parent, fresh.target_root, fixture.roots.state_root, fixture.roots.audit_root};
            const auto inspected = usk::transaction::TransactionSession::inspect_recovery(spec);
            if (inspected.current_state == "completed") ++completed_journals;
            else if (inspected.current_state == "recovery_required" && inspected.staging_exists &&
                inspected.available_actions == std::vector<std::string>{"retain_for_operator"} &&
                read(fixture.roots.staging_parent / (std::string(".usk-stage-") + id) / "bin/probe.txt") == probe_content()) ++retained_journals;
        }
        if (completed_journals != 1 || retained_journals != 1) return 122;
    }
    return 0;
}

int ancestor_commit_uncertainty() {
    for (bool deflate : {false, true}) {
        Fixture fixture; auto original = plan(fixture, deflate);
        std::mutex mutex; std::condition_variable ready; bool verified = false, release = false;
        std::thread owner([&] {
            try {
                (void)usk::lifecycle::apply_install(original, original.plan_digest, "old", "2026-09-07T00:00:01Z",
                    [&](const std::string&, const std::string& point) {
                        if (point == "transaction.verified.after_journal") {
                            std::unique_lock<std::mutex> lock(mutex); verified = true; ready.notify_all();
                            if (!ready.wait_for(lock, std::chrono::seconds(20), [&] { return release; })) throw std::runtime_error("owner wait expired");
                        }
                        if (point == "after_target_commit") throw std::runtime_error("uncertain ancestor commit before audit completion");
                    });
            } catch (const std::exception&) {}
        });
        bool owner_ready = false;
        { std::unique_lock<std::mutex> lock(mutex); owner_ready = ready.wait_for(lock, std::chrono::seconds(20), [&] { return verified; }); }
        bool replay_retained = false;
        if (owner_ready) {
            try {
                auto fresh = plan(fixture, deflate);
                (void)usk::lifecycle::restart_install(fresh, fresh.plan_digest, "new", "2026-09-07T00:00:02Z",
                    native_restart_request(fixture, fresh, "old"), [](const std::string&, const std::string& point) {
                        if (point == "after_replay_audit_create") throw std::runtime_error("retained intermediate replay");
                    });
            } catch (const usk::lifecycle::RestartEffectsRetained&) { replay_retained = true; }
            catch (const std::exception&) {}
        }
        { std::lock_guard<std::mutex> lock(mutex); release = true; } ready.notify_all(); owner.join();
        if (!owner_ready || !replay_retained || !fs::exists(fixture.root / "target")) return 130;
        fs::rename(fixture.root / "target", fixture.root / "original-target");
        auto third_plan = plan(fixture, deflate);
        const auto restart = native_restart_request(fixture, third_plan, "new");
        const auto before = snapshot(fixture.root); bool refused = false;
        try { (void)usk::lifecycle::restart_install(third_plan, third_plan.plan_digest, "third", "2026-09-07T00:00:03Z", restart); }
        catch (const std::runtime_error&) { refused = true; }
        if (!refused || snapshot(fixture.root) != before) return 131;
    }
    return 0;
}
} // namespace
int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "ancestor") return ancestor_commit_uncertainty();
        if (argc == 2 && std::string(argv[1]) == "audit-bound") return public_audit_observation_bound();
        if (argc == 4 && std::string(argv[1]) == "child") return child(fs::u8path(argv[2]), argv[3]);
        if (const int result = pending_source_binding()) return result;
        if (const int result = public_audit_observation_bound()) return result;
        const auto executable = fs::absolute(fs::u8path(argv[0]));
        if (const int result = public_process_boundaries(executable)) return result;
        if (const int result = admission_and_custody(executable)) return result;
        if (const int result = replay_creation_boundaries(executable)) return result;
        if (const int result = absent_target_commit_uncertainty(executable)) return result;
        if (const int result = native_replay_finalization()) return result;
        if (const int result = concurrent_original_and_replay()) return result;
        if (const int result = ancestor_commit_uncertainty()) return result;
        std::cout << "ZIP replay: stored/Deflate, 50 process exits, admission/retention, finalization and competing commits PASS\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 250; }
}
