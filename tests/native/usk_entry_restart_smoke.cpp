// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_json.h"
#include "usk_sha256.h"
#include "usk_transaction_session.h"
#include "usk_streaming_source_target.h"
#include "usk_stable_file.h"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <map>
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
namespace tx = usk::transaction;
namespace {
struct Fixture {
    fs::path root;
    bool owner = true;
    explicit Fixture(const fs::path& existing = {}) : root(existing.empty() ? fs::temp_directory_path() /
        ("usk-er-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())) : existing),
        owner(existing.empty())
    {
        for (const auto* name : {"source", "stage", "target", "state/transactions", "audit"}) {
            fs::create_directories(root / name);
        }
    }
    ~Fixture() { if (owner) { std::error_code ignored; fs::remove_all(root, ignored); } }
    tx::TransactionSpec spec() const {
        return {"tx", "plan", std::string(64, 'a'), "install_local", root / "stage",
                root / "target/new", root / "state", root / "audit"};
    }
};
std::string read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
std::string digest(const std::string& bytes) {
    usk::base::Sha256 hash;
    hash.update(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    return hash.finish();
}
void stage(tx::TransactionSession& session, const std::string& bytes) {
    std::size_t offset = 0;
    session.stage_file_stream("child/payload.bin", bytes.size(), digest(bytes), 4096,
        [&](unsigned char* data, std::size_t capacity) {
            const auto count = std::min(capacity, bytes.size() - offset);
            std::copy_n(bytes.data() + offset, count, data);
            offset += count;
            return count;
        });
}
int pending_entry() {
    Fixture fixture;
    tx::TransactionSession session(fixture.spec(), [](const std::string&, const std::string& point) {
        if (point == "before_stream_read") throw std::runtime_error("interrupted");
    });
    try { stage(session, "payload"); } catch (const std::runtime_error&) {}
    const auto journal = usk::json::parse(read(session.journal_path()));
    const auto& metadata = journal.at("recovery_metadata");
    if (metadata.as_object().count("stream_journal") == 0) return 201;
    const auto& entry = metadata.at("stream_journal").at("entries").as_array().at(0);
    if (entry.at("relative_path").as_string() != "child/payload.bin" ||
        entry.at("phase").as_string() != "writing" ||
        entry.at("expected_size").as_unsigned() != 7 ||
        entry.at("sha256").as_string() != digest("payload")) return 202;
    return 0;
}
int substituted_completion() {
    Fixture fixture;
    tx::TransactionSession session(fixture.spec());
    stage(session, "payload");
    const auto path = session.staging_root() / "child/payload.bin";
    fs::rename(path, fixture.root / "original.bin");
    { std::ofstream output(path, std::ios::binary); output << "payload"; }
    session.mark_staged();
    bool refused = false;
    try { session.mark_verified(); } catch (const std::runtime_error&) { refused = true; }
    if (!refused) return 203;
    if (read(path) != "payload" || read(fixture.root / "original.bin") != "payload") return 204;
    return 0;
}
void write(const fs::path& path, const std::string& bytes) {
    std::ofstream output(path, std::ios::binary); output << bytes;
    if (!output) throw std::runtime_error("fixture write failed");
}
using Snapshot = std::map<std::string, std::string>;
Snapshot snapshot(const fs::path& root) {
    Snapshot result;
    for (const auto& item : fs::recursive_directory_iterator(root)) {
        const auto name = item.path().lexically_relative(root).generic_string();
        if (item.is_directory()) result[name] = "directory";
        else {
            usk::base::StableFile file(item.path());
            result[name] = file.identity().volume_id + ":" + file.identity().file_id + ":" + file.sha256_hex();
        }
    }
    return result;
}
usk::streaming::StreamRequest request(const Fixture& fixture) {
    usk::streaming::StreamRequest result;
    result.transaction = fixture.spec();
    result.source = usk::streaming::inspect_directory_source(fixture.root / "source");
    result.audit_chain_id = "audit";
    result.recorded_at = "2026-09-07T00:00:00Z";
    return result;
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
    Fixture fixture(root);
    auto value = request(fixture);
    value.fault = [&](const std::string& observed, const std::string&, std::uint64_t) {
        if (observed == point) std::_Exit(77); // No destructors or catch recovery: real process interruption.
    };
    (void)usk::streaming::stream_directory_to_target(std::move(value));
    return 249;
}
int process_boundaries(const fs::path& executable) {
    const std::vector<std::string> points = {
        "transaction:staging:after_stream_intent", "transaction:staging:after_stream_open",
        "transaction:staging:after_stream_write", "transaction:staging:after_stage_stream",
        "transaction:staged:after_journal", "transaction:verified:after_journal",
        "transaction:committing:after_journal", "transaction:committing:after_commit_effect",
        "transaction:committed:after_journal"};
    for (std::size_t index = 0; index < points.size(); ++index) {
        Fixture fixture;
        const std::string payload(2 * usk::streaming::kPayloadBufferBytes + 17, 'p');
        write(fixture.root / "source/a.bin", payload);
        write(fixture.root / "source/b.bin", "second entry");
        const auto original = request(fixture);
        if (run_child(executable, fixture.root, points[index]) != 77) return 100 + static_cast<int>(index);
        const auto inspection = tx::TransactionSession::inspect_recovery(fixture.spec());
        auto replay = original;
        replay.transaction.transaction_id = "replay";
        replay.restart_transaction_id = "tx";
        replay.restart_snapshot_sha256 = inspection.snapshot_sha256;
        const auto old_staging = fixture.root / "stage/.usk-stage-tx";
        if (index < 6) {
            if (index == 3) {
                fs::rename(old_staging / "a.bin", fixture.root / "original.bin");
                write(old_staging / "a.bin", payload); // Different object with exactly the same bytes.
            }
            const auto retained = snapshot(old_staging);
            bool durable_origin = false;
            replay.fault = [&](const std::string& point, const std::string&, std::uint64_t) {
                if (point != "transaction:created:after_journal") return;
                const auto journal = usk::json::parse(read(fixture.root / "state/transactions/replay.journal.json"));
                const auto& metadata = journal.at("recovery_metadata");
                const auto& origin = metadata.at("stream_journal").at("restart_origin");
                durable_origin = origin.at("transaction_id").as_string() == "tx" &&
                    origin.at("snapshot_sha256").as_string() == inspection.snapshot_sha256 &&
                    metadata.at("stream_cleanup_policy").as_string() == "retain_only" &&
                    metadata.at("staging_identity").type() == usk::json::Value::Type::null_value &&
                    !fs::exists(fixture.root / "stage/.usk-stage-replay");
            };
            const auto result = usk::streaming::stream_directory_to_target(std::move(replay));
            if (!result.completed || !durable_origin || result.entries_completed != 2 ||
                result.peak_payload_buffer_bytes != usk::streaming::kPayloadBufferBytes ||
                read(fixture.spec().target_root / "a.bin") != payload ||
                snapshot(old_staging) != retained) return 120 + static_cast<int>(index);
            if (index == 3 && read(fixture.root / "original.bin") != payload) return 129;
        } else {
            const auto before = snapshot(fixture.root);
            const auto result = usk::streaming::stream_directory_to_target(std::move(replay));
            if (result.completed || snapshot(fixture.root) != before) return 140 + static_cast<int>(index);
            if (index > 6) {
                auto finalization = tx::TransactionSession::resume_finalization(fixture.spec());
                if (finalization->current_state() == "committing") finalization->mark_committed();
                finalization->mark_completed();
                if (tx::TransactionSession::inspect_recovery(fixture.spec()).current_state != "completed") return 150;
            }
        }
    }
    return 0;
}
int input_refusals() {
    Fixture fixture;
    write(fixture.root / "source/a.bin", "payload");
    const auto original = request(fixture);
    auto interrupted = original;
    interrupted.fault = [](const std::string& point, const std::string&, std::uint64_t) {
        if (point == "transaction:staging:before_stream_read") throw std::runtime_error("interrupted");
    };
    if (usk::streaming::stream_directory_to_target(std::move(interrupted)).completed) return 160;
    const auto inspection = tx::TransactionSession::inspect_recovery(fixture.spec());
    const auto replay = [&]() {
        auto value = original; value.transaction.transaction_id = "replay";
        value.restart_transaction_id = "tx"; value.restart_snapshot_sha256 = inspection.snapshot_sha256;
        return value;
    };
    for (int variation = 0; variation < 4; ++variation) {
        auto value = replay();
        if (variation == 0) value.restart_snapshot_sha256 = std::string(64, 'b');
        if (variation == 1) value.transaction.plan_digest = std::string(64, 'c');
        if (variation == 2) value.transaction.transaction_id = "tx";
        if (variation == 3) {
            fs::rename(fixture.root / "source/a.bin", fixture.root / "source-original.bin");
            write(fixture.root / "source/a.bin", "payload");
        }
        const auto before = snapshot(fixture.root);
        const auto result = usk::streaming::stream_directory_to_target(std::move(value));
        if (result.completed || result.disposition != "refused_before_transaction" ||
            snapshot(fixture.root) != before) return 161 + variation;
    }
    return 0;
}
int construction_disposition() {
    Fixture fixture;
    write(fixture.root / "source/a.bin", "payload");
    auto original = request(fixture);
    original.fault = [](const std::string& point, const std::string&, std::uint64_t) {
        if (point == "transaction:staging:before_stream_read") throw std::runtime_error("interrupted source");
    };
    (void)usk::streaming::stream_directory_to_target(std::move(original));
    auto replay = request(fixture);
    replay.transaction.transaction_id = "replay";
    replay.restart_transaction_id = "tx";
    replay.restart_snapshot_sha256 = tx::TransactionSession::inspect_recovery(fixture.spec()).snapshot_sha256;
    replay.fault = [](const std::string& point, const std::string&, std::uint64_t) {
        if (point == "transaction:created:after_journal") throw std::runtime_error("interrupted constructor");
    };
    const auto result = usk::streaming::stream_directory_to_target(std::move(replay));
    if (!fs::is_regular_file(fixture.root / "state/transactions/replay.journal.json")) return 189;
    if (result.disposition != "recovery_required_no_target_visible") return 190;
    return 0;
}

int malformed_metadata() {
    Fixture fixture;
    tx::TransactionSession session(fixture.spec());
    session.bind_stream_source(std::string(64, 'b'));
    stage(session, "payload");
    const auto original = read(session.journal_path());
    for (int variation = 0; variation < 5; ++variation) {
        auto document = usk::json::parse(original);
        auto& metadata = document.as_object().at("recovery_metadata").as_object();
        auto& journal = metadata.at("stream_journal");
        if (variation == 0) metadata.erase("stream_cleanup_policy");
        if (variation == 1) journal.as_object().at("entries").as_array()[0].as_object()["phase"] = usk::json::Value("writing");
        if (variation == 2) journal.as_object().at("entries").as_array()[0].as_object()["output_identity"] = usk::json::Value{};
        if (variation == 3) journal.as_object()["source_digest"] = usk::json::Value("");
        if (variation == 4) journal.as_object()["unknown_authority"] = usk::json::Value(true);
        // A self-consistent digest must not excuse semantically invalid metadata.
        journal.as_object().erase("digest");
        const auto hash = usk::json::sha256_canonical(journal);
        journal.as_object().emplace("digest", usk::json::Value(hash));
        write(session.journal_path(), usk::json::canonical(document));
        const auto before = snapshot(fixture.root);
        bool refused = false;
        try { (void)tx::TransactionSession::inspect_recovery(fixture.spec()); }
        catch (const std::exception&) { refused = true; }
        if (!refused || snapshot(fixture.root) != before) return 170 + variation;
    }
    write(session.journal_path(), original);
    return 0;
}
int concurrent_replays() {
    Fixture fixture;
    const std::string source_digest(64, 'b');
    { tx::TransactionSession original(fixture.spec()); original.bind_stream_source(source_digest); stage(original, "payload"); }
    const auto inspection = tx::TransactionSession::inspect_recovery(fixture.spec());
    const auto retained = snapshot(fixture.root / "stage/.usk-stage-tx");
    auto first = tx::TransactionSession::restart_streaming(fixture.spec(), "r1", inspection.snapshot_sha256, source_digest);
    auto second = tx::TransactionSession::restart_streaming(fixture.spec(), "r2", inspection.snapshot_sha256, source_digest);
    for (const auto* item : {&first, &second}) {
        stage(**item, "payload"); (*item)->mark_staged(); (*item)->mark_verified();
    }
    std::atomic<int> ready{0}; std::atomic<bool> go{false}; std::atomic<int> completed{0};
    const auto finish = [&](tx::TransactionSession& session) {
        ++ready; while (!go.load()) std::this_thread::yield();
        try { session.commit(); ++completed; } catch (const std::exception&) {}
    };
    std::thread a(finish, std::ref(*first)); std::thread b(finish, std::ref(*second));
    while (ready.load() != 2) std::this_thread::yield(); go = true; a.join(); b.join();
    if (completed != 1 || read(fixture.spec().target_root / "child/payload.bin") != "payload" ||
        snapshot(fixture.root / "stage/.usk-stage-tx") != retained) return 180;
    auto& loser = first->current_state() == "completed" ? second : first;
    if (read(loser->staging_root() / "child/payload.bin") != "payload") return 181;
    bool refused = false; try { loser->rollback(); } catch (const std::exception&) { refused = true; }
    if (!refused || read(loser->staging_root() / "child/payload.bin") != "payload") return 182;
    return 0;
}
}
int main(int argc, char** argv) {
    try {
        if (argc == 4 && std::string(argv[1]) == "child") return child(fs::u8path(argv[2]), argv[3]);
        if (argc > 1 && std::string(argv[1]) == "construction") return construction_disposition();
        if (argc > 1) return substituted_completion();
        for (const auto check : {pending_entry, substituted_completion, input_refusals, construction_disposition, malformed_metadata, concurrent_replays}) {
            if (const auto result = check()) { std::cerr << "entry restart regression failed: " << result << '\n'; return result; }
        }
        if (const auto result = process_boundaries(fs::absolute(fs::u8path(argv[0])))) {
            std::cerr << "entry restart process regression failed: " << result << '\n'; return result;
        }
        std::cout << "entry restart: nine process boundaries, identity/refusal/concurrency checks passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 250; }
}
