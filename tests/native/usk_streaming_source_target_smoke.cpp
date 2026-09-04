// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_sha256.h"
#include "usk_streaming_source_target.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
namespace streaming = usk::streaming;

namespace {

constexpr std::size_t kBufferBytes = streaming::kPayloadBufferBytes;

struct Fixture {
    fs::path root;
    fs::path source;
    fs::path staging;
    fs::path targets;
    fs::path state;
    fs::path audit;

    explicit Fixture(const std::string& name)
    {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        root = fs::temp_directory_path() /
            ("usk-streaming-" + name + "-" + std::to_string(nonce));
        source = root / "source";
        staging = root / "staging";
        targets = root / "targets";
        state = root / "state";
        audit = root / "audit";
        fs::create_directories(source);
        fs::create_directories(staging);
        fs::create_directories(targets);
        fs::create_directories(state / "transactions");
        fs::create_directories(audit);
    }

    ~Fixture()
    {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }

    usk::transaction::TransactionSpec spec(const std::string& id) const
    {
        return {
            "tx.stream." + id,
            "plan.stream." + id,
            std::string(64u, 'a'),
            "install_local",
            staging,
            targets / id,
            state,
            audit};
    }
};

void write_generated(const fs::path& path, std::size_t bytes, unsigned char seed)
{
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    if (!output) throw std::runtime_error("cannot create streaming fixture");
    std::vector<unsigned char> buffer(kBufferBytes);
    std::size_t offset = 0;
    while (offset < bytes) {
        const std::size_t count = std::min(buffer.size(), bytes - offset);
        for (std::size_t index = 0; index < count; ++index) {
            buffer[index] = static_cast<unsigned char>((seed + offset + index) % 251u);
        }
        output.write(
            reinterpret_cast<const char*>(buffer.data()),
            static_cast<std::streamsize>(count));
        offset += count;
    }
}

streaming::StreamRequest request(
    const streaming::DirectorySource& source,
    const usk::transaction::TransactionSpec& spec,
    const std::string& suffix)
{
    streaming::StreamRequest value;
    value.source = source;
    value.transaction = spec;
    value.audit_chain_id = "audit.stream." + suffix;
    value.recorded_at = "2026-08-26T00:00:00Z";
    value.budget = {kBufferBytes, 1024u};
    return value;
}

struct ToggleCancellation final : streaming::CancellationView, streaming::ProgressSink {
    bool value = false;
    bool cancelled() const noexcept override { return value; }
    void advanced(const std::string&, std::uint64_t, std::uint64_t total) override
    {
        if (total >= kBufferBytes) value = true;
    }
};

bool contains(const std::string& value, const std::string& expected)
{
    return value.find(expected) != std::string::npos;
}

int successful_vertical()
{
    Fixture fixture("success");
    write_generated(fixture.source / "bin/tool.exe", 3u * kBufferBytes + 17u, 7u);
    write_generated(fixture.source / "data/settings.json", kBufferBytes + 9u, 19u);
    const streaming::DirectorySource source = streaming::inspect_directory_source(
        fixture.source, {kBufferBytes, 1024u});
    const auto spec = fixture.spec("success");
    const streaming::StreamResult result = streaming::stream_directory_to_target(
        request(source, spec, "success"));
    if (!result.completed || result.disposition != "target_committed_audited" ||
        result.entries_completed != 2u || result.bytes_completed != source.total_bytes ||
        result.peak_payload_buffer_bytes != kBufferBytes || result.public_abi_changed ||
        result.audit_event_digest.size() != 64u ||
        usk::base::sha256_hex_file(spec.target_root / "bin/tool.exe") != source.entries[0].sha256) {
        return 10;
    }
    return 0;
}

int bounded_memory_proof()
{
    const streaming::ResourceBudget budget{kBufferBytes, 8u};
    const std::vector<std::uint64_t> sizes = {
        1ull * 1024ull * 1024ull,
        64ull * 1024ull * 1024ull,
        512ull * 1024ull * 1024ull};
    for (std::uint64_t size : sizes) {
        if (streaming::measure_generated_payload_buffer(size, budget) != kBufferBytes) return 20;
    }
    for (const std::size_t invalid : {4096u, 128u * 1024u, 4u * 1024u * 1024u}) {
        try {
            (void)streaming::measure_generated_payload_buffer(
                2u * kBufferBytes, {invalid, 8u});
            return 21;
        } catch (const std::runtime_error&) {
        }
    }
    return 0;
}

int cancellation_and_faults()
{
    {
        Fixture fixture("cancel");
        write_generated(fixture.source / "payload.bin", 4u * kBufferBytes, 3u);
        auto source = streaming::inspect_directory_source(fixture.source);
        const auto spec = fixture.spec("cancel");
        auto value = request(source, spec, "cancel");
        ToggleCancellation cancellation;
        value.cancellation = &cancellation;
        value.progress = &cancellation;
        const auto result = streaming::stream_directory_to_target(std::move(value));
        if (result.completed || result.error_code != "stream_cancelled" ||
            result.disposition != "rolled_back_no_target_visible" ||
            fs::exists(spec.target_root)) {
            return 30;
        }
    }
    {
        Fixture fixture("write-fault");
        write_generated(fixture.source / "payload.bin", 2u * kBufferBytes, 4u);
        auto source = streaming::inspect_directory_source(fixture.source);
        const auto spec = fixture.spec("write-fault");
        auto value = request(source, spec, "write-fault");
        value.fault = [](const std::string& point, const std::string&, std::uint64_t) {
            if (contains(point, "before_stream_write")) {
                throw std::runtime_error("injected disk full before stream write");
            }
        };
        const auto result = streaming::stream_directory_to_target(std::move(value));
        if (result.completed || result.disposition != "rolled_back_no_target_visible" ||
            fs::exists(spec.target_root)) return 31;
    }
    for (const std::string boundary : {
             "transaction:staging:before_stream_finalize",
             "transaction:staged:before_journal",
             "before_commit"}) {
        Fixture fixture("late-cancel");
        write_generated(fixture.source / "payload.bin", 2u * kBufferBytes, 4u);
        auto source = streaming::inspect_directory_source(fixture.source);
        const auto spec = fixture.spec("late-cancel");
        auto value = request(source, spec, "late-cancel");
        ToggleCancellation cancellation;
        value.cancellation = &cancellation;
        value.fault = [&](const std::string& point, const std::string&, std::uint64_t) {
            if (point == boundary) cancellation.value = true;
        };
        const auto result = streaming::stream_directory_to_target(std::move(value));
        if (result.completed || result.error_code != "stream_cancelled" ||
            result.disposition != "rolled_back_no_target_visible" ||
            fs::exists(spec.target_root)) return 35;
    }
    {
        Fixture fixture("journal-fault");
        write_generated(fixture.source / "payload.bin", kBufferBytes, 5u);
        auto source = streaming::inspect_directory_source(fixture.source);
        const auto spec = fixture.spec("journal-fault");
        auto value = request(source, spec, "journal-fault");
        value.fault = [](const std::string& point, const std::string&, std::uint64_t) {
            if (point == "transaction:staged:before_journal") {
                throw std::runtime_error("injected journal write failure");
            }
        };
        const auto result = streaming::stream_directory_to_target(std::move(value));
        if (result.completed || result.disposition != "rolled_back_no_target_visible" ||
            fs::exists(spec.target_root)) return 32;
    }
    {
        Fixture fixture("precreate-fault");
        write_generated(fixture.source / "nested/payload.bin", kBufferBytes, 5u);
        auto source = streaming::inspect_directory_source(fixture.source);
        const auto spec = fixture.spec("precreate-fault");
        auto value = request(source, spec, "precreate-fault");
        value.fault = [](const std::string& point, const std::string&, std::uint64_t) {
            if (point == "transaction:staging:before_stage_stream") {
                throw std::runtime_error("injected interruption before stream file create");
            }
        };
        const auto result = streaming::stream_directory_to_target(std::move(value));
        if (result.completed || result.disposition != "rolled_back_no_target_visible" ||
            fs::exists(spec.target_root)) return 34;
    }
    {
        Fixture fixture("audit-fault");
        write_generated(fixture.source / "payload.bin", kBufferBytes, 6u);
        auto source = streaming::inspect_directory_source(fixture.source);
        const auto spec = fixture.spec("audit-fault");
        auto value = request(source, spec, "audit-fault");
        value.fault = [](const std::string& point, const std::string&, std::uint64_t) {
            if (point == "after_commit_before_audit") {
                throw std::runtime_error("injected failure after finalize before audit");
            }
        };
        const auto result = streaming::stream_directory_to_target(std::move(value));
        if (result.completed ||
            result.disposition != "target_visible_recovery_or_audit_required" ||
            !fs::is_directory(spec.target_root)) return 33;
    }
    return 0;
}

int identity_and_integrity_faults()
{
    Fixture fixture("identity");
    write_generated(fixture.source / "payload.bin", kBufferBytes, 8u);
    auto source = streaming::inspect_directory_source(fixture.source);
    write_generated(fixture.source / "payload.bin", kBufferBytes + 1u, 9u);
    const auto spec = fixture.spec("identity");
    const auto result = streaming::stream_directory_to_target(
        request(source, spec, "identity"));
    if (result.completed || result.error_code != "source_identity_changed" ||
        result.disposition != "rolled_back_no_target_visible" ||
        fs::exists(spec.target_root)) {
        return 40;
    }
    return 0;
}

} // namespace

int main()
{
    if (const int result = successful_vertical()) return result;
    if (const int result = bounded_memory_proof()) return result;
    if (const int result = cancellation_and_faults()) return result;
    if (const int result = identity_and_integrity_faults()) return result;
    std::cout << "usk-streaming-source-target: ok; peak_payload_buffer_bytes="
              << kBufferBytes << "; logical_max_bytes=" << (512ull * 1024ull * 1024ull)
              << "; public_abi=1.0-unchanged\n";
    return 0;
}
