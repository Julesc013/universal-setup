// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_repair_source_admission_internal.h"

#include <algorithm>
#include <atomic>
#include <memory>
#include <stdexcept>
#include <thread>
#include <utility>

namespace usk::lifecycle::detail {
namespace {
struct ExpectedFile {
    std::string path, sha256;
    std::uint64_t size;
};

// Owns exactly one public repair's selected readers. No bytes or native effects
// can escape this owner before fresh complete-source admission succeeds.
struct RepairSource final {
    std::string request, prefix, source_sha256, source_identity, entry_set;
    std::uint64_t archive_size;
    std::function<void()> original_source_keepalive;
    std::vector<ExpectedFile> expected;
    std::vector<archive::PayloadReader> readers;
    std::chrono::milliseconds budget;
    RepairSourceClock now;
    const std::thread::id owner = std::this_thread::get_id();
    std::atomic<bool> failed{false};
    bool attempted = false, ready = false, checking = false;
    std::chrono::steady_clock::time_point deadline{};
    LifecycleCancellation cancellation;

    RepairSource(std::string input, std::string strip,
        const archive::StreamingStoredArchivePayload& original,
        const std::vector<PayloadFile>& selected,
        std::chrono::milliseconds duration, RepairSourceClock clock)
        : request(std::move(input)), prefix(std::move(strip)),
          source_sha256(original.source_sha256), source_identity(original.source_identity_digest),
          entry_set(original.entry_set_digest), archive_size(original.archive_size_bytes),
          original_source_keepalive(original.validate_source), budget(duration), now(std::move(clock))
    {
        if (!now) now = [] { return std::chrono::steady_clock::now(); };
        if (!original_source_keepalive || selected.empty() || selected.size() > 10000u ||
            duration.count() < 1 || duration.count() > 600000)
            throw std::runtime_error("repair source admission has invalid bounded inputs");
        for (const auto& file : selected) {
            if (!file.reader || !file.bytes.empty() ||
                file.stream_buffer_bytes != archive::streaming_payload_buffer_bytes ||
                (!expected.empty() && expected.back().path >= file.relative_path))
                throw std::runtime_error("repair source admission requires ordered streaming replacements");
            expected.push_back({file.relative_path, file.sha256, file.size_bytes});
        }
    }

    void require_owner() {
        if (owner != std::this_thread::get_id() || failed.load()) {
            failed.store(true);
            throw std::runtime_error("repair source admission owner is unavailable or failed");
        }
    }
    void check_phase() {
        require_owner();
        if (checking) {
            failed.store(true);
            throw std::runtime_error("repair source admission cannot be reentered");
        }
        checking = true;
        try {
            if ((cancellation && cancellation()) || now() > deadline)
                throw std::runtime_error("repair archive extraction phase expired or was cancelled");
            // A caller callback cannot swallow a nested owner's failure.
            require_owner();
            checking = false;
        } catch (...) {
            checking = false;
            failed.store(true);
            throw;
        }
    }
    void prepare(LifecycleCancellation cancel) {
        try {
            require_owner();
            if (attempted) throw std::runtime_error("repair source admission cannot be restarted");
            attempted = true;
            cancellation = std::move(cancel);
            // This deadline includes the new identity, full archive hash,
            // metadata/CRC/expanded-boundary checks and all selected reads.
            deadline = now() + budget;
            check_phase();
            // Archive readers retain this checker, but this owner owns those
            // readers. A raw back-reference avoids a shared_ptr ownership cycle;
            // the outer callable retains this owner throughout every invocation.
            auto fresh = archive::inspect_streaming_payload(request, prefix,
                archive::streaming_payload_buffer_bytes, nullptr, [this] {
                    check_phase();
                    return false;
                });
            check_phase();
            if (fresh.source_sha256 != source_sha256 ||
                fresh.source_identity_digest != source_identity ||
                fresh.entry_set_digest != entry_set || fresh.archive_size_bytes != archive_size)
                throw std::runtime_error("repair source changed before extraction admission");
            readers.resize(expected.size());
            for (auto& file : fresh.files) {
                const auto selected = std::lower_bound(expected.begin(), expected.end(), file.relative_path,
                    [](const ExpectedFile& left, const std::string& right) { return left.path < right; });
                if (selected == expected.end() || selected->path != file.relative_path) continue;
                const auto index = static_cast<std::size_t>(selected - expected.begin());
                if (readers[index] || file.sha256 != selected->sha256 || file.size_bytes != selected->size)
                    throw std::runtime_error("repair source replacement closure changed before extraction");
                readers[index] = std::move(file.reader);
            }
            if (std::any_of(readers.begin(), readers.end(), [](const auto& reader) { return !reader; }))
                throw std::runtime_error("repair source omitted a reviewed replacement");
            fresh.validate_source();
            check_phase();
            ready = true;
        } catch (...) {
            failed.store(true);
            throw;
        }
    }
    std::size_t read(std::size_t index, std::uint64_t offset, unsigned char* output, std::size_t capacity) {
        try {
            require_owner();
            if (!ready || index >= readers.size())
                throw std::runtime_error("repair replacement read preceded source admission");
            check_phase();
            const auto count = readers[index](offset, output, capacity);
            check_phase();
            return count;
        } catch (...) {
            failed.store(true);
            throw;
        }
    }
};
}

void bind_repair_source_admission(RepairPlan& plan, std::string request, std::string prefix,
    const archive::StreamingStoredArchivePayload& original,
    std::chrono::milliseconds budget, RepairSourceClock now)
{
    if (plan.prepare_payload || plan.source_digest != original.source_sha256)
        throw std::runtime_error("repair source admission is already bound or differs from its plan");
    auto source = std::make_shared<RepairSource>(std::move(request), std::move(prefix),
        original, plan.replacement_files, budget, std::move(now));
    for (std::size_t index = 0; index < plan.replacement_files.size(); ++index)
        plan.replacement_files[index].reader = [source, index](std::uint64_t offset,
            unsigned char* output, std::size_t capacity) {
                const auto lifetime = source;
                return lifetime->read(index, offset, output, capacity);
            };
    plan.prepare_payload = [source](LifecycleCancellation cancellation) {
        const auto lifetime = source;
        lifetime->prepare(std::move(cancellation));
    };
}
}
