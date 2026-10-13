// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_DIAGNOSTIC_METRICS_H
#define USK_DIAGNOSTIC_METRICS_H

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace usk::diagnostics {
// Process-wide diagnostics only: no native observation or authority is kept.
enum class Counter : std::size_t {
    held_file_instances, hash_calls, hash_successes, hash_bytes,
    exact_read_calls, exact_read_bytes, provider_open_calls, provider_open_successes,
    wire_send_packets, wire_send_bytes, wire_receive_packets, wire_receive_bytes,
    access_check_calls, not_submitted_events, count
};
enum class Phase : std::uint32_t {
    machine_request = 1, engine_request, response_write, authority_fence,
    record_proof, child_native_before, child_native_after, broker_collect,
    record_first_round, record_byte_read, record_second_round,
    record_final_validation
};
struct Snapshot {
    std::array<std::uint64_t, static_cast<std::size_t>(Counter::count)> totals{};
    bool saturated = false;
};
struct Event {
    Phase phase;
    std::uint64_t scope_id;
    bool exiting;
    bool unwinding;
    bool sink_selected;
    std::uint64_t elapsed_us;
    Snapshot counters;
};
using Sink = bool (*)(const Event&) noexcept;
// Private opt-in bootstrap/test seam; never installed or reachable through C ABI.
bool enable(Sink sink) noexcept;
bool disable(Sink sink) noexcept;
void note(Counter counter, std::uint64_t amount = 1) noexcept;
Snapshot snapshot() noexcept;

class Scope final {
public:
    explicit Scope(Phase phase) noexcept;
    ~Scope() noexcept;
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;
    Scope(Scope&&) = delete;
    Scope& operator=(Scope&&) = delete;
private:
    Sink sink_ = nullptr;
    Phase phase_;
    std::uint64_t id_ = 0;
    int exceptions_ = 0;
    std::chrono::steady_clock::time_point started_{};
};
} // namespace usk::diagnostics
#endif
