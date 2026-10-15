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
    access_check_calls, not_submitted_events, hash_elapsed_us, wire_receive_elapsed_us,
    wire_read_elapsed_us, wire_write_elapsed_us, wire_parse_elapsed_us, wire_peer_elapsed_us,
    authenticated_access_calls, authenticated_access_elapsed_us,
    client_token_facts_calls, client_token_facts_elapsed_us,
    handle_observation_calls, handle_observation_elapsed_us,
    handle_name_calls, handle_name_elapsed_us, count
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

// Inclusive wall time for a complete call, including failure cleanup. No events
// are emitted. Overlapping calls/timers are not exclusive costs; in-flight calls
// and calls whose original sink is no longer selected are not charged.
class DurationCounter final {
public:
    explicit DurationCounter(Counter counter) noexcept;
    // Count completed calls alongside their inclusive duration, including unwind.
    // The two relaxed totals are not an atomic pair in a concurrent snapshot.
    DurationCounter(Counter counter, Counter completed_calls) noexcept;
    ~DurationCounter() noexcept;
    DurationCounter(const DurationCounter&) = delete;
    DurationCounter& operator=(const DurationCounter&) = delete;
    DurationCounter(DurationCounter&&) = delete;
    DurationCounter& operator=(DurationCounter&&) = delete;
private:
    Counter counter_;
    Counter completed_calls_;
    Sink sink_ = nullptr;
    std::chrono::steady_clock::time_point started_{};
};

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
