// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_diagnostic_metrics.h"
#include <atomic>
#include <cerrno>
#include <exception>
#include <limits>
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace usk::diagnostics {
namespace {
struct Cell { std::atomic<std::uint64_t> value{0}; };
std::array<Cell, static_cast<std::size_t>(Counter::count)> totals;
std::atomic<Sink> active{nullptr};
std::atomic<std::uint64_t> sequence{0};
std::atomic<bool> saturated{false};
std::uint64_t add(std::atomic<std::uint64_t>& value, std::uint64_t amount) noexcept {
    auto previous = value.load(std::memory_order_relaxed);
    for (;;) {
        const bool overflow = amount > std::numeric_limits<std::uint64_t>::max() - previous;
        const auto next = overflow ? std::numeric_limits<std::uint64_t>::max() : previous + amount;
        if (value.compare_exchange_weak(previous, next, std::memory_order_relaxed)) {
            if (overflow) saturated.store(true, std::memory_order_relaxed);
            return next;
        }
    }
}
// Diagnostics preserve the calling code's Win32 error across clock/emission APIs.
struct ErrorPreserver {
#if defined(_WIN32)
    DWORD error = GetLastError();
#endif
    int saved_errno = errno;
    ~ErrorPreserver() noexcept {
        errno = saved_errno;
#if defined(_WIN32)
        SetLastError(error);
#endif
    }
};
void emit(Sink sink, const Event& event) noexcept {
    if (!sink(event)) add(totals[static_cast<std::size_t>(Counter::not_submitted_events)].value, 1);
}
}
bool enable(Sink sink) noexcept {
    if (!sink) return false;
    Sink absent = nullptr;
    return active.compare_exchange_strong(absent, sink);
}
bool disable(Sink sink) noexcept {
    if (!sink) return false;
    return active.compare_exchange_strong(sink, nullptr);
}
void note(Counter counter, std::uint64_t amount) noexcept {
    const auto index = static_cast<std::size_t>(counter);
    if (index < totals.size() && active.load(std::memory_order_relaxed)) add(totals[index].value, amount);
}
Snapshot snapshot() noexcept {
    Snapshot result;
    for (std::size_t i = 0; i != totals.size(); ++i) result.totals[i] = totals[i].value.load(std::memory_order_relaxed);
    result.saturated = saturated.load(std::memory_order_relaxed);
    return result; // Independent relaxed counters, not an atomic transaction snapshot.
}
DurationCounter::DurationCounter(Counter counter) noexcept
    : DurationCounter(counter, Counter::count) {}
DurationCounter::DurationCounter(Counter counter, Counter completed_calls) noexcept
    : counter_(counter), completed_calls_(completed_calls), sink_(active.load()) {
    if (!sink_ || static_cast<std::size_t>(counter_) >= totals.size() ||
            (completed_calls_ != Counter::count &&
             static_cast<std::size_t>(completed_calls_) >= totals.size())) {
        sink_ = nullptr;
        return;
    }
    ErrorPreserver preserve;
    started_ = std::chrono::steady_clock::now();
}
DurationCounter::~DurationCounter() noexcept {
    if (!sink_ || active.load() != sink_) return;
    ErrorPreserver preserve;
    const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started_).count();
    add(totals[static_cast<std::size_t>(counter_)].value,
        duration < 0 ? 0 : static_cast<std::uint64_t>(duration));
    if (completed_calls_ != Counter::count)
        add(totals[static_cast<std::size_t>(completed_calls_)].value, 1);
}
Scope::Scope(Phase phase) noexcept : sink_(active.load()), phase_(phase) {
    if (!sink_) return;
    ErrorPreserver preserve;
    id_ = add(sequence, 1);
    exceptions_ = std::uncaught_exceptions();
    started_ = std::chrono::steady_clock::now();
    emit(sink_, {phase_, id_, false, false, active.load() == sink_, 0, snapshot()});
}
Scope::~Scope() noexcept {
    if (!sink_) return;
    ErrorPreserver preserve;
    const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_).count();
    emit(sink_, {phase_, id_, true, std::uncaught_exceptions() > exceptions_, active.load() == sink_,
        duration < 0 ? 0 : static_cast<std::uint64_t>(duration), snapshot()});
}
} // namespace usk::diagnostics
