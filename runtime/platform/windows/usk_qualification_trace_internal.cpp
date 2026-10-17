// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_qualification_trace_internal.h"
#include "usk_diagnostic_metrics.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winmeta.h>
#include <TraceLoggingProvider.h>
#include <atomic>

TRACELOGGING_DEFINE_PROVIDER(usk_qualification_provider, "UniversalSetup.Qualification",
    (0x7e4a4d0e, 0x4d53, 0x4c2d, 0x93, 0xa3, 0x6b, 0xa6, 0x1c, 0xf4, 0x67, 0x11));

namespace usk::platform::windows {
namespace {
// Preserve the process-wide 16384-event ceiling. Ordinary events cannot
// consume the final32 slots needed to observe the fixed request/terminal path.
// An entry or unwinding exit is diagnostic data, never a completion verdict.
constexpr std::uint64_t event_limit = 16384, final_event_reserve = 32;
std::atomic<std::uint64_t> ordinary_emitted{0}, final_emitted{0};
std::atomic<bool> owned{false};
bool final_path_phase(usk::diagnostics::Phase phase) noexcept {
    using usk::diagnostics::Phase;
    switch (phase) {
    case Phase::machine_request:
    case Phase::engine_request:
    case Phase::response_write:
    case Phase::maintenance_recovery_run:
    case Phase::maintenance_recovery_lease_finish:
    case Phase::effect_worker_finalization:
    case Phase::effect_terminal_validation:
    case Phase::effect_worker_terminal_send:
    case Phase::effect_worker_parent_retirement:
    case Phase::effect_broker_worker_closure:
    case Phase::effect_broker_volume_closure:
    case Phase::publisher_response_projection:
    case Phase::effect_worker_failure_reporting:
        return true;
    default: return false;
    }
}
bool claim_event(usk::diagnostics::Phase phase) noexcept {
    const bool final = final_path_phase(phase);
    auto& emitted = final ? final_emitted : ordinary_emitted;
    const auto limit = final ? final_event_reserve : event_limit - final_event_reserve;
    auto previous = emitted.load(std::memory_order_relaxed);
    while (previous < limit) {
        if (emitted.compare_exchange_weak(previous, previous + 1, std::memory_order_relaxed)) return true;
    }
    return false;
}
bool write_event(const usk::diagnostics::Event& event) noexcept {
    const DWORD error = GetLastError();
    if (!TraceLoggingProviderEnabled(usk_qualification_provider, WINEVENT_LEVEL_INFO, 1) ||
        !claim_event(event.phase)) {
        SetLastError(error);
        return false;
    }
    const auto& c = event.counters.totals;
    TraceLoggingWrite(usk_qualification_provider, "Phase",
        TraceLoggingLevel(WINEVENT_LEVEL_INFO), TraceLoggingKeyword(1),
        TraceLoggingUInt32(static_cast<std::uint32_t>(event.phase), "PhaseId"),
        TraceLoggingUInt64(event.scope_id, "ScopeId"), TraceLoggingBool(event.exiting, "Exiting"),
        TraceLoggingBool(event.unwinding, "Unwinding"), TraceLoggingBool(event.sink_selected, "SinkSelectedAtEmission"),
        TraceLoggingUInt64(event.elapsed_us, "ElapsedUs"),
        TraceLoggingUInt64(c[0], "HeldFileInstances"), TraceLoggingUInt64(c[1], "HashCalls"),
        TraceLoggingUInt64(c[2], "HashSuccesses"), TraceLoggingUInt64(c[3], "HashBytes"),
        TraceLoggingUInt64(c[4], "ExactReadCalls"), TraceLoggingUInt64(c[5], "ExactReadBytes"),
        TraceLoggingUInt64(c[6], "ProviderOpenCalls"), TraceLoggingUInt64(c[7], "ProviderOpenSuccesses"),
        TraceLoggingUInt64(c[8], "WireSendPackets"), TraceLoggingUInt64(c[9], "WireSendBytes"),
        TraceLoggingUInt64(c[10], "WireReceivePackets"), TraceLoggingUInt64(c[11], "WireReceiveBytes"),
        TraceLoggingUInt64(c[12], "AccessCheckCalls"), TraceLoggingUInt64(c[13], "NotSubmittedEvents"),
        TraceLoggingUInt64(c[14], "HashElapsedUs"), TraceLoggingUInt64(c[15], "WireReceiveElapsedUs"),
        TraceLoggingUInt64(c[16], "WireReadElapsedUs"), TraceLoggingUInt64(c[17], "WireWriteElapsedUs"),
        TraceLoggingUInt64(c[18], "WireParseElapsedUs"), TraceLoggingUInt64(c[19], "WirePeerElapsedUs"),
        TraceLoggingBool(event.counters.saturated, "CountersSaturated"),
        TraceLoggingBool(false, "NativeWriteResultAvailable"),
        // Append fields: preserve all existing ordinals and the old payload prefix.
        TraceLoggingUInt64(c[20], "AuthenticatedAccessCalls"), TraceLoggingUInt64(c[21], "AuthenticatedAccessElapsedUs"),
        TraceLoggingUInt64(c[22], "ClientTokenFactsCalls"), TraceLoggingUInt64(c[23], "ClientTokenFactsElapsedUs"),
        TraceLoggingUInt64(c[24], "HandleObservationCalls"), TraceLoggingUInt64(c[25], "HandleObservationElapsedUs"),
        TraceLoggingUInt64(c[26], "HandleNameCalls"), TraceLoggingUInt64(c[27], "HandleNameElapsedUs"));
    // TraceLoggingWrite returns void. Submission is not confirmation of ETW
    // retention, coverage or native write success; analyse actual capture loss.
    SetLastError(error);
    return true;
}
}
QualificationTrace::QualificationTrace() noexcept {
    const DWORD error = GetLastError();
    bool absent = false;
    owner_ = owned.compare_exchange_strong(absent, true);
    if (owner_) {
        registered_ = SUCCEEDED(TraceLoggingRegister(usk_qualification_provider));
        // The owned WPR wrapper starts capture before launching the process.
        // No listener means no counters/clocks; later attachment is unsupported.
        if (registered_ && TraceLoggingProviderEnabled(usk_qualification_provider, WINEVENT_LEVEL_INFO, 1))
            enabled_ = usk::diagnostics::enable(write_event);
    }
    SetLastError(error);
}
QualificationTrace::~QualificationTrace() noexcept {
    const DWORD error = GetLastError();
    if (enabled_) (void)usk::diagnostics::disable(write_event);
    if (registered_) TraceLoggingUnregister(usk_qualification_provider);
    if (owner_) owned.store(false);
    SetLastError(error);
}
} // namespace usk::platform::windows
