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
std::atomic<std::uint64_t> emitted{0};
std::atomic<bool> owned{false};
bool claim_event() noexcept {
    auto previous = emitted.load(std::memory_order_relaxed);
    while (previous < 16384) {
        if (emitted.compare_exchange_weak(previous, previous + 1, std::memory_order_relaxed)) return true;
    }
    return false;
}
bool write_event(const usk::diagnostics::Event& event) noexcept {
    const DWORD error = GetLastError();
    if (!TraceLoggingProviderEnabled(usk_qualification_provider, WINEVENT_LEVEL_INFO, 1) ||
        !claim_event()) {
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
