// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_FIXTURE_SCM_WAIT_H
#define USK_PUBLISHER_FIXTURE_SCM_WAIT_H
#include <algorithm>
#include <cstdint>
#include <stdexcept>

namespace usk::test {
// Test-fixture completion only, after its own confirmed DeleteService and
// closure. No product absence, retirement or retry policy is changed.
enum class FixtureScmState { present, pending_deletion, absent };
struct FixtureScmDeletionObservation {
    unsigned probes = 0, present = 0, pending = 0;
};
template<typename Observe, typename Now, typename Sleep>
FixtureScmDeletionObservation wait_for_fixture_service_deletion(
        Observe observe, Now now, Sleep sleep) {
    constexpr std::uint64_t window = 2000, interval = 25;
    constexpr unsigned maximum_probes = 81;
    const std::uint64_t started = now();
    FixtureScmDeletionObservation result;
    for (;;) {
        if (result.probes && now() - started >= window)
            throw std::runtime_error("fixture service deletion did not reach native absence within 2000ms");
        ++result.probes;
        const auto state = observe(); // Adapter must close every successful open.
        const std::uint64_t elapsed = now() - started;
        if (elapsed >= window)
            throw std::runtime_error("fixture service deletion did not reach native absence within 2000ms");
        switch (state) {
        case FixtureScmState::absent: return result; // Only a fresh native1060.
        case FixtureScmState::present: ++result.present; break;
        case FixtureScmState::pending_deletion: ++result.pending; break;
        default: throw std::runtime_error("fixture service deletion observation is invalid");
        }
        if (result.probes == maximum_probes)
            throw std::runtime_error("fixture service deletion exceeded its 81-probe bound");
        sleep((std::min)(interval, window - elapsed));
    }
}
} // namespace usk::test
#endif
