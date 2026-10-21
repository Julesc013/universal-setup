// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_fixture_scm_wait.h"
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {
using State = usk::test::FixtureScmState;
void require(bool okay) { if (!okay) throw std::runtime_error("fixture SCM wait control failed"); }
template<typename Function>
void refused(Function function, const char* expected) {
    try { function(); }
    catch (const std::exception& error) {
        require(std::string(error.what()).find(expected) != std::string::npos);
        return;
    }
    throw std::runtime_error("fixture SCM wait incorrectly accepted incomplete deletion");
}
}
int main() {
    try {
        for (const auto& sequence : std::vector<std::vector<State>>{
                {State::absent}, {State::present, State::present, State::absent},
                {State::pending_deletion, State::absent},
                {State::present, State::pending_deletion, State::present, State::absent}}) {
            std::size_t calls = 0;
            std::uint64_t tick = 0;
            const auto result = usk::test::wait_for_fixture_service_deletion(
                [&] { return sequence.at(calls++); }, [&] { return tick; },
                [&](std::uint64_t duration) { require(duration == 25); tick += duration; });
            require(calls == sequence.size() && result.probes == calls);
            require(result.present == static_cast<unsigned>(std::count(sequence.begin(), sequence.end(), State::present)));
            require(result.pending == static_cast<unsigned>(std::count(sequence.begin(), sequence.end(), State::pending_deletion)));
        }
        // A runtime-valued stalled clock retains the real callback shape. A
        // literal-zero callback triggers template warningC4127 on MSVC19.44.
        volatile std::uint64_t frozen_tick = 0;
        for (const auto state : {State::present, State::pending_deletion}) {
            unsigned calls = 0, sleeps = 0;
            std::uint64_t tick = 0;
            refused([&] { (void)usk::test::wait_for_fixture_service_deletion(
                [&] { ++calls; return state; }, [&] { return tick; },
                [&](std::uint64_t duration) { ++sleeps; tick += duration; }); }, "2000ms");
            require(calls == 80 && sleeps == 80 && tick == 2000);
            calls = 0;
            refused([&] { (void)usk::test::wait_for_fixture_service_deletion(
                [&] { ++calls; return state; }, [&] { return frozen_tick; },
                [](std::uint64_t) {}); }, "81-probe");
            require(calls == 81); // A stalled clock cannot make the wait unbounded.
        }
        std::uint64_t tick = 0;
        refused([&] { (void)usk::test::wait_for_fixture_service_deletion(
            [&] { tick = 2000; return State::absent; }, [&] { return tick; },
            [](std::uint64_t) {}); }, "2000ms"); // Late absence is not timely completion.
        volatile bool fail_observation = true;
        refused([&] { (void)usk::test::wait_for_fixture_service_deletion(
            [&]() -> State {
                if (fail_observation) throw std::runtime_error("native close unconfirmed");
                return State::absent;
            },
            [&] { return frozen_tick; }, [](std::uint64_t) {}); }, "native close unconfirmed");
        // Elapsed subtraction remains bounded across the native tick wrap.
        tick = (std::numeric_limits<std::uint64_t>::max)() - 10;
        unsigned calls = 0;
        const auto wrapped = usk::test::wait_for_fixture_service_deletion(
            [&] { return ++calls == 1 ? State::present : State::absent; }, [&] { return tick; },
            [&](std::uint64_t duration) { tick += duration; });
        require(wrapped.probes == 2 && wrapped.present == 1);
        std::cout << "fixture SCM deletion completion controls passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
