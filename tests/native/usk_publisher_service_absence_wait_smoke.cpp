// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_service_absence_internal.h"
#include "usk_publisher_service_absence_fixture_checks.h"
#include <iostream>
#include <limits>
#include <vector>

namespace {
namespace native = usk::platform::windows::detail;
using Probe = native::PublisherServiceOpenError;
void require(bool value) { if (!value) throw std::runtime_error("SCM completion control failed"); }
template<typename Function>
std::string refused(Function function, const char* reason) {
    try { function(); }
    catch (const std::exception& error) {
        require(std::string(error.what()).find(reason) != std::string::npos);
        return error.what();
    }
    throw std::runtime_error("SCM completion accepted an unconfirmed or late observation");
}
}
int main() {
    try {
        const Probe present = std::nullopt, pending = ERROR_SERVICE_MARKED_FOR_DELETE;
        const Probe absent = ERROR_SERVICE_DOES_NOT_EXIST;
        for (const auto& sequence : std::vector<std::vector<Probe>>{
                {absent}, {present, present, absent}, {pending, absent},
                {present, pending, present, absent}}) {
            std::size_t calls = 0; ULONGLONG tick = 0;
            const auto result = native::wait_for_deleted_publisher_service_absence_observed(
                [&] { return sequence.at(calls++); }, [&] { return tick; },
                [&](ULONGLONG duration) { require(duration == 25); tick += duration; });
            require(result.probes == sequence.size());
            require(result.present_observations == static_cast<unsigned>(std::count(sequence.begin(), sequence.end(), present)));
            require(result.pending_deletion_observations == static_cast<unsigned>(std::count(sequence.begin(), sequence.end(), pending)));
        }
        volatile ULONGLONG frozen_tick = 0;
        // These are the same predicates used by the hosted fixture, exercised
        // against actual product diagnostics without creating a native service.
        const auto strict_pending = refused([&] {
            native::refuse_publisher_service_absence("owned retirement strict SCM revalidation",
                pending, native::PublisherServiceAbsenceObservation{1, 1});
        }, "Win32 1072");
        require(strict_pending == "owned retirement strict SCM revalidation: SCM absence is unconfirmed; "
            "Win32 1072; probes 1; pending-deletion observations 1");
        require(usk::test::strict_service_absence_refusal(strict_pending));
        require(usk::test::strict_service_absence_refusal(
            "owned retirement strict SCM revalidation: service is present"));
        for (const auto state : {present, pending}) {
            unsigned calls = 0, sleeps = 0; ULONGLONG tick = 0;
            const auto bounded = refused([&] { (void)native::wait_for_deleted_publisher_service_absence_observed(
                [&] { ++calls; return state; }, [&] { return tick; },
                [&](ULONGLONG duration) { ++sleeps; tick += duration; }); }, "completion bound reached");
            require(calls == 80 && sleeps == 80 && tick == 2000);
            require(usk::test::bounded_service_absence_refusal(bounded, true));
            require(usk::test::bounded_service_absence_refusal(bounded, false) == !state);
            calls = 0;
            refused([&] { (void)native::wait_for_deleted_publisher_service_absence_observed(
                [&] { ++calls; return state; }, [&] { return frozen_tick; },
                [](ULONGLONG) {}); }, "81-probe bound reached");
            require(calls == 81);
        }
        for (const DWORD error : {static_cast<DWORD>(ERROR_ACCESS_DENIED),
                static_cast<DWORD>(ERROR_INVALID_NAME), static_cast<DWORD>(ERROR_SUCCESS)}) {
            unsigned calls = 0, sleeps = 0;
            const auto unexpected = refused([&] { (void)native::wait_for_deleted_publisher_service_absence_observed(
                [&] { ++calls; return Probe{error}; }, [&] { return frozen_tick; },
                [&](ULONGLONG) { ++sleeps; }); }, "SCM absence is unconfirmed");
            require(calls == 1 && sleeps == 0);
            require(!usk::test::bounded_service_absence_refusal(unexpected, true));
            require(!usk::test::strict_service_absence_refusal(unexpected));
            const auto strict_error = refused([&] {
                native::refuse_publisher_service_absence("owned retirement strict SCM revalidation",
                    Probe{error}, native::PublisherServiceAbsenceObservation{1, 0});
            }, "SCM absence is unconfirmed");
            require(!usk::test::strict_service_absence_refusal(strict_error));
        }
        ULONGLONG tick = 0;
        const auto late = refused([&] { (void)native::wait_for_deleted_publisher_service_absence_observed(
            [&] { tick = 2000; return absent; }, [&] { return tick; },
            [](ULONGLONG) {}); }, "completion bound reached");
        require(!usk::test::bounded_service_absence_refusal(late, true));
        volatile bool fail_observation = true;
        refused([&] { (void)native::wait_for_deleted_publisher_service_absence_observed(
            [&]() -> Probe {
                if (fail_observation) throw std::runtime_error("native probe close unconfirmed");
                return absent;
            }, [&] { return frozen_tick; }, [](ULONGLONG) {}); }, "native probe close unconfirmed");
        refused([&] { (void)native::wait_for_deleted_publisher_service_absence_observed(
            [&] { return present; }, [&] { return frozen_tick; },
            [](ULONGLONG) { throw std::runtime_error("wait interruption"); }); }, "wait interruption");
        tick = (std::numeric_limits<ULONGLONG>::max)() - 10;
        unsigned calls = 0;
        const auto wrapped = native::wait_for_deleted_publisher_service_absence_observed(
            [&] { return ++calls == 1 ? present : absent; }, [&] { return tick; },
            [&](ULONGLONG duration) { tick += duration; });
        require(wrapped.probes == 2 && wrapped.present_observations == 1);
        std::cout << "SCM completion controls passed without native service effects\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
