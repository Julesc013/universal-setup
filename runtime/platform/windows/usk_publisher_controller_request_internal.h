// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_CONTROLLER_REQUEST_INTERNAL_H
#define USK_PUBLISHER_CONTROLLER_REQUEST_INTERNAL_H

#include <cstdio>

namespace usk::platform::windows::detail {
// Conservative uncertainty for one synchronous controller invocation only.
// Enter before calling transport: even constructing a typed failure can throw.
// This records no operation outcome and supplies no dispatch authority.
class PublisherControllerRequestBoundary final {
public:
    PublisherControllerRequestBoundary() = default;
    PublisherControllerRequestBoundary(const PublisherControllerRequestBoundary&) = delete;
    PublisherControllerRequestBoundary& operator=(const PublisherControllerRequestBoundary&) = delete;
    void enter_transport() noexcept { possible_ = true; }
    bool dispatch_possible() const noexcept { return possible_; }
private:
    bool possible_ = false;
};

template<class Action>
int run_admitted_controller_request(Action&& action) {
    PublisherControllerRequestBoundary boundary;
    try {
        return action(boundary);
    } catch (...) {
        if (!boundary.dispatch_possible()) throw;
        // Never allocate an exception or response while preserving uncertainty.
        // An output failure cannot turn this exit status into a positive refusal.
        std::fputs("usk_publisher_service_control: request outcome unknown; inspect the original transaction before retrying\n", stderr);
        return 5;
    }
}
}
#endif
