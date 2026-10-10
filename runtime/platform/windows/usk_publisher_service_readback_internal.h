// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_SERVICE_READBACK_INTERNAL_H
#define USK_PUBLISHER_SERVICE_READBACK_INTERNAL_H
#if defined(_WIN32)
#include "usk_publisher_token_observation.h"
#include <memory>

namespace usk::platform::windows {
class RegisteredPublisherAdmission;

// Read routing for the original admission's actual held SCM service object.
// Only that concrete admission can create a scope. This supplies neither
// registration/effect authority nor cached mutable service or token facts.
class PublisherServiceReadbackScope final {
public:
    ~PublisherServiceReadbackScope();
    PublisherServiceReadbackScope(const PublisherServiceReadbackScope&) = delete;
    PublisherServiceReadbackScope& operator=(const PublisherServiceReadbackScope&) = delete;
    PublisherServiceReadbackScope(PublisherServiceReadbackScope&&) = delete;
    PublisherServiceReadbackScope& operator=(PublisherServiceReadbackScope&&) = delete;
private:
    friend class RegisteredPublisherAdmission;
    friend PublisherServiceObservation observe_current_restricted_publisher_service(
        const std::wstring& service_name);
    struct State;
    struct Routing;
    static Routing& current_routing();
    static void require_available();
    PublisherServiceReadbackScope(void* original_service,
        std::shared_ptr<void> original_native_owner,
        const PublisherServiceObservation& original);
    void require_current() const;
    std::shared_ptr<const State> state_;
};
} // namespace usk::platform::windows
#endif
#endif
