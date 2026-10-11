// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_CONSUMER_ACCESS_H
#define USK_PUBLISHER_CONSUMER_ACCESS_H
#include "usk_publisher_tree_observation.h"
#if defined(_WIN32)
#include <functional>
namespace usk::platform::windows {
// Candidate primitive, not authority: caller retains admitted service/volume,
// verified visible binding and durable reader policy. No private parent ACLs
// are changed. Mixed exact old/new payload descriptors replay idempotently.
std::size_t grant_publisher_consumer_read(HANDLE visible,
    const PublisherTreeObservation& verified, const std::string& service_sid,
    const std::string& consumer_sid, HANDLE stop_event,
    const std::function<void(std::size_t)>& after_grant = {});
}
#endif
#endif
