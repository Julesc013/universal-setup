// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_REGISTERED_INSTALL_PLAN_INTERNAL_H
#define USK_REGISTERED_INSTALL_PLAN_INTERNAL_H
#if defined(_WIN32)
#include "usk_json.h"
namespace usk::platform::windows {
class RegisteredPublisherAdmission;
class PublisherRequestChannel;
}
namespace usk::lifecycle {
// Authenticated read-only planning of the original administrator-bound scope.
// Never initializes setup state, acquires an installation lease or runs effects.
usk::json::Value registered_install_plan(
    usk::platform::windows::RegisteredPublisherAdmission& admission,
    const usk::platform::windows::PublisherRequestChannel& channel);
}
#endif
#endif
