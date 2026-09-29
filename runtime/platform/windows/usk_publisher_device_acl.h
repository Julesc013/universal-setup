// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_DEVICE_ACL_H
#define USK_PUBLISHER_DEVICE_ACL_H

#if defined(_WIN32)
#include <windows.h>

namespace usk::platform::windows {

// Refuse a raw volume device DACL that grants mutation to a principal other
// than SYSTEM, Administrators, or the exact restricted publisher service.
// The device owner must also be SYSTEM or Administrators: ownership can
// carry implicit DACL-change authority. Returns whether the exact service
// full-access ACE is already present.
bool require_publisher_device_acl_shape(PSID owner, PACL dacl, PSID service_sid);

} // namespace usk::platform::windows
#endif
#endif
