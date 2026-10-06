// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_DEVICE_ACL_H
#define USK_PUBLISHER_DEVICE_ACL_H

#if defined(_WIN32)
#include <windows.h>
#include <vector>

namespace usk::platform::windows {

// Refuse a raw volume device DACL that grants mutation to a principal other
// than SYSTEM, Administrators, or the exact restricted publisher service.
// The device owner must also be SYSTEM or Administrators: ownership can
// carry implicit DACL-change authority. Returns whether the exact service
// full-access ACE is already present.
bool require_publisher_device_acl_shape(PSID owner, PACL dacl, PSID service_sid);

// Construct a stricter copy of the known Windows Authenticated Users modify
// grant. This pure data transformation does not install security or admit a
// target. All other ACEs and the owner must pass the existing strict profile.
std::vector<BYTE> restrict_publisher_default_device_acl(PSID owner, PACL dacl, PSID service_sid);

// Pure bounded bootstrap postimage. Retains the trusted owner and ordered ACEs,
// reduces only the recognized default when necessary, adds the exact service
// grant and protects inheritance. Caller must separately bind original intent,
// unpublished target/custody and exclusive admission before accepting a target.
std::vector<BYTE> publisher_device_admission_postimage(PSID owner, PACL dacl, PSID service_sid);

} // namespace usk::platform::windows
#endif
#endif
