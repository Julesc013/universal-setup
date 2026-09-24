// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_SECURITY_DESCRIPTOR_H
#define USK_PUBLISHER_SECURITY_DESCRIPTOR_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <vector>

namespace usk::platform::windows {

DWORD publisher_directory_access_mask();

// Builds a self-relative owner SYSTEM, protected-DACL descriptor with exactly
// SYSTEM and the supplied Windows service SID as allow ACEs. The caller must
// independently bind the SID to a restricted SCM service and create each
// anchor from inception under a protected parent. Building this descriptor
// grants no authority and does not enable strict publication.
std::vector<unsigned char> make_publisher_directory_security_descriptor(
    const std::wstring& service_sid);

} // namespace usk::platform::windows
#endif

#endif
