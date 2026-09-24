// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_ANCHOR_CREATE_H
#define USK_PUBLISHER_ANCHOR_CREATE_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <vector>

namespace usk::platform::windows {

// Internal candidate primitive for disposable fixtures. Creates exactly one
// directory component relative to a held parent handle with FILE_CREATE and
// the supplied creation-time descriptor. The caller owns the returned handle.
// The caller must independently establish protected-parent provenance,
// service identity, post-create facts, durable intent, and recovery. This
// function is not linked to the strict production publisher.
HANDLE create_directory_relative_with_descriptor(
    HANDLE parent, const std::wstring& name,
    const std::vector<unsigned char>& security_descriptor);

// Create a regular staged file with the same parent-bound, create-only and
// creation-time descriptor rules. The returned non-inheritable handle permits
// writing and must be closed by the caller. This primitive does not establish
// protected-parent provenance or enable the strict publisher.
HANDLE create_file_relative_with_descriptor(
    HANDLE parent, const std::wstring& name,
    const std::vector<unsigned char>& security_descriptor);

} // namespace usk::platform::windows
#endif

#endif
