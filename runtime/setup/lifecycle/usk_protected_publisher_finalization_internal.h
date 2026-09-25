// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PROTECTED_PUBLISHER_FINALIZATION_INTERNAL_H
#define USK_PROTECTED_PUBLISHER_FINALIZATION_INTERNAL_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>

#include "usk_lifecycle.h"

#include <string>

namespace usk::lifecycle {

// Restricted-service-only input. The writer reobserves every held object and
// verifies the bound durable records before touching public installed state.
// This is deliberately absent from the public lifecycle and C ABI headers.
struct ProtectedPublisherEvidence {
    HANDLE volume = nullptr;
    HANDLE journal = nullptr;
    HANDLE state = nullptr;
    HANDLE visible_root = nullptr;
    std::wstring volume_guid_root;
    std::wstring service_name;
    std::string prepared_record;
    std::string visible_record;
    std::string reviewed_snapshot_record;
    std::string completion_record;
};

InstallResult finalize_protected_visible_install(
    const InstallPlan& plan,
    const std::string& transaction_id,
    const std::string& applied_at,
    const ProtectedPublisherEvidence& evidence);

} // namespace usk::lifecycle
#endif
#endif
