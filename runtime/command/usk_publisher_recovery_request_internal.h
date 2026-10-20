// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_RECOVERY_REQUEST_INTERNAL_H
#define USK_PUBLISHER_RECOVERY_REQUEST_INTERNAL_H
#include "usk_json.h"

namespace usk::command::detail {
// Pure closed public request decoding, never native observation or authority.
// A non-null pointer borrows the inspection member of the unchanged input;
// keep that complete input alive and unmodified while using it. Only unrelated
// schemas return null. Malformed recognized families throw. Derive lookup
// identity without replacing the authenticated request, reviewed digest or
// selected action. Absolute target paths use this host's filesystem grammar.
const usk::json::Value* publisher_public_recovery_inspection(const usk::json::Value&);
}
#endif
