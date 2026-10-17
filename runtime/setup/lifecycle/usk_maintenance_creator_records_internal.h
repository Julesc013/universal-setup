// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_MAINTENANCE_CREATOR_RECORDS_INTERNAL_H
#define USK_MAINTENANCE_CREATOR_RECORDS_INTERNAL_H
#include "usk_json.h"
#include <string>
namespace usk::lifecycle::detail {
// Bounded canonical metadata only. These readers perform no path/native
// observation and create no service, caller, creator, lease or effect authority.
// Callers separately bind every supplied expectation to their retained native
// records and current operation; a parsed historical record is not a grant.
usk::json::Value decode_maintenance_original_custody_record(const std::string& text);
// Parse/identity checking precedes the caller's actual context recheck.
// Keep that native observation at its existing boundary; do not evaluate it
// as an argument before decoding the record.
usk::json::Value decode_maintenance_created_closure_record(const std::string& text,
    const std::string& transaction_id, const std::string& plan_digest);
void require_maintenance_created_closure_binding(const usk::json::Value& created,
    const usk::json::Value& original, const std::string& original_context_sha256,
    const std::string& original_admission_sha256, const std::string& lease_ownership_sha256);
}
#endif
