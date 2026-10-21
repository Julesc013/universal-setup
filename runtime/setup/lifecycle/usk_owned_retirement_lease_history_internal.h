// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_OWNED_RETIREMENT_LEASE_HISTORY_INTERNAL_H
#define USK_OWNED_RETIREMENT_LEASE_HISTORY_INTERNAL_H
#include "usk_json.h"
#include <string>
#include <vector>

namespace usk::lifecycle::detail {
// Historical metadata only. A repeated completion has equal recorded entry
// and exit revisions; that does not prove an absence of intervening effects.
// Every operation still needs its own context, creator, sealed effect/audit
// history, native membership, ended holders and payload-absence validation.
struct OwnedRetirementLeaseCompletion {
    usk::json::Value original_active;
    usk::json::Value completed;
    bool repeated_completion = false;
};

// Validate at most4096 ordered records in one pass, using the existing closed
// lease transition protocol. Every admitted operation must reach completion;
// moves/other unsupported operation families refuse. No path, process, native
// owner or current filesystem revision is observed. Supplied expectations and
// returned values confer no retirement, replay, cleanup or mutation authority.
std::vector<OwnedRetirementLeaseCompletion> decode_owned_retirement_lease_history(
    const std::vector<usk::json::Value>& history, const std::string& install_id,
    const usk::json::Value& state_root_identity, const std::string& current_revision);
}
#endif
