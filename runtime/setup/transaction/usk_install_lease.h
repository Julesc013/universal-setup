// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_INSTALL_LEASE_H
#define USK_INSTALL_LEASE_H

#include "usk_json.h"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace usk::transaction {

class InstallLeaseConflict final : public std::runtime_error {
public:
    InstallLeaseConflict() : std::runtime_error("installation has an outstanding operation") {}
};
class InstallLeaseStale final : public std::runtime_error {
public:
    InstallLeaseStale() : std::runtime_error("installation ownership generation is stale") {}
};
class InstallStateRevisionStale final : public std::runtime_error {
public:
    InstallStateRevisionStale() : std::runtime_error("installed state changed before effects") {}
};

struct InstallLeaseRequest {
    std::string install_id;
    std::string operation;
    std::string operation_id;
    std::string attempt_id;
    std::string expected_state_revision;
    bool recovery = false;
    std::string operation_context_sha256;
};

enum class InstallLeasePreviousHolder { unknown, live, ended, identity_reused };

// Closed data protocol only. The native backend must independently obtain the
// root/holder observations, hold exclusive OS ownership, persist the record,
// and re-read it before effects. Deriving or parsing data grants no authority.
void require_install_lease_record(const usk::json::Value& record);
usk::json::Value derive_install_lease_ownership(
    const std::optional<usk::json::Value>& previous,
    const InstallLeaseRequest& request,
    const usk::json::Value& observed_state_root,
    const usk::json::Value& observed_holder,
    const std::string& observed_state_revision,
    InstallLeasePreviousHolder previous_holder = InstallLeasePreviousHolder::unknown);
void require_install_lease_start(const usk::json::Value& ownership,
    const std::string& observed_state_revision);
void require_install_lease_fence(const usk::json::Value& ownership,
    const usk::json::Value& current,
    const usk::json::Value& observed_state_root,
    const usk::json::Value& observed_holder);
usk::json::Value finish_install_lease_ownership(
    const usk::json::Value& ownership,
    const usk::json::Value& observed_state_root,
    const usk::json::Value& observed_holder,
    const std::string& observed_state_revision,
    bool handoff);

// Bounded closed data history only. The native reader independently proves
// protected records, root identity and exact membership under its OS guard.
// A result is an old completed record, never current health or effect authority.
std::optional<usk::json::Value> select_completed_install_lease_history(
    const std::vector<usk::json::Value>& history,
    const usk::json::Value& original_active);

} // namespace usk::transaction
#endif
