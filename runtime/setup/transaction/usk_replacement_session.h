// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_REPLACEMENT_SESSION_H
#define USK_REPLACEMENT_SESSION_H

#include "usk_commit_authority.h"

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace usk::transaction {

struct ReplacementSpec {
    std::string transaction_id;
    std::string plan_id;
    std::string plan_digest;
    std::filesystem::path live_root;
    std::filesystem::path staged_root;
    std::filesystem::path retained_root;
    std::filesystem::path state_root;
    std::string old_root_identity;
    std::string old_snapshot_digest;
    std::string new_root_identity;
    std::string new_snapshot_digest;
    CommitAuthorityRequirement required_commit_authority =
        CommitAuthorityRequirement::staged_child_bound_v1;
};

struct ReplacementInspection {
    std::string phase;
    std::string disposition;
    std::string journal_digest;
    bool live_root_exists = false;
    bool staged_root_exists = false;
    bool retained_root_exists = false;
    std::vector<std::string> available_actions;
};

using ReplacementFaultInjector = std::function<void(
    const std::string& phase,
    const std::string& point)>;

// Internal whole-root exchange state machine. Public update always requires
// staged_child_bound_v1, which is currently unavailable and therefore refuses
// before this session is created. legacy_observed exists only to qualify the
// durable rename/recovery mechanics without claiming production authority.
class ReplacementSession {
public:
    explicit ReplacementSession(ReplacementSpec spec, ReplacementFaultInjector injector = {});

    const std::string& phase() const noexcept { return phase_; }
    const std::filesystem::path& journal_path() const noexcept { return journal_path_; }

    void retire_old_root();
    void activate_new_root();
    void mark_state_published();
    void mark_completed();

    static ReplacementInspection inspect(const ReplacementSpec& spec);

private:
    void persist(const std::string& next_phase);

    ReplacementSpec spec_;
    ReplacementFaultInjector injector_;
    std::filesystem::path journal_path_;
    std::string phase_;
    std::string journal_directory_identity_;
    unsigned long long sequence_ = 0;
};

std::string replacement_snapshot_digest(const std::filesystem::path& root);

} // namespace usk::transaction

#endif
