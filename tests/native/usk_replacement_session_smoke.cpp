// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_replacement_session.h"
#include "usk_transaction_session.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
namespace tx = usk::transaction;

namespace {

void write_text(const fs::path& path, const std::string& value)
{
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << value;
    if (!output) throw std::runtime_error("cannot write fixture");
}

struct Fixture {
    fs::path root;
    fs::path live;
    fs::path staged;
    fs::path retained;
    fs::path state;
    tx::ReplacementSpec spec;

    Fixture(const fs::path& parent, const std::string& id,
        tx::CommitAuthorityRequirement authority = tx::CommitAuthorityRequirement::legacy_observed)
        : root(parent / id), live(root / "live"), staged(root / "stage"),
          retained(root / "retained"), state(root / "state")
    {
        fs::create_directories(state / "replacement-transactions");
        write_text(live / "bin/tool.txt", "old\n");
        write_text(live / "foreign/operator.txt", "retain\n");
        write_text(staged / "bin/tool.txt", "new\n");
        write_text(staged / "data/new.txt", "replacement\n");
        spec.transaction_id = "tx." + id;
        spec.plan_id = "plan." + id;
        spec.plan_digest = std::string(64, 'a');
        spec.live_root = live;
        spec.staged_root = staged;
        spec.retained_root = retained;
        spec.state_root = state;
        spec.old_root_identity = tx::observe_directory_identity(live);
        spec.old_snapshot_digest = tx::replacement_snapshot_digest(live);
        spec.new_root_identity = tx::observe_directory_identity(staged);
        spec.new_snapshot_digest = tx::replacement_snapshot_digest(staged);
        spec.required_commit_authority = authority;
    }
};

} // namespace

int main()
{
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path root = fs::temp_directory_path() /
        ("usk-replacement-session-" + std::to_string(nonce));
    std::error_code error;
    fs::create_directories(root, error);
    if (error) return 1;
    try {
        Fixture strict(root, "strict", tx::CommitAuthorityRequirement::staged_child_bound_v1);
        tx::ReplacementSession strict_session(strict.spec);
        bool unavailable = false;
        try {
            strict_session.retire_old_root();
        } catch (const tx::CommitAuthorityUnavailable&) {
            unavailable = true;
        }
        const auto strict_inspection = tx::ReplacementSession::inspect(strict.spec);
        if (!unavailable || strict_inspection.disposition != "no_replacement_effect" ||
            !fs::is_directory(strict.live) || !fs::is_directory(strict.staged) ||
            fs::exists(strict.retained)) return 2;

        Fixture prepared(root, "prepared");
        bool prepared_fault = false;
        tx::ReplacementSession prepared_session(prepared.spec,
            [&](const std::string& phase, const std::string& point) {
                if (phase == "old_retire_prepared" && point == "after_journal" && !prepared_fault) {
                    prepared_fault = true;
                    throw std::runtime_error("injected pre-retirement interruption");
                }
            });
        try {
            prepared_session.retire_old_root();
            return 3;
        } catch (const std::runtime_error&) {}
        const auto prepared_inspection = tx::ReplacementSession::inspect(prepared.spec);
        if (!prepared_fault || prepared_inspection.phase != "old_retire_prepared" ||
            prepared_inspection.disposition != "no_replacement_effect" ||
            !fs::is_directory(prepared.live) || !fs::is_directory(prepared.staged) ||
            fs::exists(prepared.retained)) return 4;

        Fixture interrupted(root, "interrupted");
        bool faulted = false;
        tx::ReplacementSession interrupted_session(interrupted.spec,
            [&](const std::string&, const std::string& point) {
                if (point == "after_old_root_rename" && !faulted) {
                    faulted = true;
                    throw std::runtime_error("injected retirement interruption");
                }
            });
        try {
            interrupted_session.retire_old_root();
            return 5;
        } catch (const std::runtime_error&) {}
        const auto retired = tx::ReplacementSession::inspect(interrupted.spec);
        if (!faulted || retired.disposition != "old_retired" || fs::exists(interrupted.live) ||
            !fs::is_regular_file(interrupted.retained / "foreign/operator.txt") ||
            retired.available_actions != std::vector<std::string>{"retain_for_operator"}) return 6;

        Fixture activated(root, "activated");
        bool activation_fault = false;
        tx::ReplacementSession activation_session(activated.spec,
            [&](const std::string&, const std::string& point) {
                if (point == "after_new_root_rename" && !activation_fault) {
                    activation_fault = true;
                    throw std::runtime_error("injected activation interruption");
                }
            });
        activation_session.retire_old_root();
        try {
            activation_session.activate_new_root();
            return 7;
        } catch (const std::runtime_error&) {}
        const auto active = tx::ReplacementSession::inspect(activated.spec);
        if (!activation_fault || active.disposition != "new_active" ||
            !fs::is_regular_file(activated.live / "data/new.txt") ||
            !fs::is_regular_file(activated.retained / "foreign/operator.txt") ||
            fs::exists(activated.staged)) return 8;

        Fixture completed(root, "completed");
        tx::ReplacementSession session(completed.spec);
        session.retire_old_root();
        session.activate_new_root();
        session.mark_state_published();
        session.mark_completed();
        const auto terminal = tx::ReplacementSession::inspect(completed.spec);
        if (terminal.disposition != "completed" || !terminal.available_actions.empty() ||
            !fs::is_regular_file(completed.live / "data/new.txt") ||
            !fs::is_regular_file(completed.retained / "foreign/operator.txt") ||
            fs::exists(completed.staged)) return 9;

        write_text(session.journal_path() / "foreign.txt", "corrupt\n");
        const auto corrupt = tx::ReplacementSession::inspect(completed.spec);
        if (corrupt.disposition != "indeterminate" || corrupt.phase != "corrupt" ||
            corrupt.available_actions != std::vector<std::string>{"retain_for_operator"} ||
            !fs::is_regular_file(completed.live / "data/new.txt") ||
            !fs::is_regular_file(completed.retained / "foreign/operator.txt")) return 10;
    } catch (const std::exception&) {
        fs::remove_all(root, error);
        return 11;
    }
    fs::remove_all(root, error);
    return error ? 12 : 0;
}
