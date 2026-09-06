// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_TRANSACTION_SESSION_H
#define USK_TRANSACTION_SESSION_H

#include "usk_stream_entry_journal.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace usk::transaction {

class NoReplaceCommitUnavailable final : public std::runtime_error {
public:
    explicit NoReplaceCommitUnavailable(const std::string& message)
        : std::runtime_error(message) {}
};

struct TransactionSpec {
    std::string transaction_id;
    std::string plan_id;
    std::string plan_digest;
    std::string operation;
    std::filesystem::path staging_parent;
    std::filesystem::path target_root;
    std::filesystem::path state_root;
    std::filesystem::path audit_root;
};

// Checks all fixed and transaction-derived paths without filesystem effects.
void require_path_capacity(const TransactionSpec& spec);
// Native identity observation only; never deletion or lease authority.
std::string observe_directory_identity(const std::filesystem::path& path);

using FaultInjector = std::function<void(const std::string& state, const std::string& point)>;
using StreamReader = std::function<std::size_t(unsigned char* output, std::size_t capacity)>;

struct StreamStageResult {
    std::string sha256;
    std::uint64_t size_bytes = 0;
    std::uint64_t peak_buffer_bytes = 0;
};

struct RecoveryInspection {
    std::string current_state;
    std::string journal_digest;
    std::string recorded_at;
    std::string snapshot_sha256;
    std::string stream_source_digest;
    std::string stream_source_context;
    std::string restart_origin_transaction_id;
    std::string restart_origin_snapshot_sha256;
    bool staging_exists = false;
    bool target_exists = false;
    bool commit_started = false;
    std::vector<std::string> available_actions;
};

class TransactionSession {
public:
    explicit TransactionSession(TransactionSpec spec, FaultInjector injector = {});

    TransactionSession(const TransactionSession&) = delete;
    TransactionSession& operator=(const TransactionSession&) = delete;

    const std::string& current_state() const noexcept { return current_state_; }
    bool is_stream_restart() const noexcept { return !stream_journal_.origin_transaction_id.empty(); }
    const std::filesystem::path& staging_root() const noexcept { return staging_root_; }
    const std::filesystem::path& target_root() const noexcept { return spec_.target_root; }
    const std::filesystem::path& journal_path() const noexcept { return journal_path_; }

    void stage_file(const std::filesystem::path& relative_path, const std::vector<unsigned char>& bytes);
    StreamStageResult stage_file_stream(
        const std::filesystem::path& relative_path,
        std::uint64_t expected_size,
        const std::string& expected_sha256,
        std::size_t buffer_bytes,
        const StreamReader& reader,
        const std::string& source_identity_digest = {});
    void bind_stream_source(const std::string& source_digest, const std::string& source_context = {});
    void mark_staged();
    void mark_verified();
    void commit_effect();
    void mark_committed();
    void mark_completed();
    void mark_recovery_required();
    void resume_committing();
    void commit();
    void rollback();

    // Explicit replay into fresh staging. Never reuses or cleans prior staging.
    static std::unique_ptr<TransactionSession> restart_streaming(
        const TransactionSpec& prior_spec,
        const std::string& new_transaction_id,
        const std::string& expected_snapshot_sha256,
        const std::string& source_digest,
        FaultInjector injector = {});
    static RecoveryInspection inspect_recovery(const TransactionSpec& spec);
    static std::unique_ptr<TransactionSession> resume_finalization(
        const TransactionSpec& spec,
        FaultInjector injector = {});
    static std::unique_ptr<TransactionSession> resume_rollback(
        const TransactionSpec& spec,
        FaultInjector injector = {});

private:
    struct Transition {
        std::uint64_t sequence = 0;
        std::string from;
        std::string to;
        std::string recorded_at;
    };

    struct StagedFile {
        std::filesystem::path relative_path;
        std::string sha256;
        std::uint64_t size_bytes = 0;
    };

    void persist_transition(const std::string& next_state);
    void verify_roots_for_plan();
    void verify_staging_identity() const;
    void create_staging_root();
    void persist_snapshot();
    void verify_recorded_staging_closure() const;
    void remove_recorded_staging_closure();
    std::string render_journal() const;
    enum class ResumeMode { none, finalization, rollback };
    TransactionSession(TransactionSpec spec, FaultInjector injector, ResumeMode resume_mode,
        StreamJournal stream_journal = {});

    TransactionSpec spec_;
    FaultInjector injector_;
    std::filesystem::path staging_root_;
    std::filesystem::path journal_path_;
    std::string created_at_;
    std::string current_state_;
    std::string staging_identity_;
    bool retain_stream_cleanup_ = false;
    StreamJournal stream_journal_;
    std::string staging_parent_identity_;
    std::string target_parent_identity_;
    std::string journal_directory_identity_;
    std::vector<Transition> transitions_;
    std::vector<StagedFile> staged_files_;
};

} // namespace usk::transaction

#endif
