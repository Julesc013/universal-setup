#ifndef USK_TRANSACTION_SESSION_H
#define USK_TRANSACTION_SESSION_H

#include <cstdint>
#include <filesystem>
#include <functional>
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

using FaultInjector = std::function<void(const std::string& state, const std::string& point)>;

struct RecoveryInspection {
    std::string current_state;
    bool staging_exists = false;
    bool target_exists = false;
    std::vector<std::string> available_actions;
};

class TransactionSession {
public:
    explicit TransactionSession(TransactionSpec spec, FaultInjector injector = {});

    TransactionSession(const TransactionSession&) = delete;
    TransactionSession& operator=(const TransactionSession&) = delete;

    const std::string& current_state() const noexcept { return current_state_; }
    const std::filesystem::path& staging_root() const noexcept { return staging_root_; }
    const std::filesystem::path& target_root() const noexcept { return spec_.target_root; }
    const std::filesystem::path& journal_path() const noexcept { return journal_path_; }

    void stage_file(const std::filesystem::path& relative_path, const std::vector<unsigned char>& bytes);
    void mark_staged();
    void mark_verified();
    void commit_effect();
    void mark_committed();
    void mark_completed();
    void mark_recovery_required();
    void commit();
    void rollback();

    static RecoveryInspection inspect_recovery(const TransactionSpec& spec);

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
    void remove_recorded_staging_closure();
    std::string render_journal() const;

    TransactionSpec spec_;
    FaultInjector injector_;
    std::filesystem::path staging_root_;
    std::filesystem::path journal_path_;
    std::string created_at_;
    std::string current_state_;
    std::string staging_identity_;
    std::string staging_parent_identity_;
    std::string target_parent_identity_;
    std::string journal_directory_identity_;
    std::vector<Transition> transitions_;
    std::vector<StagedFile> staged_files_;
};

} // namespace usk::transaction

#endif
