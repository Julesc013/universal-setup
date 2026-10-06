// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_MAINTENANCE_EFFECT_JOURNAL_H
#define USK_MAINTENANCE_EFFECT_JOURNAL_H

#include "usk_transaction_session.h"
#include "usk_json.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace usk::transaction {

struct CompletedMaintenanceEffect {
    std::uint64_t intent_sequence = 0;
    std::string kind;
    json::Value details;
    std::string outcome;
    std::string result_digest;
};

struct MaintenanceEffectInspection {
    std::string source_context;
    std::string source_digest;
    std::string journal_digest;
    std::uint64_t completed_effects = 0;
    std::uint64_t next_sequence = 0;
    std::uint64_t pending_sequence = 0;
    std::uint64_t serialized_bytes = 0;
    std::string directory_identity;
    bool sealed = false;
    // An intent without completion means the effect may have happened.
    // Inspection never replays it or confers filesystem mutation authority.
    std::string pending_kind;
    json::Value pending_details;
    // Optional ordered observations for whole-operation continuation. These
    // remain journal facts, never native custody or evidence of the actor.
    std::vector<CompletedMaintenanceEffect> completed;
};

// Internal append-only observations for the original maintenance transaction.
// RecordWriteOperations may supply a protected metadata writer; this class
// supplies neither native payload authority nor pathname cleanup permission.
class MaintenanceEffectJournal {
public:
    MaintenanceEffectJournal(TransactionSpec spec, const std::string& source_context,
        FaultInjector injector = {});
    MaintenanceEffectJournal(const MaintenanceEffectJournal&) = delete;
    MaintenanceEffectJournal& operator=(const MaintenanceEffectJournal&) = delete;

    void begin_effect(const std::string& kind, const json::Value& details);
    void complete_effect(const std::string& outcome = "applied",
        const std::string& result_digest = {});
    void seal();
    const std::filesystem::path& directory() const noexcept { return directory_; }

    // The caller obtains expected_source_digest from the original transaction
    // journal and separately validates the immutable installed-state context.
    static MaintenanceEffectInspection inspect(const TransactionSpec& spec,
        const std::string& expected_source_digest, bool retain_completed = false);
    // Metadata continuation only, against an exact inspected snapshot. The
    // caller must separately prove any effect and hold its required authority.
    static std::unique_ptr<MaintenanceEffectJournal> resume(const TransactionSpec& spec,
        const std::string& expected_source_digest, const std::string& expected_history_digest,
        FaultInjector injector = {});

private:
    MaintenanceEffectJournal(TransactionSpec spec, MaintenanceEffectInspection inspected,
        FaultInjector injector);
    void persist(const std::string& phase, const json::Value& details);
    TransactionSpec spec_;
    FaultInjector injector_;
    std::filesystem::path directory_;
    std::string directory_identity_;
    std::string source_digest_;
    std::string last_digest_;
    std::string pending_kind_;
    std::uint64_t pending_sequence_ = 0;
    std::uint64_t sequence_ = 0;
    std::uint64_t bytes_ = 0;
    bool sealed_ = false;
    bool failed_ = false;
};

} // namespace usk::transaction
#endif
