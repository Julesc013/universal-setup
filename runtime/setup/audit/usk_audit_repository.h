// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_AUDIT_REPOSITORY_H
#define USK_AUDIT_REPOSITORY_H

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace usk::audit {

struct AuditInput {
    std::string created_at;
    std::string operation;
    std::string phase;
    std::string status;
    std::string subject_type;
    std::string subject_id;
    std::string details_digest;
    std::string transaction_id;
    std::string plan_id;
    std::string message;
};

struct AuditEvent : AuditInput {
    std::string event_id;
    std::string event_digest;
    std::string audit_chain_id;
    std::uint64_t sequence = 0;
    std::string previous_event_digest;
};

class AuditRepository {
public:
    explicit AuditRepository(std::filesystem::path audit_root);

    static void initialize_layout(const std::filesystem::path& audit_root);
    void initialize_chain(const std::string& chain_id) const;
    AuditEvent append(const std::string& chain_id, const AuditInput& input) const;
    std::vector<AuditEvent> read_and_validate_chain(const std::string& chain_id) const;

private:
    std::filesystem::path root_;
};

} // namespace usk::audit

#endif
