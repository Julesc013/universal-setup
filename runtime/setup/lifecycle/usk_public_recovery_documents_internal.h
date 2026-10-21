// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLIC_RECOVERY_DOCUMENTS_INTERNAL_H
#define USK_PUBLIC_RECOVERY_DOCUMENTS_INTERNAL_H

#include "usk_json.h"
#include "usk_transaction_session.h"
#include <string>

namespace usk::lifecycle::detail {
// A synchronous borrowed view for document formatting only. The acquiring
// caller owns every referenced value and all policy/custody/revalidation.
// This view neither observes files nor grants recovery or mutation authority.
struct PublicRecoveryDocumentContext {
    const std::string& install_id;
    const std::string& request_id;
    const transaction::TransactionSpec& spec;
    const transaction::RecoveryInspection& inspection;
    const std::string& audit_chain_id;
    const std::string& audit_chain_digest;
};

json::Value recovery_effects(const transaction::RecoveryInspection& inspection);
json::Value recovery_report_document(const PublicRecoveryDocumentContext& context);
json::Value recovery_plan_document(const PublicRecoveryDocumentContext& context,
    const std::string& created_at, const std::string& plan_id);
} // namespace usk::lifecycle::detail
#endif
