// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_COMPLETED_MAINTENANCE_RECORDS_INTERNAL_H
#define USK_COMPLETED_MAINTENANCE_RECORDS_INTERNAL_H

#include "usk_maintenance_inspection_internal.h"
#include "usk_transaction_session.h"
#include <string>
#include <utility>
#include <vector>

namespace usk::lifecycle::detail {

// One completed repair/uninstall's historical byte inputs, not a filesystem
// adapter or authority object. Names/order and bytes are validated below, but
// the owner must independently prove complete native membership, original
// creator/lease/currentness, actual directory identities and absence of payload.
// No path is opened, no callback is invoked and no live read fallback exists.
// Inputs are bounded to16MiB each and64MiB aggregate before decoding; existing
// journal/effect/plan/state/audit decoders retain their narrower limits.
// The aggregate includes the separately bounded effect directory identity.
// Those input limits are not a total allocation or execution-time guarantee.
struct CompletedMaintenanceHistoryBytes {
    std::string transaction;
    std::string effect_directory_identity;
    std::vector<std::pair<std::string, std::string>> effects;
    std::string reviewed_plan;
    std::string original_installed;
    std::string original_ownership;
    std::string resulting_installed;
    std::string resulting_ownership;
    std::vector<std::pair<std::string, std::string>> audit;
};

// Reuses the full original completed-effect selection, reviewed plan,
// ownership/installed postimage and unique audit validation. Results are
// historical metadata only, never a native-retirement or mutation permission.
// Completed history can retain content (uninstall_blocked); this is not a
// retired-target verdict. Actual retired state and fresh absence are separate.
MaintenanceContinuationInspection decode_completed_maintenance_history(
    const transaction::TransactionSpec& spec,
    const CompletedMaintenanceHistoryBytes& bytes);

} // namespace usk::lifecycle::detail
#endif
