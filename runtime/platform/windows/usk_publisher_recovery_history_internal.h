// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_RECOVERY_HISTORY_INTERNAL_H
#define USK_PUBLISHER_RECOVERY_HISTORY_INTERNAL_H
#if defined(_WIN32)
#include "usk_publisher_installation_lease.h"
#include "usk_maintenance_effect_journal.h"

namespace usk::platform::windows {
class PublisherEffectExecutionOwner;

// Owned metadata observations, not a lease, payload/namespace verdict or an
// action grant. Missing journal/effects/plan remain explicit. Nothing keeps
// these facts current after return; native apply must revalidate its reviewed
// bindings, current state, pending work, holder liveness and action predicates.
struct PublisherOriginalMaintenanceHistory {
    usk::transaction::TransactionSpec spec;
    std::string original_intent_sha256;
    std::string original_custody_sha256;
    std::string current_installed_revision;
    PublisherInstallLeaseHistoryObservation lease;
    std::uint64_t lease_pending_entry_count = 0;
    // Canonical sorted name array only. Pending children are not opened and
    // their bytes/identity/eligibility are NOT established by this digest.
    std::string lease_pending_names_sha256;
    std::optional<usk::transaction::TransactionJournalHistory> journal;
    bool effect_directory_present = false;
    std::string effect_directory_identity;
    std::optional<usk::transaction::MaintenanceEffectInspection> effects;
    std::optional<std::string> observed_reviewed_plan_sha256;
};

// Existing-only, read/list acquisition through the actual original child
// owner and held volume/install guards. The context must be inspect_existing;
// this cannot construct a writer, bootstrap records or acquire a lease. The
// engine supplies its existing borrowed cancellation observer and remaining
// absolute GetTickCount64 deadline, at most 120 seconds away. Budget/cancel
// checks bracket native calls; they cannot preempt a blocked Windows call.
//
// Selected journal <=4 MiB, plan <=8 MiB; effect records <=200002, <=32768
// bytes each and <=64 MiB per complete read pass. Recheck reads are separately
// bounded by those actual first-read sizes. These are serialized read bounds,
// not a total-memory ceiling. Existing original/installed/lease readers retain
// their own bounds (including <=4096 lease records). Parent enumeration has
// its existing 64 MiB bound. No provisional result/callback escapes; any
// failure abandons the entire acquisition without a generic-path fallback.
PublisherOriginalMaintenanceHistory observe_publisher_original_maintenance_history(
    HANDLE volume, const std::wstring& volume_root, const std::wstring& service_name,
    const PublisherInstallOperationGuard& guard, const PublisherInstallOperationContext& context,
    const PublisherMaintenanceStateSnapshot& original_state, PublisherEffectExecutionOwner& owner,
    HANDLE cancellation_observer, std::uint64_t deadline_tick);
}
#endif
#endif
