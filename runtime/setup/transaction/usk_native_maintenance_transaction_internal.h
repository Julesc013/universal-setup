// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_NATIVE_MAINTENANCE_TRANSACTION_INTERNAL_H
#define USK_NATIVE_MAINTENANCE_TRANSACTION_INTERNAL_H
#if defined(_WIN32)
#include "usk_transaction_session.h"
#include <functional>
#include <memory>
#include <optional>
namespace usk::lifecycle::detail { class NativeMaintenanceContext; }
namespace usk::transaction { class MaintenanceEffectJournal; struct MaintenanceEffectInspection; }
namespace usk::transaction::detail {
struct NativeMaintenanceFileObservation {
    std::string native_identity, sha256;
    std::uint64_t size_bytes = 0;
};
// Read-only facts from the current concrete owner's retained file. Absence of
// a native scope returns null; an active scope never falls back by pathname.
// These values confer no custody, completion or mutation authority.
std::optional<NativeMaintenanceFileObservation> observe_current_native_maintenance_file(
    const std::filesystem::path& path);
// Read-only lifetime policy. Supplied identities confer no native scope or
// authority; the session separately uses the engine's private current binding.
void require_native_maintenance_origin_binding(bool native_origin,
    const std::weak_ptr<const void>& original, const std::weak_ptr<const void>& current);
// Read-only binding validation. It creates neither an owner nor effects.
void require_native_maintenance_journal_binding(const TransactionSpec& spec,
    const std::filesystem::path& path, const std::string& content,
    const std::string& predecessor_sha256, bool first);
// Private engine adapter. The concrete native context alone can construct it;
// no public caller, JSON field, setter or test callback activates this scope.
// Presence is not authority: every entry independently calls the native owner.
struct NativeMaintenanceTransactionOperations {
    struct EffectResult { std::string outcome, result_digest; };
    std::function<void(const TransactionSpec&)> require_authority;
    // The original owner publishes an exact journal postimage, with initial
    // no-replace and subsequent exact-predecessor replacement semantics.
    std::function<void(const TransactionSpec&, const std::filesystem::path&,
        const std::string&, const std::string&, bool)> persist_journal;
    std::function<void(const TransactionSpec&, const std::filesystem::path&)> create_staging_root;
    std::function<void(const TransactionSpec&, const std::filesystem::path&)> ensure_stream_parent;
    // Returned native handle is borrowed. The engine keeps custody through
    // publication or worker disposal; the generic session never closes it.
    std::function<std::intptr_t(const TransactionSpec&, const std::filesystem::path&,
        std::uint64_t, const std::string&)> open_stream;
    std::function<void(const TransactionSpec&, std::intptr_t)> require_stream;
    std::function<void(const TransactionSpec&, std::intptr_t, const std::string&,
        std::uint64_t, const std::string&)> finish_stream;
    std::function<CommitClosureObservation(const TransactionSpec&, const std::filesystem::path&,
        const std::vector<CommitClosureFile>&)> observe_commit_closure;
    std::function<NativeMaintenanceFileObservation(const std::filesystem::path&)> observe_file;
    std::function<void(const TransactionSpec&, const std::filesystem::path&,
        const std::string&, const CommitClosureObservation&)> commit;
    // Exact durable original pending payload or metadata intent; the owner alone selects
    // held native objects and returns an independently confirmed outcome.
    std::function<EffectResult(const TransactionSpec&, const MaintenanceEffectInspection&)> apply_effect;
    // Completion of a resumed journal still requires this original owner's
    // actual confirmed outcome. Compatible observations alone are insufficient.
    std::function<void(const TransactionSpec&, const MaintenanceEffectInspection&,
        const std::string&, const std::string&)> confirm_effect_completion;
};
class ScopedNativeMaintenanceTransaction final {
public:
    ~ScopedNativeMaintenanceTransaction();
    ScopedNativeMaintenanceTransaction(const ScopedNativeMaintenanceTransaction&) = delete;
    ScopedNativeMaintenanceTransaction& operator=(const ScopedNativeMaintenanceTransaction&) = delete;
private:
    friend class usk::transaction::TransactionSession;
    friend class usk::transaction::MaintenanceEffectJournal;
    friend class usk::lifecycle::detail::NativeMaintenanceContext;
    explicit ScopedNativeMaintenanceTransaction(const NativeMaintenanceTransactionOperations& operations);
    ScopedNativeMaintenanceTransaction(NativeMaintenanceTransactionOperations&&) = delete;
    static const NativeMaintenanceTransactionOperations* current();
    static std::weak_ptr<const void> current_binding();
    const NativeMaintenanceTransactionOperations& operations_;
    std::shared_ptr<const void> identity_;
};
}
#endif
#endif
