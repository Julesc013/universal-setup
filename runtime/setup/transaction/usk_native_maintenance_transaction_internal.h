// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_NATIVE_MAINTENANCE_TRANSACTION_INTERNAL_H
#define USK_NATIVE_MAINTENANCE_TRANSACTION_INTERNAL_H
#if defined(_WIN32)
#include "usk_transaction_session.h"
#include <functional>
namespace usk::lifecycle::detail { class NativeMaintenanceContext; }
namespace usk::transaction::detail {
// Private engine adapter. The concrete native context alone can construct it;
// no public caller, JSON field, setter or test callback activates this scope.
// Presence is not authority: every entry independently calls the native owner.
struct NativeMaintenanceTransactionOperations {
    std::function<void(const TransactionSpec&)> require_authority;
    std::function<void(const TransactionSpec&, const std::filesystem::path&)> create_staging_root;
    std::function<void(const TransactionSpec&, const std::filesystem::path&)> ensure_stream_parent;
    // Returned native handle is borrowed. The engine keeps custody through
    // publication or worker disposal; the generic session never closes it.
    std::function<std::intptr_t(const TransactionSpec&, const std::filesystem::path&,
        std::uint64_t, const std::string&)> open_stream;
    std::function<void(const TransactionSpec&, std::intptr_t)> require_stream;
    std::function<void(const TransactionSpec&, std::intptr_t, const std::string&,
        std::uint64_t, const std::string&)> finish_stream;
    std::function<void(const TransactionSpec&, const std::filesystem::path&,
        const std::string&, const CommitClosureObservation&)> commit;
};
class ScopedNativeMaintenanceTransaction final {
public:
    ~ScopedNativeMaintenanceTransaction();
    ScopedNativeMaintenanceTransaction(const ScopedNativeMaintenanceTransaction&) = delete;
    ScopedNativeMaintenanceTransaction& operator=(const ScopedNativeMaintenanceTransaction&) = delete;
private:
    friend class usk::transaction::TransactionSession;
    friend class usk::lifecycle::detail::NativeMaintenanceContext;
    explicit ScopedNativeMaintenanceTransaction(const NativeMaintenanceTransactionOperations& operations);
    ScopedNativeMaintenanceTransaction(NativeMaintenanceTransactionOperations&&) = delete;
    static const NativeMaintenanceTransactionOperations* current();
    const NativeMaintenanceTransactionOperations& operations_;
};
}
#endif
#endif
