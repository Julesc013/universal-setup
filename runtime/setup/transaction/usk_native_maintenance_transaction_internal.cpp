// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_native_maintenance_transaction_internal.h"
#if defined(_WIN32)
#include <stdexcept>
#include <exception>
namespace usk::transaction::detail {
namespace {
thread_local const NativeMaintenanceTransactionOperations* active_operations = nullptr;
thread_local std::weak_ptr<const void> active_binding;
}
void require_native_maintenance_origin_binding(bool native_origin,
    const std::weak_ptr<const void>& original, const std::weak_ptr<const void>& current) {
    if (!native_origin) {
        if (!current.expired()) throw std::runtime_error("ordinary transaction cannot adopt a native maintenance owner");
        return;
    }
    if (original.expired() || current.expired() || original.owner_before(current) || current.owner_before(original))
        throw std::runtime_error("native maintenance transaction lost its original owner; no generic fallback");
}
ScopedNativeMaintenanceTransaction::ScopedNativeMaintenanceTransaction(
    const NativeMaintenanceTransactionOperations& operations) : operations_(operations) {
    if (active_operations || !operations.require_authority || !operations.create_staging_root ||
        !operations.ensure_stream_parent || !operations.open_stream || !operations.require_stream ||
        !operations.finish_stream || !operations.commit)
        throw std::runtime_error("native maintenance transaction owner is absent, incomplete or nested");
    // A distinct control block identifies this lifetime even if an operations
    // object or native owner address is later reused. Sessions retain weak
    // identity only, and cannot prolong or resurrect an ended engine scope.
    identity_ = std::make_shared<const unsigned char>(static_cast<unsigned char>(0));
    active_binding = identity_;
    active_operations = &operations_;
}
ScopedNativeMaintenanceTransaction::~ScopedNativeMaintenanceTransaction() {
    if (active_operations != &operations_) std::terminate();
    active_operations = nullptr;
    active_binding.reset();
}
const NativeMaintenanceTransactionOperations* ScopedNativeMaintenanceTransaction::current() { return active_operations; }
std::weak_ptr<const void> ScopedNativeMaintenanceTransaction::current_binding() { return active_binding; }
}
#endif
