// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_native_maintenance_transaction_internal.h"
#if defined(_WIN32)
#include <stdexcept>
#include <exception>
namespace usk::transaction::detail {
namespace { thread_local const NativeMaintenanceTransactionOperations* active_operations = nullptr; }
ScopedNativeMaintenanceTransaction::ScopedNativeMaintenanceTransaction(
    const NativeMaintenanceTransactionOperations& operations) : operations_(operations) {
    if (active_operations || !operations.require_authority || !operations.create_staging_root ||
        !operations.ensure_stream_parent || !operations.open_stream || !operations.require_stream ||
        !operations.finish_stream || !operations.commit)
        throw std::runtime_error("native maintenance transaction owner is absent, incomplete or nested");
    active_operations = &operations_;
}
ScopedNativeMaintenanceTransaction::~ScopedNativeMaintenanceTransaction() {
    if (active_operations != &operations_) std::terminate();
    active_operations = nullptr;
}
const NativeMaintenanceTransactionOperations* ScopedNativeMaintenanceTransaction::current() { return active_operations; }
}
#endif
