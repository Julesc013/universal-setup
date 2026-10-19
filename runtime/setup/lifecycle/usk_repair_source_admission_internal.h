// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_REPAIR_SOURCE_ADMISSION_INTERNAL_H
#define USK_REPAIR_SOURCE_ADMISSION_INTERNAL_H

#include "usk_archive_payload.h"
#include "usk_lifecycle.h"

#include <chrono>
#include <functional>
#include <string>

namespace usk::lifecycle::detail {
// Internal construction seam only. The public repair dispatcher supplies the
// fixed archive budget and the real steady clock; neither is caller authority.
// The injected clock permits deterministic phase-boundary qualification.
using RepairSourceClock = std::function<std::chrono::steady_clock::time_point()>;
void bind_repair_source_admission(RepairPlan& plan,
    std::string inspection_request, std::string strip_prefix,
    const archive::StreamingStoredArchivePayload& original,
    std::chrono::milliseconds extraction_budget, RepairSourceClock now = {});
}
#endif
