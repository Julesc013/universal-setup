// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_OWNED_RETIREMENT_OBJECT_HISTORY_INTERNAL_H
#define USK_OWNED_RETIREMENT_OBJECT_HISTORY_INTERNAL_H
#if defined(_WIN32)
#include "usk_maintenance_effect_journal.h"
#include "usk_json.h"
namespace usk::lifecycle::detail {
// Replay historical object roles only, after the existing complete transaction,
// effect and custody-chain decoders. No native handle, grant, callback, reusable
// validation token or partially successful result can escape this function.
void require_owned_retirement_object_history(
    const transaction::TransactionSpec& spec,const json::Value& original,
    const json::Value& created,const json::Value& reviewed_artifact,
    const transaction::StreamJournal& stream,const transaction::MaintenanceEffectInspection& effects,
    const std::vector<json::Value>& custody,const std::string& consumer_sid,
    const std::string& service_sid,const std::string& original_visible_root_file_id,
    const std::string& resulting_lifecycle_status);
}
#endif
#endif
