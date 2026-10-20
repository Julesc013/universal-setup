// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_recovery_request_internal.h"
#include "usk_record_io.h"
#include <algorithm>
#include <filesystem>
#include <set>
#include <stdexcept>
#include <string>

namespace usk::command::detail {
namespace {
using usk::json::Value;
void require(bool okay, const char* reason) {
    if (!okay) throw std::runtime_error(reason);
}
bool hex(const std::string& text, std::size_t size) {
    return text.size() == size && std::all_of(text.begin(), text.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
}
const Value* publisher_public_recovery_inspection(const Value& request) {
    const auto closed = [](const Value& value, const std::set<std::string>& fields) {
        require(value.as_object().size() == fields.size(), "public recovery request is not closed");
        for (const auto& item : value.as_object())
            require(fields.count(item.first) != 0, "public recovery request field is unknown");
    };
    const auto text = [](const Value& value, const char* field, std::size_t limit) -> const std::string& {
        const auto& result = value.at(field).as_string();
        require(!result.empty() && result.size() <= limit && result.find('\0') == std::string::npos,
            "public recovery request string exceeds its bound");
        return result;
    };
    const auto identifier = [&](const Value& value, const char* field) {
        require(usk::record_io::valid_identifier(text(value, field, 128u)),
            "public recovery request identifier is invalid");
    };
    const auto& schema = request.at("schema").as_string();
    const Value* inspection = nullptr;
    const Value* plan = nullptr;
    if (schema == "usk.recovery_inspect_request.v1") inspection = &request;
    else if (schema == "usk.recovery_plan_request.v1") plan = &request;
    else if (schema == "usk.recovery_apply_request.v1") {
        closed(request, {"schema", "plan_request", "reviewed_plan_id", "reviewed_plan_digest",
            "selected_action", "applied_at", "confirmation"});
        identifier(request, "reviewed_plan_id");
        require(hex(text(request, "reviewed_plan_digest", 64u), 64u), "public recovery reviewed digest differs");
        const auto& action = text(request, "selected_action", 16u);
        require((action == "finalize" || action == "rollback") &&
            text(request, "confirmation", 5u) == "APPLY", "public recovery action or confirmation differs");
        (void)text(request, "applied_at", 64u);
        plan = &request.at("plan_request");
    } else return nullptr; // Decline only an unrelated request family.
    if (plan) {
        closed(*plan, {"schema", "inspection", "recovery_plan_id", "created_at"});
        require(plan->at("schema").as_string() == "usk.recovery_plan_request.v1",
            "public recovery nested plan family differs");
        identifier(*plan, "recovery_plan_id");
        (void)text(*plan, "created_at", 64u);
        if (schema == "usk.recovery_apply_request.v1")
            require(request.at("reviewed_plan_id").as_string() == plan->at("recovery_plan_id").as_string(),
                "public recovery reviewed plan ID differs from its complete plan request");
        inspection = &plan->at("inspection");
    }
    if (!inspection || inspection->at("schema").as_string() != "usk.recovery_inspect_request.v1")
        throw std::runtime_error("public recovery inspection family differs");
    const auto& operation = text(*inspection, "operation", 16u);
    require(operation == "install_local" || operation == "repair" || operation == "move" || operation == "uninstall",
        "public recovery operation differs");
    std::set<std::string> fields{"schema", "request_id", "install_id", "transaction_id",
        "plan_id", "plan_digest", "operation", "target_root"};
    if (inspection->contains("install_plan_request")) {
        require(operation == "install_local", "public maintenance recovery supplied an install plan");
        (void)inspection->at("install_plan_request").as_object();
        fields.insert("install_plan_request");
    }
    closed(*inspection, fields);
    for (const auto* field : {"request_id", "install_id", "transaction_id", "plan_id"}) identifier(*inspection, field);
    require(hex(text(*inspection, "plan_digest", 64u), 64u), "public recovery original plan digest differs");
    const auto target = std::filesystem::u8path(text(*inspection, "target_root", 32767u));
    require(target.is_absolute() && target.lexically_normal() == target,
        "public recovery target must be absolute and normalized");
    return inspection;
}

}
