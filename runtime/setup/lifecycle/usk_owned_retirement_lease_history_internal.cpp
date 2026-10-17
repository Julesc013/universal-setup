// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_owned_retirement_lease_history_internal.h"
#include "usk_install_lease.h"
#include <algorithm>
#include <map>
#include <optional>
#include <stdexcept>
#include <utility>

namespace usk::lifecycle::detail {
namespace {
using usk::json::Value;
void require(bool value) {
    if (!value) throw std::runtime_error("owned retirement lease history is incomplete or inconsistent");
}
bool same(const Value& left, const Value& right) { return json::equal_values(left, right); }
}

std::vector<OwnedRetirementLeaseCompletion> decode_owned_retirement_lease_history(
    const std::vector<Value>& history, const std::string& install_id,
    const Value& state_root_identity, const std::string& current_revision)
{
    using namespace usk::transaction;
    require(!history.empty() && history.size() <= 4096u);
    require(current_revision.size() == 64u &&
        std::all_of(current_revision.begin(), current_revision.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        }));
    std::optional<Value> previous, original;
    // Indices refer only to completed original spans; repeated spans do not
    // replace an operation's immutable original context or completion.
    std::map<std::string, std::size_t> completed_operations;
    std::vector<OwnedRetirementLeaseCompletion> result;
    bool repeated = false;
    for (const auto& record : history) {
        require_install_lease_record(record);
        require(record.at("install_id").as_string() == install_id &&
            same(record.at("state_root_identity"), state_root_identity));
        const auto& operation = record.at("operation").as_string();
        const auto& id = record.at("operation_id").as_string();
        require(operation == "install_local" || operation == "repair" || operation == "uninstall");
        const auto& status = record.at("status").as_string();
        Value expected;
        if (status == "active") {
            InstallLeaseRequest request{install_id, operation, id,
                record.at("attempt_id").as_string(), record.at("expected_state_revision").as_string(),
                true, record.at("operation_context_sha256").as_string()};
            // This is the existing recorded-data transition check. The enum
            // does not assert that any actual native process has ended.
            expected = derive_install_lease_ownership(previous, request, state_root_identity,
                record.at("holder"), request.expected_state_revision, InstallLeasePreviousHolder::ended);
            if (!original) {
                if (!previous) require(operation == "install_local");
                const auto found = completed_operations.find(id);
                repeated = found != completed_operations.end();
                if (repeated) {
                    const auto& first = result.at(found->second).original_active;
                    require(previous && previous->at("status").as_string() == "completed" &&
                        first.at("operation").as_string() == operation &&
                        same(first.at("operation_context_sha256"), record.at("operation_context_sha256")) &&
                        record.at("expected_state_revision").as_string() ==
                            previous->at("result_state_revision").as_string());
                }
                original = record;
            } else {
                require(original->at("operation").as_string() == operation &&
                    original->at("operation_id").as_string() == id &&
                    same(original->at("operation_context_sha256"), record.at("operation_context_sha256")));
                if (repeated) require(same(original->at("expected_state_revision"), record.at("expected_state_revision")));
            }
        } else {
            require(previous && original);
            expected = finish_install_lease_ownership(*previous, state_root_identity,
                previous->at("holder"), record.at("result_state_revision").as_string(), status == "handoff");
            if (repeated) require(same(original->at("expected_state_revision"), record.at("result_state_revision")));
        }
        require(same(record, expected));
        if (status == "completed") {
            require(original.has_value());
            if (repeated) require(same(original->at("expected_state_revision"), record.at("result_state_revision")));
            else require(completed_operations.emplace(id, result.size()).second);
            result.push_back({std::move(*original), record, repeated});
            original.reset();
        }
        previous = record;
    }
    require(!original && previous && previous->at("status").as_string() == "completed" &&
        previous->at("result_state_revision").as_string() == current_revision);
    return result;
}
}
