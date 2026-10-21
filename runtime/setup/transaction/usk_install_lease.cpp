// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_install_lease.h"
#include "usk_record_io.h"

#include <limits>
#include <set>

namespace usk::transaction {
namespace {
using usk::json::Value;

void members(const Value& value, const std::set<std::string>& names)
{
    const auto& object = value.as_object();
    if (object.size() != names.size()) throw std::runtime_error("installation lease fields differ");
    for (const auto& [name, unused] : object) {
        (void)unused;
        if (names.count(name) == 0) throw std::runtime_error("installation lease field is unknown");
    }
}

bool hex(const std::string& text, std::size_t size)
{
    if (text.size() != size) return false;
    for (const char ch : text)
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
    return true;
}

void revision(const std::string& value)
{
    if (!hex(value, 64)) throw std::runtime_error("installation state revision is not a SHA-256");
}

void root_identity(const Value& root)
{
    members(root, {"file_id", "volume_serial"});
    const auto& id = root.at("file_id").as_string();
    const auto& serial = root.at("volume_serial").as_string();
    if (!hex(id, 32) || id == std::string(32, '0') || serial.empty() || serial.size() > 20 ||
        serial.front() == '0') throw std::runtime_error("installation lease root identity is invalid");
    std::uint64_t number = 0;
    for (const char ch : serial) {
        if (ch < '0' || ch > '9' || number >
            (std::numeric_limits<std::uint64_t>::max() - static_cast<unsigned>(ch - '0')) / 10)
            throw std::runtime_error("installation lease volume serial is invalid");
        number = number * 10 + static_cast<unsigned>(ch - '0');
    }
}

void holder_identity(const Value& holder)
{
    members(holder, {"process_id", "process_creation_time"});
    const auto process = holder.at("process_id").as_unsigned();
    const auto& creation = holder.at("process_creation_time").as_string();
    if (!process || process > std::numeric_limits<std::uint32_t>::max() ||
        !hex(creation, 16) || creation == std::string(16, '0'))
        throw std::runtime_error("installation lease holder identity is invalid");
}

void request_identity(const InstallLeaseRequest& request)
{
    if (!usk::record_io::valid_identifier(request.install_id) ||
        !usk::record_io::valid_identifier(request.operation_id) ||
        !usk::record_io::valid_identifier(request.attempt_id) ||
        std::set<std::string>{"install_local", "repair", "move", "update", "uninstall",
            "generation_activate", "generation_retire"}.count(request.operation) == 0)
        throw std::runtime_error("installation lease request identity is invalid");
    revision(request.expected_state_revision);
    revision(request.operation_context_sha256);
}

Value seal(Value value)
{
    value.as_object().erase("ownership_sha256");
    const auto digest = usk::json::sha256_canonical(value);
    value.as_object().emplace("ownership_sha256", Value(digest));
    return value;
}

bool equal(const Value& left, const Value& right)
{
    return usk::json::canonical(left) == usk::json::canonical(right);
}
} // namespace

void require_install_lease_record(const Value& record)
{
    members(record, {"schema", "install_id", "operation", "operation_id", "attempt_id",
        "state_root_identity", "holder", "generation", "expected_state_revision", "status",
        "result_state_revision", "predecessor_sha256", "ownership_sha256", "operation_context_sha256"});
    if (record.at("schema").as_string() != "usk.installation_lease_ownership.v1")
        throw std::runtime_error("installation lease schema is unsupported");
    request_identity({record.at("install_id").as_string(), record.at("operation").as_string(),
        record.at("operation_id").as_string(), record.at("attempt_id").as_string(),
        record.at("expected_state_revision").as_string(), false,
        record.at("operation_context_sha256").as_string()});
    root_identity(record.at("state_root_identity"));
    holder_identity(record.at("holder"));
    const auto generation = record.at("generation").as_unsigned();
    if (!generation) throw std::runtime_error("installation lease generation is zero");
    const auto& predecessor = record.at("predecessor_sha256");
    if (generation == 1 ? predecessor.type() != Value::Type::null_value :
        !hex(predecessor.as_string(), 64))
        throw std::runtime_error("installation lease predecessor binding is invalid");
    const auto& status = record.at("status").as_string();
    if (status == "active") {
        if (record.at("result_state_revision").type() != Value::Type::null_value)
            throw std::runtime_error("active installation lease has a terminal revision");
    } else if (status == "completed" || status == "handoff") {
        revision(record.at("result_state_revision").as_string());
    } else throw std::runtime_error("installation lease status is invalid");
    revision(record.at("ownership_sha256").as_string());
    if (!equal(record, seal(record))) throw std::runtime_error("installation lease digest differs");
}

Value derive_install_lease_ownership(const std::optional<Value>& previous,
    const InstallLeaseRequest& request, const Value& observed_state_root,
    const Value& observed_holder, const std::string& observed_state_revision,
    InstallLeasePreviousHolder previous_holder)
{
    request_identity(request);
    root_identity(observed_state_root);
    holder_identity(observed_holder);
    revision(observed_state_revision);
    if (request.expected_state_revision != observed_state_revision) throw InstallStateRevisionStale();
    std::uint64_t generation = 1;
    Value predecessor;
    if (previous) {
        require_install_lease_record(*previous);
        if (previous->at("install_id").as_string() != request.install_id ||
            !equal(previous->at("state_root_identity"), observed_state_root)) throw InstallLeaseStale();
        const auto previous_generation = previous->at("generation").as_unsigned();
        if (previous_generation == std::numeric_limits<std::uint64_t>::max())
            throw std::runtime_error("installation lease generation is exhausted");
        const auto& status = previous->at("status").as_string();
        if (previous->at("attempt_id").as_string() == request.attempt_id)
            throw InstallLeaseStale();
        if (status != "completed") {
            if (!request.recovery || previous->at("operation").as_string() != request.operation ||
                previous->at("operation_id").as_string() != request.operation_id ||
                previous->at("operation_context_sha256").as_string() != request.operation_context_sha256)
                throw InstallLeaseConflict();
            if (status == "active" && previous_holder != InstallLeasePreviousHolder::ended &&
                previous_holder != InstallLeasePreviousHolder::identity_reused) throw InstallLeaseConflict();
            if (status == "handoff" &&
                previous->at("result_state_revision").as_string() != observed_state_revision)
                throw InstallStateRevisionStale();
        }
        generation = previous_generation + 1;
        predecessor = previous->at("ownership_sha256");
    }
    return seal(Value(Value::Object{
        {"schema", Value("usk.installation_lease_ownership.v1")},
        {"install_id", Value(request.install_id)}, {"operation", Value(request.operation)},
        {"operation_id", Value(request.operation_id)}, {"attempt_id", Value(request.attempt_id)},
        {"operation_context_sha256", Value(request.operation_context_sha256)},
        {"state_root_identity", observed_state_root}, {"holder", observed_holder},
        {"generation", Value(generation)}, {"expected_state_revision", Value(observed_state_revision)},
        {"status", Value("active")}, {"result_state_revision", Value()},
        {"predecessor_sha256", predecessor}}));
}

void require_install_lease_start(const Value& ownership, const std::string& observed_state_revision)
{
    require_install_lease_record(ownership);
    revision(observed_state_revision);
    if (ownership.at("status").as_string() != "active") throw InstallLeaseStale();
    if (ownership.at("expected_state_revision").as_string() != observed_state_revision)
        throw InstallStateRevisionStale();
}

void require_install_lease_fence(const Value& ownership, const Value& current,
    const Value& observed_state_root, const Value& observed_holder)
{
    require_install_lease_record(ownership);
    require_install_lease_record(current);
    root_identity(observed_state_root);
    holder_identity(observed_holder);
    if (ownership.at("status").as_string() != "active" || !equal(ownership, current) ||
        !equal(ownership.at("state_root_identity"), observed_state_root) ||
        !equal(ownership.at("holder"), observed_holder)) throw InstallLeaseStale();
}

Value finish_install_lease_ownership(const Value& ownership,
    const Value& observed_state_root, const Value& observed_holder,
    const std::string& observed_state_revision, bool handoff)
{
    require_install_lease_fence(ownership, ownership, observed_state_root, observed_holder);
    revision(observed_state_revision);
    Value result = ownership;
    result.as_object().at("status") = Value(handoff ? "handoff" : "completed");
    result.as_object().at("result_state_revision") = Value(observed_state_revision);
    return seal(std::move(result));
}

std::optional<Value> select_completed_install_lease_history(
    const std::vector<Value>& history, const Value& original_active)
{
    require_install_lease_record(original_active);
    if (original_active.at("status").as_string() != "active" || history.empty() || history.size() > 4096u)
        throw InstallLeaseStale();
    const auto& root = original_active.at("state_root_identity");
    const auto& install_id = original_active.at("install_id").as_string();
    const auto& operation_id = original_active.at("operation_id").as_string();
    const auto same_operation = [&](const Value& value) {
        return value.at("operation").as_string() == original_active.at("operation").as_string() &&
            value.at("operation_id").as_string() == operation_id &&
            value.at("operation_context_sha256").as_string() == original_active.at("operation_context_sha256").as_string();
    };
    std::optional<Value> previous, completed;
    bool found_original = false;
    for (const auto& value : history) {
        require_install_lease_record(value);
        if (value.at("install_id").as_string() != install_id || !equal(value.at("state_root_identity"), root))
            throw InstallLeaseStale();
        Value expected;
        if (value.at("status").as_string() == "active") {
            InstallLeaseRequest transition{install_id, value.at("operation").as_string(),
                value.at("operation_id").as_string(), value.at("attempt_id").as_string(),
                value.at("expected_state_revision").as_string(), true, value.at("operation_context_sha256").as_string()};
            // Validate recorded data transitions; this makes no claim about a
            // historical holder's actual termination or current native custody.
            expected = derive_install_lease_ownership(previous, transition, root, value.at("holder"),
                transition.expected_state_revision, InstallLeasePreviousHolder::ended);
        } else {
            if (!previous) throw InstallLeaseStale();
            expected = finish_install_lease_ownership(*previous, root, previous->at("holder"),
                value.at("result_state_revision").as_string(), value.at("status").as_string() == "handoff");
        }
        if (!equal(value, expected)) throw InstallLeaseStale();
        if (completed) {
            // An immutable operation cannot acquire another continuation after
            // its completion, even if a caller supplies a different context.
            if (value.at("operation_id").as_string() == operation_id) throw InstallLeaseStale();
        } else if (found_original) {
            if (!same_operation(value)) throw InstallLeaseStale();
            if (value.at("status").as_string() == "completed") completed = value;
        } else if (value.at("generation").as_unsigned() == original_active.at("generation").as_unsigned() &&
            value.at("status").as_string() == "active") {
            if (!equal(value, original_active)) throw InstallLeaseStale();
            found_original = true;
        }
        previous = value;
    }
    if (!found_original) throw InstallLeaseStale();
    return completed;
}
} // namespace usk::transaction
