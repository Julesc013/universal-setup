// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_client_context_internal.h"
#include "usk_publisher_client_bridge.h"
#include "usk_publisher_response_internal.h"
#include "usk_effect_dispatch.h"
#include "usk/usk_result.h"
#include <cstring>
#include <algorithm>
#include <vector>
#include <memory>
#include <stdexcept>
#include <utility>
#if defined(_WIN32)
#include "usk_publisher_registered_client_internal.h"
#endif

namespace usk::command::detail {
namespace {
using usk::json::Value;
constexpr std::size_t request_limit = 1024u * 1024u;
constexpr char preparation_failed[] =
    "{\"schema\":\"usk.command_response.v1\",\"status\":\"error\",\"payload\":null,"
    "\"error\":{\"code\":\"publisher_request_not_dispatched\","
    "\"message\":\"Publisher request preparation failed before dispatch\"}}";

constexpr char invalid_request[] =
    "{\"schema\":\"usk.command_response.v1\",\"status\":\"invalid_argument\",\"payload\":null,"
    "\"error\":{\"code\":\"invalid_argument\",\"message\":\"Public publisher request is invalid\"}}";

void require_shape(const std::string& command, const Value& submitted) {
    if (submitted.type() != Value::Type::object)
        throw std::invalid_argument("publisher input must be an object");
    const bool verify = command == "installed.verify";
    const bool recovery = command == "recovery.apply";
    const std::vector<std::string> fields = verify ?
        std::vector<std::string>{"schema", "request_id", "install_id", "report_id", "verified_at"} :
        std::vector<std::string>{"schema", "plan_request", "reviewed_plan_id",
            "reviewed_plan_digest", recovery ? "selected_action" : "transaction_id",
            "applied_at", "confirmation"};
    const auto& object = submitted.as_object();
    for (const auto& field : fields) {
        const auto found = object.find(field);
        if (found == object.end())
            throw std::invalid_argument("publisher input lacks a required member");
        if (field == "plan_request") {
            if (found->second.type() != Value::Type::object)
                throw std::invalid_argument("publisher plan request is not an object");
        } else {
            try {
                if (found->second.as_string().empty())
                    throw std::invalid_argument("publisher string is empty");
            } catch (...) { throw std::invalid_argument("publisher member is not a nonempty string"); }
        }
    }
    for (const auto& item : object) {
        if (std::find(fields.begin(), fields.end(), item.first) != fields.end()) continue;
        if (command != "install_local.apply" || item.first != "restart_from")
            throw std::invalid_argument("publisher input contains an extra member");
    }
    if (!verify && submitted.at("confirmation").as_string() != "APPLY")
        throw std::invalid_argument("publisher effect requires explicit confirmation");
    if (recovery && submitted.at("selected_action").as_string() != "finalize" &&
        submitted.at("selected_action").as_string() != "rollback")
        throw std::invalid_argument("publisher recovery action differs");
}
void identity_field(Value& result, const Value& source, const char* field) {
    const auto& value = source.at(field).as_string();
    // Identity receipts contain bounded IDs/digests, never arbitrary input
    // trees, paths, archives or payload bytes. Native validation is still fresh.
    if (value.empty() || value.size() > 1024u)
        throw std::invalid_argument("publisher identity exceeds its bound");
    result.as_object().emplace(field, Value(value));
}
Value invocation_identity(const std::string& command, const Value& submitted) {
    Value result(Value::Object{{"schema", Value("usk.publisher_client_outcome.v1")},
        {"command", Value(command)}, {"request_sha256", Value(usk::json::sha256_canonical(submitted))}});
    if (command == "installed.verify") {
        for (const auto field : {"request_id", "install_id", "report_id"})
            identity_field(result, submitted, field);
    } else {
        for (const auto field : {"reviewed_plan_id", "reviewed_plan_digest"})
            identity_field(result, submitted, field);
        if (command == "recovery.apply") {
            const auto& inspection = submitted.at("plan_request").at("inspection");
            for (const auto field : {"request_id", "install_id", "transaction_id", "operation"})
                identity_field(result, inspection, field);
            identity_field(result, submitted, "selected_action");
        } else {
            identity_field(result, submitted, "transaction_id");
            identity_field(result, submitted.at("plan_request"), "request_id");
            identity_field(result, submitted.at("plan_request"), "install_id");
        }
    }
    return result;
}
Value outcome(const char* status, const char* code, Value invocation) {
    return Value(Value::Object{{"schema", Value("usk.command_response.v1")},
        {"status", Value(status)}, {"payload", std::move(invocation)},
        {"error", Value(Value::Object{{"code", Value(code)}})}});
}
const char* request_schema(const std::string& command) {
    if (command == "install_local.apply") return "usk.install_local_apply_request.v1";
    if (command == "installed.verify") return "usk.installed_verify_request.v1";
    if (command == "repair.apply") return "usk.repair_apply_request.v1";
    if (command == "move.apply") return "usk.move_apply_request.v1";
    if (command == "uninstall.apply") return "usk.uninstall_apply_request.v1";
    if (command == "recovery.apply") return "usk.recovery_apply_request.v1";
    throw std::invalid_argument("registered public command is unavailable");
}
}

PublisherClientContext::PublisherClientContext(std::string endpoint) : endpoint_(std::move(endpoint)) {
    if (endpoint_.size() != 40u || endpoint_.compare(0, 8, "USK_PUB_") != 0 ||
        endpoint_.find_first_not_of("0123456789abcdef", 8) != std::string::npos)
        throw std::invalid_argument("publisher endpoint identity differs");
}
void PublisherClientContext::clear() noexcept {
    output_.clear();
    unknown_.clear();
}
PublisherClientResult PublisherClientContext::execute(const char* command_name,
    const char* request, std::size_t size, const PublisherClientTransport& transport,
    const PublisherClientPrepare& prepare) noexcept {
    clear(); // No previous invocation's identity is an emergency response.
    bool possible_dispatch = false;
    Value invocation;
    try {
        if (!command_name || !request || !size || size > request_limit)
            throw std::invalid_argument("bounded registered request is required");
        const std::string command(command_name);
        const auto expected_schema = request_schema(command);
        usk::json::ParseLimits limits;
        limits.max_bytes = request_limit;
        limits.max_string_bytes = request_limit / 2;
        const auto submitted = usk::json::parse(std::string(request, size), limits);
        require_shape(command, submitted);
        if (submitted.at("schema").as_string() != expected_schema)
            throw std::invalid_argument("registered command schema differs");
        // The wire retains the complete public request. The bounded receipt
        // binds its digest and recovery identity, never permission to replay.
        invocation = invocation_identity(command, submitted);
        auto fallback = usk::json::canonical(
            outcome("unknown", "publisher_outcome_unknown", invocation));
        if (fallback.size() > 64u * 1024u)
            throw std::invalid_argument("publisher uncertainty response exceeds bound");
        unknown_.swap(fallback); // Owned and bound before preparation or transport.
        if (!prepare || !transport)
            throw std::invalid_argument("registered client route unavailable");
        const auto wire = prepare(command, submitted);
        const auto bytes = usk::json::canonical(wire);
        if (bytes.empty() || bytes.size() > request_limit)
            throw std::invalid_argument("registered wire request exceeds bound");
        possible_dispatch = true; // A throwing write may already have sent bytes.
        const auto received = transport(bytes);
        auto result = validate_publisher_response(command, wire, received);
        if (result.disposition == PublisherResponseDisposition::completed) {
            output_ = usk::json::canonical(result.result);
            return {USK_STATUS_OK, output_.c_str()};
        }
        const bool refused = result.disposition == PublisherResponseDisposition::refused;
        if (result.result.type() != Value::Type::null_value)
            invocation.as_object().emplace("diagnostic", std::move(result.result));
        output_ = usk::json::canonical(outcome(refused ? "refused" : "recovery_required",
            result.error_code ? result.error_code : "publisher_failed", std::move(invocation)));
        return {USK_STATUS_ERROR, output_.c_str()};
    } catch (const usk::base::EffectRequestNotDispatched& error) {
        possible_dispatch = false; // Only the concrete transport supplies this proof.
        try {
            using Reason = usk::base::EffectRequestNotDispatched::Reason;
            const char* code = error.reason() == Reason::operation_cancelled ? "operation_cancelled" :
                error.reason() == Reason::operation_conflict ? "operation_conflict" :
                "publisher_admission_refused";
            if (!error.inspection_reference().empty()) {
                const Value observed(Value::Object{
                    {"operation_inspection_ref", Value(error.inspection_reference())}});
                invocation.as_object().emplace("diagnostic", publisher_operation_diagnostic(observed, code));
            }
            output_ = usk::json::canonical(outcome("refused", code, std::move(invocation)));
            return {USK_STATUS_ERROR, output_.c_str()};
        } catch (...) { return {USK_STATUS_ERROR, preparation_failed}; }
    } catch (const std::invalid_argument&) {
        if (possible_dispatch && !unknown_.empty())
            return {USK_STATUS_ERROR, unknown_.c_str()};
        return {USK_STATUS_INVALID_ARGUMENT, invalid_request};
    } catch (...) {
        if (possible_dispatch && !unknown_.empty())
            return {USK_STATUS_ERROR, unknown_.c_str()};
        return {USK_STATUS_ERROR, preparation_failed};
    }
}


}

extern "C" void* usk_publisher_client_create_internal(const char* name, size_t size) noexcept {
    try {
        if (!name || size != 40) return nullptr;
        return new usk::command::detail::PublisherClientContext(std::string(name, size));
    } catch (...) { return nullptr; }
}
extern "C" void usk_publisher_client_destroy_internal(void* client) noexcept {
    delete static_cast<usk::command::detail::PublisherClientContext*>(client);
}
extern "C" void usk_publisher_client_clear_internal(void* client) noexcept {
    if (client) static_cast<usk::command::detail::PublisherClientContext*>(client)->clear();
}
extern "C" const char* usk_publisher_client_execute_internal(void* client,
    const char* command, const char* request, size_t size, int* status) noexcept {
    if (!status) return nullptr;
    *status = USK_STATUS_ERROR;
    if (!client) return nullptr;
    try {
#if defined(_WIN32)
        auto& context = *static_cast<usk::command::detail::PublisherClientContext*>(client);
        const usk::command::detail::PublisherClientTransport transport = [&context](const std::string& bytes) {
            const std::wstring endpoint(context.endpoint().begin(), context.endpoint().end());
            return usk::platform::windows::submit_service_admitted_publisher_request(endpoint, bytes);
        };
        const usk::command::detail::PublisherClientPrepare prepare =
            [](const std::string&, const usk::json::Value& input) { return input; };
        const auto result = context.execute(command, request, size, transport, prepare);
        *status = result.status;
        return result.json;
#else
        (void)command; (void)request; (void)size;
        return nullptr;
#endif
    } catch (...) {
        // Callback construction precedes execute(). The noexcept executor
        // itself contains every failure after a possible dispatch.
        return nullptr;
    }
}
