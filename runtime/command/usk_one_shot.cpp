// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_one_shot.h"

#include "usk/usk_api.h"
#include "usk_json.h"

#include <array>
#include <cstdint>
#include <istream>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <string>
#include <utility>

namespace usk::command {
namespace {

using usk::json::Value;

OneShotResult failure(const std::string& request_id, const char* code)
{
    const Value envelope(Value::Object{
        {"schema", Value("usk.oneshot_response.v1")},
        {"request_id", Value(request_id)},
        {"status", Value("refused")},
        {"result", Value()},
        {"error", Value(Value::Object{{"code", Value(code)}})}
    });
    return {usk::json::canonical(envelope), "request refused", 2};
}

OneShotResult candidate_outcome(const std::string& request_id, const char* status,
    const Value& result, const char* error_code, int exit_code)
{
    const Value error = error_code == nullptr ? Value() :
        Value(Value::Object{{"code", Value(error_code)}});
    const Value envelope(Value::Object{
        {"schema", Value("usk.oneshot_response.v1")},
        {"request_id", Value(request_id)},
        {"status", Value(status)},
        {"result", result},
        {"error", error}
    });
    const std::string document = usk::json::canonical(envelope);
    if (document.size() > max_response_bytes)
        return candidate_outcome(request_id, "unknown", Value(),
            "publisher_outcome_unknown", 5);
    return {document, "", exit_code};
}

bool safe_id(const std::string& value)
{
    if (value.empty() || value.size() > 128) return false;
    for (const unsigned char ch : value) {
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
              (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-')) {
            return false;
        }
    }
    return true;
}

bool valid_context(const OneShotContextConfig& config)
{
    return !config.state_root.empty() && !config.authorized_acceptance_root.empty() &&
        !config.target_policy_activation.empty() &&
        config.state_root.find('\0') == std::string::npos &&
        config.authorized_acceptance_root.find('\0') == std::string::npos &&
        config.target_policy_activation.find('\0') == std::string::npos;
}

bool initial_command(const std::string& command)
{
    return command == "command_graph.inspect" || command == "command_graph.inspect_v2" ||
        command == "policy.inspect" || command == "diagnostics.report" ||
        command == "install_local.inspect" || command == "install_local.plan";
}

} // namespace

OneShotContextConfig read_context_config(std::istream& input)
{
    constexpr std::size_t limit = 16384;
    std::string document;
    std::array<char, 4096> buffer{};
    for (;;) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) {
            if (document.size() + static_cast<std::size_t>(count) > limit) {
                throw std::runtime_error("context configuration exceeds bound");
            }
            document.append(buffer.data(), static_cast<std::size_t>(count));
        }
        if (input.bad()) throw std::runtime_error("context configuration read failed");
        if (input.eof()) break;
        if (!input) throw std::runtime_error("context configuration read failed");
    }
    usk::json::ParseLimits limits;
    limits.max_bytes = limit;
    limits.max_string_bytes = 8192;
    const Value parsed = usk::json::parse(document, limits);
    const auto& fields = parsed.as_object();
    if (fields.size() != 4 || !parsed.contains("schema") ||
        !parsed.contains("state_root") || !parsed.contains("authorized_acceptance_root") ||
        !parsed.contains("target_policy_activation") ||
        parsed.at("schema").as_string() != "usk.oneshot_context.v1") {
        throw std::runtime_error("invalid context configuration");
    }
    OneShotContextConfig result{
        parsed.at("state_root").as_string(),
        parsed.at("authorized_acceptance_root").as_string(),
        parsed.at("target_policy_activation").as_string()};
    if (!valid_context(result)) {
        throw std::runtime_error("invalid context configuration");
    }
    return result;
}

OneShotResult run_one_shot(const std::string& request_json,
                           const OneShotContextConfig* context_config)
{
    std::string request_id;
    try {
        usk::json::ParseLimits limits;
        limits.max_bytes = max_request_bytes;
        limits.max_string_bytes = max_request_bytes / 2;
        const Value input = usk::json::parse(request_json, limits);
        const auto& fields = input.as_object();
        if (fields.size() != 5 || !input.contains("schema") || !input.contains("request_id") ||
            !input.contains("command") || !input.contains("payload") || !input.contains("dry_run") ||
            input.at("schema").as_string() != "usk.oneshot_request.v1") {
            return failure("", "invalid_request");
        }
        request_id = input.at("request_id").as_string();
        if (!safe_id(request_id)) return failure("", "invalid_request_id");
        const std::string command = input.at("command").as_string();
        if (!initial_command(command)) return failure(request_id, "command_unavailable");
        if (!input.at("dry_run").as_boolean() ||
            input.at("payload").type() != Value::Type::object) {
            return failure(request_id, "invalid_request");
        }
        if ((command == "install_local.plan") != (context_config != nullptr)) {
            return failure(request_id, "context_mismatch");
        }
        if (context_config != nullptr && !valid_context(*context_config)) {
            return failure(request_id, "invalid_context");
        }
        if (command == "install_local.plan" &&
            (!input.at("payload").contains("required_commit_authority") ||
             input.at("payload").at("required_commit_authority").as_string() !=
                 "staged_child_bound_v1")) {
            return failure(request_id, "protected_authority_required");
        }
        const std::string payload = usk::json::canonical(input.at("payload"));
        usk_context* raw = nullptr;
        usk_config_v1 config{};
        const usk_config_v1* config_ptr = nullptr;
        if (context_config != nullptr) {
            config.struct_size = sizeof(config);
            config.state_root = context_config->state_root.c_str();
            config.authorized_acceptance_root =
                context_config->authorized_acceptance_root.c_str();
            config.target_policy_activation =
                context_config->target_policy_activation.c_str();
            config_ptr = &config;
        }
        if (usk_context_create_v1(config_ptr, &raw) != USK_STATUS_OK || raw == nullptr) {
            return failure(request_id, "context_unavailable");
        }
        std::unique_ptr<usk_context, decltype(&usk_context_destroy_v1)> context(
            raw, &usk_context_destroy_v1);
        usk_command_request_v1 request{};
        request.struct_size = sizeof(request);
        request.command_name = {command.data(), static_cast<usk_size>(command.size())};
        request.json_payload = {payload.data(), static_cast<usk_size>(payload.size())};
        request.dry_run = 1;
        usk_command_response_v1 response{};
        response.struct_size = sizeof(response);
        const int status = usk_command_execute_v1(context.get(), &request, &response);
        if (response.json_payload.data == nullptr ||
            response.json_payload.size > max_response_bytes || status < 0) {
            return failure(request_id, "response_unavailable");
        }
        // The public ABI borrows this view; copy before the context is released.
        const std::string owned(response.json_payload.data,
                                static_cast<std::size_t>(response.json_payload.size));
        limits.max_bytes = max_response_bytes;
        limits.max_string_bytes = max_response_bytes / 2;
        const Value body = usk::json::parse(owned, limits);
        const Value envelope(Value::Object{
            {"schema", Value("usk.oneshot_response.v1")},
            {"request_id", Value(request_id)},
            {"status", Value(status == USK_STATUS_OK ? "ok" : "refused")},
            {"result", body},
            {"error", Value()}
        });
        std::string document = usk::json::canonical(envelope);
        if (document.size() > max_response_bytes) {
            return failure(request_id, "response_unavailable");
        }
        return {std::move(document), "", status == USK_STATUS_OK ? 0 : 4};
    } catch (const std::exception&) {
        // Parser and provider diagnostics may include input; never echo them.
        return failure(request_id, "invalid_request");
    }
}

OneShotResult run_candidate_one_shot(const std::string& request_json,
    const CandidateTransport& transport)
{
    std::string request_id;
    std::string request;
    std::string response_field;
    std::string candidate_command;
    try {
        usk::json::ParseLimits limits;
        limits.max_bytes = max_request_bytes;
        limits.max_string_bytes = max_request_bytes / 2;
        const Value input = usk::json::parse(request_json, limits);
        const auto& fields = input.as_object();
        if (fields.size() != 5 || !input.contains("schema") ||
            !input.contains("request_id") || !input.contains("command") ||
            !input.contains("payload") || !input.contains("dry_run") ||
            input.at("schema").as_string() != "usk.oneshot_request.v1")
            return failure("", "invalid_request");
        request_id = input.at("request_id").as_string();
        if (!safe_id(request_id)) return failure("", "invalid_request_id");
        const std::string command = input.at("command").as_string();
        candidate_command = command;
        std::string expected_schema;
        if (command == "install_local.apply") {
            expected_schema = "usk.install_local_apply_request.v1";
            response_field = "apply_response";
        } else if (command == "installed.verify") {
            expected_schema = "usk.publisher_installed_verify_request.v1";
            response_field = "verify_response";
        } else if (command == "install_local.recover") {
            expected_schema = "usk.publisher_recovery_request.v1";
            response_field = "recovery_installed_response";
        } else {
            return failure(request_id, "command_unavailable");
        }
        if (input.at("dry_run").as_boolean() ||
            input.at("payload").type() != Value::Type::object ||
            input.at("payload").at("schema").as_string() != expected_schema)
            return failure(request_id, "invalid_request");
        request = usk::json::canonical(input.at("payload"));
    } catch (const std::exception&) {
        return failure(request_id, "invalid_request");
    }

    // Dispatch may have changed the target even when its reply is lost. Never
    // translate transport failure or malformed service output into refusal.
    try {
        if (!transport) return failure(request_id, "transport_unavailable");
        const std::string response = transport(request);
        usk::json::ParseLimits limits;
        limits.max_bytes = max_response_bytes;
        limits.max_string_bytes = max_response_bytes / 2;
        const Value observed = usk::json::parse(response, limits);
        if (observed.at("schema").as_string() !=
                "usk.publisher_lab_service_observation.v1")
            throw std::runtime_error("candidate response schema differs");
        const std::string status = observed.at("status").as_string();
        if (status == "pass") {
            const Value* public_response = &observed.at(response_field);
            if (candidate_command == "install_local.apply") {
                const auto& replayed = observed.at("recovery_installed_response");
                const bool direct_present = public_response->type() != Value::Type::null_value;
                const bool replay_present = replayed.type() != Value::Type::null_value;
                if (direct_present == replay_present)
                    throw std::runtime_error("candidate apply completion is ambiguous");
                if (replay_present) public_response = &replayed;
            }
            if (public_response->at("schema").as_string() !=
                    "usk.command_response.v1" ||
                public_response->at("status").as_string() != "ok")
                throw std::runtime_error("candidate public response differs");
            return candidate_outcome(request_id, "ok", observed, nullptr, 0);
        }
        if (status == "failed" && candidate_command == "installed.verify" &&
            observed.contains("verify_response")) {
            const auto& public_response = observed.at("verify_response");
            if (public_response.at("schema").as_string() !=
                    "usk.command_response.v1" ||
                public_response.at("status").as_string() != "ok" ||
                public_response.at("payload").at("schema").as_string() !=
                    "usk.verification_report.v1")
                throw std::runtime_error("candidate verification response differs");
            const std::string report_status =
                public_response.at("payload").at("status").as_string();
            if ((report_status != "fail" && report_status != "warn" &&
                    report_status != "unknown") ||
                public_response.at("payload").at("report_digest").as_string() !=
                    observed.at("bound_report_digest").as_string())
                throw std::runtime_error("candidate verification report differs");
            // A valid drift report is a completed diagnosis, not a refusal.
            return candidate_outcome(request_id, "ok", observed, nullptr, 0);
        }
        if (status == "failed")
            return candidate_outcome(request_id, "refused", observed,
                "publisher_failed", 4);
        if (status == "recovery_required")
            return candidate_outcome(request_id, "recovery_required", observed,
                "recovery_required", 5);
    } catch (const std::exception&) {
        return candidate_outcome(request_id, "unknown", Value(),
            "publisher_outcome_unknown", 5);
    }
    return candidate_outcome(request_id, "unknown", Value(),
        "publisher_outcome_unknown", 5);
}

OneShotResult invalid_frame_result()
{
    return failure("", "invalid_frame");
}

OneShotResult invalid_context_result()
{
    return failure("", "invalid_context");
}

std::string read_bounded_request(std::istream& input, bool length_prefixed)
{
    if (length_prefixed) {
        std::array<unsigned char, 4> header{};
        input.read(reinterpret_cast<char*>(header.data()),
                   static_cast<std::streamsize>(header.size()));
        if (input.gcount() != static_cast<std::streamsize>(header.size())) {
            throw std::runtime_error("truncated frame header");
        }
        const std::uint32_t length = (static_cast<std::uint32_t>(header[0]) << 24) |
            (static_cast<std::uint32_t>(header[1]) << 16) |
            (static_cast<std::uint32_t>(header[2]) << 8) |
            static_cast<std::uint32_t>(header[3]);
        if (length == 0 || length > max_request_bytes) {
            throw std::runtime_error("frame length exceeds bound");
        }
        std::string body(length, '\0');
        input.read(body.data(), static_cast<std::streamsize>(length));
        if (input.gcount() != static_cast<std::streamsize>(length)) {
            throw std::runtime_error("truncated frame or trailing bytes");
        }
        const int trailing = input.peek();
        if (input.bad() || trailing != std::char_traits<char>::eof() || !input.eof()) {
            throw std::runtime_error("truncated frame or trailing bytes");
        }
        return body;
    }
    std::string body;
    std::array<char, 4096> buffer{};
    for (;;) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count = input.gcount();
        if (count > 0) {
            if (body.size() + static_cast<std::size_t>(count) > max_request_bytes) {
                throw std::runtime_error("request exceeds bound");
            }
            body.append(buffer.data(), static_cast<std::size_t>(count));
        }
        if (input.bad()) throw std::runtime_error("input read failed");
        if (input.eof()) break;
        if (!input) throw std::runtime_error("input read failed");
    }
    if (body.empty()) throw std::runtime_error("empty request");
    return body;
}

void write_result(std::ostream& output, const std::string& document, bool length_prefixed)
{
    if (document.size() > max_response_bytes) throw std::runtime_error("response exceeds bound");
    if (length_prefixed) {
        const std::uint32_t length = static_cast<std::uint32_t>(document.size());
        const std::array<char, 4> header{
            static_cast<char>(length >> 24), static_cast<char>(length >> 16),
            static_cast<char>(length >> 8), static_cast<char>(length)};
        output.write(header.data(), static_cast<std::streamsize>(header.size()));
        output.write(document.data(), static_cast<std::streamsize>(document.size()));
    } else {
        output << document << '\n';
    }
    output.flush();
    if (!output) throw std::runtime_error("output write failed");
}

} // namespace usk::command
