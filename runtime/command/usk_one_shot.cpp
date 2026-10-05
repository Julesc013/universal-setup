// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_one_shot.h"

#include "usk/usk_api.h"
#include "usk_json.h"
#include "usk_effect_dispatch.h"

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

bool lower_hex(const std::string& value, std::size_t length)
{
    return value.size() == length &&
        value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

// These are diagnostics from the authenticated service, not reconstructed
// native exceptions or a grant to retry. Preserve the service's effects status.
const char* publisher_operation_error_code(const Value& observed)
{
    if (!observed.contains("error_code")) return nullptr;
    const auto& code = observed.at("error_code").as_string();
    if (code == "operation_conflict") return "operation_conflict";
    if (code == "operation_cancelled") return "operation_cancelled";
    if (code == "lease_stale") return "lease_stale";
    if (code == "state_revision_stale") return "state_revision_stale";
    return nullptr;
}

Value publisher_operation_diagnostic(const Value& observed, const char* code)
{
    if (!code || !observed.contains("operation_inspection_ref")) return Value();
    const auto& reference = observed.at("operation_inspection_ref").as_string();
    const std::string prefix = "usk.operation-inspection.v1:";
    if (reference.compare(0, prefix.size(), prefix) != 0 ||
        !lower_hex(reference.substr(prefix.size()), 64))
        throw std::runtime_error("publisher operation inspection reference differs");
    return Value(Value::Object{
        {"schema", Value("usk.publisher_operation_diagnostic.v1")},
        {"error_code", Value(code)},
        {"inspection_reference", Value(reference)}});
}

bool sid_text(const std::string& value, bool service = false)
{
    if (value.size() < 7 || value.size() > 184 || value.compare(0, 4, "S-1-") != 0) return false;
    std::size_t begin = 4;
    unsigned parts = 0;
    while (begin < value.size()) {
        const auto end = value.find('-', begin);
        const auto count = (end == std::string::npos ? value.size() : end) - begin;
        if (count == 0 || (count > 1 && value[begin] == '0')) return false;
        const std::uint64_t maximum = parts == 0 ? 0xffffffffffffULL : 0xffffffffULL;
        std::uint64_t number = 0;
        for (std::size_t index = begin; index < begin + count; ++index) {
            const auto ch = value[index];
            if (ch < '0' || ch > '9' || number > (maximum - static_cast<unsigned>(ch - '0')) / 10)
                return false;
            number = number * 10 + static_cast<unsigned>(ch - '0');
        }
        if ((parts == 0 && number != 5) || (parts == 1 && number != (service ? 80u : 21u))) return false;
        ++parts;
        if (parts > 16) return false;
        if (end == std::string::npos) return service ? parts == 7 : parts == 6;
        begin = end + 1;
    }
    return false;
}

void require_capability_observation(const Value& value, const std::string& request_id)
{
    // This closed version reports observations, never execution authority or
    // qualification. A caller flag or a more optimistic transport response
    // cannot upgrade its independent record dimensions.
    if (value.as_object().size() != 20 ||
        value.at("schema").as_string() != "usk.publisher_capability.v1" ||
        value.at("request_id").as_string() != request_id ||
        value.at("provider_id").as_string() != "windows_nt_x64_local_ntfs_service_sid_noreplace_v1" ||
        value.at("implementation").as_string() != "partial" ||
        value.at("realization").as_string() != "restricted_service" ||
        value.at("availability").as_boolean() ||
        value.at("required_privilege").as_string() != "SeBackupPrivilege_and_disk_read" ||
        value.at("permission").as_string() != "registered_caller_observed" ||
        value.at("authority").as_string() != "not_granted_by_discovery" ||
        value.at("qualification").as_string() != "incomplete" ||
        value.at("qualification_scope").as_string() != "registered_target_observation" ||
        value.at("support").as_string() != "unsupported" ||
        value.at("recovery_ceiling").as_string() != "candidate_source_free_restart" ||
        value.at("power_loss_qualified").as_boolean() ||
        !value.at("revalidation_required_before_effects").as_boolean() ||
        value.at("execution_lease_held").as_boolean() ||
        value.at("service_state").as_unsigned() < 1 || value.at("service_state").as_unsigned() > 7 ||
        !value.at("effects").as_array().empty())
        throw std::runtime_error("publisher capability dimensions differ");
    const auto& platform = value.at("platform");
    if (platform.as_object().size() != 5 || platform.at("os_family").as_string() != "Windows NT" ||
        platform.at("native_arch").as_string() != "x64" || platform.at("process_arch").as_string() != "x64" ||
        platform.at("minimum_windows_build").as_unsigned() != 17763 ||
        platform.at("windows_build").as_unsigned() < 17763 || platform.at("windows_build").as_unsigned() > 0xffffffffULL)
        throw std::runtime_error("publisher capability platform differs");
    const auto& binding = value.at("binding");
    const auto& service = binding.at("service_name").as_string();
    const auto& service_sid = binding.at("service_sid").as_string();
    const auto& volume = binding.at("volume_guid_root").as_string();
    if (binding.as_object().size() != 8 || service.size() != 40 ||
        service.compare(0, 8, "USK_PUB_") != 0 || !lower_hex(service.substr(8), 32) ||
        !sid_text(service_sid, true) ||
        !sid_text(binding.at("caller_sid").as_string()) ||
        !lower_hex(binding.at("binary_sha256").as_string(), 64) ||
        !lower_hex(binding.at("registration_sha256").as_string(), 64) ||
        !lower_hex(binding.at("target_sha256").as_string(), 64) ||
        !lower_hex(binding.at("boundary_sha256").as_string(), 64) ||
        volume.size() != 49 || volume.compare(0, 11, "\\\\?\\Volume{") != 0 ||
        volume.compare(47, 2, "}\\") != 0)
        throw std::runtime_error("publisher capability binding differs");
    for (std::size_t index = 11; index < 47; ++index) {
        const auto ch = volume[index];
        const bool hyphen = index == 19 || index == 24 || index == 29 || index == 34;
        if (hyphen ? ch != '-' : std::string("0123456789abcdefABCDEF").find(ch) == std::string::npos)
            throw std::runtime_error("publisher capability volume identity differs");
    }
}

void require_service_capability_observation(const Value& response, const std::string& request_id, bool scoped_profile)
{
    if (response.as_object().size() != 8 ||
        response.at("schema").as_string() != "usk.publisher_service_capability_observation.v1" ||
        response.at("status").as_string() != "observed" ||
        response.at("request_id").as_string() != request_id)
        throw std::runtime_error("service capability response differs");
    const auto& value=response.at("capability_observation");
    const auto& effects=value.at("effects").as_array();
    const auto& platform=value.at("platform");
    bool qualified = false;
    if (scoped_profile) {
        const auto& bounds = value.at("qualification_bounds");
        const auto& sdk = platform.at("sdk_version").as_string();
        if (bounds.as_object().size() != 4 ||
            bounds.at("phase_schema").as_string() != "usk.publisher.lab_phase_evidence.v9" ||
            bounds.at("execution_schema").as_string() != "usk.publisher_execution_observation.v6" ||
            bounds.at("sdk_version").as_string() != "10.0.26100.0" ||
            bounds.at("qualified_windows_build").as_unsigned() != 20348 || sdk.size() > 32)
            throw std::runtime_error("scoped publisher qualification bounds differ");
        if (!sdk.empty()) {
            std::size_t separators = 0;
            bool component = false;
            for (const char ch : sdk) {
                if (ch == '.') {
                    if (!component) throw std::runtime_error("scoped publisher SDK differs");
                    ++separators;
                    component = false;
                } else {
                    if (ch < '0' || ch > '9') throw std::runtime_error("scoped publisher SDK differs");
                    component = true;
                }
            }
            if (!component || separators != 3) throw std::runtime_error("scoped publisher SDK differs");
        }
        qualified = platform.at("windows_build").as_unsigned() == 20348 && sdk == "10.0.26100.0";
    }
    if (value.as_object().size() != (scoped_profile ? 22u : 21u) ||
        value.at("schema").as_string() != (scoped_profile ? "usk.publisher_capability.v3" : "usk.publisher_capability.v2") ||
        value.at("request_id").as_string() != request_id ||
        value.at("provider_id").as_string() != "windows_nt_x64_local_ntfs_service_sid_noreplace_v1" ||
        value.at("implementation").as_string() != "partial" ||
        value.at("realization").as_string() != "restricted_service" || value.at("availability").as_boolean() != qualified ||
        value.at("required_privilege").as_string() != "none_for_registered_caller" ||
        value.at("permission").as_string() != "registered_caller_observed" ||
        value.at("authority").as_string() != "not_granted_by_discovery" ||
        value.at("qualification").as_string() != (qualified ? "qualified_for_scope" : "incomplete") ||
        value.at("qualification_scope").as_string() != (scoped_profile ?
            "registered_public_apply_v9_process_restart_replay_verify" : "service_admitted_target_observation") ||
        value.at("binding_provenance").as_string() != "retained_controller_admission_and_current_disk_identity" ||
        value.at("support").as_string() != (qualified ? "supported_for_scope" : "unsupported") ||
        value.at("recovery_ceiling").as_string() != (scoped_profile ? "source_free_process_restart_v9" : "candidate_source_free_restart") ||
        value.at("power_loss_qualified").as_boolean() ||
        !value.at("revalidation_required_before_effects").as_boolean() ||
        value.at("execution_lease_held").as_boolean() || value.at("service_state").as_unsigned() != 4 ||
        effects.size() != 2 || effects[0].as_string() != "service_start_may_occur" ||
        effects[1].as_string() != "controller_guard_held_during_observation")
        throw std::runtime_error("service capability dimensions differ");
    if (platform.as_object().size() != (scoped_profile ? 6u : 5u) || platform.at("os_family").as_string() != "Windows NT" ||
        platform.at("native_arch").as_string() != "x64" || platform.at("process_arch").as_string() != "x64" ||
        platform.at("minimum_windows_build").as_unsigned() != 17763 ||
        platform.at("windows_build").as_unsigned() < 17763 ||
        platform.at("windows_build").as_unsigned() > 0xffffffffULL)
        throw std::runtime_error("service capability platform differs");
    const auto& binding=value.at("binding");
    const auto& admitted=response.at("registered_admission");
    const auto& volume=binding.at("volume_guid_root").as_string();
    const auto& file_id=binding.at("root_file_id").as_string();
    const auto& serial=binding.at("volume_serial").as_string();
    const auto& service=binding.at("service_name").as_string();
    if (binding.as_object().size() != 10 || admitted.as_object().size() != 10 ||
        admitted.at("schema").as_string() != "usk.publisher_registered_admission_observation.v1" ||
        admitted.at("scope").as_string() != "held_registered_service_image_and_controller_target_admission" ||
        service.size() != 40 || service.compare(0,8,"USK_PUB_") != 0 || !lower_hex(service.substr(8),32) ||
        !sid_text(binding.at("service_sid").as_string(),true) ||
        !sid_text(binding.at("caller_sid").as_string()) ||
        binding.at("process_id").as_unsigned() == 0 || binding.at("process_id").as_unsigned() > 0xffffffffULL ||
        !lower_hex(binding.at("binary_sha256").as_string(),64) ||
        !lower_hex(binding.at("registration_sha256").as_string(),64) ||
        !lower_hex(binding.at("target_admitted_sha256").as_string(),64) ||
        file_id.size() != 49 || file_id[16] != ':' ||
        !lower_hex(file_id.substr(0,16),16) || !lower_hex(file_id.substr(17),32) ||
        serial.empty() || serial.size() > 20 || serial.find_first_not_of("0123456789") != std::string::npos ||
        (serial.size() > 1 && serial[0] == '0') ||
        std::stoull(serial) != std::stoull(file_id.substr(0,16),nullptr,16) ||
        volume.size() != 49 || volume.compare(0,11,"\\\\?\\Volume{") != 0 || volume.compare(47,2,"}\\") != 0)
        throw std::runtime_error("service capability binding differs");
    for (std::size_t index=11; index<47; ++index) {
        const auto ch=volume[index];
        const bool hyphen=index==19 || index==24 || index==29 || index==34;
        if (hyphen ? ch!='-' : std::string("0123456789abcdefABCDEF").find(ch)==std::string::npos)
            throw std::runtime_error("service capability volume identity differs");
    }
    for (const char* key : {"service_name","service_sid","process_id"})
        if (usk::json::canonical(binding.at(key)) != usk::json::canonical(response.at(key)) ||
            usk::json::canonical(binding.at(key)) != usk::json::canonical(admitted.at(key)))
            throw std::runtime_error("service capability worker differs from admission");
    const auto& target_volume=admitted.at("target_identity").at("volume_identity");
    if (binding.at("caller_sid").as_string() != admitted.at("configured_caller_sid").as_string() ||
        binding.at("binary_sha256").as_string() != admitted.at("publisher_image").at("sha256").as_string() ||
        binding.at("registration_sha256").as_string() != admitted.at("registration_sha256").as_string() ||
        binding.at("target_admitted_sha256").as_string() != admitted.at("target_admitted_sha256").as_string() ||
        volume != target_volume.at("volume_root").as_string() ||
        file_id != target_volume.at("root_file_id").as_string() ||
        serial != target_volume.at("volume_serial").as_string())
        throw std::runtime_error("service capability target differs from admission");
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

static OneShotResult run_publisher_request(const std::string& request_json,
    const CandidateTransport& transport, bool retain_observation)
{
    std::string request_id;
    std::string request;
    std::string response_field;
    std::string candidate_command;
    Value submitted;
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
        } else if (command == "publisher.inspect" && !retain_observation) {
            expected_schema = "usk.publisher_capability_request.v1";
        } else if (command == "publisher.observe") {
            expected_schema = input.at("payload").at("schema").as_string() == "usk.publisher_capability_request.v3" ?
                "usk.publisher_capability_request.v3" : "usk.publisher_capability_request.v2";
        } else {
            return failure(request_id, "command_unavailable");
        }
        const bool inspection = command == "publisher.inspect";
        if (input.at("dry_run").as_boolean() != inspection ||
            input.at("payload").type() != Value::Type::object ||
            input.at("payload").at("schema").as_string() != expected_schema)
            return failure(request_id, "invalid_request");
        submitted = input.at("payload");
        if ((inspection || command == "publisher.observe") && (submitted.as_object().size() != 2 ||
            submitted.at("request_id").as_string() != request_id))
            return failure(request_id, "invalid_request");
        request = usk::json::canonical(submitted);
    } catch (const std::exception&) {
        return failure(request_id, "invalid_request");
    }

    if (candidate_command == "publisher.inspect") {
        try {
            if (!transport) return failure(request_id, "transport_unavailable");
            usk::json::ParseLimits limits;
            limits.max_bytes = 16384;
            limits.max_string_bytes = 4096;
            const auto observation = usk::json::parse(transport(request), limits);
            require_capability_observation(observation, request_id);
            return candidate_outcome(request_id, "ok", observation, nullptr, 0);
        } catch (const std::exception&) {
            // Read-only discovery requested no target effects. An unavailable
            // observation must not become an available provider or unknown install.
            return failure(request_id, "publisher_capability_unavailable");
        }
    }

    if (candidate_command == "publisher.observe") {
        try {
            if (!transport) return failure(request_id,"transport_unavailable");
            const std::string raw=transport(request);
            usk::json::ParseLimits limits;
            limits.max_bytes=16384;
            limits.max_string_bytes=4096;
            const auto response=usk::json::parse(raw,limits);
            require_service_capability_observation(response,request_id,
                submitted.at("schema").as_string() == "usk.publisher_capability_request.v3");
            return candidate_outcome(request_id,"ok",
                retain_observation ? response : response.at("capability_observation"),nullptr,0);
        } catch (const usk::base::EffectRequestNotDispatched&) {
            // Startup or controller admission may already have occurred.
            return candidate_outcome(request_id,"unknown",Value(),"publisher_observation_unknown",5);
        } catch (const std::exception&) {
            return candidate_outcome(request_id,"unknown",Value(),"publisher_observation_unknown",5);
        }
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
                const bool direct_present = public_response->type() != Value::Type::null_value;
                const bool replay_present =
                    observed.at("recovery_installed_response").type() !=
                    Value::Type::null_value;
                if (direct_present == replay_present)
                    throw std::runtime_error("candidate apply completion is ambiguous");
                if (replay_present)
                    public_response = &observed.at("recovery_installed_response");
            }
            if (public_response->at("schema").as_string() !=
                    "usk.command_response.v1" ||
                public_response->at("status").as_string() != "ok")
                throw std::runtime_error("candidate public response differs");
            if (!retain_observation) {
                const auto& payload = public_response->at("payload");
                if (candidate_command == "installed.verify") {
                    if (payload.at("schema").as_string() != "usk.verification_report.v1" ||
                        payload.at("status").as_string() != "pass" ||
                        payload.at("install_id").as_string() != submitted.at("install_id").as_string() ||
                        payload.at("report_id").as_string() != submitted.at("report_id").as_string() ||
                        payload.at("verified_at").as_string() != submitted.at("verified_at").as_string() ||
                        payload.at("report_digest").as_string() != observed.at("bound_report_digest").as_string())
                        throw std::runtime_error("publisher verification binding differs");
                } else {
                    const std::string install_id = candidate_command == "install_local.apply" ?
                        submitted.at("plan_request").at("install_id").as_string() :
                        submitted.at("install_id").as_string();
                    if (payload.at("schema").as_string() != "usk.installed_state.v1" ||
                        payload.at("lifecycle_status").as_string() != "installed" ||
                        payload.at("install_id").as_string() != install_id ||
                        payload.at("transaction_id").as_string() != submitted.at("transaction_id").as_string() ||
                        (candidate_command == "install_local.apply" &&
                         payload.at("created_at").as_string() != submitted.at("applied_at").as_string()))
                        throw std::runtime_error("publisher installation binding differs");
                }
            }
            return candidate_outcome(request_id, "ok",
                retain_observation ? observed : *public_response, nullptr, 0);
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
            if (!retain_observation) {
                const auto& report = public_response.at("payload");
                if (report.at("install_id").as_string() != submitted.at("install_id").as_string() ||
                    report.at("report_id").as_string() != submitted.at("report_id").as_string() ||
                    report.at("verified_at").as_string() != submitted.at("verified_at").as_string())
                    throw std::runtime_error("publisher drift report binding differs");
            }
            return candidate_outcome(request_id, "ok",
                retain_observation ? observed : public_response, nullptr, 0);
        }
        if (status == "failed") {
            const auto code = publisher_operation_error_code(observed);
            const auto diagnostic = publisher_operation_diagnostic(observed, code);
            return candidate_outcome(request_id, "refused", retain_observation ? observed : diagnostic,
                code ? code : "publisher_failed", 4);
        }
        if (status == "recovery_required") {
            const auto code = publisher_operation_error_code(observed);
            const auto diagnostic = publisher_operation_diagnostic(observed, code);
            return candidate_outcome(request_id, "recovery_required", retain_observation ? observed : diagnostic,
                code ? code : "recovery_required", 5);
        }
    } catch (const usk::base::EffectRequestNotDispatched&) {
        return failure(request_id, "publisher_admission_refused");
    } catch (const std::exception&) {
        return candidate_outcome(request_id, "unknown", Value(),
            "publisher_outcome_unknown", 5);
    }
    return candidate_outcome(request_id, "unknown", Value(),
        "publisher_outcome_unknown", 5);
}

OneShotResult run_candidate_one_shot(const std::string& request_json,
    const CandidateTransport& transport)
{
    return run_publisher_request(request_json, transport, true);
}

OneShotResult run_publisher_one_shot(const std::string& request_json,
    const CandidateTransport& transport)
{
    return run_publisher_request(request_json, transport, false);
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
