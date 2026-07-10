#include "usk/usk_api.h"

#include <stdlib.h>
#include <string.h>

struct usk_context {
    char reserved;
};

typedef struct usk_static_response {
    int status;
    const char* payload;
    const char* error_message;
} usk_static_response;

static int usk_string_equals(usk_string_view value, const char* expected)
{
    usk_size index;
    usk_size expected_size;

    if (value.data == 0 || expected == 0) {
        return 0;
    }

    expected_size = (usk_size)strlen(expected);
    if (value.size != expected_size) {
        return 0;
    }

    for (index = 0; index < expected_size; ++index) {
        if (value.data[index] != expected[index]) {
            return 0;
        }
    }

    return 1;
}

static void usk_set_response(
    usk_command_response_v1* response,
    int status,
    const char* payload,
    const char* error_message
)
{
    response->status = 0;
    response->json_payload.data = 0;
    response->json_payload.size = 0;
    memset(&response->error, 0, sizeof(response->error));
    response->struct_size = sizeof(*response);
    response->status = status;

    if (payload != 0) {
        response->json_payload.data = payload;
        response->json_payload.size = (usk_size)strlen(payload);
    }

    response->error.struct_size = sizeof(response->error);
    response->error.code = status;
    if (error_message != 0) {
        response->error.message.data = error_message;
        response->error.message.size = (usk_size)strlen(error_message);
    }
}

static usk_static_response usk_dispatch_command(const usk_command_request_v1* request)
{
    static const char command_graph_payload[] =
        "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\",\"payload\":{\"schema\":\"usk.command_graph.v1\",\"commands\":[{\"command\":\"command_graph.inspect\",\"request_schema\":\"usk.command_request.v1\",\"response_schema\":\"usk.command_response.v1\",\"dry_run\":true},{\"command\":\"policy.inspect\",\"request_schema\":\"usk.command_request.v1\",\"response_schema\":\"usk.command_response.v1\",\"dry_run\":true},{\"command\":\"install_local.plan\",\"request_schema\":\"usk.command_request.v1\",\"response_schema\":\"usk.command_response.v1\",\"dry_run\":true},{\"command\":\"verify.report\",\"request_schema\":\"usk.command_request.v1\",\"response_schema\":\"usk.command_response.v1\",\"dry_run\":true},{\"command\":\"uninstall.plan\",\"request_schema\":\"usk.command_request.v1\",\"response_schema\":\"usk.command_response.v1\",\"dry_run\":true},{\"command\":\"audit.log\",\"request_schema\":\"usk.command_request.v1\",\"response_schema\":\"usk.command_response.v1\",\"dry_run\":true},{\"command\":\"diagnostics.report\",\"request_schema\":\"usk.command_request.v1\",\"response_schema\":\"usk.command_response.v1\",\"dry_run\":true}]},\"error\":null}";
    static const char policy_payload[] =
        "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\",\"payload\":{\"schema\":\"usk.policy.v1\",\"policy_id\":\"usk.policy.local_only.v1\",\"mutation_scope\":\"staged_root_only\",\"network_allowed\":false,\"registry_allowed\":false,\"package_manager_allowed\":false,\"product_specific_installer_allowed\":false,\"rules\":[{\"rule_id\":\"no_network\",\"effect\":\"refuse\",\"message\":\"network access is not part of the minimal setup contract\"},{\"rule_id\":\"no_registry\",\"effect\":\"refuse\",\"message\":\"registry mutation is not part of the minimal setup contract\"},{\"rule_id\":\"no_package_manager\",\"effect\":\"refuse\",\"message\":\"package-manager mutation is not part of the minimal setup contract\"}]},\"error\":null}";
    static const char install_plan_payload[] =
        "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\",\"payload\":{\"schema\":\"usk.install_plan.v1\",\"plan_id\":\"usk.plan.install_local.preview\",\"operation\":\"install_local\",\"dry_run\":true,\"product_id\":\"external.product\",\"target\":{\"root\":\"operator.required\",\"platform\":\"portable\"},\"ownership\":{\"kind\":\"staged\",\"may_mutate\":true,\"reason\":\"dry-run local plan only\"},\"steps\":[{\"step_id\":\"stage_root\",\"action\":\"create_dir\",\"path\":\"operator.required\",\"rollback_required\":true},{\"step_id\":\"write_state\",\"action\":\"write_state\",\"path\":\"operator.required/installed-state.json\",\"rollback_required\":true}],\"refusal_policy\":{\"refuse_network\":true,\"refuse_registry\":true,\"refuse_package_manager\":true,\"refuse_product_specific_installer\":true}},\"error\":null}";
    static const char verify_report_payload[] =
        "{\"schema\":\"usk.command_response.v1\",\"status\":\"unavailable\",\"payload\":{\"schema\":\"usk.verify_report.v1\",\"report_id\":\"usk.verify.unavailable\",\"install_id\":null,\"status\":\"not_implemented\",\"checked_at\":\"not-run\",\"checks\":[]},\"error\":{\"code\":\"verification_not_implemented\",\"message\":\"package verification is not implemented\"}}";
    static const char verify_report_message[] = "package verification is not implemented";
    static const char uninstall_plan_payload[] =
        "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\",\"payload\":{\"schema\":\"usk.install_plan.v1\",\"plan_id\":\"usk.plan.uninstall.preview\",\"operation\":\"uninstall\",\"dry_run\":true,\"product_id\":\"external.product\",\"target\":{\"root\":\"operator.required\",\"platform\":\"portable\"},\"ownership\":{\"kind\":\"managed\",\"may_mutate\":true,\"reason\":\"dry-run uninstall plan only\"},\"steps\":[{\"step_id\":\"remove_state\",\"action\":\"delete_file\",\"path\":\"operator.required/installed-state.json\",\"rollback_required\":true},{\"step_id\":\"remove_root\",\"action\":\"remove_dir\",\"path\":\"operator.required\",\"rollback_required\":true}],\"refusal_policy\":{\"refuse_network\":true,\"refuse_registry\":true,\"refuse_package_manager\":true,\"refuse_product_specific_installer\":true}},\"error\":null}";
    static const char audit_log_payload[] =
        "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\",\"payload\":{\"schema\":\"usk.audit_log.v1\",\"audit_log_id\":\"usk.audit.minimal\",\"events\":[{\"event_id\":\"usk.audit.command_graph\",\"created_at\":\"not-recorded\",\"operation\":\"audit\",\"status\":\"pass\",\"message\":\"minimal setup command graph is available\"}]},\"error\":null}";
    static const char diagnostics_payload[] =
        "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\",\"payload\":{\"schema\":\"usk.diagnostic_report.v1\",\"report_id\":\"usk.diagnostic.minimal\",\"status\":\"ok\",\"checks\":[{\"id\":\"contract_spine\",\"status\":\"ok\"},{\"id\":\"mutation_execution\",\"status\":\"not_implemented\"},{\"id\":\"network_access\",\"status\":\"forbidden\"}]},\"error\":null}";
    static const char unsupported_payload[] =
        "{\"schema\":\"usk.command_response.v1\",\"status\":\"unsupported\",\"payload\":null,\"error\":{\"code\":\"unsupported_command\",\"message\":\"command is not implemented by the minimal universal setup graph\"}}";
    static const char unsupported_message[] =
        "command is not implemented by the minimal universal setup graph";
    usk_static_response result;

    result.status = USK_STATUS_OK;
    result.error_message = 0;

    if (usk_string_equals(request->command_name, "command_graph.inspect")) {
        result.payload = command_graph_payload;
        return result;
    }
    if (usk_string_equals(request->command_name, "policy.inspect")) {
        result.payload = policy_payload;
        return result;
    }
    if (usk_string_equals(request->command_name, "install_local.plan")) {
        result.payload = install_plan_payload;
        return result;
    }
    if (usk_string_equals(request->command_name, "verify.report")) {
        result.status = USK_STATUS_ERROR;
        result.payload = verify_report_payload;
        result.error_message = verify_report_message;
        return result;
    }
    if (usk_string_equals(request->command_name, "uninstall.plan")) {
        result.payload = uninstall_plan_payload;
        return result;
    }
    if (usk_string_equals(request->command_name, "audit.log")) {
        result.payload = audit_log_payload;
        return result;
    }
    if (usk_string_equals(request->command_name, "diagnostics.report")) {
        result.payload = diagnostics_payload;
        return result;
    }

    result.status = USK_STATUS_UNSUPPORTED_VERSION;
    result.payload = unsupported_payload;
    result.error_message = unsupported_message;
    return result;
}

int usk_context_create_v1(
    const usk_config_v1* config,
    usk_context** out_context
)
{
    usk_context* context;

    if (out_context == 0) {
        return USK_STATUS_INVALID_ARGUMENT;
    }
    if (config != 0 && config->struct_size < (usk_size)sizeof(*config)) {
        *out_context = 0;
        return USK_STATUS_INVALID_ARGUMENT;
    }

    context = (usk_context*)malloc(sizeof(*context));
    if (context == 0) {
        *out_context = 0;
        return USK_STATUS_ERROR;
    }

    memset(context, 0, sizeof(*context));
    *out_context = context;
    return USK_STATUS_OK;
}

int usk_command_execute_v1(
    usk_context* context,
    const usk_command_request_v1* request,
    usk_command_response_v1* response
)
{
    static const char invalid_payload[] =
        "{\"schema\":\"usk.command_response.v1\",\"status\":\"invalid_argument\",\"payload\":null,\"error\":{\"code\":\"invalid_argument\",\"message\":\"command request is invalid\"}}";
    static const char invalid_message[] = "command request is invalid";
    usk_static_response dispatched;

    (void)context;

    if (response == 0 || response->struct_size < (usk_size)sizeof(*response)) {
        return USK_STATUS_INVALID_ARGUMENT;
    }

    if (request == 0 ||
        request->struct_size < (usk_size)sizeof(*request) ||
        request->command_name.data == 0 ||
        request->command_name.size == 0) {
        usk_set_response(response, USK_STATUS_INVALID_ARGUMENT, invalid_payload, invalid_message);
        return USK_STATUS_INVALID_ARGUMENT;
    }

    dispatched = usk_dispatch_command(request);
    usk_set_response(response, dispatched.status, dispatched.payload, dispatched.error_message);
    return dispatched.status;
}

uint32_t usk_abi_version_v1(void)
{
    return ((uint32_t)USK_API_VERSION_MAJOR << 16) | (uint32_t)USK_API_VERSION_MINOR;
}

void usk_context_destroy_v1(usk_context* context)
{
    free(context);
}
