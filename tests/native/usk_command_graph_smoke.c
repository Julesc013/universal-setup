#include "usk/usk_api.h"

#include <string.h>

static usk_string_view view_from_cstr(const char* text)
{
    usk_string_view view;
    view.data = text;
    view.size = (usk_size)strlen(text);
    return view;
}

static int contains(usk_string_view haystack, const char* needle)
{
    usk_size index;
    usk_size needle_size;

    if (haystack.data == 0 || needle == 0) {
        return 0;
    }

    needle_size = (usk_size)strlen(needle);
    if (needle_size == 0 || needle_size > haystack.size) {
        return 0;
    }

    for (index = 0; index + needle_size <= haystack.size; ++index) {
        if (memcmp(haystack.data + index, needle, (size_t)needle_size) == 0) {
            return 1;
        }
    }

    return 0;
}

static int run_command(
    usk_context* context,
    const char* command_name,
    int dry_run,
    const char* required_fragment
)
{
    usk_command_request_v1 request;
    usk_command_response_v1 response;
    int status;

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    response.struct_size = sizeof(response);
    request.struct_size = sizeof(request);
    request.command_name = view_from_cstr(command_name);
    request.json_payload = view_from_cstr("{}");
    request.dry_run = dry_run;

    status = usk_command_execute_v1(context, &request, &response);
    if (status != USK_STATUS_OK) {
        return 1;
    }
    if (response.status != USK_STATUS_OK) {
        return 2;
    }
    if (!contains(response.json_payload, "\"status\":\"ok\"")) {
        return 3;
    }
    if (!contains(response.json_payload, required_fragment)) {
        return 4;
    }

    return 0;
}

int main(void)
{
    usk_context* context = 0;
    usk_command_request_v1 request;
    usk_command_response_v1 response;
    int status;
    usk_config_v1 truncated_config;

    if (usk_context_create_v1(0, &context) != USK_STATUS_OK || context == 0) {
        return 10;
    }
    if (usk_abi_version_v1() != ((USK_API_VERSION_MAJOR << 16) | USK_API_VERSION_MINOR)) {
        return 11;
    }

    if (run_command(context, "command_graph.inspect", 1, "\"command\":\"install_local.plan\"") != 0) {
        return 20;
    }
    if (run_command(context, "policy.inspect", 1, "\"network_allowed\":false") != 0) {
        return 21;
    }
    if (run_command(context, "install_local.plan", 1, "\"schema\":\"usk.install_plan.v1\"") != 0) {
        return 22;
    }
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    request.struct_size = sizeof(request);
    response.struct_size = sizeof(response);
    request.command_name = view_from_cstr("verify.report");
    request.json_payload = view_from_cstr("{}");
    request.dry_run = 1;
    status = usk_command_execute_v1(context, &request, &response);
    if (status != USK_STATUS_ERROR || response.status != USK_STATUS_ERROR ||
        !contains(response.json_payload, "\"status\":\"not_implemented\"") ||
        !contains(response.json_payload, "\"code\":\"verification_not_implemented\"")) {
        return 23;
    }
    if (run_command(context, "uninstall.plan", 1, "\"operation\":\"uninstall\"") != 0) {
        return 24;
    }
    if (run_command(context, "audit.log", 1, "\"schema\":\"usk.audit_log.v1\"") != 0) {
        return 25;
    }
    if (run_command(context, "diagnostics.report", 1, "\"mutation_execution\",\"status\":\"not_implemented\"") != 0) {
        return 26;
    }

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    response.struct_size = sizeof(response);
    request.struct_size = sizeof(request);
    request.command_name = view_from_cstr("missing.command");
    request.json_payload = view_from_cstr("{}");
    request.dry_run = 1;
    status = usk_command_execute_v1(context, &request, &response);
    if (status != USK_STATUS_UNSUPPORTED_VERSION ||
        response.status != USK_STATUS_UNSUPPORTED_VERSION ||
        !contains(response.json_payload, "\"status\":\"unsupported\"")) {
        return 30;
    }

    memset(&response, 0, sizeof(response));
    response.struct_size = sizeof(response);
    status = usk_command_execute_v1(context, 0, &response);
    if (status != USK_STATUS_INVALID_ARGUMENT ||
        response.status != USK_STATUS_INVALID_ARGUMENT ||
        !contains(response.json_payload, "\"status\":\"invalid_argument\"")) {
        return 31;
    }

    memset(&response, 0, sizeof(response));
    response.struct_size = sizeof(response) - 1;
    status = usk_command_execute_v1(context, &request, &response);
    if (status != USK_STATUS_INVALID_ARGUMENT) {
        return 32;
    }

    usk_context_destroy_v1(context);

    memset(&truncated_config, 0, sizeof(truncated_config));
    truncated_config.struct_size = sizeof(truncated_config) - 1;
    context = 0;
    if (usk_context_create_v1(&truncated_config, &context) != USK_STATUS_INVALID_ARGUMENT || context != 0) {
        return 33;
    }
    return 0;
}
