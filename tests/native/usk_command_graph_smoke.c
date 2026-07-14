// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk/usk_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct test_allocator_state {
    int allocation_count;
    int free_count;
    int fail_at_allocation;
} test_allocator_state;

typedef struct legacy_usk_config_v1 {
    usk_size struct_size;
    const char* state_root;
} legacy_usk_config_v1;

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

static int count_occurrences(usk_string_view haystack, const char* needle)
{
    usk_size index;
    usk_size needle_size = (usk_size)strlen(needle);
    int count = 0;
    if (haystack.data == 0 || needle_size == 0 || needle_size > haystack.size) {
        return 0;
    }
    for (index = 0; index + needle_size <= haystack.size; ++index) {
        if (memcmp(haystack.data + index, needle, (size_t)needle_size) == 0) {
            ++count;
        }
    }
    return count;
}

static void* test_alloc(void* user, usk_size size)
{
    test_allocator_state* state = (test_allocator_state*)user;
    ++state->allocation_count;
    if (state->fail_at_allocation == state->allocation_count) {
        return 0;
    }
    return malloc((size_t)size);
}

static void test_free(void* user, void* ptr)
{
    test_allocator_state* state = (test_allocator_state*)user;
    ++state->free_count;
    free(ptr);
}

static int execute_status(
    usk_context* context,
    const char* command_name,
    usk_command_response_v1* response)
{
    usk_command_request_v1 request;
    memset(&request, 0, sizeof(request));
    memset(response, 0, sizeof(*response));
    request.struct_size = sizeof(request);
    request.command_name = view_from_cstr(command_name);
    request.json_payload = view_from_cstr("{}");
    request.dry_run = 1;
    response->struct_size = sizeof(*response);
    return usk_command_execute_v1(context, &request, response);
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
    static const char* expected_commands[] = {
        "command_graph.inspect",
        "policy.inspect",
        "package.verify",
        "package.audit",
        "install_local.inspect",
        "install_local.plan",
        "install_local.apply",
        "installed.inspect",
        "installed.verify",
        "repair.plan",
        "repair.apply",
        "move.plan",
        "move.apply",
        "uninstall.plan",
        "uninstall.apply",
        "recovery.inspect",
        "recovery.plan",
        "live_evidence.capture",
        "recovery.apply",
        "audit.list",
        "audit.inspect",
        "audit.export",
        "verify.report",
        "audit.log",
        "diagnostics.report"
    };
    usk_context* context = 0;
    usk_command_request_v1 request;
    usk_command_response_v1 response;
    usk_allocator_v1 allocator;
    usk_config_v1 config;
    int status;
    usk_size index;
    usk_config_v1 truncated_config;
    legacy_usk_config_v1 legacy_config;
    test_allocator_state allocator_state;
    char* graph_copy;
    usk_size graph_size;

    if (usk_context_create_v1(0, &context) != USK_STATUS_OK || context == 0) {
        return 10;
    }
    if (usk_abi_version_v1() != ((USK_API_VERSION_MAJOR << 16) | USK_API_VERSION_MINOR)) {
        return 11;
    }

    status = execute_status(context, "command_graph.inspect", &response);
    if (status != USK_STATUS_OK || response.status != USK_STATUS_OK ||
        response.json_payload.size == 0 || response.json_payload.size >= 64u * 1024u ||
        !contains(response.json_payload, "\"availability\":\"planned\"") ||
        !contains(response.json_payload, "\"mutating\":true") ||
        !contains(response.json_payload, "\"executable\":false")) {
        return 12;
    }
    for (index = 0; index < (usk_size)(sizeof(expected_commands) / sizeof(expected_commands[0])); ++index) {
        char marker[96];
        int marker_size = snprintf(marker, sizeof(marker), "\"command\":\"%s\"", expected_commands[index]);
        if (marker_size <= 0 || marker_size >= (int)sizeof(marker) ||
            count_occurrences(response.json_payload, marker) != 1) {
            return 13;
        }
    }
    graph_size = response.json_payload.size;
    graph_copy = (char*)malloc((size_t)graph_size + 1);
    if (graph_copy == 0) {
        return 14;
    }
    memcpy(graph_copy, response.json_payload.data, (size_t)graph_size);
    graph_copy[graph_size] = '\0';
    if (!contains(response.json_payload, "\"command\":\"move.apply\"")) {
        free(graph_copy);
        return 15;
    }
    status = execute_status(context, "command_graph.inspect", &response);
    if (status != USK_STATUS_OK || response.json_payload.size != graph_size ||
        memcmp(response.json_payload.data, graph_copy, (size_t)graph_size) != 0) {
        free(graph_copy);
        return 16;
    }
    free(graph_copy);

    for (index = 0; index < (usk_size)(sizeof(expected_commands) / sizeof(expected_commands[0])); ++index) {
        status = execute_status(context, expected_commands[index], &response);
        if (status == USK_STATUS_UNSUPPORTED_VERSION ||
            response.status == USK_STATUS_UNSUPPORTED_VERSION) {
            return 17;
        }
    }
    status = execute_status(context, "repair.apply", &response);
    if (status != USK_STATUS_INVALID_ARGUMENT ||
        !contains(response.json_payload, "\"code\":\"invalid_argument\"")) {
        return 18;
    }

    if (run_command(context, "command_graph.inspect", 1, "\"command\":\"install_local.plan\"") != 0) {
        return 20;
    }
    if (run_command(context, "command_graph.inspect", 1, "\"command\":\"package.verify\"") != 0 ||
        run_command(context, "command_graph.inspect", 1, "\"command\":\"package.audit\"") != 0) {
        return 34;
    }
    if (run_command(context, "policy.inspect", 1, "\"network_allowed\":false") != 0) {
        return 21;
    }
    status = execute_status(context, "install_local.plan", &response);
    if (status != USK_STATUS_ERROR ||
        !contains(response.json_payload, "\"code\":\"live_target_acceptance_required\"")) {
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
        !contains(response.json_payload, "\"code\":\"verification_not_implemented\"")) {
        return 23;
    }
    status = execute_status(context, "uninstall.plan", &response);
    if (status != USK_STATUS_ERROR ||
        !contains(response.json_payload, "\"code\":\"live_target_acceptance_required\"")) {
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

    memset(&legacy_config, 0, sizeof(legacy_config));
    legacy_config.struct_size = sizeof(legacy_config);
    if (legacy_config.struct_size != USK_CONFIG_V1_BASE_SIZE ||
        usk_context_create_v1((const usk_config_v1*)&legacy_config, &context) != USK_STATUS_OK ||
        context == 0) {
        return 35;
    }
    usk_context_destroy_v1(context);

    memset(&truncated_config, 0, sizeof(truncated_config));
    truncated_config.struct_size = sizeof(truncated_config) - 1;
    context = 0;
    if (usk_context_create_v1(&truncated_config, &context) != USK_STATUS_INVALID_ARGUMENT || context != 0) {
        return 33;
    }

    memset(&allocator, 0, sizeof(allocator));
    memset(&config, 0, sizeof(config));
    memset(&allocator_state, 0, sizeof(allocator_state));
    allocator.struct_size = sizeof(allocator);
    allocator.user = &allocator_state;
    allocator.alloc = test_alloc;
    allocator.free = test_free;
    config.struct_size = sizeof(config);
    config.allocator = &allocator;

    allocator_state.fail_at_allocation = 1;
    if (usk_context_create_v1(&config, &context) != USK_STATUS_ERROR || context != 0 ||
        allocator_state.allocation_count != 1 || allocator_state.free_count != 0) {
        return 36;
    }

    memset(&allocator_state, 0, sizeof(allocator_state));
    allocator_state.fail_at_allocation = 2;
    if (usk_context_create_v1(&config, &context) != USK_STATUS_OK || context == 0) {
        return 37;
    }
    status = execute_status(context, "command_graph.inspect", &response);
    if (status != USK_STATUS_ERROR || response.status != USK_STATUS_ERROR ||
        !contains(response.json_payload, "\"code\":\"graph_projection_failed\"") ||
        allocator_state.allocation_count != 2) {
        return 38;
    }
    usk_context_destroy_v1(context);
    if (allocator_state.free_count != 1) {
        return 39;
    }

    memset(&allocator_state, 0, sizeof(allocator_state));
    if (usk_context_create_v1(&config, &context) != USK_STATUS_OK || context == 0) {
        return 40;
    }
    if (execute_status(context, "command_graph.inspect", &response) != USK_STATUS_OK ||
        allocator_state.allocation_count != 2 || allocator_state.free_count != 0) {
        return 41;
    }
    if (execute_status(context, "policy.inspect", &response) != USK_STATUS_OK ||
        allocator_state.free_count != 1) {
        return 42;
    }
    usk_context_destroy_v1(context);
    if (allocator_state.free_count != 2) {
        return 43;
    }
    return 0;
}
