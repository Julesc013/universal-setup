#include "usk/usk_api.h"
#include "usk_package_verify.h"

#include <stdlib.h>
#include <string.h>

#define USK_COMMAND_GRAPH_BUDGET_BYTES (64u * 1024u)

typedef enum usk_response_storage_kind {
    USK_RESPONSE_STORAGE_NONE = 0,
    USK_RESPONSE_STORAGE_CONTEXT_ALLOCATOR,
    USK_RESPONSE_STORAGE_PACKAGE_VERIFY
} usk_response_storage_kind;

struct usk_context {
    usk_allocator_v1 allocator;
    char* response_storage;
    usk_response_storage_kind response_storage_kind;
};

typedef struct usk_static_response {
    int status;
    const char* payload;
    const char* error_message;
} usk_static_response;

typedef struct usk_json_buffer {
    char* data;
    usk_size length;
    usk_size capacity;
} usk_json_buffer;

typedef struct usk_command_descriptor usk_command_descriptor;

typedef usk_static_response (*usk_command_handler)(
    usk_context* context,
    const usk_command_request_v1* request,
    const usk_command_descriptor* descriptor);

struct usk_command_descriptor {
    const char* command_name;
    const char* request_schema;
    const char* response_schema;
    const char* effects_json;
    const char* dry_run_behavior;
    const char* availability;
    const char* owner;
    const char* binding;
    int dry_run;
    int mutating;
    usk_command_handler handler;
    int response_status;
    const char* response_payload;
    const char* response_error_message;
};

static const char USK_POLICY_PAYLOAD[] =
    "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\",\"payload\":{\"schema\":\"usk.policy.v1\",\"policy_id\":\"usk.policy.local_only.v1\",\"mutation_scope\":\"staged_root_only\",\"network_allowed\":false,\"registry_allowed\":false,\"package_manager_allowed\":false,\"product_specific_installer_allowed\":false,\"rules\":[{\"rule_id\":\"no_network\",\"effect\":\"refuse\",\"message\":\"network access is not part of the minimal setup contract\"},{\"rule_id\":\"no_registry\",\"effect\":\"refuse\",\"message\":\"registry mutation is not part of the minimal setup contract\"},{\"rule_id\":\"no_package_manager\",\"effect\":\"refuse\",\"message\":\"package-manager mutation is not part of the minimal setup contract\"}]},\"error\":null}";
static const char USK_INSTALL_PLAN_PAYLOAD[] =
    "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\",\"payload\":{\"schema\":\"usk.install_plan.v1\",\"plan_id\":\"usk.plan.install_local.preview\",\"operation\":\"install_local\",\"dry_run\":true,\"product_id\":\"external.product\",\"target\":{\"root\":\"operator.required\",\"platform\":\"portable\"},\"ownership\":{\"kind\":\"staged\",\"may_mutate\":true,\"reason\":\"dry-run local plan only\"},\"steps\":[{\"step_id\":\"stage_root\",\"action\":\"create_dir\",\"path\":\"operator.required\",\"rollback_required\":true},{\"step_id\":\"write_state\",\"action\":\"write_state\",\"path\":\"operator.required/installed-state.json\",\"rollback_required\":true}],\"refusal_policy\":{\"refuse_network\":true,\"refuse_registry\":true,\"refuse_package_manager\":true,\"refuse_product_specific_installer\":true}},\"error\":null}";
static const char USK_VERIFY_REPORT_PAYLOAD[] =
    "{\"schema\":\"usk.command_response.v1\",\"status\":\"unavailable\",\"payload\":{\"schema\":\"usk.verify_report.v1\",\"report_id\":\"usk.verify.unavailable\",\"install_id\":null,\"status\":\"not_implemented\",\"checked_at\":\"not-run\",\"checks\":[]},\"error\":{\"code\":\"verification_not_implemented\",\"message\":\"installed-state verification is not implemented\"}}";
static const char USK_UNINSTALL_PLAN_PAYLOAD[] =
    "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\",\"payload\":{\"schema\":\"usk.install_plan.v1\",\"plan_id\":\"usk.plan.uninstall.preview\",\"operation\":\"uninstall\",\"dry_run\":true,\"product_id\":\"external.product\",\"target\":{\"root\":\"operator.required\",\"platform\":\"portable\"},\"ownership\":{\"kind\":\"managed\",\"may_mutate\":true,\"reason\":\"dry-run uninstall plan only\"},\"steps\":[{\"step_id\":\"remove_state\",\"action\":\"delete_file\",\"path\":\"operator.required/installed-state.json\",\"rollback_required\":true},{\"step_id\":\"remove_root\",\"action\":\"remove_dir\",\"path\":\"operator.required\",\"rollback_required\":true}],\"refusal_policy\":{\"refuse_network\":true,\"refuse_registry\":true,\"refuse_package_manager\":true,\"refuse_product_specific_installer\":true}},\"error\":null}";
static const char USK_AUDIT_LOG_PAYLOAD[] =
    "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\",\"payload\":{\"schema\":\"usk.audit_log.v1\",\"audit_log_id\":\"usk.audit.minimal\",\"events\":[{\"event_id\":\"usk.audit.command_graph\",\"created_at\":\"not-recorded\",\"operation\":\"audit\",\"status\":\"pass\",\"message\":\"authoritative setup command graph is available\"}]},\"error\":null}";
static const char USK_DIAGNOSTICS_PAYLOAD[] =
    "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\",\"payload\":{\"schema\":\"usk.diagnostic_report.v1\",\"report_id\":\"usk.diagnostic.minimal\",\"status\":\"ok\",\"checks\":[{\"id\":\"contract_spine\",\"status\":\"ok\"},{\"id\":\"descriptor_dispatch\",\"status\":\"ok\"},{\"id\":\"mutation_execution\",\"status\":\"not_implemented\"},{\"id\":\"network_access\",\"status\":\"forbidden\"}]},\"error\":null}";
static const char USK_PLANNED_COMMAND_PAYLOAD[] =
    "{\"schema\":\"usk.command_response.v1\",\"status\":\"unavailable\",\"payload\":null,\"error\":{\"code\":\"planned_command_unavailable\",\"message\":\"command is declared for M1 but has no mutation authority or implementation yet\"}}";
static const char USK_UNSUPPORTED_PAYLOAD[] =
    "{\"schema\":\"usk.command_response.v1\",\"status\":\"unsupported\",\"payload\":null,\"error\":{\"code\":\"unsupported_command\",\"message\":\"command is not declared by the Universal Setup descriptor registry\"}}";
static const char USK_INVALID_PAYLOAD[] =
    "{\"schema\":\"usk.command_response.v1\",\"status\":\"invalid_argument\",\"payload\":null,\"error\":{\"code\":\"invalid_argument\",\"message\":\"command request is invalid\"}}";
static const char USK_GRAPH_ERROR_PAYLOAD[] =
    "{\"schema\":\"usk.command_response.v1\",\"status\":\"error\",\"payload\":null,\"error\":{\"code\":\"graph_projection_failed\",\"message\":\"authoritative command graph projection failed within its allocation budget\"}}";

static usk_static_response usk_handle_command_graph(
    usk_context* context,
    const usk_command_request_v1* request,
    const usk_command_descriptor* descriptor);
static usk_static_response usk_handle_package_verify(
    usk_context* context,
    const usk_command_request_v1* request,
    const usk_command_descriptor* descriptor);
static usk_static_response usk_handle_static(
    usk_context* context,
    const usk_command_request_v1* request,
    const usk_command_descriptor* descriptor);

#define USK_DESCRIPTOR(name, request_schema, response_schema, effects, dry_run_behavior, availability, dry_run, mutating, handler, status, payload, message) \
    { name, request_schema, response_schema, effects, dry_run_behavior, availability, "universal-setup", "builtin", dry_run, mutating, handler, status, payload, message }

static const usk_command_descriptor USK_COMMANDS[] = {
    USK_DESCRIPTOR("command_graph.inspect", "usk.command_request.v1", "usk.command_response.v1", "[\"none\"]", "read_only", "available", 1, 0, usk_handle_command_graph, USK_STATUS_OK, 0, 0),
    USK_DESCRIPTOR("policy.inspect", "usk.command_request.v1", "usk.policy.v1", "[\"none\"]", "read_only", "available", 1, 0, usk_handle_static, USK_STATUS_OK, USK_POLICY_PAYLOAD, 0),
    USK_DESCRIPTOR("package.verify", "usk.package_verify_request.v1", "usk.package_verify_report.v1", "[\"source_read\"]", "read_only", "available", 1, 0, usk_handle_package_verify, USK_STATUS_OK, 0, 0),
    USK_DESCRIPTOR("package.audit", "usk.package_verify_request.v1", "usk.package_verify_report.v1", "[\"source_read\"]", "read_only", "available", 1, 0, usk_handle_package_verify, USK_STATUS_OK, 0, 0),
    USK_DESCRIPTOR("install_local.inspect", "usk.command_request.v1", "usk.install_inspection.v1", "[\"source_read\",\"target_read\"]", "read_only", "planned", 1, 0, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("install_local.plan", "usk.command_request.v1", "usk.install_plan.v1", "[\"source_read\",\"target_read\"]", "always_preview", "available", 1, 0, usk_handle_static, USK_STATUS_OK, USK_INSTALL_PLAN_PAYLOAD, 0),
    USK_DESCRIPTOR("install_local.apply", "usk.command_request.v1", "usk.operation_result.v1", "[\"owned_target_write\",\"state_write\",\"audit_write\"]", "reviewed_plan_required", "planned", 0, 1, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("installed.inspect", "usk.command_request.v1", "usk.installed_state.v1", "[\"state_read\"]", "read_only", "planned", 1, 0, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("installed.verify", "usk.command_request.v1", "usk.verify_report.v1", "[\"owned_target_read\",\"state_read\"]", "read_only", "planned", 1, 0, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("repair.plan", "usk.command_request.v1", "usk.repair_plan.v1", "[\"source_read\",\"owned_target_read\",\"state_read\"]", "always_preview", "planned", 1, 0, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("repair.apply", "usk.command_request.v1", "usk.repair_report.v1", "[\"owned_target_write\",\"state_write\",\"audit_write\"]", "reviewed_plan_required", "planned", 0, 1, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("move.plan", "usk.command_request.v1", "usk.move_plan.v1", "[\"owned_target_read\",\"state_read\",\"target_read\"]", "always_preview", "planned", 1, 0, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("move.apply", "usk.command_request.v1", "usk.move_report.v1", "[\"owned_target_write\",\"state_write\",\"audit_write\"]", "reviewed_plan_required", "planned", 0, 1, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("uninstall.plan", "usk.command_request.v1", "usk.install_plan.v1", "[\"owned_target_read\",\"state_read\"]", "always_preview", "available", 1, 0, usk_handle_static, USK_STATUS_OK, USK_UNINSTALL_PLAN_PAYLOAD, 0),
    USK_DESCRIPTOR("uninstall.apply", "usk.command_request.v1", "usk.uninstall_report.v1", "[\"owned_target_write\",\"state_write\",\"audit_write\"]", "reviewed_plan_required", "planned", 0, 1, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("recovery.inspect", "usk.command_request.v1", "usk.recovery_report.v1", "[\"journal_read\"]", "read_only", "planned", 1, 0, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("recovery.plan", "usk.command_request.v1", "usk.operation_plan.v1", "[\"journal_read\",\"owned_target_read\"]", "always_preview", "planned", 1, 0, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("recovery.apply", "usk.command_request.v1", "usk.recovery_report.v1", "[\"owned_target_write\",\"state_write\",\"audit_write\"]", "reviewed_plan_required", "planned", 0, 1, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("audit.list", "usk.command_request.v1", "usk.audit_log.v1", "[\"audit_read\"]", "read_only", "planned", 1, 0, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("audit.inspect", "usk.command_request.v1", "usk.audit_event.v1", "[\"audit_read\"]", "read_only", "planned", 1, 0, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("audit.export", "usk.command_request.v1", "usk.audit_log.v1", "[\"audit_read\"]", "read_only", "planned", 1, 0, usk_handle_static, USK_STATUS_ERROR, USK_PLANNED_COMMAND_PAYLOAD, "planned command is unavailable"),
    USK_DESCRIPTOR("verify.report", "usk.command_request.v1", "usk.verify_report.v1", "[\"none\"]", "read_only", "compatibility", 1, 0, usk_handle_static, USK_STATUS_ERROR, USK_VERIFY_REPORT_PAYLOAD, "installed-state verification is not implemented"),
    USK_DESCRIPTOR("audit.log", "usk.command_request.v1", "usk.audit_log.v1", "[\"none\"]", "read_only", "compatibility", 1, 0, usk_handle_static, USK_STATUS_OK, USK_AUDIT_LOG_PAYLOAD, 0),
    USK_DESCRIPTOR("diagnostics.report", "usk.command_request.v1", "usk.diagnostic_report.v1", "[\"none\"]", "read_only", "compatibility", 1, 0, usk_handle_static, USK_STATUS_OK, USK_DIAGNOSTICS_PAYLOAD, 0)
};

#define USK_COMMAND_COUNT ((usk_size)(sizeof(USK_COMMANDS) / sizeof(USK_COMMANDS[0])))

static int usk_string_equals(usk_string_view value, const char* expected)
{
    usk_size expected_size;
    if (value.data == 0 || expected == 0) {
        return 0;
    }
    expected_size = (usk_size)strlen(expected);
    return value.size == expected_size &&
        memcmp(value.data, expected, (size_t)expected_size) == 0;
}

static void* usk_default_alloc(void* user, usk_size size)
{
    (void)user;
    if (size > (usk_size)((size_t)-1)) {
        return 0;
    }
    return malloc((size_t)size);
}

static void usk_default_free(void* user, void* ptr)
{
    (void)user;
    free(ptr);
}

static void usk_release_response_storage(usk_context* context)
{
    if (context == 0 || context->response_storage == 0) {
        return;
    }
    if (context->response_storage_kind == USK_RESPONSE_STORAGE_PACKAGE_VERIFY) {
        usk_package_verify_command_free(context->response_storage);
    } else {
        context->allocator.free(context->allocator.user, context->response_storage);
    }
    context->response_storage = 0;
    context->response_storage_kind = USK_RESPONSE_STORAGE_NONE;
}

static void usk_set_response(
    usk_command_response_v1* response,
    int status,
    const char* payload,
    const char* error_message)
{
    memset(response, 0, sizeof(*response));
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

static int usk_json_append_char(usk_json_buffer* buffer, char value)
{
    if (buffer->length == (usk_size)((size_t)-1)) {
        return 0;
    }
    if (buffer->data != 0) {
        if (buffer->length + 1 >= buffer->capacity) {
            return 0;
        }
        buffer->data[buffer->length] = value;
        buffer->data[buffer->length + 1] = '\0';
    }
    ++buffer->length;
    return 1;
}

static int usk_json_append_raw(usk_json_buffer* buffer, const char* value)
{
    const char* current = value;
    if (value == 0) {
        return 0;
    }
    while (*current != '\0') {
        if (!usk_json_append_char(buffer, *current++)) {
            return 0;
        }
    }
    return 1;
}

static int usk_json_append_string(usk_json_buffer* buffer, const char* value)
{
    static const char hex[] = "0123456789abcdef";
    const unsigned char* current = (const unsigned char*)value;
    if (value == 0 || !usk_json_append_char(buffer, '"')) {
        return 0;
    }
    while (*current != '\0') {
        unsigned char byte = *current++;
        if (byte == '"' || byte == '\\') {
            if (!usk_json_append_char(buffer, '\\') ||
                !usk_json_append_char(buffer, (char)byte)) {
                return 0;
            }
        } else if (byte < 0x20) {
            if (!usk_json_append_raw(buffer, "\\u00") ||
                !usk_json_append_char(buffer, hex[(byte >> 4) & 0x0f]) ||
                !usk_json_append_char(buffer, hex[byte & 0x0f])) {
                return 0;
            }
        } else if (!usk_json_append_char(buffer, (char)byte)) {
            return 0;
        }
    }
    return usk_json_append_char(buffer, '"');
}

static int usk_json_append_field(
    usk_json_buffer* buffer,
    const char* name,
    const char* value)
{
    return usk_json_append_string(buffer, name) &&
        usk_json_append_char(buffer, ':') &&
        usk_json_append_string(buffer, value);
}

static int usk_descriptor_is_executable(const usk_command_descriptor* descriptor)
{
    return strcmp(descriptor->availability, "planned") != 0;
}

static int usk_json_append_descriptor(
    usk_json_buffer* buffer,
    const usk_command_descriptor* descriptor,
    int prepend_comma)
{
    return (!prepend_comma || usk_json_append_char(buffer, ',')) &&
        usk_json_append_char(buffer, '{') &&
        usk_json_append_field(buffer, "command", descriptor->command_name) &&
        usk_json_append_char(buffer, ',') &&
        usk_json_append_field(buffer, "request_schema", descriptor->request_schema) &&
        usk_json_append_char(buffer, ',') &&
        usk_json_append_field(buffer, "response_schema", descriptor->response_schema) &&
        usk_json_append_raw(buffer, descriptor->dry_run ? ",\"dry_run\":true," : ",\"dry_run\":false,") &&
        usk_json_append_field(buffer, "dry_run_behavior", descriptor->dry_run_behavior) &&
        usk_json_append_char(buffer, ',') &&
        usk_json_append_field(buffer, "availability", descriptor->availability) &&
        usk_json_append_char(buffer, ',') &&
        usk_json_append_field(buffer, "owner", descriptor->owner) &&
        usk_json_append_char(buffer, ',') &&
        usk_json_append_field(buffer, "binding", descriptor->binding) &&
        usk_json_append_raw(buffer, descriptor->mutating ? ",\"mutating\":true," : ",\"mutating\":false,") &&
        usk_json_append_raw(buffer, usk_descriptor_is_executable(descriptor) ? "\"executable\":true,\"effects\":" : "\"executable\":false,\"effects\":") &&
        usk_json_append_raw(buffer, descriptor->effects_json) &&
        usk_json_append_char(buffer, '}');
}

static int usk_project_command_graph(usk_json_buffer* buffer)
{
    usk_size index;
    if (!usk_json_append_raw(
            buffer,
            "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\","
            "\"payload\":{\"schema\":\"usk.command_graph.v1\",\"commands\":[")) {
        return 0;
    }
    for (index = 0; index < USK_COMMAND_COUNT; ++index) {
        if (!usk_json_append_descriptor(buffer, &USK_COMMANDS[index], index != 0)) {
            return 0;
        }
    }
    return usk_json_append_raw(buffer, "]},\"error\":null}");
}

static const usk_command_descriptor* usk_find_descriptor(usk_string_view command_name)
{
    usk_size index;
    for (index = 0; index < USK_COMMAND_COUNT; ++index) {
        if (usk_string_equals(command_name, USK_COMMANDS[index].command_name)) {
            return &USK_COMMANDS[index];
        }
    }
    return 0;
}

static usk_static_response usk_handle_command_graph(
    usk_context* context,
    const usk_command_request_v1* request,
    const usk_command_descriptor* descriptor)
{
    usk_json_buffer measure;
    usk_json_buffer output;
    usk_static_response result;
    char* graph;
    (void)request;
    (void)descriptor;

    memset(&measure, 0, sizeof(measure));
    result.status = USK_STATUS_ERROR;
    result.payload = USK_GRAPH_ERROR_PAYLOAD;
    result.error_message = "authoritative command graph projection failed";
    if (!usk_project_command_graph(&measure) ||
        measure.length >= (usk_size)USK_COMMAND_GRAPH_BUDGET_BYTES) {
        return result;
    }
    graph = (char*)context->allocator.alloc(context->allocator.user, measure.length + 1);
    if (graph == 0) {
        return result;
    }
    memset(&output, 0, sizeof(output));
    output.data = graph;
    output.capacity = measure.length + 1;
    graph[0] = '\0';
    if (!usk_project_command_graph(&output) || output.length != measure.length) {
        context->allocator.free(context->allocator.user, graph);
        return result;
    }
    context->response_storage = graph;
    context->response_storage_kind = USK_RESPONSE_STORAGE_CONTEXT_ALLOCATOR;
    result.status = USK_STATUS_OK;
    result.payload = graph;
    result.error_message = 0;
    return result;
}

static usk_static_response usk_handle_package_verify(
    usk_context* context,
    const usk_command_request_v1* request,
    const usk_command_descriptor* descriptor)
{
    usk_static_response result;
    int command_status = USK_STATUS_ERROR;
    context->response_storage = usk_package_verify_command_json(
        request->json_payload.data,
        (size_t)request->json_payload.size,
        strcmp(descriptor->command_name, "package.audit") == 0,
        &command_status);
    context->response_storage_kind = context->response_storage == 0
        ? USK_RESPONSE_STORAGE_NONE
        : USK_RESPONSE_STORAGE_PACKAGE_VERIFY;
    result.status = command_status;
    result.payload = context->response_storage;
    result.error_message = command_status == USK_STATUS_OK
        ? 0
        : "package verification request was refused";
    return result;
}

static usk_static_response usk_handle_static(
    usk_context* context,
    const usk_command_request_v1* request,
    const usk_command_descriptor* descriptor)
{
    usk_static_response result;
    (void)context;
    (void)request;
    result.status = descriptor->response_status;
    result.payload = descriptor->response_payload;
    result.error_message = descriptor->response_error_message;
    return result;
}

int usk_context_create_v1(const usk_config_v1* config, usk_context** out_context)
{
    usk_allocator_v1 allocator;
    usk_context* context;
    if (out_context == 0) {
        return USK_STATUS_INVALID_ARGUMENT;
    }
    *out_context = 0;
    memset(&allocator, 0, sizeof(allocator));
    allocator.struct_size = sizeof(allocator);
    allocator.alloc = usk_default_alloc;
    allocator.free = usk_default_free;

    if (config != 0) {
        if (config->struct_size < USK_CONFIG_V1_BASE_SIZE ||
            (config->struct_size > USK_CONFIG_V1_BASE_SIZE &&
             config->struct_size < (usk_size)sizeof(*config))) {
            return USK_STATUS_INVALID_ARGUMENT;
        }
        if (config->struct_size >= (usk_size)sizeof(*config) && config->allocator != 0) {
            if (config->allocator->struct_size < (usk_size)sizeof(*config->allocator) ||
                config->allocator->alloc == 0 || config->allocator->free == 0) {
                return USK_STATUS_INVALID_ARGUMENT;
            }
            allocator = *config->allocator;
        }
    }

    context = (usk_context*)allocator.alloc(allocator.user, sizeof(*context));
    if (context == 0) {
        return USK_STATUS_ERROR;
    }
    memset(context, 0, sizeof(*context));
    context->allocator = allocator;
    *out_context = context;
    return USK_STATUS_OK;
}

int usk_command_execute_v1(
    usk_context* context,
    const usk_command_request_v1* request,
    usk_command_response_v1* response)
{
    const usk_command_descriptor* descriptor;
    usk_static_response dispatched;
    if (response == 0 || response->struct_size < (usk_size)sizeof(*response)) {
        return USK_STATUS_INVALID_ARGUMENT;
    }
    if (request == 0 ||
        request->struct_size < (usk_size)sizeof(*request) ||
        request->command_name.data == 0 ||
        request->command_name.size == 0 ||
        context == 0) {
        usk_set_response(response, USK_STATUS_INVALID_ARGUMENT, USK_INVALID_PAYLOAD, "command request is invalid");
        return USK_STATUS_INVALID_ARGUMENT;
    }

    usk_release_response_storage(context);
    descriptor = usk_find_descriptor(request->command_name);
    if (descriptor == 0) {
        usk_set_response(
            response,
            USK_STATUS_UNSUPPORTED_VERSION,
            USK_UNSUPPORTED_PAYLOAD,
            "command is not declared by the Universal Setup descriptor registry");
        return USK_STATUS_UNSUPPORTED_VERSION;
    }
    dispatched = descriptor->handler(context, request, descriptor);
    usk_set_response(response, dispatched.status, dispatched.payload, dispatched.error_message);
    return dispatched.status;
}

uint32_t usk_abi_version_v1(void)
{
    return ((uint32_t)USK_API_VERSION_MAJOR << 16) | (uint32_t)USK_API_VERSION_MINOR;
}

void usk_context_destroy_v1(usk_context* context)
{
    usk_allocator_v1 allocator;
    if (context == 0) {
        return;
    }
    allocator = context->allocator;
    usk_release_response_storage(context);
    allocator.free(allocator.user, context);
}
