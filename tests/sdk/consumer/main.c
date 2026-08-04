// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk/usk_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(USK_SDK_CONTRACTS_VALIDATED)
#error "SDK contract fixtures must be validated at configure time"
#endif

static usk_string_view usk_view(const char* value)
{
    usk_string_view result;
    result.data = value;
    result.size = value == NULL ? 0u : (usk_size)strlen(value);
    return result;
}

static int file_contains(const char* path, const char* expected)
{
    FILE* stream;
    long length;
    char* content;
    int found;
    stream = fopen(path, "rb");
    if (stream == NULL || fseek(stream, 0, SEEK_END) != 0) {
        if (stream != NULL) {
            fclose(stream);
        }
        return 0;
    }
    length = ftell(stream);
    if (length < 0 || fseek(stream, 0, SEEK_SET) != 0) {
        fclose(stream);
        return 0;
    }
    content = (char*)malloc((size_t)length + 1u);
    if (content == NULL) {
        fclose(stream);
        return 0;
    }
    if (fread(content, 1u, (size_t)length, stream) != (size_t)length) {
        free(content);
        fclose(stream);
        return 0;
    }
    content[length] = '\0';
    found = strstr(content, expected) != NULL;
    free(content);
    fclose(stream);
    return found;
}

static int view_contains(usk_string_view view, const char* expected)
{
    const size_t expected_size = strlen(expected);
    usk_size index;
    if (view.data == NULL || expected_size == 0u ||
        view.size < (usk_size)expected_size) {
        return 0;
    }
    for (index = 0; index + (usk_size)expected_size <= view.size; ++index) {
        if (memcmp(view.data + index, expected, expected_size) == 0) {
            return 1;
        }
    }
    return 0;
}

static int execute_read_only(
    usk_context* context,
    const char* command,
    usk_command_response_v1* response)
{
    usk_command_request_v1 request;
    memset(&request, 0, sizeof(request));
    memset(response, 0, sizeof(*response));
    request.struct_size = sizeof(request);
    request.command_name = usk_view(command);
    request.json_payload = usk_view("{}");
    request.dry_run = 1;
    response->struct_size = sizeof(*response);
    return usk_command_execute_v1(context, &request, response);
}

int main(int argc, char** argv)
{
    usk_context* context = NULL;
    usk_command_response_v1 response;

    if (argc != 3 ||
        !file_contains(argv[1], "\"schema\": \"usk.product_package.v1\"") ||
        !file_contains(argv[1], "\"kind\": \"local_package\"") ||
        !file_contains(argv[2], "\"schema\": \"usk.setup_recipe.v1\"") ||
        !file_contains(argv[2], "\"rollback_disposition\": \"required\"")) {
        return 10;
    }
    if (usk_abi_version_v1() !=
        (((uint32_t)USK_API_VERSION_MAJOR << 16) | (uint32_t)USK_API_VERSION_MINOR)) {
        return 11;
    }
    if (usk_context_create_v1(NULL, &context) != USK_STATUS_OK || context == NULL) {
        return 12;
    }
    if (execute_read_only(context, "policy.inspect", &response) != USK_STATUS_OK ||
        !view_contains(response.json_payload, "\"network_allowed\":false") ||
        !view_contains(response.json_payload, "\"installer_execution_allowed\":false")) {
        usk_context_destroy_v1(context);
        return 13;
    }
    if (execute_read_only(context, "command_graph.inspect", &response) != USK_STATUS_OK ||
        !view_contains(response.json_payload, "\"command\":\"install_local.plan\"") ||
        !view_contains(response.json_payload, "\"dry_run\":true") ||
        !view_contains(response.json_payload, "\"mutating\":false")) {
        usk_context_destroy_v1(context);
        return 14;
    }
    usk_context_destroy_v1(context);

    printf("{\"abi\":\"%u.%u\",\"local_source\":\"valid\","
           "\"no_mutation\":\"validated\",\"package\":\"valid\","
           "\"recipe\":\"valid\"}\n",
           (unsigned int)USK_API_VERSION_MAJOR,
           (unsigned int)USK_API_VERSION_MINOR);
    return 0;
}
