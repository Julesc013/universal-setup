// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk/usk_publisher_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* This consumer uses only public C headers and the chosen public Core target. */
static usk_string_view view(const char* value) {
    usk_string_view result;
    result.data = value;
    result.size = (usk_size)strlen(value);
    return result;
}
int main(int argc, char** argv) {
    const size_t limit = 1024u * 1024u;
    FILE* stream;
    char* bytes;
    size_t size;
    int status;
    usk_context* context = NULL;
    usk_publisher_client_config_v1 publisher;
    usk_command_request_v1 request;
    usk_command_response_v1 response;
    if (argc != 4) return 2;
    stream = fopen(argv[3], "rb");
    if (!stream) return 2;
    bytes = (char*)malloc(limit + 1u);
    if (!bytes) { fclose(stream); return 2; }
    size = fread(bytes, 1u, limit + 1u, stream);
    if (ferror(stream) || !size || size > limit) {
        fclose(stream); free(bytes); return 2;
    }
    if (fclose(stream) != 0) { free(bytes); return 2; }
    memset(&publisher, 0, sizeof(publisher));
    publisher.struct_size = sizeof(publisher);
    publisher.service_name = view(argv[1]);
    status = usk_context_create_publisher_v1(NULL, &publisher, &context);
    if (status != USK_STATUS_OK) { free(bytes); return 2; }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.command_name = view(argv[2]);
    request.dry_run = strcmp(argv[2], "install_local.plan") == 0;
    request.json_payload.data = bytes;
    request.json_payload.size = (usk_size)size;
    memset(&response, 0, sizeof(response));
    response.struct_size = sizeof(response);
    status = usk_command_execute_v1(context, &request, &response);
    if (!response.json_payload.data || response.json_payload.size > 4u * 1024u * 1024u ||
        fwrite(response.json_payload.data, 1u, (size_t)response.json_payload.size, stdout) !=
            (size_t)response.json_payload.size || fflush(stdout) != 0) status = USK_STATUS_ERROR;
    usk_context_destroy_v1(context);
    free(bytes);
    return status == USK_STATUS_OK ? 0 : 1;
}
