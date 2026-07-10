#ifndef USK_COMMAND_H
#define USK_COMMAND_H

#include "usk_error.h"
#include "usk_types.h"

typedef struct usk_command_request_v1 {
    usk_size struct_size;
    usk_string_view command_name;
    usk_string_view json_payload;
    usk_bool dry_run;
} usk_command_request_v1;

typedef struct usk_command_response_v1 {
    usk_size struct_size;
    int status;
    usk_string_view json_payload;
    usk_error_v1 error;
} usk_command_response_v1;

/*
 * Response string views are borrowed. They remain valid until the next
 * command call on the same context or until that context is destroyed.
 * Callers set response.struct_size before every call. No disposal is required.
 */

#endif
