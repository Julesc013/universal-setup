#ifndef USK_ARCHIVE_INSPECT_H
#define USK_ARCHIVE_INSPECT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char* usk_archive_inspect_command_json(
    const char* request_json,
    size_t request_size,
    int* out_command_status);

void usk_archive_inspect_command_free(char* value);

#ifdef __cplusplus
}
#endif

#endif
