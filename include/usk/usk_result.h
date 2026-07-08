#ifndef USK_RESULT_H
#define USK_RESULT_H

#include "usk_types.h"

typedef enum usk_status {
    USK_STATUS_OK = 0,
    USK_STATUS_ERROR = 1,
    USK_STATUS_INVALID_ARGUMENT = 2,
    USK_STATUS_UNSUPPORTED_VERSION = 3
} usk_status;

typedef struct usk_result_v1 {
    usk_size struct_size;
    int status;
    const char* message;
} usk_result_v1;

#endif
