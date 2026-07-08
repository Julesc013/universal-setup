#ifndef USK_ERROR_H
#define USK_ERROR_H

#include "usk_types.h"

typedef struct usk_error_v1 {
    usk_size struct_size;
    int code;
    usk_string_view message;
    usk_string_view detail;
} usk_error_v1;

#endif
