// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_VERIFY_H
#define USK_VERIFY_H

#include "usk_result.h"

typedef struct usk_verify_request_v1 {
    usk_size struct_size;
    const char* install_id;
} usk_verify_request_v1;

#endif
