// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_AUDIT_H
#define USK_AUDIT_H

#include "usk_result.h"

typedef struct usk_audit_event_v1 {
    usk_size struct_size;
    const char* event_type;
    const char* json_payload;
} usk_audit_event_v1;

#endif
