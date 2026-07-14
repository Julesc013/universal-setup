// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_MANIFEST_H
#define USK_MANIFEST_H

#include "usk_result.h"

typedef struct usk_manifest_ref_v1 {
    usk_size struct_size;
    const char* schema_id;
    const char* json_payload;
} usk_manifest_ref_v1;

#endif
