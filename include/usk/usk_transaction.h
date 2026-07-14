// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_TRANSACTION_H
#define USK_TRANSACTION_H

#include "usk_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct usk_transaction_ref_v1 {
    usk_size struct_size;
    usk_string_view transaction_id;
    usk_string_view plan_id;
} usk_transaction_ref_v1;

#ifdef __cplusplus
}
#endif

#endif
