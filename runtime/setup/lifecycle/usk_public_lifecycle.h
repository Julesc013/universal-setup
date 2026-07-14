// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLIC_LIFECYCLE_H
#define USK_PUBLIC_LIFECYCLE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char* usk_public_lifecycle_command_json(
    const char* command_name,
    const char* request_json,
    size_t request_size,
    const char* state_root,
    const char* authorized_acceptance_root,
    const char* target_policy_activation,
    int* out_command_status);

void usk_public_lifecycle_command_free(char* value);

#ifdef __cplusplus
}
#endif

#endif
