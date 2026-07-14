// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USU_PLATFORM_CAPS_H
#define USU_PLATFORM_CAPS_H

#include "usu_abi.h"

typedef struct usu_platform_caps_v1 {
    usu_size struct_size;
    int supports_atomic_replace;
    int supports_file_locks;
    int supports_symlinks;
} usu_platform_caps_v1;

#endif
