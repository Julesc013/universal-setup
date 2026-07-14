// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USU_PLATFORM_IFACE_H
#define USU_PLATFORM_IFACE_H

#include "usu_platform_caps.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct usu_platform_iface_v1 {
    usu_size struct_size;
    void* user;
    int (*query_caps)(void* user, usu_platform_caps_v1* out_caps);
} usu_platform_iface_v1;

#ifdef __cplusplus
}
#endif

#endif
