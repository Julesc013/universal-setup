// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_CLIENT_BRIDGE_H
#define USK_PUBLISHER_CLIENT_BRIDGE_H
#include <stddef.h>
#if defined(__cplusplus)
#define USK_CLIENT_INTERNAL_NOEXCEPT noexcept
extern "C" {
#else
#define USK_CLIENT_INTERNAL_NOEXCEPT
#endif
void* usk_publisher_client_create_internal(const char* service_name, size_t size)
    USK_CLIENT_INTERNAL_NOEXCEPT;
void usk_publisher_client_destroy_internal(void* client) USK_CLIENT_INTERNAL_NOEXCEPT;
void usk_publisher_client_clear_internal(void* client) USK_CLIENT_INTERNAL_NOEXCEPT;
const char* usk_publisher_client_execute_internal(void* client,
    const char* command, const char* request, size_t size, int* out_status) USK_CLIENT_INTERNAL_NOEXCEPT;
#if defined(__cplusplus)
}
#endif
#undef USK_CLIENT_INTERNAL_NOEXCEPT
#endif
