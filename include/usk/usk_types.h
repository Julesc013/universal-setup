// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_TYPES_H
#define USK_TYPES_H

#include <stdint.h>

#define USK_API_VERSION_MAJOR 1
#define USK_API_VERSION_MINOR 0

typedef uint64_t usk_size;
typedef int usk_bool;

#if defined(_WIN32)
#define USK_CALL __cdecl
#if defined(USK_BUILD_SHARED)
#define USK_API __declspec(dllexport)
#elif defined(USK_USE_SHARED)
#define USK_API __declspec(dllimport)
#else
#define USK_API
#endif
#else
#define USK_CALL
#if defined(__GNUC__) && defined(USK_BUILD_SHARED)
#define USK_API __attribute__((visibility("default")))
#else
#define USK_API
#endif
#endif

typedef struct usk_string_view {
    const char* data;
    usk_size size;
} usk_string_view;

#endif
