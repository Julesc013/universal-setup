#ifndef USK_TYPES_H
#define USK_TYPES_H

#define USK_API_VERSION_MAJOR 1
#define USK_API_VERSION_MINOR 0

typedef unsigned long usk_size;
typedef int usk_bool;

typedef struct usk_string_view {
    const char* data;
    usk_size size;
} usk_string_view;

#endif
