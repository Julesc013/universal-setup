#ifndef USK_ALLOCATOR_H
#define USK_ALLOCATOR_H

#include "usk_types.h"

typedef struct usk_allocator_v1 {
    usk_size struct_size;
    void* user;
    void* (*alloc)(void* user, usk_size size);
    void (*free)(void* user, void* ptr);
} usk_allocator_v1;

#endif
