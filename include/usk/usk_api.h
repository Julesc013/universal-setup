#ifndef USK_API_H
#define USK_API_H

#include "usk_result.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct usk_context usk_context;

typedef struct usk_config_v1 {
    usk_size struct_size;
    const char* state_root;
} usk_config_v1;

int usk_context_create_v1(
    const usk_config_v1* config,
    usk_context** out_context
);

void usk_context_destroy_v1(usk_context* context);

#ifdef __cplusplus
}
#endif

#endif
