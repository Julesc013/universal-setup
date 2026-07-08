#ifndef USU_CALLBACKS_H
#define USU_CALLBACKS_H

#include "usu_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*usu_log_callback_v1)(void* user, int level, const char* message);

typedef struct usu_callbacks_v1 {
    usu_size struct_size;
    void* user;
    usu_log_callback_v1 log;
} usu_callbacks_v1;

#ifdef __cplusplus
}
#endif

#endif
