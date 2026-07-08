#ifndef USU_EXECUTE_H
#define USU_EXECUTE_H

#include "usu_callbacks.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct usu_execute_options_v1 {
    usu_size struct_size;
    const usu_callbacks_v1* callbacks;
    int dry_run;
} usu_execute_options_v1;

#ifdef __cplusplus
}
#endif

#endif
