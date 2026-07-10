#ifndef USK_API_H
#define USK_API_H

#include "usk_command.h"
#include "usk_result.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct usk_context usk_context;

typedef struct usk_config_v1 {
    usk_size struct_size;
    const char* state_root;
} usk_config_v1;

USK_API int USK_CALL usk_context_create_v1(
    const usk_config_v1* config,
    usk_context** out_context
);

USK_API int USK_CALL usk_command_execute_v1(
    usk_context* context,
    const usk_command_request_v1* request,
    usk_command_response_v1* response
);

USK_API uint32_t USK_CALL usk_abi_version_v1(void);

USK_API void USK_CALL usk_context_destroy_v1(usk_context* context);

#ifdef __cplusplus
}
#endif

#endif
