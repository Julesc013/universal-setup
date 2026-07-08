#include "usk/usk_api.h"

#include <stdlib.h>
#include <string.h>

struct usk_context {
    char reserved;
};

int usk_context_create_v1(
    const usk_config_v1* config,
    usk_context** out_context
)
{
    usk_context* context;

    (void)config;

    if (out_context == 0) {
        return USK_STATUS_INVALID_ARGUMENT;
    }

    context = (usk_context*)malloc(sizeof(*context));
    if (context == 0) {
        *out_context = 0;
        return USK_STATUS_ERROR;
    }

    memset(context, 0, sizeof(*context));
    *out_context = context;
    return USK_STATUS_OK;
}

void usk_context_destroy_v1(usk_context* context)
{
    free(context);
}
