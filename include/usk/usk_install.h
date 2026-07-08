#ifndef USK_INSTALL_H
#define USK_INSTALL_H

#include "usk_result.h"

typedef struct usk_install_request_v1 {
    usk_size struct_size;
    const char* install_id;
    const char* source_uri;
    int dry_run;
} usk_install_request_v1;

#endif
