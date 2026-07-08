#ifndef USU_REPORT_H
#define USU_REPORT_H

#include "usu_abi.h"

typedef struct usu_report_v1 {
    usu_size struct_size;
    int status;
    const char* json_payload;
} usu_report_v1;

#endif
