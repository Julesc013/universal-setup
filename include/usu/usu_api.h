#ifndef USU_API_H
#define USU_API_H

#include "usu_execute.h"
#include "usu_platform_iface.h"
#include "usu_report.h"

#ifdef __cplusplus
extern "C" {
#endif

int usu_execute_setup_command_v1(
    const char* command_name,
    const char* json_payload,
    const usu_execute_options_v1* options,
    usu_report_v1* out_report
);

#ifdef __cplusplus
}
#endif

#endif
