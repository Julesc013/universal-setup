// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_CLIENT_H
#define USK_PUBLISHER_CLIENT_H
#include "usk_api.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Additive opt-in client configuration. The endpoint is copied at creation;
 * it does not confer service, target, caller or publication authority.
 * Existing usk_config_v1 layouts, entry points and response lifetime remain.
 * Recovery commands in this explicit publisher context use the versioned
 * native recovery_report.v2 / recovery_plan.v2 documents advertised by its
 * command graph. Ordinary local contexts retain their v1 recovery documents.
 * A native maintenance plan currently offers finalize only when its actual
 * original interrupted post-commit state qualifies; rollback is not aliased
 * to forward recovery and unsupported states are refused.
 */
typedef struct usk_publisher_client_config_v1 {
    usk_size struct_size;
    usk_string_view service_name;
} usk_publisher_client_config_v1;

USK_API int USK_CALL usk_context_create_publisher_v1(
    const usk_config_v1* local_config,
    const usk_publisher_client_config_v1* publisher_config,
    usk_context** out_context);

#ifdef __cplusplus
}
#endif
#endif
