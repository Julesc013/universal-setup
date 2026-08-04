// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk/usk_api.h"
#include "usk/usk_transaction.h"

#include <stddef.h>

#define USK_ABI_ASSERT(name, expression) typedef char name[(expression) ? 1 : -1]

USK_ABI_ASSERT(usk_size_is_64_bits, sizeof(usk_size) == 8u);
USK_ABI_ASSERT(usk_bool_matches_int, sizeof(usk_bool) == sizeof(int));
USK_ABI_ASSERT(
    usk_config_base_size_matches_allocator,
    USK_CONFIG_V1_BASE_SIZE == (usk_size)offsetof(usk_config_v1, allocator));
USK_ABI_ASSERT(
    usk_config_m1_size_matches_acceptance_root,
    USK_CONFIG_V1_M1_SIZE ==
        (usk_size)offsetof(usk_config_v1, authorized_acceptance_root));
USK_ABI_ASSERT(
    usk_request_command_follows_size,
    offsetof(usk_command_request_v1, command_name) >
        offsetof(usk_command_request_v1, struct_size));
USK_ABI_ASSERT(
    usk_request_payload_follows_command,
    offsetof(usk_command_request_v1, json_payload) >
        offsetof(usk_command_request_v1, command_name));
USK_ABI_ASSERT(
    usk_request_dry_run_follows_payload,
    offsetof(usk_command_request_v1, dry_run) >
        offsetof(usk_command_request_v1, json_payload));
USK_ABI_ASSERT(
    usk_response_status_follows_size,
    offsetof(usk_command_response_v1, status) >
        offsetof(usk_command_response_v1, struct_size));
USK_ABI_ASSERT(
    usk_response_payload_follows_status,
    offsetof(usk_command_response_v1, json_payload) >
        offsetof(usk_command_response_v1, status));
USK_ABI_ASSERT(
    usk_response_error_follows_payload,
    offsetof(usk_command_response_v1, error) >
        offsetof(usk_command_response_v1, json_payload));
USK_ABI_ASSERT(
    usk_transaction_ref_has_required_fields,
    sizeof(usk_transaction_ref_v1) >= sizeof(usk_size) + 2u * sizeof(usk_string_view));

int main(void)
{
    return 0;
}
