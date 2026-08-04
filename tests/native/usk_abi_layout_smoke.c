// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk/usk_api.h"
#include "usk/usk_transaction.h"

#include <stddef.h>

int main(void)
{
    if (sizeof(usk_size) != 8u || sizeof(usk_bool) != sizeof(int)) {
        return 1;
    }
    if (USK_CONFIG_V1_BASE_SIZE != (usk_size)offsetof(usk_config_v1, allocator) ||
        USK_CONFIG_V1_M1_SIZE !=
            (usk_size)offsetof(usk_config_v1, authorized_acceptance_root)) {
        return 2;
    }
    if (offsetof(usk_command_request_v1, command_name) <=
            offsetof(usk_command_request_v1, struct_size) ||
        offsetof(usk_command_request_v1, json_payload) <=
            offsetof(usk_command_request_v1, command_name) ||
        offsetof(usk_command_request_v1, dry_run) <=
            offsetof(usk_command_request_v1, json_payload)) {
        return 3;
    }
    if (offsetof(usk_command_response_v1, status) <=
            offsetof(usk_command_response_v1, struct_size) ||
        offsetof(usk_command_response_v1, json_payload) <=
            offsetof(usk_command_response_v1, status) ||
        offsetof(usk_command_response_v1, error) <=
            offsetof(usk_command_response_v1, json_payload)) {
        return 4;
    }
    if (sizeof(usk_transaction_ref_v1) <
        sizeof(usk_size) + 2u * sizeof(usk_string_view)) {
        return 5;
    }
    return 0;
}
