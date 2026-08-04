// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk/usk_allocator.h"
#include "usk/usk_api.h"
#include "usk/usk_audit.h"
#include "usk/usk_command.h"
#include "usk/usk_context.h"
#include "usk/usk_error.h"
#include "usk/usk_install.h"
#include "usk/usk_manifest.h"
#include "usk/usk_result.h"
#include "usk/usk_transaction.h"
#include "usk/usk_types.h"
#include "usk/usk_verify.h"

int main()
{
    return USK_API_VERSION_MAJOR == 1 && USK_API_VERSION_MINOR == 0 ? 0 : 1;
}
