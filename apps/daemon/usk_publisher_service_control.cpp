// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_registration.h"

int wmain(int argc, wchar_t** argv)
{
    return usk::platform::windows::publisher_service_control_main(argc, argv);
}
