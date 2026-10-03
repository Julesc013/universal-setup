// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_DATA_PARTITION_H
#define USK_PUBLISHER_DATA_PARTITION_H
#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>

namespace usk::platform::windows {
// Classify an already bounded kernel layout. This grants no device or volume
// authority; locality, NTFS, OS-volume exclusion and exclusive admission remain
// separate checks. Only ordinary data and one preceding GPT MSR are supported.
const PARTITION_INFORMATION_EX& require_publisher_data_partition(
    DWORD style, const PARTITION_INFORMATION_EX* entries, DWORD count,
    const DISK_EXTENT& extent);
}
#endif
#endif
