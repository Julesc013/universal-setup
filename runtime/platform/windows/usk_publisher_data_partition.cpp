// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_data_partition.h"
#if defined(_WIN32)
#include <limits>
#include <stdexcept>

namespace usk::platform::windows {
namespace {
constexpr GUID basic_data{0xebd0a0a2, 0xb9e5, 0x4433,
    {0x87,0xc0,0x68,0xb6,0xb7,0x26,0x99,0xc7}};
constexpr GUID microsoft_reserved{0xe3c9e316, 0x0b5c, 0x4db8,
    {0x81,0x7d,0xf9,0x2d,0xf0,0x02,0x15,0xae}};
LONGLONG range_end(LONGLONG offset, LONGLONG length) {
    if (offset <= 0 || length <= 0 ||
        length > (std::numeric_limits<LONGLONG>::max)() - offset)
        throw std::runtime_error("target partition range is invalid");
    return offset + length;
}
}

const PARTITION_INFORMATION_EX& require_publisher_data_partition(
    DWORD style, const PARTITION_INFORMATION_EX* entries, DWORD count,
    const DISK_EXTENT& extent) {
    if ((style != PARTITION_STYLE_GPT && style != PARTITION_STYLE_MBR) ||
        !entries || !count || count > 128)
        throw std::runtime_error("target disk layout is unsupported");
    const auto extent_end = range_end(extent.StartingOffset.QuadPart,
        extent.ExtentLength.QuadPart);
    const PARTITION_INFORMATION_EX* selected = nullptr;
    const PARTITION_INFORMATION_EX* reserved = nullptr;
    LONGLONG first_data = (std::numeric_limits<LONGLONG>::max)();
    for (DWORD index = 0; index < count; ++index) {
        const auto& part = entries[index];
        if (part.PartitionLength.QuadPart == 0) continue;
        const auto end = range_end(part.StartingOffset.QuadPart,
            part.PartitionLength.QuadPart);
        if (static_cast<DWORD>(part.PartitionStyle) != style || !part.PartitionNumber)
            throw std::runtime_error("target partition identity is inconsistent");
        bool data = false;
        if (style == PARTITION_STYLE_GPT) {
            if (part.Gpt.Attributes != 0)
                throw std::runtime_error("target disk contains unsupported partition attributes");
            data = IsEqualGUID(part.Gpt.PartitionType, basic_data) != FALSE;
            if (!data) {
                // Windows GPT data disks carry an MSR. It is not a mounted
                // payload or an EFI/system partition. Admit only the known,
                // bounded, non-overlapping metadata role, never as the target.
                if (!IsEqualGUID(part.Gpt.PartitionType, microsoft_reserved) ||
                    reserved || part.PartitionLength.QuadPart > 128LL * 1024 * 1024)
                    throw std::runtime_error("target disk contains system or unclassified partition roles");
                reserved = &part;
            }
        } else {
            if (part.Mbr.BootIndicator || part.Mbr.PartitionType != PARTITION_IFS)
                throw std::runtime_error("target disk contains system or unclassified partition roles");
            data = true;
        }
        if (data && part.StartingOffset.QuadPart < first_data)
            first_data = part.StartingOffset.QuadPart;
        for (DWORD previous = 0; previous < index; ++previous) {
            const auto& other = entries[previous];
            if (other.PartitionLength.QuadPart == 0) continue;
            const auto other_end = range_end(other.StartingOffset.QuadPart,
                other.PartitionLength.QuadPart);
            if (part.PartitionNumber == other.PartitionNumber ||
                (part.StartingOffset.QuadPart < other_end && other.StartingOffset.QuadPart < end))
                throw std::runtime_error("target partition layout is ambiguous");
        }
        if (part.StartingOffset.QuadPart == extent.StartingOffset.QuadPart && end == extent_end) {
            if (!data || selected)
                throw std::runtime_error("target extent is not an ordinary data partition");
            selected = &part;
        }
    }
    if (!selected || (reserved && range_end(reserved->StartingOffset.QuadPart,
            reserved->PartitionLength.QuadPart) > first_data))
        throw std::runtime_error("target data partition or preceding MSR is invalid");
    return *selected;
}
}
#endif
