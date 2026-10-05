// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_data_partition.h"
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

namespace {
constexpr GUID data_type{0xebd0a0a2, 0xb9e5, 0x4433,
    {0x87,0xc0,0x68,0xb6,0xb7,0x26,0x99,0xc7}};
constexpr GUID msr_type{0xe3c9e316, 0x0b5c, 0x4db8,
    {0x81,0x7d,0xf9,0x2d,0xf0,0x02,0x15,0xae}};
constexpr GUID efi_type{0xc12a7328, 0xf81f, 0x11d2,
    {0xba,0x4b,0x00,0xa0,0xc9,0x3e,0xc9,0x3b}};
constexpr GUID recovery_type{0xde94bba4, 0x06d1, 0x4d40,
    {0xa1,0x6a,0xbf,0xd5,0x01,0x79,0xd6,0xac}};
constexpr LONGLONG mib = 1024 * 1024;
PARTITION_INFORMATION_EX gpt(DWORD number, LONGLONG offset, LONGLONG length, GUID type) {
    PARTITION_INFORMATION_EX result{};
    result.PartitionStyle = PARTITION_STYLE_GPT;
    result.PartitionNumber = number;
    result.StartingOffset.QuadPart = offset;
    result.PartitionLength.QuadPart = length;
    result.Gpt.PartitionType = type;
    return result;
}
void check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
void refuses(const std::vector<PARTITION_INFORMATION_EX>& parts, const DISK_EXTENT& extent,
    PARTITION_STYLE style = PARTITION_STYLE_GPT) {
    bool rejected = false;
    try {
        (void)usk::platform::windows::require_publisher_data_partition(style,
            parts.data(), static_cast<DWORD>(parts.size()), extent);
    } catch (const std::runtime_error&) { rejected = true; }
    check(rejected, "unsafe or inconsistent partition layout was admitted");
}
}

int main() {
    try {
        DISK_EXTENT extent{};
        extent.StartingOffset.QuadPart = 17 * mib;
        extent.ExtentLength.QuadPart = 494 * mib;
        const std::vector<PARTITION_INFORMATION_EX> normal{
            gpt(1, mib, 16 * mib, msr_type),
            gpt(2, extent.StartingOffset.QuadPart, extent.ExtentLength.QuadPart, data_type)};
        const auto& selected = usk::platform::windows::require_publisher_data_partition(
            PARTITION_STYLE_GPT, normal.data(), static_cast<DWORD>(normal.size()), extent);
        check(&selected == &normal[1], "standard Windows GPT data partition was not selected");
        auto model = normal;
        model.erase(model.begin());
        check(usk::platform::windows::require_publisher_data_partition(PARTITION_STYLE_GPT,
            model.data(), static_cast<DWORD>(model.size()), extent).PartitionNumber == 2,
            "ordinary GPT data-only layout was refused");
        for (const GUID type : {efi_type, recovery_type, GUID{}}) {
            model = normal;
            model[0].Gpt.PartitionType = type;
            refuses(model, extent);
        }
        model = normal;
        model[0].Gpt.Attributes = 1;
        refuses(model, extent);
        model = normal;
        model[1].Gpt.Attributes = 1;
        refuses(model, extent);
        model = normal;
        model[0].PartitionLength.QuadPart = 129 * mib;
        refuses(model, extent);
        model = normal;
        model.push_back(gpt(3, 511 * mib, mib, msr_type));
        refuses(model, extent);
        model = normal;
        model[0].StartingOffset.QuadPart = 511 * mib;
        refuses(model, extent);
        model = normal;
        model[0].PartitionLength.QuadPart += 1;
        refuses(model, extent);
        model = normal;
        model[0].PartitionNumber = 2;
        refuses(model, extent);
        model = normal;
        model[0].PartitionStyle = PARTITION_STYLE_MBR;
        refuses(model, extent);
        DISK_EXTENT msr_extent{};
        msr_extent.StartingOffset = normal[0].StartingOffset;
        msr_extent.ExtentLength = normal[0].PartitionLength;
        refuses(normal, msr_extent);
        auto wrong_extent = extent;
        --wrong_extent.ExtentLength.QuadPart;
        refuses(normal, wrong_extent);
        model = normal;
        model[1].StartingOffset.QuadPart = (std::numeric_limits<LONGLONG>::max)();
        refuses(model, extent);
        model = normal;
        model[1].PartitionNumber = 0;
        refuses(model, extent);
        model = {normal[1]};
        model[0].PartitionStyle = PARTITION_STYLE_MBR;
        model[0].Mbr = {};
        model[0].Mbr.PartitionType = PARTITION_IFS;
        check(usk::platform::windows::require_publisher_data_partition(PARTITION_STYLE_MBR,
            model.data(), static_cast<DWORD>(model.size()), extent).PartitionNumber == 2,
            "ordinary MBR data partition was refused");
        model[0].Mbr.BootIndicator = TRUE;
        refuses(model, extent, PARTITION_STYLE_MBR);
        model[0].Mbr.BootIndicator = FALSE;
        model[0].Mbr.PartitionType = 0xef;
        refuses(model, extent, PARTITION_STYLE_MBR);
        refuses({}, extent);
        refuses(normal, extent, PARTITION_STYLE_RAW);
        std::cout << "Windows publisher data partition classification PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
