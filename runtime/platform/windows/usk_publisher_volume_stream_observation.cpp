// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_volume_stream_observation.h"

#if defined(_WIN32)
#include <algorithm>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace usk::platform::windows {
PublisherVolumeObservation observe_local_ntfs_volume_handle(HANDLE handle) {
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("publisher volume observation requires a handle");
    }
    WCHAR label[MAX_PATH + 1]{};
    WCHAR filesystem[MAX_PATH + 1]{};
    DWORD serial = 0;
    DWORD maximum_component = 0;
    DWORD flags = 0;
    if (!GetVolumeInformationByHandleW(handle, label, MAX_PATH + 1, &serial,
            &maximum_component, &flags, filesystem, MAX_PATH + 1)) {
        throw std::runtime_error("publisher volume information is unavailable");
    }
    FILE_ID_INFO file_id{};
    if (!GetFileInformationByHandleEx(handle, FileIdInfo, &file_id, sizeof(file_id))) {
        throw std::runtime_error("publisher volume serial cannot be bound to the handle ID");
    }
    if (std::wstring(filesystem) != L"NTFS" || maximum_component < 255 ||
        static_cast<DWORD>(file_id.VolumeSerialNumber & 0xffffffffu) != serial) {
        throw std::runtime_error("publisher volume is outside the local NTFS profile");
    }
    FILE_REMOTE_PROTOCOL_INFO remote{};
    if (GetFileInformationByHandleEx(handle, FileRemoteProtocolInfo, &remote,
            sizeof(remote))) {
        throw std::runtime_error("publisher local NTFS profile refuses remote protocol facts");
    }
    const DWORD remote_error = GetLastError();
    if (remote_error != ERROR_INVALID_PARAMETER) {
        throw std::runtime_error("publisher local NTFS protocol query differed from the admitted error");
    }
    return {label, serial, file_id.VolumeSerialNumber, filesystem,
        maximum_component, flags, remote_error};
}

std::vector<PublisherStreamObservation> observe_publisher_handle_streams(HANDLE handle) {
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("publisher stream observation requires a handle");
    }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo,
            &attributes, sizeof(attributes))) {
        throw std::runtime_error("publisher stream type cannot be observed");
    }
    constexpr std::size_t maximum_bytes = 1024 * 1024;
    std::size_t capacity = 4096;
    std::vector<std::max_align_t> aligned;
    while (true) {
        aligned.assign((capacity + sizeof(std::max_align_t) - 1) /
            sizeof(std::max_align_t), {});
        if (GetFileInformationByHandleEx(handle, FileStreamInfo, aligned.data(),
                static_cast<DWORD>(capacity))) break;
        const DWORD error = GetLastError();
        if (error == ERROR_HANDLE_EOF &&
            (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) return {};
        if ((error != ERROR_MORE_DATA && error != ERROR_INSUFFICIENT_BUFFER) ||
            capacity >= maximum_bytes) {
            throw std::runtime_error("publisher stream enumeration failed or exceeded its byte budget; Win32 " +
                std::to_string(error));
        }
        capacity = std::min(capacity * 2, maximum_bytes);
    }
    const auto* data = reinterpret_cast<const unsigned char*>(aligned.data());
    std::vector<PublisherStreamObservation> streams;
    std::size_t offset = 0;
    while (true) {
        if (capacity - offset < offsetof(FILE_STREAM_INFO, StreamName)) {
            throw std::runtime_error("publisher stream entry is truncated");
        }
        const auto* info = reinterpret_cast<const FILE_STREAM_INFO*>(data + offset);
        const std::size_t entry_size = info->NextEntryOffset == 0 ?
            capacity - offset : info->NextEntryOffset;
        if (entry_size < offsetof(FILE_STREAM_INFO, StreamName) ||
            entry_size > capacity - offset ||
            info->StreamNameLength % sizeof(WCHAR) != 0 ||
            info->StreamNameLength > entry_size - offsetof(FILE_STREAM_INFO, StreamName) ||
            info->StreamSize.QuadPart < 0 || info->StreamAllocationSize.QuadPart < 0) {
            throw std::runtime_error("publisher stream entry is malformed");
        }
        const std::wstring name(info->StreamName,
            info->StreamNameLength / sizeof(WCHAR));
        if (name.empty() || std::any_of(streams.begin(), streams.end(),
                [&](const PublisherStreamObservation& prior) { return prior.name == name; })) {
            throw std::runtime_error("publisher stream names are empty or repeated");
        }
        streams.push_back({name, info->StreamSize.QuadPart,
            info->StreamAllocationSize.QuadPart});
        if (info->NextEntryOffset == 0) break;
        if (info->NextEntryOffset % 8 != 0 ||
            info->NextEntryOffset > capacity - offset) {
            throw std::runtime_error("publisher stream linkage is malformed");
        }
        offset += info->NextEntryOffset;
    }
    return streams;
}

void require_publisher_stream_shape(HANDLE handle) {
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!handle || handle == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandleEx(handle, FileAttributeTagInfo,
            &attributes, sizeof(attributes))) {
        throw std::runtime_error("publisher stream profile cannot read object type");
    }
    require_publisher_stream_shape(observe_publisher_handle_streams(handle),
        (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
}

void require_publisher_stream_shape(
    const std::vector<PublisherStreamObservation>& streams, bool directory) {
    if (directory) {
        if (!streams.empty()) {
            throw std::runtime_error("publisher directory has a data stream");
        }
    } else if (streams.size() != 1 || streams[0].name != L"::$DATA") {
        throw std::runtime_error("publisher file requires exactly one unnamed data stream");
    }
}
} // namespace usk::platform::windows
#endif
