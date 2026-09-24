// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_volume_stream_observation.h"

#include <windows.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using usk::platform::windows::observe_local_ntfs_volume_handle;
using usk::platform::windows::observe_publisher_handle_streams;
using usk::platform::windows::require_publisher_stream_shape;

namespace {
class Handle {
public:
    explicit Handle(HANDLE value) : value_(value) {
        if (!value_ || value_ == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("fixture handle open failed");
        }
    }
    ~Handle() { CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

bool has_stream(const std::vector<usk::platform::windows::PublisherStreamObservation>& streams,
    const std::wstring& name, std::int64_t size) {
    for (const auto& stream : streams) {
        if (stream.name == name && stream.size == size) return true;
    }
    return false;
}

void check_shape_rejected(HANDLE handle, const char* message) {
    try {
        require_publisher_stream_shape(handle);
    } catch (const std::runtime_error&) {
        return;
    }
    throw std::runtime_error(message);
}
} // namespace

int main() {
    try {
        const auto root = fs::temp_directory_path() /
            ("usk-publisher-stream-" + std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count()));
        check(fs::create_directory(root), "fixture root already exists");
        const auto file = root / "payload.bin";
        {
            Handle created(CreateFileW(file.c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL, nullptr));
            DWORD written = 0;
            check(WriteFile(created.get(), "payload", 7, &written, nullptr) != FALSE &&
                written == 7, "fixture unnamed stream write failed");
            const auto volume = observe_local_ntfs_volume_handle(created.get());
            check(volume.filesystem_name == L"NTFS" &&
                volume.remote_protocol_error == ERROR_INVALID_PARAMETER &&
                (volume.file_id_volume_serial & 0xffffffffu) ==
                    volume.volume_information_serial &&
                volume.maximum_component_length >= 255,
                "local NTFS volume facts were not bound to the handle");
            const auto unnamed = observe_publisher_handle_streams(created.get());
            check(unnamed.size() == 1 && has_stream(unnamed, L"::$DATA", 7),
                "unnamed stream enumeration diverged");
            require_publisher_stream_shape(created.get());
            const std::wstring named_path = file.wstring() + L":extra";
            {
                Handle named(CreateFileW(named_path.c_str(), GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL, nullptr));
                check(WriteFile(named.get(), "ads", 3, &written, nullptr) != FALSE &&
                    written == 3, "fixture named stream write failed");
            }
            const auto streams = observe_publisher_handle_streams(created.get());
            check(streams.size() == 2 && has_stream(streams, L"::$DATA", 7) &&
                has_stream(streams, L":extra:$DATA", 3),
                "named stream was not detected from the held file handle");
            check_shape_rejected(created.get(), "named file stream was admitted");
        }
        {
            Handle directory(CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
                    FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            check(observe_publisher_handle_streams(directory.get()).empty(),
                "ordinary directory unexpectedly exposed a data stream");
            require_publisher_stream_shape(directory.get());
            const std::wstring directory_stream_path = root.wstring() + L":extra";
            {
                Handle named(CreateFileW(directory_stream_path.c_str(), GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                    CREATE_NEW, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
                DWORD written = 0;
                check(WriteFile(named.get(), "dir", 3, &written, nullptr) != FALSE &&
                    written == 3, "fixture directory stream write failed");
            }
            check(has_stream(observe_publisher_handle_streams(directory.get()),
                L":extra:$DATA", 3),
                "named directory stream was missed after the empty-stream result");
            check_shape_rejected(directory.get(), "named directory stream was admitted");
        }
        check(fs::remove(file) && fs::remove(root), "disposable stream cleanup failed");
        std::cout << "Windows publisher local volume and unnamed/named stream facts PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
