// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_channel_io_internal.h"
#if defined(_WIN32)
#include <stdexcept>
#include <vector>
namespace usk::platform::windows::detail::channel_io {
ULONGLONG deadline(DWORD milliseconds) {
    if (!milliseconds || milliseconds > 120000) throw std::runtime_error("invalid publisher transport timeout");
    return GetTickCount64() + milliseconds;
}
DWORD remaining(ULONGLONG until) {
    const auto now = GetTickCount64();
    return now >= until ? 0 : static_cast<DWORD>(until - now);
}

std::string read_message(HANDLE pipe, DWORD limit, HANDLE stop, ULONGLONG until) {
    std::vector<char> bytes(limit + 1u);
    Io io;
    const BOOL started = ReadFile(pipe, bytes.data(), static_cast<DWORD>(bytes.size()), nullptr, &io.overlapped);
    const DWORD error = started ? ERROR_SUCCESS : GetLastError();
    const DWORD read = io.finish(pipe, started, stop, until, error);
    if (!read || read > limit) throw std::runtime_error("publisher transport message exceeds bound or is empty");
    return std::string(bytes.data(), read);
}
void write_message(HANDLE pipe, const std::string& bytes, DWORD limit, HANDLE stop, ULONGLONG until) {
    if (bytes.empty() || bytes.size() > limit) throw std::runtime_error("publisher transport message exceeds bound or is empty");
    Io io;
    const BOOL started = WriteFile(pipe, bytes.data(), static_cast<DWORD>(bytes.size()), nullptr, &io.overlapped);
    const DWORD error = started ? ERROR_SUCCESS : GetLastError();
    if (io.finish(pipe, started, stop, until, error) != bytes.size()) {
        throw std::runtime_error("publisher transport partial message");
    }
}
}
#endif
