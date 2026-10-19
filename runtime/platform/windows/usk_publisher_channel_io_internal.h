// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_CHANNEL_IO_INTERNAL_H
#define USK_PUBLISHER_CHANNEL_IO_INTERNAL_H
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <stdexcept>

namespace usk::platform::windows::detail::channel_io {
constexpr DWORD request_limit = 1024u * 1024u;
constexpr DWORD response_limit = 4u * 1024u * 1024u;

// Shared one-message I/O only. Authentication and dispatch ownership remain
// with their existing client/server callers; these helpers grant no authority.
ULONGLONG deadline(DWORD milliseconds);
DWORD remaining(ULONGLONG until);
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE v) : value(v) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
struct Io {
    Handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    OVERLAPPED overlapped{};
    Io() {
        if (!event.value) throw std::runtime_error("publisher transport event unavailable");
        overlapped.hEvent = event.value;
    }
    DWORD finish(HANDLE file, BOOL started, HANDLE stop, ULONGLONG until,
        DWORD immediate_error) {
        if (!started && immediate_error != ERROR_IO_PENDING) {
            throw std::runtime_error("publisher transport message failed; Win32 " + std::to_string(immediate_error));
        }
        HANDLE waits[2] = {event.value, stop};
        const DWORD result = started ? WAIT_OBJECT_0 :
            WaitForMultipleObjects(stop ? 2 : 1, waits, FALSE, remaining(until));
        DWORD bytes = 0;
        if (result != WAIT_OBJECT_0) {
            CancelIoEx(file, &overlapped);
            // Do not release the OVERLAPPED storage until cancellation completes.
            GetOverlappedResult(file, &overlapped, &bytes, TRUE);
            throw std::runtime_error("publisher transport cancelled or timed out");
        }
        if (!GetOverlappedResult(file, &overlapped, &bytes, FALSE)) {
            throw std::runtime_error("publisher transport message incomplete; Win32 " + std::to_string(GetLastError()));
        }
        return bytes;
    }
};
std::string read_message(HANDLE pipe, DWORD limit, HANDLE stop, ULONGLONG until);
void write_message(HANDLE pipe, const std::string& bytes, DWORD limit, HANDLE stop, ULONGLONG until);
}
#endif
#endif
