// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_anchor_create.h"
#include "usk_publisher_handle_observation.h"

#include <aclapi.h>
#include <windows.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using usk::platform::windows::create_directory_relative_with_descriptor;
using usk::platform::windows::observe_publisher_directory_handle;

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

std::vector<unsigned char> fixture_descriptor(HANDLE parent) {
    PSECURITY_DESCRIPTOR raw = nullptr;
    const DWORD status = GetSecurityInfo(parent, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        nullptr, nullptr, nullptr, nullptr, &raw);
    if (status != ERROR_SUCCESS || !raw) {
        throw std::runtime_error("disposable parent security descriptor unavailable");
    }
    const auto* first = static_cast<const unsigned char*>(raw);
    std::vector<unsigned char> bytes(first, first + GetSecurityDescriptorLength(raw));
    LocalFree(raw);
    return bytes;
}

bool refused(HANDLE parent, const std::wstring& name,
    const std::vector<unsigned char>& descriptor) {
    try {
        Handle created(create_directory_relative_with_descriptor(parent, name, descriptor));
    } catch (const std::exception&) { return true; }
    return false;
}
} // namespace

int main() {
    try {
        const auto root = fs::temp_directory_path() /
            ("usk-publisher-anchor-" + std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count()));
        check(fs::create_directory(root), "fixture root already exists");
        const auto parent = root / "parent";
        const auto moved = root / "moved";
        check(fs::create_directory(parent), "fixture parent creation failed");
        {
            Handle parent_handle(CreateFileW(parent.c_str(),
                FILE_ADD_SUBDIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            const auto descriptor = fixture_descriptor(parent_handle.get());
            const auto parent_id = observe_publisher_directory_handle(parent_handle.get()).file_id;
            std::string first_id;
            {
                Handle first(create_directory_relative_with_descriptor(
                    parent_handle.get(), L"first", descriptor));
                first_id = observe_publisher_directory_handle(first.get()).file_id;
                DWORD handle_flags = 0;
                check(fs::exists(parent / "first") &&
                    !first_id.empty() && GetHandleInformation(first.get(), &handle_flags) != FALSE &&
                    (handle_flags & HANDLE_FLAG_INHERIT) == 0,
                    "relative create did not produce a visible directory");
            }
            check(refused(parent_handle.get(), L"first", descriptor) &&
                refused(parent_handle.get(), L"CON", descriptor) &&
                refused(parent_handle.get(), L"..", descriptor) &&
                refused(parent_handle.get(), L"bad/name", descriptor),
                "collision or invalid component was accepted");
            {
                Handle unchanged(CreateFileW((parent / "first").c_str(),
                    FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
                        FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                check(observe_publisher_directory_handle(unchanged.get()).file_id == first_id,
                    "create-only collision changed the existing directory identity");
            }
            fs::rename(parent, moved);
            check(fs::create_directory(parent), "replacement parent fixture creation failed");
            {
                Handle bound(create_directory_relative_with_descriptor(
                    parent_handle.get(), L"bound", descriptor));
                check(fs::exists(moved / "bound") && !fs::exists(parent / "bound") &&
                    observe_publisher_directory_handle(parent_handle.get()).file_id == parent_id &&
                    !observe_publisher_directory_handle(bound.get()).file_id.empty(),
                    "parent path substitution redirected handle-relative creation");
            }
        }
        check(fs::remove(moved / "first") && fs::remove(moved / "bound") &&
            fs::remove(moved) && fs::remove(parent) && fs::remove(root),
            "disposable fixture cleanup failed");
        std::cout << "Windows publisher parent-bound create-only anchor probe PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
