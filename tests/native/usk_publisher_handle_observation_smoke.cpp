// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_handle_observation.h"

#include <aclapi.h>
#include <windows.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using usk::platform::windows::observe_publisher_directory_handle;
using usk::platform::windows::observe_publisher_file_handle;

namespace {
class Handle {
public:
    explicit Handle(HANDLE value) : value_(value) {
        if (value_ == INVALID_HANDLE_VALUE) throw std::runtime_error("fixture handle open failed");
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

bool refused(HANDLE handle) {
    try { (void)observe_publisher_directory_handle(handle); }
    catch (const std::exception&) { return true; }
    return false;
}
} // namespace

int main() {
    try {
        const auto root = fs::temp_directory_path() /
            ("usk-publisher-observe-" + std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count()));
        check(fs::create_directory(root), "fixture root already exists");
        const auto directory = root / "observed";
        check(fs::create_directory(directory), "fixture directory creation failed");
        {
            Handle handle(CreateFileW(directory.c_str(),
                FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE |
                    FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            const auto observed = observe_publisher_directory_handle(handle.get());
            check(observed.file_id.size() == 49 && observed.file_id[16] == ':',
                "composite native file identity is malformed");
            check(observed.native_name.size() >= 8 &&
                observed.native_name.substr(observed.native_name.size() - 8) == L"observed",
                "same-handle native name does not identify the fixture");
            check((observed.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                observed.link_count == 1, "directory facts were not observed");
            check(!observed.owner_sid.empty() && !observed.dacl_aces.empty(),
                "same-handle owner and DACL were not observed");
            check(observed.owner_sid != "S-1-5-18",
                "ordinary disposable fixture unexpectedly has the protected profile owner");

            PACL original_dacl = nullptr;
            PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
            const DWORD read_status = GetSecurityInfo(handle.get(), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION, nullptr, nullptr, &original_dacl,
                nullptr, &raw_descriptor);
            check(read_status == ERROR_SUCCESS && raw_descriptor && original_dacl,
                "fixture DACL could not be read for the protected-DACL probe");
            const DWORD write_status = SetSecurityInfo(handle.get(), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr, nullptr, original_dacl, nullptr);
            LocalFree(raw_descriptor);
            check(write_status == ERROR_SUCCESS, "fixture DACL protection failed");
            const auto protected_observation = observe_publisher_directory_handle(handle.get());
            check(protected_observation.file_id == observed.file_id &&
                protected_observation.owner_sid == observed.owner_sid &&
                protected_observation.dacl_protected,
                "same-handle reobservation missed a DACL control change");
        }
        check(refused(INVALID_HANDLE_VALUE), "invalid handle was admitted");
        {
            Handle limited(CreateFileW(directory.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            check(refused(limited.get()), "a handle lacking READ_CONTROL supplied security facts");
        }
        const auto file = root / "file.bin";
        {
            Handle created(CreateFileW(file.c_str(), GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL, nullptr));
        }
        {
            Handle regular(CreateFileW(file.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            check(refused(regular.get()), "regular file was admitted as a directory");
            const auto observed_file = observe_publisher_file_handle(regular.get());
            check((observed_file.attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
                observed_file.link_count == 1 && !observed_file.owner_sid.empty() &&
                !observed_file.dacl_aces.empty() && !observed_file.case_sensitive,
                "same-handle regular-file security facts were not observed");
            check(observed_file.native_name.size() >= 8 &&
                observed_file.native_name.substr(
                    observed_file.native_name.size() - 8) == L"file.bin",
                "same-handle regular-file native name diverged");
        }
        {
            Handle limited(CreateFileW(file.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            bool denied = false;
            try { (void)observe_publisher_file_handle(limited.get()); }
            catch (const std::runtime_error&) { denied = true; }
            check(denied, "file handle lacking READ_CONTROL supplied security facts");
        }
        fs::remove(file);
        fs::remove(directory);
        fs::remove(root);
        std::cout << "Windows publisher same-handle identity/security observation PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
