// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_directory_entries.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using usk::platform::windows::observe_publisher_directory_entries;
using usk::platform::windows::open_publisher_listed_child;

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

Handle open_directory(const fs::path& path) {
    return Handle(CreateFileW(path.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
}
} // namespace

int main() {
    try {
        const auto root = fs::temp_directory_path() /
            ("usk-publisher-entries-" + std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count()));
        check(fs::create_directory(root), "fixture root already exists");
        {
            auto directory = open_directory(root);
            check(observe_publisher_directory_entries(directory.get()).empty(),
                "empty directory produced children");
            const auto child = root / "child";
            check(fs::create_directory(child), "fixture child creation failed");
            const auto file = root / "payload.bin";
            {
                Handle payload(CreateFileW(file.c_str(), GENERIC_WRITE |
                    FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE |
                    FILE_SHARE_DELETE, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                    nullptr));
                DWORD written = 0;
                check(WriteFile(payload.get(), "payload", 7, &written, nullptr) != FALSE &&
                    written == 7, "fixture payload write failed");
                const auto entries = observe_publisher_directory_entries(directory.get());
                check(entries.size() == 2, "directory listing missed or invented a child");
                bool budget_refused = false;
                try {
                    observe_publisher_directory_entries(directory.get(), 1);
                } catch (const std::runtime_error&) {
                    budget_refused = true;
                }
                check(budget_refused, "directory enumeration ignored its byte budget");
                const auto found = std::find_if(entries.begin(), entries.end(),
                    [](const auto& entry) { return entry.name == L"payload.bin"; });
                check(found != entries.end() && found->listing_size >= 0 &&
                    (found->attributes & FILE_ATTRIBUTE_DIRECTORY) == 0,
                    "file listing facts diverged");
                FILE_ID_INFO id{};
                check(GetFileInformationByHandleEx(payload.get(), FileIdInfo,
                    &id, sizeof(id)) != FALSE &&
                    std::equal(found->file_id.begin(), found->file_id.end(),
                        std::begin(id.FileId.Identifier)),
                    "listed 128-bit file ID did not match the held file handle");
                const auto dir_found = std::find_if(entries.begin(), entries.end(),
                    [](const auto& entry) { return entry.name == L"child"; });
                check(dir_found != entries.end() &&
                    (dir_found->attributes & FILE_ATTRIBUTE_DIRECTORY) != 0,
                    "child directory listing facts diverged");
                {
                    Handle reopened(open_publisher_listed_child(directory.get(), *found));
                    FILE_ID_INFO rebound{};
                    check(GetFileInformationByHandleEx(reopened.get(), FileIdInfo,
                        &rebound, sizeof(rebound)) != FALSE &&
                        std::equal(found->file_id.begin(), found->file_id.end(),
                            std::begin(rebound.FileId.Identifier)),
                        "parent-bound file reopen did not bind the listed ID");
                }
                {
                    Handle reopened(open_publisher_listed_child(directory.get(),
                        *dir_found));
                }
                bool forged_id_refused = false;
                auto forged = *found;
                forged.file_id[0] ^= 1;
                try {
                    Handle reopened(open_publisher_listed_child(directory.get(), forged));
                } catch (const std::runtime_error&) {
                    forged_id_refused = true;
                }
                check(forged_id_refused, "forged listed file ID was admitted");
                bool invalid_name_refused = false;
                forged = *found;
                forged.name = L"payload.bin:extra";
                try {
                    Handle reopened(open_publisher_listed_child(directory.get(), forged));
                } catch (const std::runtime_error&) {
                    invalid_name_refused = true;
                }
                check(invalid_name_refused, "alternate stream component was admitted");
                bool case_changed_refused = false;
                forged = *found;
                forged.name = L"PAYLOAD.BIN";
                try {
                    Handle reopened(open_publisher_listed_child(directory.get(), forged));
                } catch (const std::runtime_error&) {
                    case_changed_refused = true;
                }
                check(case_changed_refused, "case-only name substitution was admitted");
                bool refused_file = false;
                try {
                    observe_publisher_directory_entries(payload.get());
                } catch (const std::runtime_error&) {
                    refused_file = true;
                }
                check(refused_file, "file handle was accepted as a directory");
            }
            const auto stream = file.wstring() + L":extra";
            {
                Handle named(CreateFileW(stream.c_str(), GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
            }
            check(observe_publisher_directory_entries(directory.get()).size() == 2,
                "alternate stream appeared as a directory child");
        }
        fs::remove_all(root);
        std::cout << "Windows publisher held-directory listing facts PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
