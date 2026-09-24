// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_tree_observation.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using usk::platform::windows::observe_publisher_tree;

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

void write_payload(const fs::path& path, const char* bytes, DWORD length) {
    Handle file(CreateFileW(path.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    DWORD written = 0;
    check(WriteFile(file.get(), bytes, length, &written, nullptr) != FALSE &&
        written == length, "fixture file write failed");
}

void check_refused(HANDLE root, const char* message) {
    try {
        observe_publisher_tree(root);
    } catch (const std::runtime_error&) {
        return;
    }
    throw std::runtime_error(message);
}
} // namespace

int main() {
    try {
        const auto root = fs::temp_directory_path() /
            ("usk-publisher-tree-" + std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count()));
        check(fs::create_directory(root), "fixture root already exists");
        const auto nested = root / "nested";
        check(fs::create_directory(nested), "fixture nested creation failed");
        const auto file = nested / "payload.bin";
        write_payload(file, "payload", 7);
        {
            auto held_root = open_directory(root);
            const auto first = observe_publisher_tree(held_root.get());
            check(first.descendants.size() == 2 && first.volume_serial != 0,
                "nested closure entry count or volume binding diverged");
            const auto found = std::find_if(first.descendants.begin(),
                first.descendants.end(), [](const auto& entry) {
                    return entry.relative_path == L"nested/payload.bin";
                });
            check(found != first.descendants.end() && !found->directory &&
                found->size == 7 &&
                found->sha256 ==
                    "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
                "held-handle file digest or size diverged");
            const auto second = observe_publisher_tree(held_root.get());
            check(second.descendants.size() == first.descendants.size() &&
                second.descendants[1].sha256 == first.descendants[1].sha256,
                "fresh closure observation diverged without mutation");
            const auto hardlink = nested / "second.bin";
            check(CreateHardLinkW(hardlink.c_str(), file.c_str(), nullptr) != FALSE,
                "fixture hard link creation failed");
            check_refused(held_root.get(), "multiply linked file was admitted");
            check(fs::remove(hardlink), "fixture hard link cleanup failed");
            const std::wstring stream = file.wstring() + L":extra";
            write_payload(stream, "ads", 3);
            check_refused(held_root.get(), "named descendant stream was admitted");
            check(DeleteFileW(stream.c_str()) != FALSE,
                "fixture named stream cleanup failed");
            const auto after = observe_publisher_tree(held_root.get());
            check(after.descendants.size() == 2,
                "closure did not recover after disposable attacks were removed");
            constexpr unsigned extra_files = 640;
            for (unsigned index = 0; index < extra_files; ++index) {
                const auto path = root /
                    (L"page-" + std::to_wstring(index) + L".bin");
                write_payload(path, "", 0);
            }
            check(observe_publisher_tree(held_root.get()).descendants.size() ==
                extra_files + 2,
                "directory pagination missed or repeated a descendant");
            for (unsigned index = 0; index < extra_files; ++index) {
                const auto path = root /
                    (L"page-" + std::to_wstring(index) + L".bin");
                check(fs::remove(path), "paginated fixture cleanup failed");
            }
        }
        check(fs::remove(file) && fs::remove(nested) && fs::remove(root),
            "disposable closure cleanup failed");
        std::cout << "Windows publisher read-only closure observations PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
