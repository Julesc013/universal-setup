// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_bound_rename.h"
#include "usk_publisher_tree_observation.h"

#if defined(_WIN32)
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using namespace usk::platform::windows;

namespace {
class OwnedHandle {
public:
    explicit OwnedHandle(HANDLE value) : value_(value) {
        if (value_ == INVALID_HANDLE_VALUE) throw std::runtime_error("fixture handle open failed");
    }
    ~OwnedHandle() { CloseHandle(value_); }
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};

OwnedHandle open_directory(const fs::path& path, bool rename_source) {
    const DWORD access = FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY |
        FILE_TRAVERSE | READ_CONTROL | SYNCHRONIZE |
        (rename_source ? DELETE : FILE_ADD_SUBDIRECTORY);
    return OwnedHandle(CreateFileW(path.c_str(), access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
}

bool refuses(const std::function<void()>& action) {
    try { action(); }
    catch (const PublisherRenameUnconfirmed&) { return false; }
    catch (const std::exception&) { return true; }
    return false;
}

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
} // namespace

int main() {
    const fs::path root = fs::temp_directory_path() /
        ("usk-bound-rename-" + std::to_string(GetCurrentProcessId()) + "-" +
            std::to_string(GetTickCount64()));
    try {
        const fs::path staging = root / "staging";
        const fs::path candidate = staging / "candidate";
        const fs::path destination = root / "destination";
        fs::create_directories(candidate);
        fs::create_directories(destination);
        {
            std::ofstream payload(candidate / "payload.bin", std::ios::binary);
            payload << "bound rename probe\n";
        }
        {
            auto source = open_directory(candidate, true);
            auto parent = open_directory(destination, false);
            const auto expected_source = observe_publisher_directory_handle(source.get());
            const auto expected_parent = observe_publisher_directory_handle(parent.get());
            const auto sealed = observe_publisher_tree(source.get());
            check(refuses([&] {
                (void)probe_publisher_bound_rename_no_replace(source.get(), parent.get(),
                    L"..", expected_source, expected_parent);
            }), "invalid component did not refuse");
            fs::create_directory(destination / "visible");
            check(refuses([&] {
                (void)probe_publisher_bound_rename_no_replace(source.get(), parent.get(),
                    L"visible", expected_source, expected_parent);
            }), "occupied destination did not refuse");
            check(fs::exists(candidate), "collision affected source");
            fs::remove(destination / "visible");
            const fs::path displaced_parent = root / "destination-displaced";
            fs::rename(destination, displaced_parent);
            fs::create_directory(destination);
            check(refuses([&] {
                (void)probe_publisher_bound_rename_no_replace(source.get(), parent.get(),
                    L"visible", expected_source, expected_parent);
            }), "live destination-parent substitution did not refuse");
            check(fs::exists(candidate) && !fs::exists(destination / "visible") &&
                !fs::exists(displaced_parent / "visible"),
                "parent substitution changed the source or either destination");
            fs::remove(destination);
            fs::rename(displaced_parent, destination);
            bool race_unconfirmed = false;
            try {
                (void)probe_publisher_bound_rename_no_replace(source.get(), parent.get(),
                    L"visible", expected_source, expected_parent, [&] {
                        fs::create_directory(destination / "visible");
                    });
            } catch (const PublisherRenameUnconfirmed&) {
                race_unconfirmed = true;
            }
            check(race_unconfirmed && fs::exists(candidate) &&
                fs::is_directory(destination / "visible"),
                "occupied rename race replaced an existing destination");
            fs::remove(destination / "visible");
            const auto result = probe_publisher_bound_rename_no_replace(
                source.get(), parent.get(), L"visible", expected_source, expected_parent);
            check(result.root_file_id == expected_source.file_id &&
                result.former_name == expected_source.native_name &&
                result.visible_name == expected_parent.native_name + L"\\visible",
                "bound rename returned wrong identity or path");
            const auto visible = observe_visible_publisher_tree_against_seal(
                parent.get(), L"visible", sealed);
            check(visible.root.file_id == sealed.root.file_id &&
                visible.descendants.size() == 1 &&
                fs::exists(destination / "visible" / "payload.bin") &&
                !fs::exists(candidate), "visible closure did not bind");
        }
        fs::remove_all(root);
        std::cout << "publisher-bound-rename-smoke-pass\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        std::error_code ignored;
        fs::remove_all(root, ignored);
        return 1;
    }
}
#endif
