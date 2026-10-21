// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_metadata_parent_internal.h"
#include "usk_publisher_directory_entries.h"
#include <aclapi.h>
#include <array>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>

namespace fs = std::filesystem;
using namespace usk::platform::windows;
using detail::MetadataParentComponent;
using detail::MetadataParentRead;
namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void rejects(const std::function<void()>& run) {
    bool failed = false;
    try { run(); } catch (const std::runtime_error&) { failed = true; }
    check(failed, "invalid or failed metadata parent read became usable");
}
struct Fixture {
    fs::path base;
    std::array<fs::path, 4> paths;
    std::array<HANDLE, 4> handles{};
    std::array<bool, 4> created{};
    Fixture() {
        base = fs::temp_directory_path() / ("usk-metadata-parent-" +
            std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
        paths = {base, base / "first", base / "first" / "second", base / "first" / "second" / "third"};
        try {
            check(fs::create_directory(base), "fixture root already exists");
            created[0] = true;
            for (std::size_t index = 1; index < paths.size(); ++index) {
                check(fs::create_directory(paths[index]), "fixture directory already exists");
                created[index] = true;
            }
            for (std::size_t index = 0; index < paths.size(); ++index) {
                handles[index] = CreateFileW(paths[index].c_str(),
                    FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | FILE_ADD_FILE |
                    FILE_ADD_SUBDIRECTORY | READ_CONTROL | WRITE_DAC | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                check(handles[index] && handles[index] != INVALID_HANDLE_VALUE, "fixture handle open failed");
            }
        } catch (...) { cleanup(); throw; }
    }
    ~Fixture() { cleanup(); }
    void cleanup() noexcept {
        for (auto& handle : handles) {
            if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
            handle = nullptr;
        }
        std::error_code error;
        // Bounded fixture-owned names only; no recursive removal or external root.
        if (created.back()) fs::remove(paths.back() / "ordinary.txt", error);
        for (std::size_t index = paths.size(); index != 0; --index)
            if (created[index - 1]) fs::remove(paths[index - 1], error);
    }
    std::vector<MetadataParentComponent> components() const {
        std::vector<MetadataParentComponent> result;
        for (std::size_t index = 1; index < paths.size(); ++index)
            result.push_back({paths[index].filename().wstring(), handles[index],
                observe_publisher_directory_handle(handles[index]),
                observe_publisher_handle_granted_access(handles[index])});
        return result;
    }
    std::unique_ptr<MetadataParentRead> reader(std::vector<MetadataParentComponent> components) const {
        return std::make_unique<MetadataParentRead>(handles[0],
            observe_publisher_directory_handle(handles[0]),
            observe_publisher_handle_granted_access(handles[0]), std::move(components));
    }
    std::unique_ptr<MetadataParentRead> reader() const { return reader(components()); }
};
}
int main() {
    try {
        // Real ordinary NTFS handles test this non-authoritative read primitive.
        // No service admission, global fence, publication or public result is fabricated.
        {
            Fixture f; auto read = f.reader();
            check(read->observe() == f.handles.back(), "complete bounded chain was not entered");
            std::ofstream(f.paths.back() / "ordinary.txt") << "ordinary directory growth";
            check(read->observe() == f.handles.back(), "ordinary record growth invalidated its unchanged parent");
            read.reset(); // Borrowed capabilities remain owned by the fixture.
            check(observe_publisher_handle_granted_access(f.handles.back()) != 0, "read abandonment closed its owner capability");
            auto empty = f.components(); empty.clear();
            rejects([&] { (void)f.reader(empty); });
            auto large = f.components(); large.push_back(large.back());
            rejects([&] { (void)f.reader(large); });
            auto wrong = f.components(); wrong[1].name = L"another";
            rejects([&] { (void)f.reader(wrong); });
        }
        {
            Fixture f; auto read = f.reader();
            const auto moved = f.paths.back().parent_path() / "renamed";
            // Mutate the held leaf; retaining open descendants can prevent an
            // ancestor-directory rename before the intended assertion runs.
            fs::rename(f.paths.back(), moved);
            rejects([&] { (void)read->observe(); });
            fs::rename(moved, f.paths.back());
            rejects([&] { (void)read->observe(); }); // Restored namespace cannot clear failure.
        }
        for (std::size_t index = 0; index < 4; ++index) {
            Fixture f; auto read = f.reader();
            PSECURITY_DESCRIPTOR raw = nullptr;
            PACL dacl = nullptr;
            check(GetSecurityInfo(f.handles[index], SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                nullptr, nullptr, &dacl, nullptr, &raw) == ERROR_SUCCESS && raw,
                "fixture descriptor read failed");
            std::unique_ptr<void, decltype(&LocalFree)> descriptor(raw, &LocalFree);
            SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
            check(GetSecurityDescriptorControl(raw, &control, &revision) != FALSE, "fixture descriptor control failed");
            const bool protected_before = (control & SE_DACL_PROTECTED) != 0;
            const auto set_protection = [&](bool protect) {
                check(SetSecurityInfo(f.handles[index], SE_FILE_OBJECT, DACL_SECURITY_INFORMATION |
                    (protect ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION),
                    nullptr, nullptr, dacl, nullptr) == ERROR_SUCCESS, "fixture protection change failed");
            };
            set_protection(!protected_before);
            rejects([&] { (void)read->observe(); });
            set_protection(protected_before);
            rejects([&] { (void)read->observe(); });
        }
        {
            Fixture f; auto read = f.reader(); std::atomic<bool> refused{false};
            std::thread wrong([&] { try { (void)read->observe(); } catch (const std::runtime_error&) { refused.store(true); } });
            wrong.join();
            check(refused.load(), "wrong thread obtained a retained parent");
            rejects([&] { (void)read->observe(); });
        }
        {
            Fixture f; auto read = f.reader();
            check(CloseHandle(f.handles.back()) != FALSE, "fixture capability close failed");
            f.handles.back() = nullptr;
            rejects([&] { (void)read->observe(); });
            rejects([&] { (void)read->observe(); });
        }
        std::cout << "metadata retained-parent native read controls passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
