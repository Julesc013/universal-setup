// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_anchor_create.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_tree_observation.h"
#include "usk_publisher_rename_information.h"

#if defined(_WIN32)
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <aclapi.h>
#include <winternl.h>
#include <cstring>

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

void check_record_rename(HANDLE staging, HANDLE parent,
    const std::vector<unsigned char>& descriptor) {
    using RenameFn = NTSTATUS (NTAPI *)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    auto* rename = reinterpret_cast<RenameFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile"));
    check(rename != nullptr, "record native rename unavailable");
    const std::wstring name = L".usk-owned-root.v1.json";
    PublisherRenameInformation information(parent, name);
    const auto* fields = static_cast<FILE_RENAME_INFO*>(information.data());
    check(information.size() >= sizeof(FILE_RENAME_INFO) + name.size() * sizeof(WCHAR) &&
        fields->ReplaceIfExists == FALSE && fields->RootDirectory == parent &&
        fields->FileNameLength == name.size() * sizeof(WCHAR) &&
        std::wstring(fields->FileName) == name,
        "record rename buffer contract differs");
    for (const auto* invalid : {L".", L"..", L".other", L"record:stream", L"x/y"}) {
        check(refuses([&] { PublisherRenameInformation rejected(parent, invalid); }),
            "invalid record rename component admitted");
    }
    OwnedHandle file(create_file_relative_with_descriptor(staging, L"pending-record", descriptor));
    static constexpr char payload[] = "durable metadata fixture\n";
    DWORD written = 0;
    check(WriteFile(file.get(), payload, sizeof(payload) - 1, &written, nullptr) &&
        written == sizeof(payload) - 1 && FlushFileBuffers(file.get()), "record fixture write failed");
    const auto before = observe_publisher_file_handle(file.get());
    const auto destination = observe_publisher_directory_handle(parent);
    IO_STATUS_BLOCK io{};
    const NTSTATUS status = rename(file.get(), &io, information.data(), information.size(),
        static_cast<FILE_INFORMATION_CLASS>(10));
    if (status != 0 || io.Status != 0) {
        throw std::runtime_error("record fixture rename NTSTATUS " +
            std::to_string(static_cast<unsigned long>(status)) + "; IO " +
            std::to_string(static_cast<unsigned long>(io.Status)));
    }
    const auto after = observe_publisher_file_handle(file.get());
    check(after.file_id == before.file_id && after.owner_sid == before.owner_sid &&
        after.native_name == destination.native_name + L"\\" + name && FlushFileBuffers(file.get()),
        "record rename changed identity or was not flushed");
    OwnedHandle collision(create_file_relative_with_descriptor(staging, L"collision-record", descriptor));
    const auto original_collision = observe_publisher_file_handle(collision.get());
    io = {};
    check(rename(collision.get(), &io, information.data(), information.size(),
        static_cast<FILE_INFORMATION_CLASS>(10)) != 0,
        "record no-replace rename overwrote occupied name");
    check(observe_publisher_file_handle(file.get()).file_id == after.file_id &&
        observe_publisher_file_handle(collision.get()).native_name == original_collision.native_name,
        "record collision changed retained source or destination");
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
        {
            auto staging_parent = open_directory(staging, false);
            auto root_parent = open_directory(root, false);
            PSECURITY_DESCRIPTOR raw = nullptr;
            if (GetSecurityInfo(staging_parent.get(), SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, nullptr, nullptr, &raw) != ERROR_SUCCESS ||
                !raw) {
                throw std::runtime_error("write-through fixture security descriptor unavailable");
            }
            const DWORD length = GetSecurityDescriptorLength(raw);
            std::vector<unsigned char> descriptor(length);
            std::memcpy(descriptor.data(), raw, length);
            LocalFree(raw);
            {
                OwnedHandle created(create_directory_relative_with_descriptor(
                    root_parent.get(), L"destination-created-anchor", descriptor));
            }
            HANDLE reopened_target = INVALID_HANDLE_VALUE;
            for (const auto& listed : observe_publisher_directory_entries(root_parent.get())) {
                if (listed.name == L"destination-created-anchor") {
                    check(reopened_target == INVALID_HANDLE_VALUE,
                        "duplicate created destination anchor");
                    reopened_target = open_publisher_listed_child(
                        root_parent.get(), listed, true);
                }
            }
            check(reopened_target != INVALID_HANDLE_VALUE,
                "created destination anchor was not found through held parent");
            OwnedHandle target_parent(reopened_target);
            OwnedHandle source(create_directory_relative_with_descriptor(
                staging_parent.get(), L"created-candidate", descriptor));
            {
                OwnedHandle file(create_file_relative_with_descriptor(
                    source.get(), L"payload.bin", descriptor));
                static constexpr char bytes[] = "write-through fixture\n";
                DWORD written = 0;
                check(WriteFile(file.get(), bytes, sizeof(bytes) - 1,
                    &written, nullptr) && written == sizeof(bytes) - 1 &&
                    FlushFileBuffers(file.get()), "write-through fixture write failed");
            }
            const auto sealed = observe_publisher_tree(source.get());
            const auto observed_source = observe_publisher_directory_handle(source.get());
            const auto observed_target = observe_publisher_directory_handle(target_parent.get());
            const auto result = probe_publisher_bound_rename_no_replace(
                source.get(), target_parent.get(), L"visible-created",
                observed_source, observed_target);
            const auto visible = observe_visible_publisher_tree_against_seal(
                target_parent.get(), L"visible-created", sealed);
            check(result.root_file_id == visible.root.file_id &&
                visible.descendants.size() == 1 &&
                fs::exists(root / "destination-created-anchor" /
                    "visible-created" / "payload.bin"),
                "created anchor source did not rebind visibly");
            check_record_rename(staging_parent.get(), target_parent.get(), descriptor);
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
