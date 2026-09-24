// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_tree_observation.h"
#include "usk_publisher_security_descriptor.h"

#include <aclapi.h>
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using usk::platform::windows::observe_publisher_tree;
using usk::platform::windows::PublisherTreeObservation;
using usk::platform::windows::require_publisher_tree_phase_match;
using usk::platform::windows::require_publisher_tree_security_shape;

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
    return Handle(CreateFileW(path.c_str(), FILE_LIST_DIRECTORY |
        FILE_READ_ATTRIBUTES | READ_CONTROL,
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

void check_phase_refused(const PublisherTreeObservation& before,
    const PublisherTreeObservation& after, const char* message) {
    try {
        require_publisher_tree_phase_match(before, after);
    } catch (const std::runtime_error&) {
        return;
    }
    throw std::runtime_error(message);
}

void check_security_refused(const PublisherTreeObservation& tree,
    const std::string& sid, const char* message) {
    try {
        require_publisher_tree_security_shape(tree, sid);
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
        PublisherTreeObservation sealed_for_move{};
        {
            auto held_root = open_directory(root);
            const auto first = observe_publisher_tree(held_root.get());
            check(first.descendants.size() == 2 &&
                first.volume.file_id_volume_serial != 0 &&
                !first.root.owner_sid.empty() && !first.root.dacl_aces.empty(),
                "nested closure entry count or volume binding diverged");
            const auto found = std::find_if(first.descendants.begin(),
                first.descendants.end(), [](const auto& entry) {
                    return entry.relative_path == L"nested/payload.bin";
                });
            check(found != first.descendants.end() &&
                (found->object.attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
                !found->object.owner_sid.empty() &&
                !found->object.dacl_aces.empty() &&
                found->size == 7 &&
                found->sha256 ==
                    "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
                "held-handle file digest or size diverged");
            const auto second = observe_publisher_tree(held_root.get());
            check(second.descendants.size() == first.descendants.size() &&
                second.descendants[1].sha256 == first.descendants[1].sha256,
                "fresh closure observation diverged without mutation");
            require_publisher_tree_phase_match(first, second);
            constexpr const char* service_sid = "S-1-5-80-1-2-3-4-5";
            check_security_refused(first, service_sid,
                "ordinary-user tree was accepted as protected security");
            auto synthetic = first;
            const auto mask =
                usk::platform::windows::publisher_directory_access_mask();
            const auto set_profile_facts = [&](auto& object) {
                object.owner_sid = "S-1-5-18";
                object.dacl_protected = true;
                object.dacl_aces = {
                    {ACCESS_ALLOWED_ACE_TYPE, 0, mask, "S-1-5-18"},
                    {ACCESS_ALLOWED_ACE_TYPE, 0, mask, service_sid}};
            };
            set_profile_facts(synthetic.root);
            for (auto& entry : synthetic.descendants) {
                set_profile_facts(entry.object);
            }
            require_publisher_tree_security_shape(synthetic, service_sid);
            synthetic.descendants.back().object.dacl_aces.back().sid = "S-1-1-0";
            check_security_refused(synthetic, service_sid,
                "wrong descendant ACE SID was accepted");
            check_security_refused(first, "S-1-1-0",
                "non-service SID was accepted as publisher service identity");
            {
                Handle security(CreateFileW(file.c_str(), READ_CONTROL | WRITE_DAC,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                PACL dacl = nullptr;
                PSECURITY_DESCRIPTOR descriptor = nullptr;
                check(GetSecurityInfo(security.get(), SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl,
                    nullptr, &descriptor) == ERROR_SUCCESS &&
                    descriptor && dacl,
                    "fixture descendant DACL could not be read");
                const DWORD protection = found->object.dacl_protected ?
                    UNPROTECTED_DACL_SECURITY_INFORMATION :
                    PROTECTED_DACL_SECURITY_INFORMATION;
                const DWORD changed = SetSecurityInfo(security.get(),
                    SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | protection,
                    nullptr, nullptr, dacl, nullptr);
                LocalFree(descriptor);
                check(changed == ERROR_SUCCESS,
                    "fixture descendant DACL protection failed");
            }
            const auto security_changed = observe_publisher_tree(held_root.get());
            const auto rebound = std::find_if(security_changed.descendants.begin(),
                security_changed.descendants.end(), [](const auto& entry) {
                    return entry.relative_path == L"nested/payload.bin";
                });
            check(rebound != security_changed.descendants.end() &&
                rebound->object.dacl_protected !=
                    found->object.dacl_protected &&
                rebound->object.file_id == found->object.file_id &&
                rebound->sha256 == found->sha256,
                "fresh descendant observation missed a DACL protection change");
            check_phase_refused(first, security_changed,
                "DACL mutation was accepted as an equal phase");
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
            require_publisher_tree_phase_match(security_changed, after);
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
            sealed_for_move = observe_publisher_tree(held_root.get());
            require_publisher_tree_phase_match(after, sealed_for_move);
        }
        const auto visible = fs::path(root.wstring() + L"-visible");
        check(MoveFileExW(root.c_str(), visible.c_str(), MOVEFILE_WRITE_THROUGH) != FALSE,
            "disposable visible-root rename failed");
        {
            auto held_visible = open_directory(visible);
            const auto visible_tree = observe_publisher_tree(held_visible.get());
            std::wstring expected = sealed_for_move.root.native_name;
            const auto separator = expected.find_last_of(L'\\');
            check(separator != std::wstring::npos,
                "sealed native root name has no parent separator");
            expected.resize(separator + 1);
            expected += visible.filename().wstring();
            require_publisher_tree_phase_match(sealed_for_move,
                visible_tree, expected);
            check_phase_refused(sealed_for_move, visible_tree,
                "visible rename was accepted without the expected path transition");
        }
        check(fs::remove(visible / "nested" / "payload.bin") &&
            fs::remove(visible / "nested") && fs::remove(visible),
            "disposable closure cleanup failed");
        std::cout << "Windows publisher read-only closure observations PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
