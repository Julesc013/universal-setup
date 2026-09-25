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
#include <vector>

namespace fs = std::filesystem;
using usk::platform::windows::observe_publisher_tree;
using usk::platform::windows::observe_publisher_directory_chain;
using usk::platform::windows::observe_publisher_anchor_set;
using usk::platform::windows::observe_visible_publisher_tree_against_seal;
using usk::platform::windows::PublisherAnchorNames;
using usk::platform::windows::require_publisher_anchor_set_phase_match;
using usk::platform::windows::require_publisher_anchor_set_security_shape;
using usk::platform::windows::require_publisher_directory_chain_phase_match;
using usk::platform::windows::require_publisher_directory_chain_security_shape;
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
        const auto base = fs::temp_directory_path() /
            ("usk-publisher-tree-" + std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count()));
        check(fs::create_directory(base), "fixture parent already exists");
        const auto root = base / "staging";
        check(fs::create_directory(root), "fixture root already exists");
        const auto nested = root / "nested";
        check(fs::create_directory(nested), "fixture nested creation failed");
        const auto file = nested / "payload.bin";
        write_payload(file, "payload", 7);
        {
            auto held_boundary = open_directory(base);
            const auto first = observe_publisher_directory_chain(
                held_boundary.get(), {L"staging", L"nested"});
            const auto second = observe_publisher_directory_chain(
                held_boundary.get(), {L"staging", L"nested"});
            check(first.children.size() == 2 &&
                first.children[0].object.file_id != first.boundary.file_id &&
                first.children[1].object.file_id != first.children[0].object.file_id,
                "directory chain did not bind distinct child identities");
            require_publisher_directory_chain_phase_match(first, second);
            bool wrong_case_refused = false;
            try {
                (void)observe_publisher_directory_chain(
                    held_boundary.get(), {L"STAGING", L"nested"});
            } catch (const std::runtime_error&) {
                wrong_case_refused = true;
            }
            check(wrong_case_refused,
                "directory chain accepted a case-only component assertion");
            bool ordinary_security_refused = false;
            try {
                require_publisher_directory_chain_security_shape(
                    first, "S-1-5-80-1-2-3-4-5");
            } catch (const std::runtime_error&) {
                ordinary_security_refused = true;
            }
            check(ordinary_security_refused,
                "ordinary-user directory chain passed protected security shape");
            auto tampered = second;
            tampered.children[1].object.dacl_protected =
                !tampered.children[1].object.dacl_protected;
            bool changed_child_refused = false;
            try {
                require_publisher_directory_chain_phase_match(first, tampered);
            } catch (const std::runtime_error&) {
                changed_child_refused = true;
            }
            check(changed_child_refused,
                "directory-chain phase accepted a changed child DACL flag");
            auto disconnected = second;
            disconnected.children[1].object.native_name =
                disconnected.boundary.native_name + L"\\unrelated";
            bool disconnected_refused = false;
            try {
                require_publisher_directory_chain_phase_match(first, disconnected);
            } catch (const std::runtime_error&) {
                disconnected_refused = true;
            }
            check(disconnected_refused,
                "directory-chain phase accepted an unrelated child path");
            auto repeated_identity = second;
            repeated_identity.children[1].object.file_id =
                repeated_identity.children[0].object.file_id;
            bool repeated_identity_refused = false;
            try {
                require_publisher_directory_chain_phase_match(
                    first, repeated_identity);
            } catch (const std::runtime_error&) {
                repeated_identity_refused = true;
            }
            check(repeated_identity_refused,
                "directory-chain phase accepted a repeated child identity");
            auto invalid_component = second;
            invalid_component.children[1].component = L"..";
            bool invalid_component_refused = false;
            try {
                require_publisher_directory_chain_phase_match(
                    first, invalid_component);
            } catch (const std::runtime_error&) {
                invalid_component_refused = true;
            }
            check(invalid_component_refused,
                "directory-chain phase accepted a noncanonical component");
        }
        {
            const auto anchor_parent = base / "anchor-chain";
            check(fs::create_directory(anchor_parent),
                "anchor parent fixture creation failed");
            const PublisherAnchorNames names{
                L"staging-anchor", L"destination-anchor",
                L"state-anchor", L"journal-anchor"};
            for (const auto& component : {
                    names.staging, names.destination_parent,
                    names.state, names.journal}) {
                check(fs::create_directory(anchor_parent / component),
                    "anchor sibling fixture creation failed");
            }
            auto held_boundary = open_directory(base);
            const auto first = observe_publisher_anchor_set(
                held_boundary.get(), {L"anchor-chain"}, names);
            const auto second = observe_publisher_anchor_set(
                held_boundary.get(), {L"anchor-chain"}, names);
            require_publisher_anchor_set_phase_match(first, second);
            bool ordinary_security_refused = false;
            try {
                require_publisher_anchor_set_security_shape(
                    first, "S-1-5-80-1-2-3-4-5");
            } catch (const std::runtime_error&) {
                ordinary_security_refused = true;
            }
            check(ordinary_security_refused,
                "ordinary-user anchor set passed protected security shape");
            auto repeated = second;
            repeated.journal.object.file_id = repeated.state.object.file_id;
            bool repeated_refused = false;
            try {
                require_publisher_anchor_set_phase_match(first, repeated);
            } catch (const std::runtime_error&) {
                repeated_refused = true;
            }
            check(repeated_refused,
                "anchor role comparison accepted a repeated identity");
            auto changed = second;
            changed.journal.object.dacl_protected =
                !changed.journal.object.dacl_protected;
            bool changed_refused = false;
            try {
                require_publisher_anchor_set_phase_match(first, changed);
            } catch (const std::runtime_error&) {
                changed_refused = true;
            }
            check(changed_refused,
                "anchor role comparison accepted changed DACL facts");
            bool colliding_names_refused = false;
            try {
                auto colliding = names;
                colliding.journal = L"STATE-ANCHOR";
                (void)observe_publisher_anchor_set(
                    held_boundary.get(), {L"anchor-chain"}, colliding);
            } catch (const std::runtime_error&) {
                colliding_names_refused = true;
            }
            check(colliding_names_refused,
                "anchor role observation accepted case-fold colliding names");
            for (const auto& component : {
                    names.staging, names.destination_parent,
                    names.state, names.journal}) {
                check(fs::remove(anchor_parent / component),
                    "anchor sibling fixture cleanup failed");
            }
            check(fs::remove(anchor_parent),
                "anchor parent fixture cleanup failed");
        }
        {
            const auto wide_root = base / "wide-chain";
            check(fs::create_directory(wide_root),
                "wide directory-chain root creation failed");
            std::vector<fs::path> levels;
            std::vector<fs::path> side_files;
            std::vector<std::wstring> components;
            auto current = wide_root;
            for (int depth = 0; depth < 12; ++depth) {
                for (int side = 0; side < 64; ++side) {
                    const auto sibling = current /
                        ("side-" + std::to_string(depth) + "-" +
                            std::to_string(side));
                    write_payload(sibling, "x", 1);
                    side_files.push_back(sibling);
                }
                const auto component = L"level-" + std::to_wstring(depth);
                current /= component;
                check(fs::create_directory(current),
                    "wide directory-chain level creation failed");
                components.push_back(component);
                levels.push_back(current);
            }
            auto held_wide_root = open_directory(wide_root);
            const auto observed = observe_publisher_directory_chain(
                held_wide_root.get(), components);
            check(observed.children.size() == components.size(),
                "deep wide directory chain was not completely observed");
            for (const auto& side_file : side_files) {
                check(fs::remove(side_file), "wide-chain sibling cleanup failed");
            }
            for (auto level = levels.rbegin(); level != levels.rend(); ++level) {
                check(fs::remove(*level), "wide-chain level cleanup failed");
            }
            check(fs::remove(wide_root), "wide-chain root cleanup failed");
        }
        PublisherTreeObservation sealed_for_move{};
        {
            auto held_root = open_directory(root);
            const auto first = observe_publisher_tree(held_root.get());
            check(first.descendants.size() == 2 &&
                first.volume.file_id_volume_serial != 0 &&
                first.root_streams.empty() &&
                first.descendants[0].streams.empty() &&
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
                found->streams.size() == 1 &&
                found->streams[0].name == L"::$DATA" &&
                found->streams[0].size == 7 &&
                found->sha256 ==
                    "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
                "held-handle file digest or size diverged");
            const auto second = observe_publisher_tree(held_root.get());
            check(second.descendants.size() == first.descendants.size() &&
                second.descendants[1].sha256 == first.descendants[1].sha256,
                "fresh closure observation diverged without mutation");
            require_publisher_tree_phase_match(first, second);
            auto stream_changed = second;
            stream_changed.descendants.back().streams[0].size += 1;
            check_phase_refused(first, stream_changed,
                "changed exact stream size was accepted as an equal phase");
            stream_changed = second;
            stream_changed.descendants.back().streams[0].allocation_size += 1;
            check_phase_refused(first, stream_changed,
                "changed stream allocation was accepted as an equal phase");
            stream_changed = second;
            stream_changed.root_streams.push_back({L":unexpected:$DATA", 1, 1});
            check_phase_refused(first, stream_changed,
                "changed root stream set was accepted as an equal phase");
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
        const auto visible = base / "visible";
        auto actual_parent = base;
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
        {
            auto held_parent = open_directory(base);
            const auto bound_visible = observe_visible_publisher_tree_against_seal(
                held_parent.get(), L"visible", sealed_for_move);
            check(bound_visible.root.file_id == sealed_for_move.root.file_id,
                "parent-bound reopen did not recover the sealed root identity");
            bool wrong_case_refused = false;
            try {
                (void)observe_visible_publisher_tree_against_seal(
                    held_parent.get(), L"VISIBLE", sealed_for_move);
            } catch (const std::runtime_error&) {
                wrong_case_refused = true;
            }
            check(wrong_case_refused,
                "case-only destination assertion was accepted by the held parent");
            const auto moved_parent = fs::path(base.wstring() + L"-moved");
            check(MoveFileExW(base.c_str(), moved_parent.c_str(),
                MOVEFILE_WRITE_THROUGH) != FALSE,
                "held destination parent rename failed");
            actual_parent = moved_parent;
            check(fs::create_directory(base) &&
                fs::create_directory(base / "visible"),
                "substituted parent path fixture creation failed");
            const auto rebound_after_substitution =
                observe_visible_publisher_tree_against_seal(
                    held_parent.get(), L"visible", sealed_for_move);
            check(rebound_after_substitution.root.file_id ==
                sealed_for_move.root.file_id,
                "held parent was replaced by the substituted path");
            check(fs::remove(base / "visible") && fs::remove(base),
                "substituted parent fixture cleanup failed");
        }
        const auto actual_visible = actual_parent / "visible";
        check(fs::remove(actual_visible / "nested" / "payload.bin") &&
            fs::remove(actual_visible / "nested") &&
            fs::remove(actual_visible) && fs::remove(actual_parent),
            "disposable closure cleanup failed");
        std::cout << "Windows publisher read-only closure observations PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
