// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_metadata.h"

#if defined(_WIN32)
#include "usk_publisher_anchor_create.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_handle_observation.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_token_observation.h"
#include "usk_publisher_tree_observation.h"
#include "usk_publisher_volume_stream_observation.h"
#include "usk_record_io.h"
#include "usk_utf8_path.h"

#include <winternl.h>
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <vector>

namespace fs = std::filesystem;
namespace usk::platform::windows {
namespace {
class OwnedHandle {
public:
    explicit OwnedHandle(HANDLE handle) : handle_(handle) {
        if (!handle || handle == INVALID_HANDLE_VALUE) throw std::runtime_error("metadata handle is unavailable");
    }
    ~OwnedHandle() { if (handle_) CloseHandle(handle_); }
    OwnedHandle(OwnedHandle&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
    HANDLE get() const { return handle_; }
private:
    HANDLE handle_;
};

std::optional<PublisherDirectoryEntry> find_child(HANDLE parent, const std::wstring& name) {
    for (const auto& entry : observe_publisher_directory_entries(parent)) {
        if (CompareStringOrdinal(entry.name.c_str(), -1, name.c_str(), -1, TRUE) == CSTR_EQUAL) {
            if (entry.name != name) throw std::runtime_error("metadata name collides with a noncanonical spelling");
            return entry;
        }
    }
    return {};
}

void require_boundary_rights(const PublisherHandleObservation& boundary,
    const std::string& service_sid) {
    // Use the accepted profile's exact owner/protected-DACL predicate for the
    // volume boundary as well as its children; do not admit a broader parent.
    require_publisher_object_security_shape(boundary, service_sid);
}

void publish_record(HANDLE file, HANDLE parent, const std::wstring& name,
    const std::string& service_sid) {
    const auto before_file = observe_publisher_file_handle(file);
    const auto before_parent = observe_publisher_directory_handle(parent);
    require_publisher_object_security_shape(before_file, service_sid);
    require_publisher_object_security_shape(before_parent, service_sid);
    if (find_child(parent, name)) throw std::runtime_error("metadata record already exists");
    using RenameFn = NTSTATUS (NTAPI *)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    auto* rename = reinterpret_cast<RenameFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile"));
    if (!rename) throw std::runtime_error("metadata native rename is unavailable");
    struct RenameInformation { BOOLEAN replace; HANDLE root; ULONG bytes; WCHAR name[1]; };
    const std::size_t bytes = offsetof(RenameInformation, name) + name.size() * sizeof(WCHAR);
    std::vector<unsigned char> storage(bytes, 0);
    auto* information = reinterpret_cast<RenameInformation*>(storage.data());
    information->root = parent;
    information->bytes = static_cast<ULONG>(name.size() * sizeof(WCHAR));
    std::memcpy(information->name, name.data(), information->bytes);
    IO_STATUS_BLOCK io{};
    const NTSTATUS status = rename(file, &io, information, static_cast<ULONG>(bytes),
        static_cast<FILE_INFORMATION_CLASS>(10)); // FileRenameInformation, ReplaceIfExists=false.
    if (status != 0 || io.Status != 0) throw std::runtime_error("metadata record rename failed or is unconfirmed");
    const auto after_file = observe_publisher_file_handle(file);
    const auto after_parent = observe_publisher_directory_handle(parent);
    require_publisher_object_security_shape(after_file, service_sid);
    require_publisher_object_security_shape(after_parent, service_sid);
    if (after_file.file_id != before_file.file_id || after_parent.file_id != before_parent.file_id ||
        after_parent.native_name != before_parent.native_name ||
        after_file.native_name != before_parent.native_name + L"\\" + name) {
        throw std::runtime_error("metadata published identity or namespace is unconfirmed");
    }
    if (!FlushFileBuffers(file)) throw std::runtime_error("metadata published record flush failed");
}
} // namespace

struct PublisherMetadataSession::Impl {
    HANDLE volume;
    fs::path volume_path;
    fs::path root_path;
    fs::path final_root_path;
    std::wstring root_name;
    std::string service_sid;
    std::vector<unsigned char> descriptor;
    std::unique_ptr<OwnedHandle> root;
    std::unique_ptr<OwnedHandle> pending;
    record_io::RecordWriteOperations operations;
    std::unique_ptr<record_io::ScopedRecordWriteOperations> scope;
    bool initializing = false;

    Impl(HANDLE boundary, const std::wstring& guid, const fs::path& physical_root,
        const std::wstring& service_name, bool require_existing)
        : volume(boundary), volume_path(guid), root_path(physical_root.lexically_normal()),
          final_root_path(root_path), root_name(root_path.filename().wstring()) {
        const auto service = observe_current_restricted_publisher_service(service_name);
        service_sid = service.service_sid;
        descriptor = make_publisher_directory_security_descriptor(std::wstring(service_sid.begin(), service_sid.end()));
        // MSVC treats Volume{GUID} as a relative component below \\?\ rather
        // than as a drive root; parent_path() drops its trailing separator.
        // Compare the complete direct-child path, preserving the GUID alias.
        if (!volume || volume == INVALID_HANDLE_VALUE ||
            root_path != (volume_path / root_name).lexically_normal() ||
            !is_publisher_canonical_component(root_name)) {
            throw std::runtime_error("metadata root must be one canonical child of the held volume");
        }
        const auto boundary_facts = observe_publisher_directory_handle(volume);
        OwnedHandle alias(CreateFileW(guid.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL |
            FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (observe_publisher_directory_handle(alias.get()).file_id != boundary_facts.file_id) {
            throw std::runtime_error("metadata volume GUID does not name the held boundary");
        }
        require_boundary_rights(boundary_facts, service_sid);
        observe_local_ntfs_volume_handle(volume);
        if (const auto existing = find_child(volume, root_name)) {
            root = std::make_unique<OwnedHandle>(open_publisher_listed_child(volume, *existing, true, false, true));
            require_publisher_tree_security_shape(observe_publisher_tree(root->get()), service_sid);
        } else {
            if (require_existing) throw std::runtime_error("protected metadata root is absent");
            // Build the ownership marker and complete empty repository layout
            // privately. A crash cannot expose a root lacking its marker.
            static std::atomic<unsigned long long> sequence{0};
            root_name = L"metadata-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(++sequence);
            root_path = volume_path / root_name;
            initializing = true;
        }
        operations.create_directory = [this](const fs::path& parent, const std::string& name) { create_directory(parent, name); };
        operations.write_new_text = [this](const fs::path& path, const std::string& content) { write_record(path, content); };
        scope = std::make_unique<record_io::ScopedRecordWriteOperations>(operations);
    }

    std::vector<OwnedHandle> parents(const fs::path& parent) {
        if (!root) throw std::runtime_error("protected metadata root has not been created");
        const fs::path normalized = parent.lexically_normal();
        const fs::path relative = normalized.lexically_relative(root_path);
        if (relative.empty()) throw std::runtime_error("metadata parent lies outside protected root");
        std::vector<OwnedHandle> handles;
        HANDLE current = root->get();
        require_publisher_object_security_shape(observe_publisher_directory_handle(current), service_sid);
        if (relative == fs::path(L".")) return handles;
        for (const fs::path& component : relative) {
            const std::wstring name = component.wstring();
            if (!is_publisher_canonical_component(name)) throw std::runtime_error("unsafe metadata parent component");
            const auto entry = find_child(current, name);
            if (!entry) throw std::runtime_error("metadata parent is absent");
            handles.emplace_back(open_publisher_listed_child(current, *entry, true, false, true));
            current = handles.back().get();
            require_publisher_object_security_shape(observe_publisher_directory_handle(current), service_sid);
        }
        return handles;
    }

    void create_directory(const fs::path& parent, const std::string& name) {
        if (!base::valid_utf8(name)) throw std::runtime_error("invalid metadata component UTF-8");
        const std::wstring component = fs::u8path(name).wstring();
        if (parent.lexically_normal() == volume_path && component == root_name && !root) {
            require_boundary_rights(observe_publisher_directory_handle(volume), service_sid);
            root = std::make_unique<OwnedHandle>(create_directory_relative_with_descriptor(volume, component, descriptor));
            require_publisher_object_security_shape(observe_publisher_directory_handle(root->get()), service_sid);
            return;
        }
        auto held = parents(parent);
        HANDLE anchor = held.empty() ? root->get() : held.back().get();
        OwnedHandle created(create_directory_relative_with_descriptor(anchor, component, descriptor));
        require_publisher_object_security_shape(observe_publisher_directory_handle(created.get()), service_sid);
    }

    void write_record(const fs::path& path, const std::string& content) {
        if (content.size() > 16u * 1024u * 1024u) throw std::runtime_error("protected metadata record exceeds its byte budget");
        const std::wstring name = path.filename().wstring();
        if (!is_publisher_canonical_component(name)) throw std::runtime_error("unsafe metadata record name");
        auto held = parents(path.parent_path());
        HANDLE parent = held.empty() ? root->get() : held.back().get();
        if (!pending) {
            if (const auto existing = find_child(root->get(), L"pending")) {
                pending = std::make_unique<OwnedHandle>(open_publisher_listed_child(root->get(), *existing, true, false, true));
            } else {
                pending = std::make_unique<OwnedHandle>(create_directory_relative_with_descriptor(root->get(), L"pending", descriptor));
            }
            require_publisher_tree_security_shape(observe_publisher_tree(pending->get()), service_sid);
        }
        static std::atomic<unsigned long long> sequence{0};
        const std::wstring temporary = L"record-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(++sequence);
        OwnedHandle file(create_file_relative_with_descriptor(pending->get(), temporary, descriptor));
        std::size_t offset = 0;
        while (offset < content.size()) {
            const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(64u * 1024u, content.size() - offset));
            DWORD written = 0;
            if (!WriteFile(file.get(), content.data() + offset, requested, &written, nullptr) || written != requested) {
                throw std::runtime_error("protected metadata pending write failed");
            }
            offset += written;
        }
        if (!FlushFileBuffers(file.get())) throw std::runtime_error("protected metadata pending flush failed");
        publish_record(file.get(), parent, name, service_sid);
    }

    void publish_initialized_root() {
        if (!initializing) return;
        if (!root || !find_child(root->get(), L".usk-owned-root.v1.json")) {
            throw std::runtime_error("protected metadata initialization has no ownership marker");
        }
        const auto tree = observe_publisher_tree(root->get());
        require_publisher_tree_security_shape(tree, service_sid);
        const auto parent = observe_publisher_directory_handle(volume);
        require_boundary_rights(parent, service_sid);
        // NTFS directory publication can refuse while a descendant handle is
        // open. All record handles are already closed; release this private
        // pending-directory handle before the held root's rename.
        pending.reset();
        probe_publisher_bound_rename_no_replace(root->get(), volume,
            final_root_path.filename().wstring(), tree.root, parent);
        root_path = final_root_path;
        root_name = root_path.filename().wstring();
        initializing = false;
    }
};

PublisherMetadataSession::PublisherMetadataSession(HANDLE volume, const std::wstring& guid,
    const fs::path& root, const std::wstring& service, bool require_existing)
    : impl_(std::make_unique<Impl>(volume, guid, root, service, require_existing)) {}
PublisherMetadataSession::~PublisherMetadataSession() = default;
const fs::path& PublisherMetadataSession::initialization_root() const { return impl_->root_path; }
void PublisherMetadataSession::publish_initialized_root() { impl_->publish_initialized_root(); }
} // namespace usk::platform::windows
#endif
