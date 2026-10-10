// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_metadata.h"

#if defined(_WIN32)
#include "usk_publisher_anchor_create.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_handle_observation.h"
#include "usk_publisher_rename_information.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_token_observation.h"
#include "usk_publisher_effect_execution_internal.h"
#include "usk_publisher_tree_observation.h"
#include "usk_publisher_volume_stream_observation.h"
#include "usk_record_io.h"
#include "usk_sha256.h"
#include "usk_utf8_path.h"

#include <winternl.h>
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <exception>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
namespace usk::platform::windows {
namespace {
thread_local const std::function<void()>* effect_fence = nullptr;
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
    HANDLE release() noexcept { const HANDLE result = handle_; handle_ = nullptr; return result; }
    bool close_once() noexcept {
        const HANDLE closing = handle_;
        handle_ = nullptr; // Unknown close is never retried by destruction.
        return closing && CloseHandle(closing) != FALSE;
    }
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

std::string held_journal_sha256(HANDLE file) {
    LARGE_INTEGER size{}, zero{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 1 || size.QuadPart > 4u * 1024u * 1024u ||
        !SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
        throw std::runtime_error("protected journal content size or position unavailable");
    base::Sha256 digest;
    std::vector<unsigned char> buffer(64u * 1024u);
    std::uint64_t total = 0;
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr))
            throw std::runtime_error("protected journal same-handle read failed");
        if (!read) break;
        if (total + read > static_cast<std::uint64_t>(size.QuadPart))
            throw std::runtime_error("protected journal grew during same-handle read");
        digest.update(buffer.data(), read);
        total += read;
    }
    LARGE_INTEGER after{};
    if (total != static_cast<std::uint64_t>(size.QuadPart) || !GetFileSizeEx(file, &after) ||
        after.QuadPart != size.QuadPart)
        throw std::runtime_error("protected journal content size changed");
    return digest.finish();
}

} // namespace

ScopedPublisherEffectFence::ScopedPublisherEffectFence(const std::function<void()>& check) {
    if (effect_fence || !check) throw std::runtime_error("publisher effect fence scope is unavailable");
    check();
    effect_fence = &check;
}
ScopedPublisherEffectFence::~ScopedPublisherEffectFence() { effect_fence = nullptr; }
void require_current_publisher_effect_fence() { if (effect_fence) (*effect_fence)(); }
void require_active_publisher_effect_fence() {
    if (!effect_fence) throw std::runtime_error("publisher native maintenance effect fence unavailable");
    (*effect_fence)();
}

namespace {
void publish_record_no_replace(HANDLE file, HANDLE parent, const std::wstring& name,
    const std::string& service_sid, const std::function<void()>* before_issue) {
    const auto before_file = observe_publisher_file_handle(file);
    const auto before_parent = observe_publisher_directory_handle(parent);
    require_publisher_object_security_shape(before_file, service_sid);
    require_publisher_object_security_shape(before_parent, service_sid);
    if (find_child(parent, name)) throw std::runtime_error("metadata record already exists");
    using RenameFn = NTSTATUS (NTAPI *)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    auto* rename = reinterpret_cast<RenameFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile"));
    if (!rename) throw std::runtime_error("metadata native rename is unavailable");
    PublisherRenameInformation information(parent, name);
    IO_STATUS_BLOCK io{};
    require_current_publisher_effect_fence();
    // The owner latches the exact prepared revision immediately before the
    // issued call. No allocation or other effect occurs between these steps.
    if (before_issue) (*before_issue)();
    const NTSTATUS status = rename(file, &io, information.data(), information.size(),
        static_cast<FILE_INFORMATION_CLASS>(10)); // FileRenameInformation, ReplaceIfExists=false.
    if (status != 0 || io.Status != 0) {
        throw PublisherRenameUnconfirmed("metadata record rename failed or is unconfirmed; NTSTATUS " +
            std::to_string(static_cast<unsigned long>(status)) + "; IO status " +
            std::to_string(static_cast<unsigned long>(io.Status)) + "; buffer bytes " +
            std::to_string(information.size()) + "; name " + fs::path(name).u8string());
    }
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
}
void publish_publisher_record_no_replace(HANDLE file, HANDLE parent, const std::wstring& name,
    const std::string& service_sid) {
    publish_record_no_replace(file, parent, name, service_sid, nullptr);
}

struct PublisherMetadataSession::Impl {
    HANDLE volume;
    fs::path volume_path;
    fs::path root_path;
    fs::path final_root_path;
    fs::path public_alias;
    std::wstring root_name;
    std::string service_sid;
    std::vector<unsigned char> descriptor;
    std::unique_ptr<OwnedHandle> root;
    std::unique_ptr<OwnedHandle> pending;
    record_io::RecordWriteOperations operations;
    std::unique_ptr<record_io::ScopedRecordWriteOperations> scope;
    std::unique_ptr<detail::MetadataRecordPublicationHooks> publication_hooks;
    bool initializing = false;
    bool journal_publication_unconfirmed = false;

    Impl(HANDLE boundary, const std::wstring& guid, const fs::path& physical_root,
        const std::wstring& service_name, bool require_existing, const fs::path& alias_path)
        : volume(boundary), volume_path(guid), root_path(physical_root.lexically_normal()),
          final_root_path(root_path), public_alias(alias_path.empty() ? fs::path{} : fs::absolute(alias_path).lexically_normal()),
          root_name(root_path.filename().wstring()) {
        const auto service = observe_current_publisher_native_execution_owner(service_name).service;
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
        if (!public_alias.empty()) {
            if (!require_existing || public_alias.relative_path() != fs::path(root_name))
                throw std::runtime_error("metadata public alias must name the existing direct setup child");
            require_alias_mapping();
        }
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

    void observe_alias_mapping() const {
        const std::wstring drive = public_alias.root_name().wstring() + L"\\";
        wchar_t mapped[128]{};
        if (drive.size() != 3 || drive[1] != L':' ||
            !GetVolumeNameForVolumeMountPointW(drive.c_str(), mapped, static_cast<DWORD>(std::size(mapped))) ||
            CompareStringOrdinal(mapped, -1, volume_path.c_str(), -1, TRUE) != CSTR_EQUAL)
            throw std::runtime_error("metadata public alias lost its held volume mapping");
    }
    void require_alias_mapping() const {
        if (public_alias.empty()) return;
        require_active_publisher_effect_fence();
        observe_alias_mapping();
    }
    void require_alias_mapping_and_effect_fence() const {
        if (!public_alias.empty()) {
            // The candidate is only a native volume-name query. It grants no
            // authority and cannot issue a write, close or publication. The
            // full original fence must complete AFTER it, before the caller
            // advances. Do not claim the former separate earlier sampling
            // instant or carry this result across another native effect.
            if (!effect_fence)
                throw std::runtime_error("publisher native maintenance effect fence unavailable");
            try { observe_alias_mapping(); }
            catch (...) {
                const auto original = std::current_exception();
                // Preserve the original fence refusal precedence even when
                // the read-only candidate itself is invalid or unavailable.
                require_active_publisher_effect_fence();
                std::rethrow_exception(original);
            }
        }
        require_active_publisher_effect_fence();
    }
    std::vector<OwnedHandle> parents(const fs::path& parent) {
        if (!root) throw std::runtime_error("protected metadata root has not been created");
        require_alias_mapping();
        const fs::path normalized = parent.lexically_normal();
        fs::path relative = normalized.lexically_relative(root_path);
        if (!public_alias.empty() && (relative.empty() || *relative.begin() == fs::path(L"..")))
            relative = normalized.lexically_relative(public_alias);
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
            root = std::make_unique<OwnedHandle>(create_record_directory_relative_with_descriptor(volume, component, descriptor));
            require_publisher_object_security_shape(observe_publisher_directory_handle(root->get()), service_sid);
            return;
        }
        auto held = parents(parent);
        HANDLE anchor = held.empty() ? root->get() : held.back().get();
        OwnedHandle created(create_directory_relative_with_descriptor(anchor, component, descriptor));
        require_publisher_object_security_shape(observe_publisher_directory_handle(created.get()), service_sid);
        require_alias_mapping();
    }

    void write_record(const fs::path& path, const std::string& content) {
        if (content.size() > 16u * 1024u * 1024u) throw std::runtime_error("protected metadata record exceeds its byte budget");
        const std::wstring name = path.filename().wstring();
        if (!is_publisher_canonical_component(name)) throw std::runtime_error("unsafe metadata record name");
        std::function<void()> before_issue;
        if (publication_hooks) {
            publication_hooks->prepare(path, content);
            before_issue = [this, &path, &content] { publication_hooks->before_issue(path, content); };
        }
        try {
            auto held = parents(path.parent_path());
            HANDLE parent = held.empty() ? root->get() : held.back().get();
            if (!pending) {
                if (const auto existing = find_child(root->get(), L"pending")) {
                    pending = std::make_unique<OwnedHandle>(open_publisher_listed_child(root->get(), *existing, true, false, true));
                } else {
                    pending = std::make_unique<OwnedHandle>(create_record_directory_relative_with_descriptor(root->get(), L"pending", descriptor));
                }
                require_publisher_tree_security_shape(observe_publisher_tree(pending->get()), service_sid);
            }
            static std::atomic<unsigned long long> sequence{0};
            const std::wstring temporary = L"record-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(++sequence);
            OwnedHandle file(create_file_relative_with_descriptor(pending->get(), temporary, descriptor));
            const HANDLE output = file.get();
            if (publication_hooks && publication_hooks->created(path, content, output)) (void)file.release();
            std::size_t offset = 0;
            while (offset < content.size()) {
                const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(64u * 1024u, content.size() - offset));
                DWORD written = 0;
                require_current_publisher_effect_fence();
                if (!WriteFile(output, content.data() + offset, requested, &written, nullptr) || written != requested) {
                    throw std::runtime_error("protected metadata pending write failed");
                }
                offset += written;
            }
            if (!FlushFileBuffers(output)) throw std::runtime_error("protected metadata pending flush failed");
            publish_record_no_replace(output, parent, name, service_sid,
                publication_hooks ? &before_issue : nullptr);
            if (publication_hooks) publication_hooks->confirm(path, content, output);
            require_alias_mapping();
        } catch (...) {
            if (publication_hooks) publication_hooks->failed(path);
            throw;
        }
    }

    void persist_journal(const fs::path& path, const std::string& content,
        const std::string& predecessor, bool first) {
        require_active_publisher_effect_fence();
        if (initializing || !publication_hooks || public_alias.empty() || journal_publication_unconfirmed ||
            content.empty() || content.size() > 4u * 1024u * 1024u || first != predecessor.empty())
            throw std::runtime_error("protected original maintenance journal writer unavailable");
        const auto name = path.filename().wstring();
        if (!is_publisher_canonical_component(name))
            throw std::runtime_error("protected journal name is invalid");
        auto held = parents(path.parent_path());
        HANDLE parent = held.empty() ? root->get() : held.back().get();
        const auto parent_before = observe_publisher_directory_handle(parent);
        require_publisher_object_security_shape(parent_before, service_sid);
        const auto original = find_child(parent, name);
        if (first != !original)
            throw std::runtime_error("protected journal initial/existing namespace differs");
        std::unique_ptr<OwnedHandle> prior;
        PublisherHandleObservation prior_facts{};
        if (original) {
            prior = std::make_unique<OwnedHandle>(open_publisher_listed_child(parent, *original));
            prior_facts = observe_publisher_file_handle(prior->get());
            require_publisher_object_security_shape(prior_facts, service_sid);
            if (held_journal_sha256(prior->get()) != predecessor)
                throw std::runtime_error("protected journal predecessor differs from original session");
        }
        // Keep the actual new creation handle until publication and complete
        // readback. This path never borrows the installed-record effect hook.
        if (!pending) {
            if (const auto existing = find_child(root->get(), L"pending"))
                pending = std::make_unique<OwnedHandle>(open_publisher_listed_child(root->get(), *existing, true, false, true));
            else pending = std::make_unique<OwnedHandle>(create_record_directory_relative_with_descriptor(root->get(), L"pending", descriptor));
            require_publisher_tree_security_shape(observe_publisher_tree(pending->get()), service_sid);
        }
        static std::atomic<unsigned long long> sequence{0};
        const auto temporary = L"journal-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(++sequence);
        OwnedHandle file(create_file_relative_with_descriptor(pending->get(), temporary, descriptor));
        const auto created = observe_publisher_file_handle(file.get());
        require_publisher_object_security_shape(created, service_sid);
        std::size_t offset = 0;
        while (offset < content.size()) {
            require_active_publisher_effect_fence();
            const auto count = static_cast<DWORD>(std::min<std::size_t>(64u * 1024u, content.size() - offset));
            DWORD written = 0;
            if (!WriteFile(file.get(), content.data() + offset, count, &written, nullptr) || written != count)
                throw std::runtime_error("protected journal pending write failed; material retained");
            offset += written;
        }
        require_active_publisher_effect_fence();
        if (!FlushFileBuffers(file.get()))
            throw std::runtime_error("protected journal pending flush failed; material retained");
        base::Sha256 expected;
        expected.update(reinterpret_cast<const unsigned char*>(content.data()), content.size());
        const auto postimage = expected.finish();
        if (held_journal_sha256(file.get()) != postimage)
            throw std::runtime_error("protected journal creator bytes differ; material retained");
        const auto current = find_child(parent, name);
        if (first ? static_cast<bool>(current) : (!current || current->file_id != original->file_id))
            throw std::runtime_error("protected journal predecessor namespace changed");
        if (prior && (json::canonical(publisher_handle_observation_json(observe_publisher_file_handle(prior->get()))) !=
                json::canonical(publisher_handle_observation_json(prior_facts)) ||
            held_journal_sha256(prior->get()) != predecessor))
            throw std::runtime_error("protected journal held predecessor changed");
        if (json::canonical(publisher_handle_observation_json(observe_publisher_directory_handle(parent))) !=
            json::canonical(publisher_handle_observation_json(parent_before)))
            throw std::runtime_error("protected journal parent changed");
        const auto before_issue = observe_publisher_file_handle(file.get());
        require_publisher_object_security_shape(before_issue, service_sid);
        if (before_issue.file_id != created.file_id ||
            before_issue.native_name != created.native_name)
            throw std::runtime_error("protected journal creator identity changed");
        using RenameFn = NTSTATUS (NTAPI *)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
        auto* rename = reinterpret_cast<RenameFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile"));
        if (!rename) throw std::runtime_error("protected journal native rename unavailable");
        PublisherRenameInformation information(parent, name);
        static_cast<FILE_RENAME_INFO*>(information.data())->ReplaceIfExists = first ? FALSE : TRUE;
        IO_STATUS_BLOCK io{};
        require_alias_mapping_and_effect_fence();
        // Classic FileRenameInformation cannot replace an open target data
        // stream. Release this verified predecessor exactly once under the
        // retained protected parent and original single-owner operation fence.
        // The creator stays held; this is not an atomic compare-and-swap claim.
        if (prior && !prior->close_once()) {
            journal_publication_unconfirmed = true;
            throw std::runtime_error("protected journal predecessor close unconfirmed; no publication issued");
        }
        const auto final_target = find_child(parent, name);
        if (first ? static_cast<bool>(final_target) : (!final_target || final_target->file_id != original->file_id))
            throw std::runtime_error("protected journal predecessor namespace changed after release");
        if (json::canonical(publisher_handle_observation_json(observe_publisher_directory_handle(parent))) !=
            json::canonical(publisher_handle_observation_json(parent_before)))
            throw std::runtime_error("protected journal parent changed after predecessor release");
        require_alias_mapping_and_effect_fence();
        journal_publication_unconfirmed = true;
        const auto status = rename(file.get(), &io, information.data(), information.size(),
            static_cast<FILE_INFORMATION_CLASS>(10));
        if (status != 0 || io.Status != 0)
            throw PublisherRenameUnconfirmed("protected journal publication unconfirmed; native status " +
                std::to_string(static_cast<unsigned long>(status)) + "; IO status " +
                std::to_string(static_cast<unsigned long>(io.Status)));
        const auto after = observe_publisher_file_handle(file.get());
        require_publisher_object_security_shape(after, service_sid);
        const auto published = find_child(parent, name);
        if (!published) throw PublisherRenameUnconfirmed("protected journal published name is absent");
        OwnedHandle visible(open_publisher_listed_child(parent, *published));
        if (json::canonical(publisher_handle_observation_json(observe_publisher_file_handle(visible.get()))) !=
                json::canonical(publisher_handle_observation_json(after)) || after.file_id != created.file_id ||
            after.native_name != parent_before.native_name + L"\\" + name ||
            held_journal_sha256(file.get()) != postimage ||
            json::canonical(publisher_handle_observation_json(observe_publisher_directory_handle(parent))) !=
                json::canonical(publisher_handle_observation_json(parent_before)))
            throw PublisherRenameUnconfirmed("protected journal actual publication postimage differs");
        if (!FlushFileBuffers(file.get())) throw PublisherRenameUnconfirmed("protected journal published flush unconfirmed");
        require_alias_mapping_and_effect_fence();
        journal_publication_unconfirmed = false;
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
        // Record parents are held without DELETE. Release descendants and
        // rebind the source with DELETE only for this publication transition.
        pending.reset();
        root.reset();
        const auto source = find_child(volume, root_name);
        if (!source) throw std::runtime_error("private metadata root disappeared before publication");
        root = std::make_unique<OwnedHandle>(open_publisher_listed_child(volume, *source, true, true, true));
        require_publisher_tree_phase_match(tree, observe_publisher_tree(root->get()));
        probe_publisher_bound_rename_no_replace(root->get(), volume,
            final_root_path.filename().wstring(), tree.root, parent);
        root_path = final_root_path;
        root_name = root_path.filename().wstring();
        const auto visible = observe_publisher_tree(root->get());
        const std::wstring expected_visible = parent.native_name +
            (parent.native_name.back() == L'\\' ? L"" : L"\\") + root_name;
        require_publisher_tree_phase_match(tree, visible, expected_visible);
        root.reset();
        const auto published = find_child(volume, root_name);
        if (!published) throw std::runtime_error("published metadata root disappeared before record reentry");
        root = std::make_unique<OwnedHandle>(open_publisher_listed_child(volume, *published, true, false, true));
        require_publisher_tree_phase_match(visible, observe_publisher_tree(root->get()));
        initializing = false;
    }
};

PublisherMetadataSession::PublisherMetadataSession(HANDLE volume, const std::wstring& guid,
    const fs::path& root, const std::wstring& service, bool require_existing, const fs::path& public_alias)
    : impl_(std::make_unique<Impl>(volume, guid, root, service, require_existing, public_alias)) {}
PublisherMetadataSession::~PublisherMetadataSession() = default;
void PublisherMetadataSession::bind_native_maintenance_publication(detail::MetadataRecordPublicationHooks hooks) {
    require_active_publisher_effect_fence();
    if (impl_->publication_hooks || impl_->initializing || impl_->public_alias.empty() ||
        !hooks.prepare || !hooks.created || !hooks.before_issue || !hooks.confirm || !hooks.failed)
        throw std::runtime_error("native maintenance metadata publication binding unavailable");
    impl_->publication_hooks = std::make_unique<detail::MetadataRecordPublicationHooks>(std::move(hooks));
}
void PublisherMetadataSession::persist_maintenance_journal(const fs::path& path,
    const std::string& content, const std::string& predecessor, bool first) {
    impl_->persist_journal(path, content, predecessor, first);
}
const fs::path& PublisherMetadataSession::initialization_root() const { return impl_->root_path; }
void PublisherMetadataSession::publish_initialized_root() { impl_->publish_initialized_root(); }
} // namespace usk::platform::windows
#endif
