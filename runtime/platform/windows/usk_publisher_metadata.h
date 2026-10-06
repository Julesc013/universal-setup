// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_METADATA_H
#define USK_PUBLISHER_METADATA_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>

namespace usk::platform::windows {

// Internal, operation-local fence. Only a live service lease supplies this
// check; JSON and public callers cannot install or activate it. The borrowed
// callback and lease must outlive this scope on the owning thread.
class ScopedPublisherEffectFence final {
public:
    explicit ScopedPublisherEffectFence(const std::function<void()>& check);
    ~ScopedPublisherEffectFence();
    ScopedPublisherEffectFence(const ScopedPublisherEffectFence&) = delete;
    ScopedPublisherEffectFence& operator=(const ScopedPublisherEffectFence&) = delete;
    ScopedPublisherEffectFence(std::function<void()>&&) = delete;
};
void require_current_publisher_effect_fence();
// Mandatory for new native maintenance effects; absence is a refusal.
void require_active_publisher_effect_fence();

// Publish an already flushed, privately created protected record, relative
// to a retained protected parent. No replacement or path-based reopen.
void publish_publisher_record_no_replace(HANDLE file, HANDLE parent,
    const std::wstring& name, const std::string& service_sid);

// Internal restricted-service backend for setup metadata. Every new directory
// and record receives its protected descriptor at creation. Records are flushed
// in a separate pending directory before parent-bound no-replace publication.
// Caller must bind the volume/namespace and operation; this does not admit a
// production publisher profile or grant a public client filesystem authority.
class PublisherMetadataSession {
public:
    PublisherMetadataSession(HANDLE volume_root, const std::wstring& volume_guid_root,
        const std::filesystem::path& physical_setup_root, const std::wstring& service_name,
        bool require_existing = false);
    ~PublisherMetadataSession();
    PublisherMetadataSession(const PublisherMetadataSession&) = delete;
    PublisherMetadataSession& operator=(const PublisherMetadataSession&) = delete;
    const std::filesystem::path& initialization_root() const;
    void publish_initialized_root();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace usk::platform::windows
#endif
#endif
