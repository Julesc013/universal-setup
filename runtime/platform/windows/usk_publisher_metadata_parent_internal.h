// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_METADATA_PARENT_INTERNAL_H
#define USK_PUBLISHER_METADATA_PARENT_INTERNAL_H

#include "usk_publisher_handle_observation.h"
#if defined(_WIN32)
#include <atomic>
#include <vector>

namespace usk::platform::windows::detail {
// Borrowed capabilities and immutable comparison expectations only. This
// read-only primitive cannot admit an operation or replace an effect fence.
// The owning metadata session must outlive this object and every observe().
struct MetadataParentComponent {
    std::wstring name;
    HANDLE handle;
    PublisherHandleObservation expected;
    std::uint32_t granted_access;
};
class MetadataParentRead final {
public:
    static constexpr std::size_t maximum_components = 3;
    MetadataParentRead(HANDLE root, PublisherHandleObservation expected_root,
        std::uint32_t root_access, std::vector<MetadataParentComponent> components);
    MetadataParentRead(const MetadataParentRead&) = delete;
    MetadataParentRead& operator=(const MetadataParentRead&) = delete;
    // Returns the same borrowed parent only after fresh complete native joins.
    // The caller must still complete its original pre-effect authority fence.
    HANDLE observe() const;
private:
    void require_current() const;
    HANDLE root_;
    PublisherHandleObservation root_expected_;
    std::uint32_t root_access_;
    std::vector<MetadataParentComponent> components_;
    const DWORD process_ = GetCurrentProcessId(), thread_ = GetCurrentThreadId();
    mutable std::atomic<bool> failed_{false};
};
} // namespace usk::platform::windows::detail
#endif
#endif
