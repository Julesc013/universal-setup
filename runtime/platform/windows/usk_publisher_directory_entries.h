// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_DIRECTORY_ENTRIES_H
#define USK_PUBLISHER_DIRECTORY_ENTRIES_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "usk_publisher_handle_observation.h"

namespace usk::lifecycle::detail { class NativeMaintenanceContext; }

namespace usk::platform::windows {

struct PublisherDirectoryEntry {
    std::wstring name;
    std::array<std::uint8_t, 16> file_id;
    std::uint32_t attributes;
    std::uint32_t reparse_tag;
    std::int64_t listing_size;
};

// Exact canonical component rule used for both live names and recorded
// assertions. A true result alone does not establish that the child exists.
bool is_publisher_canonical_component(const std::wstring& name);

// Generated maintenance names are a separate internal grammar. This data
// predicate grants no ownership, mutation, publication or recovery authority.
bool is_publisher_generated_maintenance_component(const std::wstring& name,
    const std::string& transaction_id, const std::string& operation, bool staging);

// Only the concrete native owner binds these two generated names to actual
// retained parents. Ordinary payload/profile components keep their existing
// canonical rule. This object grants name admission only, never effects.
class PublisherMaintenanceNames final {
public:
    PublisherMaintenanceNames(const PublisherMaintenanceNames&) = delete;
    PublisherMaintenanceNames& operator=(const PublisherMaintenanceNames&) = delete;
    bool allows(HANDLE parent, const std::wstring& name) const;
    bool allows_native_path(const std::wstring& path) const;
private:
    friend class usk::lifecycle::detail::NativeMaintenanceContext;
    PublisherMaintenanceNames(HANDLE staging_parent, HANDLE target_parent,
        const std::string& transaction_id, const std::string& operation);
    struct Binding {
        HANDLE parent;
        PublisherHandleObservation facts;
        std::wstring name;
    };
    std::vector<Binding> bindings_;
};
bool is_publisher_admitted_component(HANDLE parent, const std::wstring& name,
    const PublisherMaintenanceNames* maintenance_names = nullptr);

// Read-only enumeration from one held directory handle. The returned 128-bit
// IDs and listing attributes are untrusted observations until each child is
// independently reopened relative to this parent and verified on that handle.
std::vector<PublisherDirectoryEntry> observe_publisher_directory_entries(
    HANDLE directory, std::size_t byte_budget = 64 * 1024 * 1024,
    const PublisherMaintenanceNames* maintenance_names = nullptr);

// Open one listed child relative to the retained parent handle without
// following a reparse point. The caller owns and must CloseHandle the result.
// Listing size is provisional; the returned handle must supply content facts.
// Publication parents may request FILE_ADD_SUBDIRECTORY. A recovery worker
// may request DELETE on the staged directory it must publish. Both retain
// the same no-follow, parent-relative identity check.
HANDLE open_publisher_listed_child(HANDLE parent,
    const PublisherDirectoryEntry& listed,
    bool require_add_subdirectory = false, bool require_delete = false,
    bool require_add_file = false, bool require_write_dac = false,
    bool backup_observation = false,
    const PublisherMaintenanceNames* maintenance_names = nullptr);

// Private maintenance open for a listed regular file. Requests read and
// DELETE only, preserving the original no-follow/128-bit listing/parent
// checks. Caller retains native operation custody; this grants no effect.
HANDLE open_publisher_listed_maintenance_file(HANDLE parent,
    const PublisherDirectoryEntry& listed);

// Separate controller admission route for the exact listed Windows metadata
// directory. Requires scoped backup/restore privileges and durable target
// intent; requests WRITE_DAC, never data/name mutation or WRITE_OWNER.
HANDLE open_publisher_metadata_dacl_child(HANDLE parent,
    const PublisherDirectoryEntry& listed);

} // namespace usk::platform::windows
#endif

#endif
