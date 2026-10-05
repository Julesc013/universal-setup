// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_SECURITY_DESCRIPTOR_H
#define USK_PUBLISHER_SECURITY_DESCRIPTOR_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <vector>

namespace usk::platform::windows {

DWORD publisher_directory_access_mask();
DWORD publisher_consumer_read_access_mask();
// Bounded stored owner/DACL bytes from the already-held object. This reads
// SE_DACL_PROTECTED without Win32 file-security normalization. It grants no
// authority; callers still admit the owner, ACEs, identity and namespace.
std::vector<unsigned char> read_publisher_owner_dacl_from_handle(HANDLE object);

// Canonical domain/local account-form SID for read-only registration discovery.
// Includes built-in account RIDs; independent TokenUser/registration checks
// still bind the actual caller. This grants no consumer access or authority.
void require_publisher_registered_account_sid(const std::string& sid);

// Canonical account-form SID; rejects privileged built-ins and service SIDs.
// Actual account identity/group membership require independent TokenUser proof.
void require_publisher_consumer_sid(const std::string& sid);

// Builds a self-relative owner SYSTEM, protected-DACL descriptor with exactly
// SYSTEM and the supplied Windows service SID as allow ACEs. The caller must
// independently bind the SID to a restricted SCM service and create each
// anchor from inception under a protected parent. Building this descriptor
// grants no authority and does not enable strict publication.
std::vector<unsigned char> make_publisher_directory_security_descriptor(
    const std::wstring& service_sid);

// Controller admission only: update the exact held boundary object through
// the native security primitive, without Win32 descendant ACL propagation.
// The caller independently admits the descriptor, root identity and target.
void set_publisher_boundary_security_from_handle(HANDLE boundary,
    const std::vector<unsigned char>& descriptor);

// Controller metadata admission only. Derive the protected poststate by
// adding SE_DACL_PROTECTED to the exact held original owner/DACL descriptor.
// Preserves owner and ACE bytes, and does not propagate to descendants. The
// caller binds the trusted metadata namespace and durable original/poststate.
void protect_publisher_metadata_dacl_from_handle(HANDLE metadata,
    const std::vector<unsigned char>& original);

// Only the visible payload may receive this explicit, non-inherited read/execute
// ACE. Private anchors retain the descriptor above. Caller must bind the reader
// durably and revalidate the published closure before applying the descriptor.
std::vector<unsigned char> make_publisher_consumer_security_descriptor(
    const std::wstring& service_sid, const std::string& consumer_sid);

} // namespace usk::platform::windows
#endif

#endif
