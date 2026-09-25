// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_TREE_OBSERVATION_H
#define USK_PUBLISHER_TREE_OBSERVATION_H

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>

#include "usk_publisher_handle_observation.h"
#include "usk_publisher_volume_stream_observation.h"

#include <cstdint>
#include <string>
#include <vector>

namespace usk::platform::windows {

struct PublisherTreeEntry {
    std::wstring relative_path;
    PublisherHandleObservation object;
    std::uint64_t size;
    std::string sha256;
    std::vector<PublisherStreamObservation> streams;
};

struct PublisherTreeObservation {
    PublisherVolumeObservation volume;
    PublisherHandleObservation root;
    std::vector<PublisherStreamObservation> root_streams;
    std::vector<PublisherTreeEntry> descendants;
};

struct PublisherDirectoryChainLink {
    std::wstring component;
    PublisherHandleObservation object;
};

struct PublisherDirectoryChainObservation {
    PublisherVolumeObservation volume;
    PublisherHandleObservation boundary;
    std::vector<PublisherDirectoryChainLink> children;
};

struct PublisherAnchorNames {
    std::wstring staging;
    std::wstring destination_parent;
    std::wstring state;
    std::wstring journal;
};

struct PublisherAnchorSetObservation {
    PublisherDirectoryChainObservation chain;
    PublisherDirectoryChainLink staging;
    PublisherDirectoryChainLink destination_parent;
    PublisherDirectoryChainLink state;
    PublisherDirectoryChainLink journal;
};

// Read-only candidate closure of namespace, identity, same-handle security
// facts, streams, and file bytes. Protected-security admission, effective
// rights, anchor facts, and phase equality are separate obligations.
PublisherTreeObservation observe_publisher_tree(HANDLE root);

// Consistency oracle for two independently observed phases. A non-empty
// visible_root_name permits only the expected root-prefix path transition;
// callers must derive that name from separately bound parent evidence.
void require_publisher_tree_phase_match(
    const PublisherTreeObservation& sealed,
    const PublisherTreeObservation& observed,
    const std::wstring& visible_root_name = {});

// Necessary exact owner/protected-DACL/ACE predicate over independently
// observed root and descendant facts. A matching structure is not proof of
// SCM restricted-service identity, effective rights, or handle provenance.
void require_publisher_tree_security_shape(
    const PublisherTreeObservation& tree, const std::string& service_sid);

// Reopen one exact visible component relative to a retained destination-parent
// handle, freshly observe its tree, and compare it with the sealed tree. This
// is a read-only consistency candidate, not protected-parent admission.
PublisherTreeObservation observe_visible_publisher_tree_against_seal(
    HANDLE destination_parent, const std::wstring& destination_component,
    const PublisherTreeObservation& sealed);

// Follow exact, enumerated directory components from one held boundary. All
// parent handles stay open until their descendants have been observed and
// each is rechecked on unwind. This does not admit the boundary as a protected
// volume root or establish effective rights and service provenance.
PublisherDirectoryChainObservation observe_publisher_directory_chain(
    HANDLE boundary, const std::vector<std::wstring>& components);

void require_publisher_directory_chain_phase_match(
    const PublisherDirectoryChainObservation& earlier,
    const PublisherDirectoryChainObservation& later);

void require_publisher_directory_chain_security_shape(
    const PublisherDirectoryChainObservation& chain,
    const std::string& service_sid);

// Observe the four distinct sibling anchors while the complete parent chain
// is still held. The supplied boundary is not independently qualified as a
// protected volume root; this is a read-only role-closure candidate.
PublisherAnchorSetObservation observe_publisher_anchor_set(
    HANDLE boundary, const std::vector<std::wstring>& ancestor_components,
    const PublisherAnchorNames& names);

void require_publisher_anchor_set_phase_match(
    const PublisherAnchorSetObservation& earlier,
    const PublisherAnchorSetObservation& later);

void require_publisher_anchor_set_security_shape(
    const PublisherAnchorSetObservation& set,
    const std::string& service_sid);

} // namespace usk::platform::windows
#endif

#endif
