// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_CREATION_OBSERVATION_H
#define USK_PUBLISHER_CREATION_OBSERVATION_H

#if defined(_WIN32)
#include "usk_json.h"
#include "usk_publisher_handle_observation.h"
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace usk::platform::windows {

struct PublisherCreationParentObservation {
    PublisherHandleObservation parent;
};

struct PublisherCreationCallObservation {
    std::uint32_t desired_access;
    std::uint32_t object_attribute_flags;
    std::uint32_t create_disposition;
    std::uint32_t create_options;
    std::uint32_t share_access;
    std::uint32_t file_attributes;
    std::uint32_t ntstatus;
    std::uint64_t creation_result;
};

// Internal thread-scoped capture of successful native FILE_CREATE calls.
// Admission requires the actual restricted service and a held volume boundary.
// Reopened objects never acquire a creation observation. No handles are copied,
// inherited or duplicated by this recorder; it observes the supplied handles.
// This does not enumerate capabilities outside the service or qualify a profile.
class PublisherCreationCapture final {
public:
    PublisherCreationCapture(HANDLE boundary, const std::wstring& service_name);
    ~PublisherCreationCapture();
    PublisherCreationCapture(const PublisherCreationCapture&) = delete;
    PublisherCreationCapture& operator=(const PublisherCreationCapture&) = delete;
    usk::json::Value certificate(const usk::json::Value& anchors,
        const usk::json::Value& sealed_tree, const usk::json::Value& execution) const;
private:
    struct Implementation;
    std::unique_ptr<Implementation> implementation_;
    friend std::optional<PublisherCreationParentObservation> prepare_publisher_creation_observation(
        HANDLE, const std::vector<unsigned char>&);
    friend void finish_publisher_creation_observation(
        const std::optional<PublisherCreationParentObservation>&, HANDLE, HANDLE,
        const std::wstring&, bool, const PublisherCreationCallObservation&);
};

// Called immediately before/after the native primitive, only when its optional
// service capture is active. The primitive checks actual NTSTATUS/FILE_CREATED,
// create-only disposition, RootDirectory and creation-time descriptor first.
std::optional<PublisherCreationParentObservation> prepare_publisher_creation_observation(
    HANDLE parent, const std::vector<unsigned char>& descriptor);
void finish_publisher_creation_observation(
    const std::optional<PublisherCreationParentObservation>& before,
    HANDLE parent, HANDLE created, const std::wstring& name, bool directory,
    const PublisherCreationCallObservation& call);

// Deterministic graph projection/retained-record validation. These functions
// validate bindings, not native creation or publisher authority by themselves.
usk::json::Value publisher_creation_graph(
    const usk::json::Value& anchors, const usk::json::Value& tree);
void require_publisher_creation_certificate(
    const usk::json::Value& certificate, const usk::json::Value& anchors,
    const usk::json::Value& tree, const usk::json::Value& execution);
} // namespace usk::platform::windows
#endif
#endif
