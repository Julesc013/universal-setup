// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_OWNED_RETIREMENT_CUSTODY_INTERNAL_H
#define USK_PUBLISHER_OWNED_RETIREMENT_CUSTODY_INTERNAL_H
#if defined(_WIN32)
#include "usk_json.h"
#include "usk_publisher_handle_observation.h"
#include <memory>
#include <string>
#include <vector>

namespace usk::lifecycle::detail {
// Defined only by the fixed domain route, never a caller-provided callback.
void retire_owned_publisher(const std::wstring& service_name);
}

namespace usk::platform::windows {

// Bytes obtained from the actual protected target. This is metadata, never a
// retirement certificate: complete domain/history validation remains mandatory.
struct PublisherRetirementRecord {
    std::wstring relative_path;
    PublisherHandleObservation object;
    std::string bytes;
    std::string sha256;
};

// Actual identities from one original held directory, for the existing lease
// and transaction metadata codecs. These are observations, not authority.
struct PublisherRetirementDirectoryMetadata {
    PublisherHandleObservation object;
    usk::json::Value lease_root_identity;
    std::string journal_identity;
};

// Administrative, existing-only custody for the fixed owned-uninstall route.
// Registration, SCM, image, volume and every observed metadata handle remain
// private. Construction and observation cannot delete SCM or the executable.
// Its private effects are reachable only through the fixed lifecycle/domain
// route, never serialized metadata, a boolean verdict or a callback.
// The actual elevated administrator is distinct from the configured consumer;
// canonical consumer/SCM bindings do not require elevating that consumer.
// Record bytes: at most16MiB per file and64MiB in total. Native entry/depth
// and separately accounted evidence bounds are not a total-memory ceiling.
// Complete retained listings and one recheck share a64MiB accounting budget.
// Installation IDs are preflighted (200000 IDs,128 bytes each,1MiB aggregate).
// Construct, use and destroy on the originating thread; cleanup is not a
// successful validation or a cross-thread mutex-release confirmation.
class PublisherOwnedRetirementCustody final {
public:
    explicit PublisherOwnedRetirementCustody(const std::wstring& service_name);
    ~PublisherOwnedRetirementCustody();
    PublisherOwnedRetirementCustody(const PublisherOwnedRetirementCustody&) = delete;
    PublisherOwnedRetirementCustody& operator=(const PublisherOwnedRetirementCustody&) = delete;
    PublisherOwnedRetirementCustody(PublisherOwnedRetirementCustody&&) = delete;
    PublisherOwnedRetirementCustody& operator=(PublisherOwnedRetirementCustody&&) = delete;

    const usk::json::Value& registration() const;
    const std::wstring& volume_root() const;
    const std::vector<PublisherRetirementRecord>& records() const;
    const std::vector<std::wstring>& directories() const;
    // Exact existing member (empty means admitted root); no path is reopened.
    // Fresh local same-handle identity/security checks bracket both codecs.
    PublisherRetirementDirectoryMetadata observe_directory_metadata(const std::wstring& relative_path);
    // The lifecycle owner must derive the complete installation set, acquire
    // these guards in order and validate every operation before final effects.
    // Partial acquisition or any observation failure permanently poisons custody.
    void acquire_installations(const std::vector<std::string>& sorted_install_ids);
    void require_unchanged();
private:
    friend void usk::lifecycle::detail::retire_owned_publisher(const std::wstring&);
    // Only the fixed lifecycle owner may call after its complete domain proof.
    // Revalidate the original custody before each native effect. A pending SCM
    // deletion keeps the image; uncertain disposition/close requires a fresh
    // invocation to establish actual absence, never an assumed rollback.
    void retire_after_owned_validation();
    struct State;
    std::unique_ptr<State> state_;
};
}
#endif
#endif
