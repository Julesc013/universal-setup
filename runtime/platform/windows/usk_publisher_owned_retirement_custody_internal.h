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

namespace usk::platform::windows {

// Bytes obtained from the actual protected target. This is metadata, never a
// retirement certificate: complete domain/history validation remains mandatory.
struct PublisherRetirementRecord {
    std::wstring relative_path;
    PublisherHandleObservation object;
    std::string bytes;
    std::string sha256;
};

// Administrative, existing-only custody for the fixed owned-uninstall route.
// Registration, SCM, image, volume and every observed metadata handle remain
// private. Construction and observation cannot delete SCM or the executable.
// This component is not yet a callable owned-retirement implementation.
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
    // The lifecycle owner must derive the complete installation set, acquire
    // these guards in order and validate every operation before final effects.
    // Partial acquisition or any observation failure permanently poisons custody.
    void acquire_installations(const std::vector<std::string>& sorted_install_ids);
    void require_unchanged();
private:
    struct State;
    std::unique_ptr<State> state_;
};
}
#endif
#endif
