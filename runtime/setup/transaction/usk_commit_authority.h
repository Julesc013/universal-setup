// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_COMMIT_AUTHORITY_H
#define USK_COMMIT_AUTHORITY_H

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace usk::transaction {
enum class CommitAuthorityRequirement { legacy_observed, staged_child_bound_v1 };
class CommitAuthorityUnavailable final : public std::runtime_error {
public:
    CommitAuthorityUnavailable() : std::runtime_error(
        "staged_child_bound_v1 requires protected namespace authority unavailable on this host; no fallback") {}
};
// An explicit requirement, never a caller-supplied capability or permission token.
const char* commit_authority_name(CommitAuthorityRequirement requirement);
void require_commit_authority(CommitAuthorityRequirement requirement);

struct CommitClosureFile {
    std::filesystem::path relative_path;
    std::string sha256;
    std::uint64_t size_bytes = 0;
    std::string stream_output_identity;
};
// Bounded observations only. Closed handles and numeric identities cannot establish
// ownership, prevent additions, or provide atomic authority through publication.
using CommitClosureObservation = std::map<std::string, std::string>;
inline constexpr std::size_t maximum_commit_closure_entries = 200000u;
inline constexpr std::size_t maximum_commit_closure_depth = 128u;
CommitClosureObservation observe_commit_closure(const std::filesystem::path& root,
    const std::vector<CommitClosureFile>& files);
} // namespace usk::transaction
#endif
