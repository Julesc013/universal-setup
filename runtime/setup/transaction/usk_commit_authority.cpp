// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_commit_authority.h"
#include "usk_transaction_session.h"
#include "usk_stable_file.h"
#include <set>

namespace fs = std::filesystem;
namespace usk::transaction {
const char* commit_authority_name(CommitAuthorityRequirement requirement) {
    switch (requirement) {
    case CommitAuthorityRequirement::legacy_observed: return "legacy_observed";
    case CommitAuthorityRequirement::staged_child_bound_v1: return "staged_child_bound_v1";
    }
    throw std::runtime_error("unknown commit authority requirement");
}
void require_commit_authority(CommitAuthorityRequirement requirement) {
    (void)commit_authority_name(requirement);
    if (requirement == CommitAuthorityRequirement::staged_child_bound_v1) {
        // No independently protected namespace publisher is qualified. Observing a
        // root, held file handles, ACLs, or journal IDs must never enable success.
        throw CommitAuthorityUnavailable();
    }
}
CommitClosureObservation observe_commit_closure(const fs::path& root,
    const std::vector<CommitClosureFile>& files) {
    if (files.size() > maximum_commit_closure_entries) throw std::runtime_error("commit closure entry budget exceeded");
    std::set<std::string> expected_files, expected_directories;
    for (const auto& file : files) {
        const auto relative = file.relative_path.generic_string();
        if (file.relative_path.empty() || file.relative_path.is_absolute() ||
            !expected_files.insert(relative).second) throw std::runtime_error("invalid commit closure path");
        if (expected_files.size() + expected_directories.size() > maximum_commit_closure_entries) {
            throw std::runtime_error("commit closure entry budget exceeded");
        }
        std::size_t depth = 0;
        for (const auto& component : file.relative_path) {
            if (component == "." || component == ".." || ++depth > maximum_commit_closure_depth) {
                throw std::runtime_error("commit closure path depth or traversal refused");
            }
        }
        for (auto parent = file.relative_path.parent_path(); !parent.empty(); parent = parent.parent_path()) {
            expected_directories.insert(parent.generic_string());
            if (expected_files.size() + expected_directories.size() > maximum_commit_closure_entries) {
                throw std::runtime_error("commit closure entry budget exceeded");
            }
        }
    }
    CommitClosureObservation result;
    result.emplace("D:", observe_directory_identity(root));
    std::vector<fs::path> pending{root};
    std::size_t observed = 0;
    while (!pending.empty()) {
        const auto directory = pending.back(); pending.pop_back();
        for (const auto& entry : fs::directory_iterator(directory)) {
            if (++observed > maximum_commit_closure_entries) throw std::runtime_error("commit closure observation budget exceeded");
            const auto relative = entry.path().lexically_relative(root).generic_string();
            const auto status = entry.symlink_status();
            if (fs::is_directory(status)) {
                if (expected_directories.count(relative) == 0) throw std::runtime_error("commit refuses an unrecorded directory");
                result.emplace("D:" + relative, observe_directory_identity(entry.path()));
                pending.push_back(entry.path());
            } else if (!fs::is_regular_file(status) || expected_files.count(relative) == 0) {
                throw std::runtime_error("commit refuses linked, unsupported, or unrecorded content");
            }
        }
    }
    if (observed != expected_files.size() + expected_directories.size()) {
        throw std::runtime_error("commit closure has missing or duplicate paths");
    }
    for (const auto& expected : files) {
        base::StableFile actual(root / expected.relative_path);
        const auto identity = actual.identity().volume_id + ":" + actual.identity().file_id;
        if ((!expected.stream_output_identity.empty() && identity != expected.stream_output_identity) ||
            actual.identity().size_bytes != expected.size_bytes || actual.sha256_hex() != expected.sha256) {
            throw std::runtime_error("commit preparation refuses changed staged child identity or bytes");
        }
        actual.verify_unchanged();
        result.emplace("F:" + expected.relative_path.generic_string(), identity);
    }
    return result;
}
} // namespace usk::transaction
