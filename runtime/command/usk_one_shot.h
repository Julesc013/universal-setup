// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_ONE_SHOT_H
#define USK_ONE_SHOT_H

#include <iosfwd>
#include <functional>
#include <string>

namespace usk::command {

inline constexpr std::size_t max_request_bytes = 1024u * 1024u;
inline constexpr std::size_t max_response_bytes = 16u * 1024u * 1024u;

struct OneShotResult {
    std::string document;
    std::string diagnostic;
    int exit_code = 2;
};

struct OneShotContextConfig {
    std::string state_root;
    std::string authorized_acceptance_root;
    std::string target_policy_activation;
};

// Planning inspects an explicitly accepted target and source but makes no changes.
OneShotResult run_one_shot(const std::string& request_json,
                           const OneShotContextConfig* context_config = nullptr);
// The candidate transport is supplied only by a caller that has selected an
// authenticated restricted service. The service revalidates all effect inputs.
using CandidateTransport = std::function<std::string(const std::string&)>;
OneShotResult run_candidate_one_shot(const std::string& request_json,
                                     const CandidateTransport& transport);
// Return the public command response through an admitted publisher transport.
// Retained native phase evidence belongs to qualification records, not the
// ordinary machine result. publisher.inspect is read-only discovery of an
// already admitted registration; it grants no authority, holds no execution
// lease, and reports incomplete qualification/unsupported strict availability.
// This does not make an unqualified profile available.
OneShotResult run_publisher_one_shot(const std::string& request_json,
                                   const CandidateTransport& transport);
OneShotContextConfig read_context_config(std::istream& input);
OneShotResult invalid_frame_result();
OneShotResult invalid_context_result();
std::string read_bounded_request(std::istream& input, bool length_prefixed);
void write_result(std::ostream& output, const std::string& document, bool length_prefixed);

} // namespace usk::command

#endif
