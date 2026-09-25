// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_ONE_SHOT_H
#define USK_ONE_SHOT_H

#include <iosfwd>
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
OneShotContextConfig read_context_config(std::istream& input);
OneShotResult invalid_frame_result();
OneShotResult invalid_context_result();
std::string read_bounded_request(std::istream& input, bool length_prefixed);
void write_result(std::ostream& output, const std::string& document, bool length_prefixed);

} // namespace usk::command

#endif
