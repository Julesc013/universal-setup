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

// These first commands are read-only and have no state-root or endpoint effect.
OneShotResult run_one_shot(const std::string& request_json);
OneShotResult invalid_frame_result();
std::string read_bounded_request(std::istream& input, bool length_prefixed);
void write_result(std::ostream& output, const std::string& document, bool length_prefixed);

} // namespace usk::command

#endif
