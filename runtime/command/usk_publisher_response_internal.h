// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_RESPONSE_INTERNAL_H
#define USK_PUBLISHER_RESPONSE_INTERNAL_H
#include "usk_json.h"
#include <cstddef>
#include <string>

namespace usk::command::detail {
inline constexpr std::size_t publisher_response_max_bytes = 16u * 1024u * 1024u;
bool safe_id(const std::string&);
bool lower_hex(const std::string&, std::size_t);
const char* publisher_operation_error_code(const usk::json::Value&);
usk::json::Value publisher_operation_diagnostic(const usk::json::Value&, const char*);

// Correlate the complete native public recovery response, including its
// independently versioned native binding and requested action. Pure decoding;
// the transport still authenticates the endpoint and live server identity.
// Pure document projection from already acquired native observations. It
// conveys no custody, liveness or authority; the engine must supply and finish
// its concrete inspector before exposing the result or considering an action.
usk::json::Value public_native_recovery_document(const usk::json::Value& inspection,
    const usk::json::Value& binding, const usk::json::Value* plan_request);
void require_public_native_recovery_response(const usk::json::Value& submitted,
    const usk::json::Value& observation);
// Correlates the complete request and original registered endpoint; no digest
// of a public projection is substituted for the native plan digest.
void require_public_install_plan_response(const usk::json::Value& submitted,
    const usk::json::Value& observation);

enum class PublisherResponseDisposition { completed, refused, recovery_required };
struct ValidatedPublisherResponse {
    PublisherResponseDisposition disposition;
    usk::json::Value result;
    const char* error_code;
};
// The caller validates the command/request framing before authenticated dispatch.
// Pure bounded decoding/correlation only: this authenticates no endpoint and
// supplies no effect authority. The caller must retain dispatch uncertainty
// if parsing, correlation, allocation or result delivery fails after dispatch.
// Endpoint/PID/request-hash binding remains with the authenticated transport;
// this layer validates the operation/report fields already checked by the CLI.
// Ordinary callers use retain_observation=false; true retains the existing
// separate qualification-client presentation. This codec does not itself
// connect the public C SDK to a publisher transport.
ValidatedPublisherResponse validate_publisher_response(const std::string& command,
    const usk::json::Value& submitted, const std::string& response,
    bool retain_observation = false);
}
#endif
