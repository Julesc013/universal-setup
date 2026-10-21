// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_AUTHENTICATED_CLIENT_INTERNAL_H
#define USK_PUBLISHER_AUTHENTICATED_CLIENT_INTERNAL_H
#if defined(_WIN32)
#include "usk_json.h"
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace usk::platform::windows::detail {
// Own all fields of the existing closed client observation. A native capture
// still reads every original token class; this type grants no authority.
struct AuthenticatedClientObservation {
    std::uint64_t process_id = 0, token_type = 0, impersonation_level = 0;
    std::uint64_t token_id = 0, authentication_id = 0, modified_id = 0;
    std::string user_sid;
    using Groups = std::vector<std::pair<std::string, std::uint64_t>>;
    Groups groups, restricted_sids;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> privileges;
};
inline bool equal_authenticated_client_observations(
    const AuthenticatedClientObservation& a, const AuthenticatedClientObservation& b) {
    return a.process_id == b.process_id && a.user_sid == b.user_sid &&
        a.token_type == b.token_type && a.impersonation_level == b.impersonation_level &&
        a.token_id == b.token_id && a.authentication_id == b.authentication_id &&
        a.modified_id == b.modified_id && a.groups == b.groups &&
        a.restricted_sids == b.restricted_sids && a.privileges == b.privileges;
}
// Transfer only the completed fresh capture, after all native afterchecks.
// Admission retains its independent typed baseline; no saved proof is reused.
inline usk::json::Value authenticated_client_observation_json(AuthenticatedClientObservation observation) {
    using usk::json::Value;
    const auto groups_json = [](AuthenticatedClientObservation::Groups groups) {
        Value::Array result;
        for (auto& group : groups)
            result.emplace_back(Value::Object{{"sid", Value(std::move(group.first))},
                {"attributes", Value(group.second)}});
        return Value(std::move(result));
    };
    Value::Array privileges;
    for (const auto& privilege : observation.privileges)
        privileges.emplace_back(Value::Object{{"luid", Value(privilege.first)},
            {"attributes", Value(privilege.second)}});
    Value::Object fields;
    fields.emplace("schema", Value("usk.publisher_authenticated_client_observation.v1"));
    fields.emplace("scope", Value("held_authenticated_identification_token"));
    fields.emplace("captured_process_id", Value(observation.process_id));
    fields.emplace("user_sid", Value(std::move(observation.user_sid)));
    fields.emplace("token_type", Value(observation.token_type));
    fields.emplace("impersonation_level", Value(observation.impersonation_level));
    fields.emplace("token_id", Value(observation.token_id));
    fields.emplace("authentication_id", Value(observation.authentication_id));
    fields.emplace("modified_id", Value(observation.modified_id));
    fields.emplace("groups", groups_json(std::move(observation.groups)));
    fields.emplace("restricted_sids", groups_json(std::move(observation.restricted_sids)));
    fields.emplace("privileges", Value(std::move(privileges)));
    return Value(std::move(fields));
}
} // namespace usk::platform::windows::detail
#endif
#endif
