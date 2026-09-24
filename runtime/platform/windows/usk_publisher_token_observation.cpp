// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_token_observation.h"

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>

namespace usk::platform::windows {
namespace {
class TokenHandle {
public:
    explicit TokenHandle(HANDLE value) : value_(value) {
        if (!value_ || value_ == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("publisher token observation cannot open a token");
        }
    }
    ~TokenHandle() { CloseHandle(value_); }
    TokenHandle(const TokenHandle&) = delete;
    TokenHandle& operator=(const TokenHandle&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};

struct LocalFreeDeleter {
    void operator()(void* pointer) const { if (pointer) LocalFree(pointer); }
};

std::string sid_text(PSID sid) {
    if (!sid || !IsValidSid(sid)) throw std::runtime_error("publisher token has an invalid SID");
    LPWSTR raw = nullptr;
    if (!ConvertSidToStringSidW(sid, &raw)) {
        throw std::runtime_error("publisher token SID cannot be rendered");
    }
    std::unique_ptr<void, LocalFreeDeleter> owned(raw);
    std::string result;
    for (const wchar_t* cursor = raw; *cursor; ++cursor) {
        if (*cursor > 0x7f) throw std::runtime_error("publisher token SID is not ASCII");
        result.push_back(static_cast<char>(*cursor));
    }
    return result;
}

std::vector<unsigned char> token_info(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    DWORD required = 0;
    if (GetTokenInformation(token, kind, nullptr, 0, &required) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0 || required > 1024 * 1024) {
        throw std::runtime_error("publisher token query size is unavailable or unbounded");
    }
    std::vector<unsigned char> buffer(required);
    if (!GetTokenInformation(token, kind, buffer.data(), required, &required) ||
        required > buffer.size()) {
        throw std::runtime_error("publisher token query failed or changed size");
    }
    buffer.resize(required);
    return buffer;
}

std::vector<ObservedTokenGroup> token_groups(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    const auto buffer = token_info(token, kind);
    if (buffer.size() < offsetof(TOKEN_GROUPS, Groups)) {
        throw std::runtime_error("publisher token groups are truncated");
    }
    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data());
    const auto capacity = (buffer.size() - offsetof(TOKEN_GROUPS, Groups)) /
        sizeof(SID_AND_ATTRIBUTES);
    if (groups->GroupCount > capacity) {
        throw std::runtime_error("publisher token group count exceeds its buffer");
    }
    std::vector<ObservedTokenGroup> result;
    result.reserve(groups->GroupCount);
    for (DWORD index = 0; index < groups->GroupCount; ++index) {
        result.push_back({sid_text(groups->Groups[index].Sid), groups->Groups[index].Attributes});
    }
    return result;
}

bool current_thread_impersonating() {
    HANDLE raw = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
        TokenHandle token(raw);
        return true;
    }
    if (GetLastError() != ERROR_NO_TOKEN) {
        throw std::runtime_error("publisher token cannot determine thread impersonation state");
    }
    return false;
}
} // namespace

PublisherTokenObservation observe_current_publisher_token() {
    const bool impersonating = current_thread_impersonating();
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) {
        throw std::runtime_error("publisher token cannot open the process token");
    }
    TokenHandle token(raw);
    const auto user_buffer = token_info(token.get(), TokenUser);
    if (user_buffer.size() < sizeof(TOKEN_USER)) {
        throw std::runtime_error("publisher token user is truncated");
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(user_buffer.data());
    return {sid_text(user->User.Sid), token_groups(token.get(), TokenGroups),
        token_groups(token.get(), TokenRestrictedSids), impersonating};
}

bool has_restricted_publisher_token_facts(
    const PublisherTokenObservation& observation, const std::string& service_sid) {
    if (observation.current_thread_impersonating ||
        observation.process_user_sid != "S-1-5-18" || service_sid.empty()) return false;
    PSID parsed_sid = nullptr;
    if (!ConvertStringSidToSidA(service_sid.c_str(), &parsed_sid)) return false;
    std::unique_ptr<void, LocalFreeDeleter> owned_sid(parsed_sid);
    const SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    if (!IsValidSid(parsed_sid) || *GetSidSubAuthorityCount(parsed_sid) != 6 ||
        *GetSidSubAuthority(parsed_sid, 0) != SECURITY_SERVICE_ID_BASE_RID ||
        std::memcmp(GetSidIdentifierAuthority(parsed_sid), &nt_authority,
            sizeof(nt_authority)) != 0) return false;
    const bool enabled_group = std::any_of(observation.process_groups.begin(),
        observation.process_groups.end(), [&](const ObservedTokenGroup& group) {
            return group.sid == service_sid && (group.attributes & SE_GROUP_ENABLED) != 0 &&
                (group.attributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0;
        });
    const bool restricted_group = std::any_of(observation.process_restricted_sids.begin(),
        observation.process_restricted_sids.end(), [&](const ObservedTokenGroup& group) {
            return group.sid == service_sid;
        });
    return enabled_group && restricted_group;
}

} // namespace usk::platform::windows
#endif
