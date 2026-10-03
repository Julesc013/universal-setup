// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_token_observation.h"

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
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

class ServiceHandle {
public:
    explicit ServiceHandle(SC_HANDLE value) : value_(value) {
        if (!value_) throw std::runtime_error("publisher SCM handle is unavailable");
    }
    ~ServiceHandle() { CloseServiceHandle(value_); }
    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;
    SC_HANDLE get() const { return value_; }
private:
    SC_HANDLE value_;
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

SERVICE_STATUS_PROCESS query_service_status(SC_HANDLE service) {
    SERVICE_STATUS_PROCESS status{};
    DWORD required = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status), sizeof(status), &required)) {
        throw std::runtime_error("publisher SCM process status is unavailable");
    }
    return status;
}

DWORD query_service_sid_type(SC_HANDLE service) {
    SERVICE_SID_INFO info{};
    DWORD required = 0;
    if (!QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO,
            reinterpret_cast<LPBYTE>(&info), sizeof(info), &required)) {
        throw std::runtime_error("publisher SCM service SID configuration is unavailable");
    }
    return info.dwServiceSidType;
}

std::string service_sid_for_name(const std::wstring& name) {
    const std::wstring account = L"NT SERVICE\\" + name;
    std::array<unsigned char, SECURITY_MAX_SID_SIZE> sid{};
    std::array<wchar_t, 256> domain{};
    DWORD sid_size = static_cast<DWORD>(sid.size());
    DWORD domain_size = static_cast<DWORD>(domain.size());
    SID_NAME_USE use{};
    if (!LookupAccountNameW(nullptr, account.c_str(), sid.data(), &sid_size,
            domain.data(), &domain_size, &use)) {
        throw std::runtime_error("publisher named service SID cannot be resolved");
    }
    return sid_text(sid.data());
}
} // namespace

std::vector<unsigned char> derive_ascii_publisher_service_sid(const std::wstring& name) {
    if (name.empty() || name.size() > 256)
        throw std::runtime_error("publisher service derivation name exceeds its bound");
    std::vector<unsigned char> uppercase_utf16;
    uppercase_utf16.reserve(name.size() * 2);
    for (wchar_t ch : name) {
        if (!((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') ||
            (ch >= L'0' && ch <= L'9') || ch == L'_' || ch == L'-' || ch == L'.'))
            throw std::runtime_error("publisher service derivation name is outside the ASCII profile");
        if (ch >= L'a' && ch <= L'z') ch = static_cast<wchar_t>(ch - (L'a' - L'A'));
        uppercase_utf16.push_back(static_cast<unsigned char>(ch));
        uppercase_utf16.push_back(0);
    }
    struct AlgorithmCloser {
        void operator()(void* value) const { if (value) BCryptCloseAlgorithmProvider(value, 0); }
    };
    struct HashCloser {
        void operator()(void* value) const { if (value) BCryptDestroyHash(value); }
    };
    BCRYPT_ALG_HANDLE algorithm_raw = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm_raw, BCRYPT_SHA1_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) < 0)
        throw std::runtime_error("publisher service identity hash provider is unavailable");
    std::unique_ptr<void, AlgorithmCloser> algorithm(algorithm_raw);
    DWORD object_length = 0;
    DWORD returned = 0;
    if (BCryptGetProperty(algorithm.get(), BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length), &returned, 0) < 0 ||
        returned != sizeof(object_length) || !object_length || object_length > 65536)
        throw std::runtime_error("publisher service identity hash object exceeds its bound");
    std::vector<unsigned char> object(object_length);
    BCRYPT_HASH_HANDLE hash_raw = nullptr;
    if (BCryptCreateHash(algorithm.get(), &hash_raw, object.data(), object_length, nullptr, 0, 0) < 0)
        throw std::runtime_error("publisher service identity hash cannot be created");
    std::unique_ptr<void, HashCloser> hash(hash_raw);
    std::array<unsigned char, 20> digest{};
    if (BCryptHashData(hash.get(), uppercase_utf16.data(),
            static_cast<ULONG>(uppercase_utf16.size()), 0) < 0 ||
        BCryptFinishHash(hash.get(), digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
        throw std::runtime_error("publisher service identity hash failed");
    // MS-LSAT documented mapping: uppercase UTF-16 name -> five little-endian
    // SHA-1 DWORDs -> S-1-5-80-H0-H1-H2-H3-H4. This identity mapping is not a
    // cryptographic authentication digest; executable bindings use SHA-256.
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    std::vector<unsigned char> sid(GetSidLengthRequired(6));
    if (!InitializeSid(sid.data(), &authority, 6))
        throw std::runtime_error("derived publisher service SID cannot be initialized");
    *GetSidSubAuthority(sid.data(), 0) = SECURITY_SERVICE_ID_BASE_RID;
    for (DWORD index = 0; index != 5; ++index) {
        const auto offset = static_cast<std::size_t>(index) * 4;
        *GetSidSubAuthority(sid.data(), index + 1) =
            static_cast<DWORD>(digest[offset]) | (static_cast<DWORD>(digest[offset + 1]) << 8) |
            (static_cast<DWORD>(digest[offset + 2]) << 16) | (static_cast<DWORD>(digest[offset + 3]) << 24);
    }
    if (!IsValidSid(sid.data())) throw std::runtime_error("derived publisher service SID is invalid");
    return sid;
}

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

PublisherServiceObservation observe_current_restricted_publisher_service(
    const std::wstring& service_name) {
    if (service_name.empty() || service_name.size() > 256 ||
        !std::all_of(service_name.begin(), service_name.end(), [](wchar_t ch) {
            return ch >= 32 && ch != 127 && ch != L'\\' && ch != L'/';
        })) {
        throw std::runtime_error("publisher service name is invalid");
    }
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    ServiceHandle service(OpenServiceW(manager.get(), service_name.c_str(),
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
    const auto before = query_service_status(service.get());
    const auto sid_type = query_service_sid_type(service.get());
    const auto service_sid = service_sid_for_name(service_name);
    const auto token = observe_current_publisher_token();
    const auto after = query_service_status(service.get());
    const auto sid_type_after = query_service_sid_type(service.get());
    if (before.dwServiceType != SERVICE_WIN32_OWN_PROCESS ||
        before.dwCurrentState != SERVICE_RUNNING ||
        before.dwProcessId != GetCurrentProcessId() ||
        before.dwServiceFlags != 0 ||
        sid_type != SERVICE_SID_TYPE_RESTRICTED ||
        sid_type_after != sid_type ||
        before.dwServiceType != after.dwServiceType ||
        before.dwCurrentState != after.dwCurrentState ||
        before.dwProcessId != after.dwProcessId ||
        before.dwServiceFlags != after.dwServiceFlags ||
        !has_restricted_publisher_token_facts(token, service_sid)) {
        throw std::runtime_error("publisher process is not the stable restricted SCM service");
    }
    return {service_name, service_sid, sid_type, before.dwServiceType,
        before.dwCurrentState, before.dwProcessId, token};
}

} // namespace usk::platform::windows
#endif
