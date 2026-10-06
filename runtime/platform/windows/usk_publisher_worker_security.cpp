// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_worker_security.h"
#if defined(_WIN32)
#include <tlhelp32.h>
#include <sddl.h>
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <vector>

namespace usk::platform::windows {
namespace {
using usk::json::Value;
void require(bool condition, const char* diagnostic) {
    if (!condition) throw std::runtime_error(diagnostic);
}
class Handle {
public:
    explicit Handle(HANDLE value) : value_(value) {
        require(value && value != INVALID_HANDLE_VALUE, "publisher worker security handle unavailable");
        DWORD flags = 0;
        if (!GetHandleInformation(value_, &flags) || flags != 0) {
            CloseHandle(value_);
            throw std::runtime_error("publisher worker security handle is inheritable or protected from close");
        }
    }
    ~Handle() { CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};
struct LocalAllocation {
    HLOCAL value;
    ~LocalAllocation() { if (value) LocalFree(value); }
};
std::string sid_text(PSID value) {
    require(value && IsValidSid(value), "publisher worker security SID invalid");
    LPSTR text = nullptr;
    require(ConvertSidToStringSidA(value, &text) != FALSE, "publisher worker security SID text unavailable");
    LocalAllocation owned{reinterpret_cast<HLOCAL>(text)};
    return text;
}
bool canonical_sid(const std::string& value) {
    if (value.empty() || value.size() > 184) return false;
    PSID parsed = nullptr;
    if (!ConvertStringSidToSidA(value.c_str(), &parsed)) return false;
    LocalAllocation owned{reinterpret_cast<HLOCAL>(parsed)};
    return IsValidSid(parsed) && *GetSidSubAuthorityCount(parsed) > 0 && sid_text(parsed) == value;
}
std::string hex64(std::uint64_t value) {
    const char* digits = "0123456789abcdef";
    std::string result(16, '0');
    for (std::size_t index = 0; index != 16; ++index) {
        result[15 - index] = digits[value & 15u]; value >>= 4;
    }
    return result;
}
std::uint64_t luid(const LUID& value) {
    return (static_cast<std::uint64_t>(static_cast<std::uint32_t>(value.HighPart)) << 32) | value.LowPart;
}
std::vector<unsigned char> token_info(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    DWORD size = 0;
    require(!GetTokenInformation(token, kind, nullptr, 0, &size) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER && size && size <= 1024 * 1024,
        "publisher worker token information size unavailable");
    std::vector<unsigned char> bytes(size);
    require(GetTokenInformation(token, kind, bytes.data(), size, &size) && size <= bytes.size(),
        "publisher worker token information changed or unavailable");
    bytes.resize(size);
    return bytes;
}
TOKEN_STATISTICS statistics(HANDLE token) {
    const auto bytes = token_info(token, TokenStatistics);
    require(bytes.size() == sizeof(TOKEN_STATISTICS), "publisher worker token statistics truncated");
    TOKEN_STATISTICS result{};
    std::memcpy(&result, bytes.data(), sizeof(result));
    require(result.TokenType == TokenPrimary, "publisher worker token is not primary");
    return result;
}
std::size_t contained(const std::vector<unsigned char>& buffer, const void* pointer, std::size_t minimum) {
    const auto base = reinterpret_cast<std::uintptr_t>(buffer.data());
    const auto address = reinterpret_cast<std::uintptr_t>(pointer);
    require(pointer && address >= base && address - base <= buffer.size() &&
        minimum <= buffer.size() - (address - base), "publisher worker token pointer exceeds returned buffer");
    return buffer.size() - (address - base);
}
Value::Array acl_aces(PACL acl) {
    require(acl && IsValidAcl(acl) && acl->AceCount <= 4096,
        "publisher worker security DACL absent or invalid");
    Value::Array result;
    for (DWORD index = 0; index != acl->AceCount; ++index) {
        void* raw = nullptr;
        require(GetAce(acl, index, &raw) && raw, "publisher worker security ACE unavailable");
        const auto* header = static_cast<const ACE_HEADER*>(raw);
        require((header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_DENIED_ACE_TYPE) &&
            header->AceSize >= offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8,
            "publisher worker security ACE type or size unsupported");
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        const auto* bytes = reinterpret_cast<const unsigned char*>(&ace->SidStart);
        require(bytes[0] == SID_REVISION && bytes[1] > 0 && bytes[1] <= SID_MAX_SUB_AUTHORITIES &&
            offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8 + 4 * bytes[1] == header->AceSize,
            "publisher worker security ACE SID exceeds its record");
        result.emplace_back(Value::Object{{"type", Value(static_cast<std::uint64_t>(header->AceType))},
            {"flags", Value(static_cast<std::uint64_t>(header->AceFlags))},
            {"access_mask", Value(static_cast<std::uint64_t>(ace->Mask))},
            {"sid", Value(sid_text(const_cast<DWORD*>(&ace->SidStart)))}});
    }
    return result;
}
Value::Object object_security(HANDLE handle) {
    constexpr SECURITY_INFORMATION information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    DWORD size = 0;
    require(!GetKernelObjectSecurity(handle, information, nullptr, 0, &size) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER && size >= SECURITY_DESCRIPTOR_MIN_LENGTH &&
        size <= 1024 * 1024, "publisher worker descriptor size unavailable");
    std::vector<unsigned char> bytes(size);
    require(GetKernelObjectSecurity(handle, information, bytes.data(), size, &size) && size <= bytes.size() &&
        IsValidSecurityDescriptor(bytes.data()), "publisher worker stored descriptor unavailable");
    PSID owner = nullptr;
    PACL dacl = nullptr;
    BOOL owner_defaulted = FALSE, present = FALSE, dacl_defaulted = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    require(GetSecurityDescriptorOwner(bytes.data(), &owner, &owner_defaulted) && owner &&
        GetSecurityDescriptorDacl(bytes.data(), &present, &dacl, &dacl_defaulted) && present && dacl &&
        GetSecurityDescriptorControl(bytes.data(), &control, &revision) &&
        revision == SECURITY_DESCRIPTOR_REVISION, "publisher worker stored owner/DACL absent");
    return {{"owner_sid", Value(sid_text(owner))}, {"dacl_present", Value(true)},
        {"dacl_protected", Value((control & SE_DACL_PROTECTED) != 0)},
        {"dacl_aces", Value(acl_aces(dacl))}};
}
std::vector<DWORD> thread_ids() {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    THREADENTRY32 entry{}; entry.dwSize = sizeof(entry);
    require(Thread32First(snapshot.get(), &entry), "publisher worker thread population unavailable");
    std::vector<DWORD> result;
    do {
        require(entry.dwSize >= offsetof(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD),
            "publisher worker thread entry truncated");
        if (entry.th32OwnerProcessID == GetCurrentProcessId()) {
            require(entry.th32ThreadID && result.size() < 4096, "publisher worker thread population exceeds bound");
            result.push_back(entry.th32ThreadID);
        }
        entry.dwSize = sizeof(entry);
    } while (Thread32Next(snapshot.get(), &entry));
    require(GetLastError() == ERROR_NO_MORE_FILES, "publisher worker thread population incomplete");
    std::sort(result.begin(), result.end());
    require(!result.empty() && std::adjacent_find(result.begin(), result.end()) == result.end() &&
        std::binary_search(result.begin(), result.end(), GetCurrentThreadId()),
        "publisher worker current thread absent or population duplicated");
    return result;
}
void require_no_thread_token(HANDLE thread) {
    HANDLE raw = nullptr;
    if (OpenThreadToken(thread, TOKEN_QUERY, TRUE, &raw)) {
        Handle token(raw);
        throw std::runtime_error("publisher worker thread carries an impersonation token");
    }
    require(GetLastError() == ERROR_NO_TOKEN,
        "publisher worker cannot establish absence of a thread impersonation token");
}
void require_acl(const Value& value, const std::set<std::string>& trusted, std::uint32_t query_rights) {
    const auto& aces = value.as_array();
    require(aces.size() <= 4096, "publisher worker retained ACE count exceeds bound");
    for (const auto& ace : aces) {
        const auto& sid = ace.at("sid").as_string();
        const auto type = ace.at("type").as_unsigned();
        const auto mask = ace.at("access_mask").as_unsigned();
        require(ace.as_object().size() == 4 && canonical_sid(sid) &&
            (type == ACCESS_ALLOWED_ACE_TYPE || type == ACCESS_DENIED_ACE_TYPE) &&
            ace.at("flags").as_unsigned() == 0 && mask <= 0xffffffffu &&
            (type == ACCESS_DENIED_ACE_TYPE || trusted.count(sid) ||
                (mask & ~static_cast<std::uint64_t>(query_rights)) == 0),
            "publisher worker DACL admits an outside mutation/duplication capability");
    }
}
void require_object(const Value& value, const std::set<std::string>& trusted, std::uint32_t query_rights) {
    require(canonical_sid(value.at("owner_sid").as_string()) &&
        trusted.count(value.at("owner_sid").as_string()) && value.at("dacl_present").as_boolean(),
        "publisher worker owner can grant an outside capability");
    (void)value.at("dacl_protected").as_boolean();
    require_acl(value.at("dacl_aces"), trusted, query_rights);
}
} // namespace

Value observe_current_publisher_worker_security() {
    HANDLE raw = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | READ_CONTROL, &raw),
        "publisher worker primary token security unavailable");
    Handle token(raw);
    const auto before = statistics(token.get());
    auto primary = object_security(token.get());
    const auto default_owner = token_info(token.get(), TokenOwner);
    require(default_owner.size() >= sizeof(TOKEN_OWNER), "publisher worker default owner truncated");
    const auto* owner = reinterpret_cast<const TOKEN_OWNER*>(default_owner.data());
    const auto owner_size = contained(default_owner, owner->Owner, 8);
    const auto* owner_bytes = static_cast<const unsigned char*>(owner->Owner);
    require(owner_bytes[0] == SID_REVISION && owner_bytes[1] > 0 && owner_bytes[1] <= SID_MAX_SUB_AUTHORITIES &&
        8u + 4u * owner_bytes[1] <= owner_size, "publisher worker default owner SID truncated");
    const auto defaults = token_info(token.get(), TokenDefaultDacl);
    require(defaults.size() >= sizeof(TOKEN_DEFAULT_DACL), "publisher worker default DACL truncated");
    const auto* dacl = reinterpret_cast<const TOKEN_DEFAULT_DACL*>(defaults.data());
    const auto available = contained(defaults, dacl->DefaultDacl, sizeof(ACL));
    require(dacl->DefaultDacl->AclSize <= available, "publisher worker default DACL exceeds token buffer");
    primary.emplace("default_owner_sid", Value(sid_text(owner->Owner)));
    primary.emplace("default_dacl_aces", Value(acl_aces(dacl->DefaultDacl)));
    primary.emplace("token_id", Value(hex64(luid(before.TokenId))));
    primary.emplace("authentication_id", Value(hex64(luid(before.AuthenticationId))));
    primary.emplace("modified_id", Value(hex64(luid(before.ModifiedId))));
    auto ids = thread_ids();
    std::map<DWORD, std::unique_ptr<Handle>> held_threads;
    std::map<DWORD, Value> recorded_threads;
    bool population_complete = false;
    // Read-only Windows APIs can initialize additional owned helper threads.
    // Extend coverage without dropping or refreshing any earlier observation;
    // loss, identity/security changes and continued churn still refuse.
    for (unsigned round = 0; round != 4; ++round) {
        for (const auto id : ids) {
            if (held_threads.count(id)) continue;
            auto held = std::make_unique<Handle>(OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION | READ_CONTROL | SYNCHRONIZE, FALSE, id));
            const auto thread = held->get();
            require(GetProcessIdOfThread(thread) == GetCurrentProcessId() && GetThreadId(thread) == id,
                "publisher worker thread is not owned by this process");
            require_no_thread_token(thread);
            FILETIME creation{}, exit{}, kernel{}, user{};
            require(GetThreadTimes(thread, &creation, &exit, &kernel, &user) &&
                (creation.dwHighDateTime || creation.dwLowDateTime) && WaitForSingleObject(thread, 0) == WAIT_TIMEOUT,
                "publisher worker observed thread is unavailable or exited");
            auto facts = object_security(thread);
            require(usk::json::canonical(Value(facts)) == usk::json::canonical(Value(object_security(thread))),
                "publisher worker thread security changed during readback");
            facts.emplace("thread_id", Value(static_cast<std::uint64_t>(id)));
            facts.emplace("creation_time", Value(hex64((static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) |
                creation.dwLowDateTime)));
            facts.emplace("thread_impersonating", Value(false));
            recorded_threads.emplace(id, Value(std::move(facts)));
            held_threads.emplace(id, std::move(held));
        }
        for (const auto& item : held_threads) {
            FILETIME creation{}, exit{}, kernel{}, user{};
            const auto& recorded = recorded_threads.at(item.first);
            const auto thread = item.second->get();
            require(GetThreadTimes(thread, &creation, &exit, &kernel, &user) &&
                GetProcessIdOfThread(thread) == GetCurrentProcessId() &&
                GetThreadId(thread) == recorded.at("thread_id").as_unsigned() &&
                WaitForSingleObject(thread, 0) == WAIT_TIMEOUT && recorded.at("creation_time").as_string() ==
                    hex64((static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime),
                "publisher worker held thread exited or changed identity");
            auto repeated = object_security(thread);
            require_no_thread_token(thread);
            repeated.emplace("thread_id", recorded.at("thread_id"));
            repeated.emplace("creation_time", recorded.at("creation_time"));
            repeated.emplace("thread_impersonating", Value(false));
            require(usk::json::canonical(Value(repeated)) == usk::json::canonical(recorded),
                "publisher worker held thread security changed across population readback");
        }
        const auto final_ids = thread_ids();
        if (final_ids == ids) { population_complete = true; break; }
        require(std::includes(final_ids.begin(), final_ids.end(), ids.begin(), ids.end()),
            "publisher worker lost an observed thread during population readback");
        ids = final_ids;
    }
    require(population_complete, "publisher worker thread population did not settle within its observation bound");
    Value::Array threads;
    for (auto& item : recorded_threads) threads.push_back(std::move(item.second));
    const auto after = statistics(token.get());
    require(luid(before.TokenId) == luid(after.TokenId) && luid(before.AuthenticationId) == luid(after.AuthenticationId) &&
        luid(before.ModifiedId) == luid(after.ModifiedId) &&
        usk::json::canonical(Value(object_security(token.get()))) ==
            usk::json::canonical(Value(Value::Object{{"owner_sid", primary.at("owner_sid")},
                {"dacl_present", primary.at("dacl_present")}, {"dacl_protected", primary.at("dacl_protected")},
                {"dacl_aces", primary.at("dacl_aces")}})),
        "publisher worker primary token or thread population changed during observation");
    return Value(Value::Object{{"schema", Value("usk.publisher_worker_security.v1")},
        {"scope", Value("stored_primary_token_defaults_and_process_thread_owner_dacls")},
        {"process_id", Value(static_cast<std::uint64_t>(GetCurrentProcessId()))},
        {"current_thread_id", Value(static_cast<std::uint64_t>(GetCurrentThreadId()))},
        {"primary_token", Value(std::move(primary))}, {"threads", Value(std::move(threads))}});
}

Value observe_settled_publisher_worker_security(const PublisherServiceObservation& service, HANDLE cancel_event) {
    if (cancel_event) require(WaitForSingleObject(cancel_event, 0) == WAIT_TIMEOUT,
        "publisher startup observation cancelled or unavailable");
    const auto started = GetTickCount64();
    auto quiet_since = started;
    auto previous = observe_current_publisher_worker_security();
    require_publisher_worker_security(previous, service);
    while (GetTickCount64() - started < 8000u) {
        if (cancel_event) {
            require(WaitForSingleObject(cancel_event, 200u) == WAIT_TIMEOUT,
                "publisher startup observation cancelled or unavailable");
        } else Sleep(200u);
        auto current = observe_current_publisher_worker_security();
        require_publisher_worker_security(current, service);
        const auto now = GetTickCount64();
        if (now - started >= 8000u) break;
        if (usk::json::canonical(current) != usk::json::canonical(previous)) quiet_since = now;
        else if (now - quiet_since >= 1200u) return current;
        previous = std::move(current);
    }
    throw std::runtime_error("publisher startup worker population did not settle before effects");
}

void require_publisher_worker_security(const Value& value, const PublisherServiceObservation& service) {
    require(value.as_object().size() == 6 && value.at("schema").as_string() == "usk.publisher_worker_security.v1" &&
        value.at("scope").as_string() == "stored_primary_token_defaults_and_process_thread_owner_dacls" &&
        service.process_id && value.at("process_id").as_unsigned() == service.process_id &&
        canonical_sid(service.service_sid) && service.token.process_groups.size() <= 4096,
        "publisher worker security context or closed schema differs");
    std::set<std::string> trusted{"S-1-5-18", "S-1-5-32-544", service.service_sid};
    std::size_t logons = 0;
    for (const auto& group : service.token.process_groups) {
        require(canonical_sid(group.sid), "publisher worker token group SID invalid");
        if ((group.attributes & SE_GROUP_LOGON_ID) != SE_GROUP_LOGON_ID) continue;
        PSID raw_sid = nullptr;
        require(ConvertStringSidToSidA(group.sid.c_str(), &raw_sid) != FALSE, "publisher worker logon SID unavailable");
        LocalAllocation owned{reinterpret_cast<HLOCAL>(raw_sid)};
        const SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
        require(++logons == 1 && *GetSidSubAuthorityCount(raw_sid) == 3 &&
            *GetSidSubAuthority(raw_sid, 0) == SECURITY_LOGON_IDS_RID &&
            std::memcmp(GetSidIdentifierAuthority(raw_sid), &nt, sizeof(nt)) == 0 &&
            (group.attributes & SE_GROUP_ENABLED) && !(group.attributes & SE_GROUP_USE_FOR_DENY_ONLY),
            "publisher worker logon identity invalid");
        trusted.insert(group.sid);
    }
    const auto& primary = value.at("primary_token");
    require(primary.as_object().size() == 9 && service.token.identity.token_type == TokenPrimary &&
        service.token.identity.token_id && service.token.identity.authentication_id && service.token.identity.modified_id &&
        primary.at("token_id").as_string() == hex64(service.token.identity.token_id) &&
        primary.at("authentication_id").as_string() == hex64(service.token.identity.authentication_id) &&
        primary.at("modified_id").as_string() == hex64(service.token.identity.modified_id),
        "publisher worker primary-token security identity differs");
    require_object(primary, trusted, TOKEN_QUERY | TOKEN_QUERY_SOURCE | READ_CONTROL);
    require(canonical_sid(primary.at("default_owner_sid").as_string()) &&
        trusted.count(primary.at("default_owner_sid").as_string()), "publisher worker default owner grants an outside capability");
    // Only READ_CONTROL is a common non-mutating default across token, process
    // and thread object mappings. Generic or object-specific outside grants
    // are refused rather than interpreted using the wrong object mapping.
    require_acl(primary.at("default_dacl_aces"), trusted, READ_CONTROL);
    const auto current = value.at("current_thread_id").as_unsigned();
    const auto& threads = value.at("threads").as_array();
    require(current && current <= 0xffffffffu && !threads.empty() && threads.size() <= 4096,
        "publisher worker thread closure incomplete");
    std::uint64_t previous = 0;
    bool found = false;
    for (const auto& thread : threads) {
        const auto id = thread.at("thread_id").as_unsigned();
        const auto& creation = thread.at("creation_time").as_string();
        require(thread.as_object().size() == 7 && id > previous && id <= 0xffffffffu &&
            !thread.at("thread_impersonating").as_boolean() &&
            creation.size() == 16 && creation != "0000000000000000" &&
            std::all_of(creation.begin(), creation.end(), [](char ch) {
                return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
            }), "publisher worker retained thread identity or order differs");
        require_object(thread, trusted, SYNCHRONIZE | READ_CONTROL | THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION);
        previous = id; found = found || id == current;
    }
    require(found, "publisher worker current thread missing from closure");
}
} // namespace usk::platform::windows
#endif
