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
#include <optional>
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
Value::Object read_primary_security(HANDLE token, const TOKEN_STATISTICS& before) {
    auto primary = object_security(token);
    const auto default_owner = token_info(token, TokenOwner);
    require(default_owner.size() >= sizeof(TOKEN_OWNER), "publisher worker default owner truncated");
    const auto* owner = reinterpret_cast<const TOKEN_OWNER*>(default_owner.data());
    const auto owner_size = contained(default_owner, owner->Owner, 8);
    const auto* owner_bytes = static_cast<const unsigned char*>(owner->Owner);
    require(owner_bytes[0] == SID_REVISION && owner_bytes[1] > 0 && owner_bytes[1] <= SID_MAX_SUB_AUTHORITIES &&
        8u + 4u * owner_bytes[1] <= owner_size, "publisher worker default owner SID truncated");
    const auto defaults = token_info(token, TokenDefaultDacl);
    require(defaults.size() >= sizeof(TOKEN_DEFAULT_DACL), "publisher worker default DACL truncated");
    const auto* dacl = reinterpret_cast<const TOKEN_DEFAULT_DACL*>(defaults.data());
    const auto available = contained(defaults, dacl->DefaultDacl, sizeof(ACL));
    require(dacl->DefaultDacl->AclSize <= available, "publisher worker default DACL exceeds token buffer");
    primary.emplace("default_owner_sid", Value(sid_text(owner->Owner)));
    primary.emplace("default_dacl_aces", Value(acl_aces(dacl->DefaultDacl)));
    primary.emplace("token_id", Value(hex64(luid(before.TokenId))));
    primary.emplace("authentication_id", Value(hex64(luid(before.AuthenticationId))));
    primary.emplace("modified_id", Value(hex64(luid(before.ModifiedId))));
    return primary;
}
void require_primary_unchanged(HANDLE token, const TOKEN_STATISTICS& before, const Value::Object& primary) {
    const auto after = statistics(token);
    require(luid(before.TokenId) == luid(after.TokenId) && luid(before.AuthenticationId) == luid(after.AuthenticationId) &&
        luid(before.ModifiedId) == luid(after.ModifiedId) &&
        usk::json::canonical(Value(object_security(token))) ==
            usk::json::canonical(Value(Value::Object{{"owner_sid", primary.at("owner_sid")},
                {"dacl_present", primary.at("dacl_present")}, {"dacl_protected", primary.at("dacl_protected")},
                {"dacl_aces", primary.at("dacl_aces")}})),
        "publisher worker primary token or thread population changed during observation");
}
} // namespace

Value observe_current_publisher_worker_security() {
    HANDLE raw = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | READ_CONTROL, &raw),
        "publisher worker primary token security unavailable");
    Handle token(raw);
    const auto before = statistics(token.get());
    auto primary = read_primary_security(token.get(), before);
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
    require_primary_unchanged(token.get(), before, primary);
    return Value(Value::Object{{"schema", Value("usk.publisher_worker_security.v1")},
        {"scope", Value("stored_primary_token_defaults_and_process_thread_owner_dacls")},
        {"process_id", Value(static_cast<std::uint64_t>(GetCurrentProcessId()))},
        {"current_thread_id", Value(static_cast<std::uint64_t>(GetCurrentThreadId()))},
        {"primary_token", Value(std::move(primary))}, {"threads", Value(std::move(threads))}});
}

Value observe_settled_publisher_worker_security(const PublisherServiceObservation& service, HANDLE cancel_event) {
    return observe_settled_publisher_worker_security(
        PublisherWorkerTokenContext{service.process_id, service.service_sid, service.token}, cancel_event);
}
Value observe_settled_publisher_worker_security(const PublisherWorkerTokenContext& worker, HANDLE cancel_event) {
    if (cancel_event) require(WaitForSingleObject(cancel_event, 0) == WAIT_TIMEOUT,
        "publisher startup observation cancelled or unavailable");
    const auto started = GetTickCount64();
    auto previous = observe_current_publisher_worker_security();
    require_publisher_worker_security(previous, worker);
    auto quiet_since = GetTickCount64();
    while (GetTickCount64() - started < 8000u) {
        if (cancel_event) {
            require(WaitForSingleObject(cancel_event, 200u) == WAIT_TIMEOUT,
                "publisher startup observation cancelled or unavailable");
        } else Sleep(200u);
        auto current = observe_current_publisher_worker_security();
        require_publisher_worker_security(current, worker);
        const auto now = GetTickCount64();
        if (now - started >= 8000u) break;
        if (usk::json::canonical(current) != usk::json::canonical(previous)) quiet_since = now;
        else if (now - quiet_since >= 1200u) return current;
        previous = std::move(current);
    }
    throw std::runtime_error("publisher startup worker population did not settle before effects");
}

struct PublisherWorkerSecurityContinuity::Impl {
    const Value baseline;
    const ULONGLONG started_at = GetTickCount64();
    std::map<DWORD, std::unique_ptr<Handle>> threads;

    static Value diagnostic_text(const wchar_t* text, std::size_t units, bool clipped = false) {
        // Failure evidence only. Never expose an unbounded optional native
        // description or module path, and never split a UTF-8 code point.
        if (!text || !units) return Value(Value::Object{{"value", Value("")}, {"truncated", Value(clipped)}});
        const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text,
            static_cast<int>(units), nullptr, 0, nullptr, nullptr);
        if (!count) return Value(Value::Object{{"conversion_error", Value(static_cast<std::uint64_t>(GetLastError()))}});
        std::string converted(static_cast<std::size_t>(count), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, static_cast<int>(units),
                converted.data(), count, nullptr, nullptr) != count)
            return Value(Value::Object{{"conversion_error", Value(static_cast<std::uint64_t>(GetLastError()))}});
        if (converted.size() > 160u) {
            std::size_t end = 160u;
            while (end && (static_cast<unsigned char>(converted[end]) & 0xc0u) == 0x80u) --end;
            converted.resize(end); clipped = true;
        }
        return Value(Value::Object{{"value", Value(std::move(converted))}, {"truncated", Value(clipped)}});
    }
    static Value diagnostic_added_thread(DWORD id) {
        Value::Object facts{{"census_thread_id", Value(static_cast<std::uint64_t>(id))}};
        const auto raw = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, id);
        if (!raw) {
            facts.emplace("open_error", Value(static_cast<std::uint64_t>(GetLastError())));
            return Value(std::move(facts));
        }
        // Optional reads cannot replace the original rejection. Every handle
        // is query-only, non-inheritable and held across identity readback.
        try {
            Handle held(raw);
            const auto process = GetProcessIdOfThread(held.get());
            const auto thread = GetThreadId(held.get());
            FILETIME creation{}, exit{}, kernel{}, user{};
            if (!GetThreadTimes(held.get(), &creation, &exit, &kernel, &user)) {
                facts.emplace("times_error", Value(static_cast<std::uint64_t>(GetLastError())));
                return Value(std::move(facts));
            }
            facts.emplace("process_id", Value(static_cast<std::uint64_t>(process)));
            facts.emplace("thread_id", Value(static_cast<std::uint64_t>(thread)));
            facts.emplace("creation_time", Value(hex64((static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime)));
            const bool same_process = process == GetCurrentProcessId() && thread == id;
            facts.emplace("identity_matches_census", Value(same_process));
            const auto wait = WaitForSingleObject(held.get(), 0);
            facts.emplace("wait_result", Value(static_cast<std::uint64_t>(wait)));
            if (wait == WAIT_FAILED) facts.emplace("wait_error", Value(static_cast<std::uint64_t>(GetLastError())));
            if (!same_process) return Value(std::move(facts));

            using Description = HRESULT (WINAPI*)(HANDLE, PWSTR*);
            const auto description = reinterpret_cast<Description>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetThreadDescription"));
            if (description) {
                PWSTR name = nullptr;
                const auto status = description(held.get(), &name);
                LocalAllocation memory{reinterpret_cast<HLOCAL>(name)};
                facts.emplace("description_hresult", Value(static_cast<std::uint64_t>(static_cast<std::uint32_t>(status))));
                if (SUCCEEDED(status) && name) {
                    std::size_t units = 0;
                    while (units != 256u && name[units]) ++units;
                    facts.emplace("description", diagnostic_text(name, units, units == 256u));
                }
            } else facts.emplace("description_unavailable", Value(true));

            using Query = LONG (WINAPI*)(HANDLE, int, PVOID, ULONG, PULONG);
            const auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
            if (query) {
                PVOID address = nullptr; ULONG returned = 0;
                // Documented ThreadQuerySetWin32StartAddress information class.
                // Dynamic lookup is diagnostic only; absence never admits it.
                const auto status = query(held.get(), 9, &address, static_cast<ULONG>(sizeof(address)), &returned);
                facts.emplace("start_address_ntstatus", Value(static_cast<std::uint64_t>(static_cast<std::uint32_t>(status))));
                facts.emplace("start_address_returned_bytes", Value(static_cast<std::uint64_t>(returned)));
                if (status >= 0 && address && returned == sizeof(address)) {
                    facts.emplace("start_address", Value(hex64(reinterpret_cast<std::uintptr_t>(address))));
                    HMODULE module = nullptr;
                    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(address), &module)) {
                        struct Module { HMODULE handle; ~Module() { FreeLibrary(handle); } } pinned{module};
                        wchar_t path[512]{};
                        const auto size = GetModuleFileNameW(module, path, static_cast<DWORD>(std::size(path)));
                        if (size) facts.emplace("start_module", diagnostic_text(path, size, size == std::size(path)));
                        else facts.emplace("start_module_error", Value(static_cast<std::uint64_t>(GetLastError())));
                    } else facts.emplace("start_module_error", Value(static_cast<std::uint64_t>(GetLastError())));
                }
            } else facts.emplace("start_address_unavailable", Value(true));
            FILETIME repeated{}, repeated_exit{}, repeated_kernel{}, repeated_user{};
            const bool read = GetThreadTimes(held.get(), &repeated, &repeated_exit, &repeated_kernel, &repeated_user) != FALSE;
            if (!read) facts.emplace("repeated_times_error", Value(static_cast<std::uint64_t>(GetLastError())));
            facts.emplace("identity_stable", Value(read && GetProcessIdOfThread(held.get()) == process &&
                GetThreadId(held.get()) == thread && CompareFileTime(&creation, &repeated) == 0));
        } catch (const std::exception& error) {
            facts.emplace("optional_read_error", Value(std::string(error.what()).substr(0, 160u)));
        }
        return Value(std::move(facts));
    }
    [[noreturn]] void reject_added_threads(const std::vector<DWORD>& ids, const char* census,
        unsigned round, const std::string& failure_context) const {
        Value::Array original, unknown;
        std::size_t added_count = 0;
        for (const auto& item : baseline.at("threads").as_array()) {
            if (original.size() == 16u) break;
            original.emplace_back(Value::Object{{"thread_id", item.at("thread_id")}, {"creation_time", item.at("creation_time")}});
        }
        for (const auto id : ids) if (!threads.count(id)) {
            ++added_count;
            if (unknown.size() != 8u) unknown.push_back(diagnostic_added_thread(id));
        }
        Value evidence(Value::Object{{"schema", Value("usk.publisher_worker_thread_addition_diagnostic.v1")},
            {"scope", Value("bounded_native_refusal_readback_no_authority")}, {"census", Value(census)},
            {"readback_round", Value(static_cast<std::uint64_t>(round + 1u))},
            {"process_id", Value(static_cast<std::uint64_t>(GetCurrentProcessId()))},
            {"current_thread_id", Value(static_cast<std::uint64_t>(GetCurrentThreadId()))},
            {"elapsed_since_continuity_creation_ms", Value(static_cast<std::uint64_t>(GetTickCount64() - started_at))},
            {"baseline_sha256", Value(usk::json::sha256_canonical(baseline))},
            {"baseline_thread_count", Value(static_cast<std::uint64_t>(baseline.at("threads").as_array().size()))},
            {"baseline_threads", Value(std::move(original))},
            {"census_thread_count", Value(static_cast<std::uint64_t>(ids.size()))},
            {"added_thread_count", Value(static_cast<std::uint64_t>(added_count))},
            {"added_threads", Value(std::move(unknown))},
            {"owner_context", Value(failure_context.substr(0, 1024u))},
            {"owner_context_truncated", Value(failure_context.size() > 1024u)},
            {"optional_details_omitted", Value(false)}});
        auto encoded = usk::json::canonical(evidence);
        if (encoded.size() > 8192u) {
            // Keep every retained actual identity/count; discard optional text
            // if unusual escaping exceeds the final diagnostic byte bound.
            for (auto& item : evidence.as_object().at("added_threads").as_array())
                for (const auto* key : {"description", "start_module", "optional_read_error"}) item.as_object().erase(key);
            evidence.as_object().at("owner_context") = Value("");
            evidence.as_object().at("owner_context_truncated") = Value(true);
            evidence.as_object().at("optional_details_omitted") = Value(true);
            encoded = usk::json::canonical(evidence);
        }
        throw std::runtime_error("publisher maintenance worker added a thread after its frozen baseline; diagnostic=" + encoded);
    }

    static void require_identity(HANDLE handle, const Value& original, FILETIME& exit) {
        FILETIME creation{}, kernel{}, user{};
        require(GetProcessIdOfThread(handle) == GetCurrentProcessId() &&
            GetThreadId(handle) == original.at("thread_id").as_unsigned() &&
            GetThreadTimes(handle, &creation, &exit, &kernel, &user) &&
            original.at("creation_time").as_string() ==
                hex64((static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime),
            "publisher maintenance retained thread identity changed or unavailable");
    }
    static void require_live(HANDLE handle, const Value& original) {
        FILETIME exit{};
        require_identity(handle, original, exit);
        const auto waited = WaitForSingleObject(handle, 0);
        const auto error = waited == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
        if (waited != WAIT_TIMEOUT)
            throw std::runtime_error("publisher maintenance original thread was not live while pinning: wait=" +
                std::to_string(waited) + " error=" + std::to_string(error));
        require_no_thread_token(handle);
        auto facts = object_security(handle);
        facts.emplace("thread_id", original.at("thread_id"));
        facts.emplace("creation_time", original.at("creation_time"));
        facts.emplace("thread_impersonating", Value(false));
        require(usk::json::canonical(Value(facts)) == usk::json::canonical(original),
            "publisher maintenance surviving original thread security changed");
    }
    explicit Impl(const Value& original) : baseline(original) {
        require(usk::json::canonical(observe_current_publisher_worker_security()) == usk::json::canonical(baseline),
            "publisher maintenance baseline differs from actual worker before thread pinning");
        for (const auto& item : baseline.at("threads").as_array()) {
            const auto id = static_cast<DWORD>(item.at("thread_id").as_unsigned());
            auto held = std::make_unique<Handle>(OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION | READ_CONTROL | SYNCHRONIZE, FALSE, id));
            require_live(held->get(), item);
            require(threads.emplace(id, std::move(held)).second,
                "publisher maintenance original thread identity repeated");
        }
        // Once all originals are actually pinned, use their retained objects
        // to distinguish retirement from a missing/reused numeric ID.
        (void)observe_current({});
    }
    std::optional<Value> read_original(HANDLE handle, const Value& original) const {
        FILETIME exit{};
        require_identity(handle, original, exit);
        const auto wait = [&] {
            const auto result = WaitForSingleObject(handle, 0);
            const auto error = result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
            if (result != WAIT_TIMEOUT && result != WAIT_OBJECT_0)
                throw std::runtime_error("publisher maintenance original thread wait unavailable: wait=" +
                    std::to_string(result) + " error=" + std::to_string(error));
            return result;
        };
        const auto require_retired = [&] {
            require(original.at("thread_id").as_unsigned() != baseline.at("current_thread_id").as_unsigned(),
                "publisher maintenance original execution thread retired");
            // Exit FILETIME is defined only after actual signaled termination.
            require_identity(handle, original, exit);
            require(exit.dwHighDateTime || exit.dwLowDateTime,
                "publisher maintenance original retirement lacks an actual exit time");
        };
        auto state = wait();
        if (state == WAIT_OBJECT_0) require_retired();
        else require_no_thread_token(handle);
        auto facts = object_security(handle);
        facts.emplace("thread_id", original.at("thread_id"));
        facts.emplace("creation_time", original.at("creation_time"));
        facts.emplace("thread_impersonating", Value(false));
        require(usk::json::canonical(Value(facts)) == usk::json::canonical(original),
            "publisher maintenance surviving original thread facts changed");
        state = wait();
        if (state == WAIT_OBJECT_0) { require_retired(); return std::nullopt; }
        require_no_thread_token(handle);
        return Value(std::move(facts));
    }
    Value observe_current(const std::function<void(const char*)>& checkpoint, const std::string& failure_context = {}) const {
        const auto require_execution = [&] {
            require(GetCurrentProcessId() == baseline.at("process_id").as_unsigned(),
                "publisher maintenance frozen worker context changed");
            require(GetCurrentThreadId() == baseline.at("current_thread_id").as_unsigned(),
                "publisher maintenance original execution thread changed");
        };
        require_execution();
        std::map<DWORD, const Value*> originals;
        for (const auto& item : baseline.at("threads").as_array())
            originals.emplace(static_cast<DWORD>(item.at("thread_id").as_unsigned()), &item);
        const auto require_known_ids = [&](const std::vector<DWORD>& ids, const char* census, unsigned round) {
            for (const auto id : ids)
                if (!originals.count(id)) reject_added_threads(ids, census, round, failure_context);
        };
        // No policy exception is caught. Only positively proved retirement of
        // a retained original can discard a sample and start another one.
        for (unsigned round = 0; round != 4; ++round) {
            HANDLE raw = nullptr;
            require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | READ_CONTROL, &raw),
                "publisher worker primary token security unavailable");
            Handle token(raw);
            const auto before = statistics(token.get());
            auto primary = read_primary_security(token.get(), before);
            require(usk::json::canonical(Value(primary)) == usk::json::canonical(baseline.at("primary_token")),
                "publisher maintenance frozen primary token or defaults changed");
            const auto first_ids = thread_ids();
            require_known_ids(first_ids, "first_population_snapshot", round);
            if (checkpoint) checkpoint("after_population_snapshot");
            Value::Array observed;
            std::vector<DWORD> live_ids;
            for (const auto& item : originals) {
                auto facts = read_original(threads.at(item.first)->get(), *item.second);
                if (facts) {
                    require(std::binary_search(first_ids.begin(), first_ids.end(), item.first),
                        "publisher maintenance live original absent from native population");
                    live_ids.push_back(item.first); observed.push_back(std::move(*facts));
                }
            }
            if (checkpoint) checkpoint("after_live_readback");
            const auto final_ids = thread_ids();
            require_known_ids(final_ids, "final_population_snapshot", round);
            require(std::includes(live_ids.begin(), live_ids.end(), final_ids.begin(), final_ids.end()),
                "publisher maintenance native population contradicts retained original retirement");
            bool retired_after_readback = false;
            for (const auto& item : originals) {
                const auto repeated = read_original(threads.at(item.first)->get(), *item.second);
                const bool was_live = std::binary_search(live_ids.begin(), live_ids.end(), item.first);
                if (repeated) {
                    require(was_live && std::binary_search(final_ids.begin(), final_ids.end(), item.first),
                        "publisher maintenance live original absent from native population");
                } else if (was_live) retired_after_readback = true;
            }
            require_primary_unchanged(token.get(), before, primary);
            require_execution();
            if (retired_after_readback) continue;
            require(final_ids == live_ids,
                "publisher maintenance thread population changed without proved original retirement");
            return Value(Value::Object{{"schema", baseline.at("schema")}, {"scope", baseline.at("scope")},
                {"process_id", Value(static_cast<std::uint64_t>(GetCurrentProcessId()))},
                {"current_thread_id", Value(static_cast<std::uint64_t>(GetCurrentThreadId()))},
                {"primary_token", Value(std::move(primary))}, {"threads", Value(std::move(observed))}});
        }
        throw std::runtime_error("publisher maintenance original retirement exceeded bounded readback samples");
    }
};
PublisherWorkerSecurityContinuity::PublisherWorkerSecurityContinuity(const Value& baseline)
    : impl_(std::make_unique<Impl>(baseline)) {}
PublisherWorkerSecurityContinuity::~PublisherWorkerSecurityContinuity() = default;
Value PublisherWorkerSecurityContinuity::observe_current(const std::string& failure_context) const {
    return impl_->observe_current({}, failure_context);
}
Value detail::observe_publisher_worker_continuity_for_test(const PublisherWorkerSecurityContinuity& continuity,
    const std::function<void(const char*)>& checkpoint) {
    return continuity.impl_->observe_current(checkpoint);
}

void require_publisher_worker_security(const Value& value, const PublisherServiceObservation& service) {
    require_publisher_worker_security(value,
        PublisherWorkerTokenContext{service.process_id, service.service_sid, service.token});
}
void require_publisher_worker_security(const Value& value, const PublisherWorkerTokenContext& worker) {
    require(value.as_object().size() == 6 && value.at("schema").as_string() == "usk.publisher_worker_security.v1" &&
        value.at("scope").as_string() == "stored_primary_token_defaults_and_process_thread_owner_dacls" &&
        worker.process_id && value.at("process_id").as_unsigned() == worker.process_id &&
        canonical_sid(worker.service_sid) && worker.token.process_groups.size() <= 4096,
        "publisher worker security context or closed schema differs");
    std::set<std::string> trusted{"S-1-5-18", "S-1-5-32-544", worker.service_sid};
    std::size_t logons = 0;
    for (const auto& group : worker.token.process_groups) {
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
    require(primary.as_object().size() == 9 && worker.token.identity.token_type == TokenPrimary &&
        worker.token.identity.token_id && worker.token.identity.authentication_id && worker.token.identity.modified_id &&
        primary.at("token_id").as_string() == hex64(worker.token.identity.token_id) &&
        primary.at("authentication_id").as_string() == hex64(worker.token.identity.authentication_id) &&
        primary.at("modified_id").as_string() == hex64(worker.token.identity.modified_id),
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
