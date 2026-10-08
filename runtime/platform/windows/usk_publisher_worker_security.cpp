// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_worker_security.h"
#if defined(_WIN32)
#include "usk_publisher_handle_observation.h"
#include <winternl.h>
#include <sddl.h>
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <exception>
#include <iterator>
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
    ~Handle() { if (value_) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(other.value_) { other.value_ = nullptr; }
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
    // One fresh system-wide census at EVERY existing before/after boundary.
    // Unlike NtGetNextThread, this snapshot does not open/filter thread objects
    // by our query rights. Original handles and all admission gates are separate.
    // Toolhelp's per-entry mapping walk was a substantial sampled cost; do not
    // reuse a census or merge boundaries to avoid that cost.
    using Query = LONG (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    const auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    require(query != nullptr, "publisher worker independent system census export unavailable");
    constexpr ULONG limit = 16u * 1024u * 1024u;
    constexpr std::uint32_t length_mismatch = 0xc0000004u;
    std::vector<std::uint8_t> bytes(1024u * 1024u);
    for (unsigned attempt = 0; attempt != 4; ++attempt) {
        ULONG returned = 0;
        const auto status = static_cast<std::uint32_t>(query(static_cast<ULONG>(SystemProcessInformation),
            bytes.data(), static_cast<ULONG>(bytes.size()), &returned));
        if (status == 0) {
            require(returned && returned <= bytes.size(), "publisher worker independent census length unavailable");
            return detail::parse_publisher_system_thread_census(bytes.data(), returned, GetCurrentProcessId(), GetCurrentThreadId());
        }
        // Only incomplete buffer sizing can expand BEFORE any census is used.
        // Every other status, exhausted bound or failed observation refuses.
        require(status == length_mismatch && attempt != 3 && returned <= limit && bytes.size() < limit,
            "publisher worker independent system census unavailable or exceeds bound");
        const auto next = (std::max)(static_cast<std::size_t>(returned), bytes.size() * 2u);
        require(next <= limit, "publisher worker independent system census exceeds byte bound");
        bytes.resize(next);
    }
    throw std::runtime_error("publisher worker independent system census exhausted sizing bound");
}
using ThreadHandles = std::map<DWORD, std::unique_ptr<Handle>>;
std::vector<DWORD> handle_ids(const ThreadHandles& handles) {
    std::vector<DWORD> result;
    for (const auto& item : handles) result.push_back(item.first);
    return result;
}
struct BrokerThreadFirstProbe {
    HANDLE original = nullptr; // Borrowed only while the native map owns it.
    DWORD process_id = 0, thread_id = 0;
    std::size_t ordinal = 0;
    bool times_read = false;
    DWORD times_error = ERROR_SUCCESS, wait_result = WAIT_FAILED, wait_error = ERROR_SUCCESS;
    std::uint64_t birth = 0;
};
std::uint64_t census_time_value(const FILETIME& value) {
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}
Value missing_broker_original_probe(DWORD id, HANDLE original, const BrokerThreadFirstProbe* first) {
    // Read only the very same still-owned native handle. This is failure
    // provenance, not a live-population exception or safe-creator assertion.
    const auto process_id = GetProcessIdOfThread(original);
    const auto process_error = process_id ? ERROR_SUCCESS : GetLastError();
    const auto thread_id = GetThreadId(original);
    const auto thread_error = thread_id ? ERROR_SUCCESS : GetLastError();
    const bool identity_matches = process_id == GetCurrentProcessId() && thread_id == id;
    FILETIME creation{}, ignored_exit{}, kernel{}, user{};
    const bool times_read = GetThreadTimes(original, &creation, &ignored_exit, &kernel, &user) != FALSE;
    const auto times_error = times_read ? ERROR_SUCCESS : GetLastError();
    const auto birth = times_read ? census_time_value(creation) : 0;
    const auto wait_result = WaitForSingleObject(original, 0);
    const auto wait_error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
    const bool first_bound = first && first->original == original &&
        first->process_id == GetCurrentProcessId() && first->thread_id == id && first->times_read && first->birth;
    const bool same_birth = first_bound && identity_matches && birth && first->birth == birth;
    const bool readable = identity_matches && times_read && birth;
    std::optional<std::uint64_t> confirmed_exit;
    std::optional<DWORD> exit_query_error, exit_wait_result, exit_wait_error;
    if (readable && wait_result == WAIT_OBJECT_0) {
        // Exit output from the earlier timing read is undefined if that read
        // preceded termination. Query it separately AFTER a positive signal.
        FILETIME later_creation{}, later_exit{}, later_kernel{}, later_user{};
        const bool later_read = GetThreadTimes(original, &later_creation, &later_exit, &later_kernel, &later_user) != FALSE;
        exit_query_error = later_read ? ERROR_SUCCESS : GetLastError();
        const bool later_identity = GetProcessIdOfThread(original) == process_id && GetThreadId(original) == id;
        exit_wait_result = WaitForSingleObject(original, 0);
        exit_wait_error = *exit_wait_result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
        if (later_read && later_identity && census_time_value(later_creation) == birth &&
                census_time_value(later_exit) && census_time_value(later_exit) >= birth && *exit_wait_result == WAIT_OBJECT_0)
            confirmed_exit = census_time_value(later_exit);
    }
    const char* lifetime = "unavailable_identity_or_query";
    if (readable && wait_result == WAIT_TIMEOUT) lifetime = "still_nonsignaled_at_refusal";
    else if (same_birth && confirmed_exit && first->wait_result == WAIT_TIMEOUT)
        lifetime = "observed_live_then_signaled";
    else if (same_birth && confirmed_exit && first->wait_result == WAIT_OBJECT_0)
        lifetime = "signaled_at_first_probe";
    const auto optional_dword = [](const std::optional<DWORD>& value) {
        return value ? Value(static_cast<std::uint64_t>(*value)) : Value();
    };
    Value initial;
    if (first && first->original == original) initial = Value(Value::Object{
        {"ordinal", Value(static_cast<std::uint64_t>(first->ordinal))},
        {"process_id", Value(static_cast<std::uint64_t>(first->process_id))},
        {"thread_id", Value(static_cast<std::uint64_t>(first->thread_id))},
        {"get_thread_times", Value(first->times_read)},
        {"get_thread_times_error", Value(static_cast<std::uint64_t>(first->times_error))},
        {"creation_time", first->times_read ? Value(hex64(first->birth)) : Value()},
        {"wait_result", Value(static_cast<std::uint64_t>(first->wait_result))},
        {"wait_error", Value(static_cast<std::uint64_t>(first->wait_error))}});
    return Value(Value::Object{{"thread_id", Value(static_cast<std::uint64_t>(id))},
        {"scope", Value("same_original_handle_sampled_lifetime_no_authority")},
        {"first_probe", std::move(initial)}, {"lifetime_status", Value(lifetime)},
        {"refusal_probe", Value(Value::Object{
            {"process_id", Value(static_cast<std::uint64_t>(process_id))},
            {"thread_id", Value(static_cast<std::uint64_t>(thread_id))},
            {"process_query_error", Value(static_cast<std::uint64_t>(process_error))},
            {"thread_query_error", Value(static_cast<std::uint64_t>(thread_error))},
            {"identity_matches", Value(identity_matches)}, {"get_thread_times", Value(times_read)},
            {"get_thread_times_error", Value(static_cast<std::uint64_t>(times_error))},
            {"creation_time", times_read ? Value(hex64(birth)) : Value()},
            {"birth_matches_first_probe", first_bound ? Value(same_birth) : Value()},
            {"wait_result", Value(static_cast<std::uint64_t>(wait_result))},
            {"wait_error", Value(static_cast<std::uint64_t>(wait_error))},
            {"post_signal_times_error", optional_dword(exit_query_error)},
            {"post_signal_wait_result", optional_dword(exit_wait_result)},
            {"post_signal_wait_error", optional_dword(exit_wait_error)},
            {"confirmed_exit_time", confirmed_exit ? Value(hex64(*confirmed_exit)) : Value()}})}});
}
[[noreturn]] void refuse_broker_census(const std::vector<DWORD>& mandatory, const std::vector<DWORD>& before,
    const std::vector<DWORD>& native, const std::vector<DWORD>& after, unsigned round, const char* phase,
    const std::function<void(const char*)>* checkpoint, bool native_after_observed, bool before_observed = true,
    const ThreadHandles* originals = nullptr, const BrokerThreadFirstProbe* first_probes = nullptr,
    std::size_t first_probe_count = 0) {
    const auto original = std::make_exception_ptr(std::runtime_error(
        "SCM broker native thread enumeration differs from independent complete census"));
    auto reported = original;
    try {
        if (checkpoint) (*checkpoint)("broker_native_before_census_refusal_diagnostic");
        Value::Object diagnostic{{"scope", Value("bounded_original_census_refusal_no_authority")},
            {"phase", Value(phase)}, {"round", Value(static_cast<std::uint64_t>(round))},
            {"acquisition_ordinal", Value(static_cast<std::uint64_t>(
                std::strcmp(phase, "initial_acquisition") == 0 ? 0u : round + 1u))},
            {"observer_process_id", Value(static_cast<std::uint64_t>(GetCurrentProcessId()))},
            {"observer_thread_id", Value(static_cast<std::uint64_t>(GetCurrentThreadId()))},
            {"mandatory_count", Value(static_cast<std::uint64_t>(mandatory.size()))},
            {"before_census_observed", Value(before_observed)},
            {"before_count", before_observed ? Value(static_cast<std::uint64_t>(before.size())) : Value()},
            {"native_walk_completed", Value(native_after_observed)},
            {"after_census_observed", Value(native_after_observed)}};
        const auto difference = [&](const char* label, const std::vector<DWORD>& left,
                const std::vector<DWORD>& right) {
            std::vector<DWORD> missing;
            std::set_difference(left.begin(), left.end(), right.begin(), right.end(), std::back_inserter(missing));
            Value::Array prefix;
            for (std::size_t index = 0; index < missing.size() && index < 8; ++index)
                prefix.emplace_back(Value(static_cast<std::uint64_t>(missing[index])));
            diagnostic.emplace(std::string(label) + "_count", Value(static_cast<std::uint64_t>(missing.size())));
            diagnostic.emplace(std::string(label) + "_prefix", Value(std::move(prefix)));
        };
        if (before_observed) difference("mandatory_missing_before", mandatory, before);
        if (native_after_observed) {
            diagnostic.emplace("current_thread_in_native", Value(std::binary_search(
                native.begin(), native.end(), GetCurrentThreadId())));
            diagnostic.emplace("native_count", Value(static_cast<std::uint64_t>(native.size())));
            diagnostic.emplace("after_count", Value(static_cast<std::uint64_t>(after.size())));
            if (before_observed) difference("before_missing_native", before, native);
            difference("native_missing_after", native, after);
            difference("after_missing_native", after, native);
            Value::Array original_prefix;
            if (originals) for (const auto id : native) {
                if (std::binary_search(after.begin(), after.end(), id)) continue;
                if (original_prefix.size() == 8) break;
                const auto held = originals->find(id);
                if (held == originals->end() || !held->second) continue;
                const BrokerThreadFirstProbe* first = nullptr;
                if (first_probes) for (std::size_t index = 0; index < first_probe_count; ++index)
                    if (first_probes[index].thread_id == id && first_probes[index].original == held->second->get()) {
                        first = &first_probes[index]; break;
                    }
                if (checkpoint) (*checkpoint)("broker_native_before_missing_original_probe");
                original_prefix.emplace_back(missing_broker_original_probe(id, held->second->get(), first));
            }
            diagnostic.emplace("native_missing_after_original_prefix", Value(std::move(original_prefix)));
        }
        const auto text = usk::json::canonical(Value(std::move(diagnostic)));
        if (text.size() <= 12288) reported = std::make_exception_ptr(std::runtime_error(
            "SCM broker native thread enumeration differs from independent complete census; census=" + text));
    } catch (...) {} // Optional diagnostics cannot replace the first refusal.
    std::rethrow_exception(reported);
}
struct NativeBrokerThreads {
    ThreadHandles handles;
    std::vector<DWORD> independent_after;
};
// Only this private owner contains completed-policy original native custody.
// A pending object never enters this map, even if some of its facts were read.
struct BrokerOriginalThreads {
    ThreadHandles handles;
    std::map<DWORD, Value> facts, retired;
    Value baseline, previous;
    bool failed = false;
    bool read(DWORD id, HANDLE another = nullptr);
};
void require_broker_census_binding(BrokerOriginalThreads& originals, const std::vector<DWORD>& census,
    const std::map<DWORD, HANDLE>& native) {
    for (const auto id : census) if (originals.handles.count(id) && !originals.read(id)) {
        require(native.count(id), "SCM broker census-present retired ID lacks same-object native coverage");
        (void)originals.read(id, native.at(id));
    }
}
NativeBrokerThreads native_broker_threads(const std::vector<DWORD>& mandatory, unsigned round, const char* phase,
    const std::function<void(const char*)>* checkpoint, BrokerOriginalThreads* originals = nullptr) {
    // Acquire current-process objects directly. A numeric snapshot followed by
    // OpenThread can lose an SDK helper before acquiring any original handle.
    // Independent Toolhelp coverage below also rejects native access filtering.
    using NextThread = LONG (NTAPI*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
    const auto next = reinterpret_cast<NextThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtGetNextThread"));
    require(next != nullptr, "SCM broker native thread enumeration export unavailable");
    constexpr DWORD rights = THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION | READ_CONTROL | SYNCHRONIZE;
    constexpr std::uint32_t no_more_entries = 0x8000001au;
    // Only the first acquisition has no earlier complete census obligation:
    // retain native objects before the FIRST independent census. Every first-
    // census ID then stays mandatory, including pending native coverage. This
    // does not claim an earlier numeric snapshot or continuous population.
    const bool first = std::strcmp(phase, "initial_acquisition") == 0;
    require(!first || (round == 0 && mandatory.empty()), "SCM broker initial acquisition has prior obligations");
    std::vector<DWORD> before;
    if (!first) {
        if (checkpoint) (*checkpoint)("broker_native_before_independent_before");
        before = thread_ids();
    } else if (checkpoint) (*checkpoint)("broker_native_before_initial_native_walk");
    const auto surviving = [&](const std::vector<DWORD>& population) {
        auto result = population;
        if (originals) result.erase(std::remove_if(result.begin(), result.end(), [&](DWORD id) {
            return originals->handles.count(id) && !originals->read(id);
        }), result.end());
        return result;
    };
    const auto required_live = surviving(mandatory);
    const auto before_live = surviving(before);
    // Subsequent walks keep every prior census ID mandatory in BEFORE, native
    // and AFTER. Never restart a failed read or drop a prior observation.
    if (!first && !std::includes(before_live.begin(), before_live.end(), required_live.begin(), required_live.end()))
        refuse_broker_census(mandatory, before, {}, {}, round, phase, checkpoint, false);
    if (!first && checkpoint) (*checkpoint)("broker_native_after_independent_before");
    ThreadHandles result;
    // Optional fixed-capacity provenance. Allocation/query failure never
    // changes admission, custody or the first-census survival obligation.
    std::unique_ptr<BrokerThreadFirstProbe[]> first_probes;
    try { first_probes = std::make_unique<BrokerThreadFirstProbe[]>(4096); } catch (...) {}
    HANDLE cursor = nullptr;
    for (;;) {
        HANDLE raw = nullptr;
        const auto status = static_cast<std::uint32_t>(next(GetCurrentProcess(), cursor, rights, 0, 0, &raw));
        if (status == no_more_entries && raw == nullptr) break;
        if (status != 0 || !raw || raw == INVALID_HANDLE_VALUE) {
            if (raw && raw != INVALID_HANDLE_VALUE) CloseHandle(raw);
            throw std::runtime_error("SCM broker native thread enumeration failed: ntstatus=" + hex64(status));
        }
        Handle acquired(raw);
        auto held = std::make_unique<Handle>(std::move(acquired));
        const auto id = GetThreadId(held->get());
        const auto process_id = GetProcessIdOfThread(held->get());
        require(id && process_id == GetCurrentProcessId() &&
            observe_publisher_handle_granted_access(held->get()) == rights,
            "SCM broker native thread identity or query-only access differs");
        require(result.size() < 4096 && !result.count(id),
            "SCM broker native thread enumeration exceeds bound or repeats an identity");
        if (originals && originals->handles.count(id)) (void)originals->read(id, held->get());
        if (checkpoint) {
            const auto point = "broker_native_before_original_first_probe." + std::to_string(id);
            (*checkpoint)(point.c_str());
        }
        if (first_probes) {
            auto& probe = first_probes[result.size()];
            probe.original = held->get(); probe.process_id = process_id; probe.thread_id = id; probe.ordinal = result.size();
            FILETIME creation{}, ignored_exit{}, kernel{}, user{};
            probe.times_read = GetThreadTimes(held->get(), &creation, &ignored_exit, &kernel, &user) != FALSE;
            probe.times_error = probe.times_read ? ERROR_SUCCESS : GetLastError();
            if (probe.times_read) probe.birth = census_time_value(creation);
            probe.wait_result = WaitForSingleObject(held->get(), 0);
            probe.wait_error = probe.wait_result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
        }
        cursor = held->get();
        result.emplace(id, std::move(held)); // Retain the cursor through the next call.
    }
    auto ids = handle_ids(result);
    if (checkpoint) (*checkpoint)("broker_native_after_native_walk");
    if (first && checkpoint) (*checkpoint)("broker_native_before_first_independent_census");
    const auto after = thread_ids();
    // BOTH independent census entries need current same-object native evidence
    // before a remembered retired ID can be removed. An original signal alone
    // cannot identify a BEFORE-only or access-filtered numerical entry.
    if (originals) {
        std::map<DWORD, HANDLE> native;
        for (const auto& item : result) native.emplace(item.first, item.second->get());
        require_broker_census_binding(*originals, before, native);
        require_broker_census_binding(*originals, after, native);
    }
    if (first && checkpoint) (*checkpoint)("broker_native_after_first_independent_census");
    const auto covered_before = surviving(before);
    if (originals) ids = surviving(ids);
    if (ids.empty() || !std::binary_search(ids.begin(), ids.end(), GetCurrentThreadId()) ||
            (!first && !std::includes(ids.begin(), ids.end(), covered_before.begin(), covered_before.end())) ||
            !std::includes(after.begin(), after.end(), ids.begin(), ids.end()))
        refuse_broker_census(mandatory, before, ids, after, round, phase, checkpoint, true, !first,
            &result, first_probes.get(), result.size());
    if (originals) for (auto item = result.begin(); item != result.end();) {
        if (originals->handles.count(item->first) && !originals->read(item->first)) item = result.erase(item);
        else ++item;
    }
    return {std::move(result), after};
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

namespace {
[[noreturn]] void refuse_thread_observation(const char* reason, HANDLE original_thread, DWORD original_thread_id,
    unsigned round, const char* checkpoint, bool times_read, DWORD times_error,
    const FILETIME& creation, const std::optional<DWORD>& wait_result, DWORD wait_error,
    const Value* recorded_thread, const std::function<void(const char*)>* control)
{
    // Capture the refusal before optional formatting. These are facts from the
    // original held object; the diagnostic cannot refresh or replace it.
    const auto original = std::make_exception_ptr(std::runtime_error(reason));
    auto reported = original;
    try {
        const auto time_value = [](const FILETIME& value) {
            return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
        };
        if (control) (*control)("broker_native_before_refusal_diagnostic");
        std::optional<std::uint64_t> confirmed_exit;
        if (times_read && time_value(creation) && wait_result == static_cast<DWORD>(WAIT_OBJECT_0)) {
            // The original pre-wait exit output may be undefined. Only this
            // separate post-signal read can observe a defined exit timestamp.
            FILETIME later_creation{}, later_exit{}, kernel{}, user{};
            if (GetThreadTimes(original_thread, &later_creation, &later_exit, &kernel, &user) &&
                GetProcessIdOfThread(original_thread) == GetCurrentProcessId() &&
                GetThreadId(original_thread) == original_thread_id &&
                time_value(later_creation) == time_value(creation) &&
                (!recorded_thread || recorded_thread->at("creation_time").as_string() == hex64(time_value(later_creation))) &&
                time_value(later_exit) && time_value(later_exit) >= time_value(later_creation) &&
                WaitForSingleObject(original_thread, 0) == WAIT_OBJECT_0)
                confirmed_exit = time_value(later_exit);
        }
        const std::string detail = std::string(reason) + "; held_process_id=" + std::to_string(GetCurrentProcessId()) +
            "; held_thread_id=" + std::to_string(original_thread_id) + "; round=" + std::to_string(round) +
            "; checkpoint=" + checkpoint + "; get_thread_times=" + (times_read ? "true" : "false") +
            "; get_thread_times_error=" + std::to_string(times_error) +
            "; creation_filetime=" + (times_read ? std::to_string(time_value(creation)) : "unobserved") +
            "; confirmed_exit_filetime=" + (confirmed_exit ? std::to_string(*confirmed_exit) : "unobserved") +
            "; wait_result=" + (wait_result ? std::to_string(*wait_result) : "unobserved") +
            "; wait_error=" + std::to_string(wait_error) + ";";
        try { throw std::runtime_error(detail); }
        catch (const std::runtime_error&) { reported = std::current_exception(); }
    } catch (...) {} // Preserve the already captured refusal if formatting fails.
    std::rethrow_exception(reported);
}
Value observe_worker_security(bool native_broker, const std::function<void(const char*)>* checkpoint = nullptr,
    ThreadHandles* retained = nullptr) {
    HANDLE raw = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | READ_CONTROL, &raw),
        "publisher worker primary token security unavailable");
    Handle token(raw);
    const auto before = statistics(token.get());
    auto primary = read_primary_security(token.get(), before);
    auto acquisition = native_broker ? native_broker_threads({}, 0, "initial_acquisition", checkpoint) : NativeBrokerThreads{};
    auto acquired = std::move(acquisition.handles);
    auto mandatory = std::move(acquisition.independent_after);
    auto ids = native_broker ? handle_ids(acquired) : thread_ids();
    if (checkpoint) (*checkpoint)("broker_native_threads_pinned");
    std::map<DWORD, std::unique_ptr<Handle>> held_threads;
    std::map<DWORD, Value> recorded_threads;
    bool population_complete = false;
    // Read-only Windows APIs can initialize additional owned helper threads.
    // Extend coverage without dropping or refreshing any earlier observation;
    // loss, identity/security changes and continued churn still refuse.
    for (unsigned round = 0; round != 4; ++round) {
        for (const auto id : ids) {
            if (held_threads.count(id)) continue;
            auto held = native_broker ? std::move(acquired.at(id)) : std::make_unique<Handle>(OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION | READ_CONTROL | SYNCHRONIZE, FALSE, id));
            const auto thread = held->get();
            require(GetProcessIdOfThread(thread) == GetCurrentProcessId() && GetThreadId(thread) == id,
                "publisher worker thread is not owned by this process");
            require_no_thread_token(thread);
            FILETIME creation{}, exit{}, kernel{}, user{};
            const bool times_read = GetThreadTimes(thread, &creation, &exit, &kernel, &user) != FALSE;
            const DWORD times_error = times_read ? ERROR_SUCCESS : GetLastError();
            if (checkpoint && times_read) {
                const auto point = "broker_native_initial_times_read." + std::to_string(id);
                (*checkpoint)(point.c_str());
            }
            std::optional<DWORD> wait_result;
            DWORD wait_error = ERROR_SUCCESS;
            if (times_read && (creation.dwHighDateTime || creation.dwLowDateTime)) {
                wait_result = WaitForSingleObject(thread, 0);
                if (*wait_result == WAIT_FAILED) wait_error = GetLastError();
            }
            if (!times_read || !(creation.dwHighDateTime || creation.dwLowDateTime) ||
                wait_result != static_cast<DWORD>(WAIT_TIMEOUT))
                refuse_thread_observation("publisher worker observed thread is unavailable or exited", thread, id, round,
                    "initial_held_thread_read", times_read, times_error, creation, wait_result, wait_error, nullptr, checkpoint);
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
        if (checkpoint) (*checkpoint)("broker_native_before_thread_readback");
        for (const auto& item : held_threads) {
            FILETIME creation{}, exit{}, kernel{}, user{};
            const auto& recorded = recorded_threads.at(item.first);
            const auto thread = item.second->get();
            const bool times_read = GetThreadTimes(thread, &creation, &exit, &kernel, &user) != FALSE;
            const DWORD times_error = times_read ? ERROR_SUCCESS : GetLastError();
            if (checkpoint && times_read) {
                const auto point = "broker_native_repeated_times_read." + std::to_string(item.first);
                (*checkpoint)(point.c_str());
            }
            const bool identity_matches = times_read &&
                GetProcessIdOfThread(thread) == GetCurrentProcessId() &&
                GetThreadId(thread) == recorded.at("thread_id").as_unsigned();
            std::optional<DWORD> wait_result;
            DWORD wait_error = ERROR_SUCCESS;
            if (identity_matches) {
                wait_result = WaitForSingleObject(thread, 0);
                if (*wait_result == WAIT_FAILED) wait_error = GetLastError();
            }
            if (!identity_matches || wait_result != static_cast<DWORD>(WAIT_TIMEOUT) || recorded.at("creation_time").as_string() !=
                    hex64((static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime))
                refuse_thread_observation("publisher worker held thread exited or changed identity", thread, item.first, round,
                    "repeated_held_thread_read", times_read, times_error, creation, wait_result, wait_error, &recorded, checkpoint);
            auto repeated = object_security(thread);
            require_no_thread_token(thread);
            repeated.emplace("thread_id", recorded.at("thread_id"));
            repeated.emplace("creation_time", recorded.at("creation_time"));
            repeated.emplace("thread_impersonating", Value(false));
            require(usk::json::canonical(Value(repeated)) == usk::json::canonical(recorded),
                "publisher worker held thread security changed across population readback");
        }
        if (checkpoint) (*checkpoint)("broker_native_before_final_census");
        if (native_broker) {
            acquisition = native_broker_threads(mandatory, round, "final_population_census", checkpoint);
            acquired = std::move(acquisition.handles);
            mandatory = std::move(acquisition.independent_after);
        }
        const auto final_ids = native_broker ? handle_ids(acquired) : thread_ids();
        if (final_ids == ids && (!native_broker || mandatory == final_ids)) { population_complete = true; break; }
        require(std::includes(final_ids.begin(), final_ids.end(), ids.begin(), ids.end()),
            "publisher worker lost an observed thread during population readback");
        ids = final_ids;
    }
    require(population_complete, "publisher worker thread population did not settle within its observation bound");
    Value::Array threads;
    for (auto& item : recorded_threads) threads.push_back(std::move(item.second));
    require_primary_unchanged(token.get(), before, primary);
    Value result(Value::Object{{"schema", Value("usk.publisher_worker_security.v1")},
        {"scope", Value("stored_primary_token_defaults_and_process_thread_owner_dacls")},
        {"process_id", Value(static_cast<std::uint64_t>(GetCurrentProcessId()))},
        {"current_thread_id", Value(static_cast<std::uint64_t>(GetCurrentThreadId()))},
        {"primary_token", Value(std::move(primary))}, {"threads", Value(std::move(threads))}});
    if (retained) *retained = std::move(held_threads);
    return result;
}
bool BrokerOriginalThreads::read(DWORD id, HANDLE another) {
    const auto handle = handles.at(id)->get();
    const auto& original = facts.at(id);
    if (another) {
        using Compare = BOOL (WINAPI*)(HANDLE, HANDLE);
        const auto compare = reinterpret_cast<Compare>(GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "CompareObjectHandles"));
        require(compare && compare(handle, another), "SCM broker native walk returned another object for an admitted TID");
    }
    const auto identity = [&] {
        FILETIME creation{}, exit{}, kernel{}, user{};
        require(GetProcessIdOfThread(handle) == baseline.at("process_id").as_unsigned() && GetThreadId(handle) == id &&
            GetThreadTimes(handle, &creation, &exit, &kernel, &user) &&
            hex64(census_time_value(creation)) == original.at("creation_time").as_string(),
            "SCM broker original-held thread identity unavailable or changed");
        return census_time_value(exit); // Defined only when called AFTER a signal.
    };
    const auto wait = [&] {
        const auto result = WaitForSingleObject(handle, 0);
        require(result == WAIT_TIMEOUT || result == WAIT_OBJECT_0, "SCM broker original-held thread wait unavailable");
        return result;
    };
    (void)identity();
    auto state = wait();
    if (state == WAIT_TIMEOUT) require_no_thread_token(handle);
    auto security = object_security(handle);
    security.emplace("thread_id", original.at("thread_id"));
    security.emplace("creation_time", original.at("creation_time"));
    security.emplace("thread_impersonating", Value(false));
    require(usk::json::canonical(Value(security)) == usk::json::canonical(original),
        "SCM broker original-held stored thread security changed");
    state = wait();
    if (state == WAIT_TIMEOUT) {
        require(!retired.count(id), "SCM broker original-held thread revived");
        require_no_thread_token(handle);
        (void)identity();
        return true;
    }
    require(id != baseline.at("current_thread_id").as_unsigned(), "SCM broker original execution thread retired");
    // Separate native time query AFTER signal; never consume live ExitTime.
    const auto exit = identity();
    require(exit && hex64(exit) >= original.at("creation_time").as_string() && wait() == WAIT_OBJECT_0 &&
        identity() == exit && wait() == WAIT_OBJECT_0, "SCM broker original-held native retirement changed or unavailable");
    Value proof(Value::Object{{"thread_id", original.at("thread_id")}, {"creation_time", original.at("creation_time")},
        {"exit_time", Value(hex64(exit))}});
    if (retired.count(id)) require(usk::json::canonical(retired.at(id)) == usk::json::canonical(proof),
        "SCM broker original-held exit evidence changed");
    else retired.emplace(id, std::move(proof));
    return false;
}
void require_same_thread_object(HANDLE original, HANDLE repeated) {
    using Compare = BOOL (WINAPI*)(HANDLE, HANDLE);
    const auto compare = reinterpret_cast<Compare>(GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "CompareObjectHandles"));
    require(compare && compare(original, repeated), "SCM broker pending native thread object changed");
}
Value read_pending_broker_thread(HANDLE handle, DWORD id, const Value* original, unsigned round,
    const std::function<void(const char*)>* checkpoint) {
    require(GetProcessIdOfThread(handle) == GetCurrentProcessId() && GetThreadId(handle) == id,
        "SCM broker pending thread identity differs");
    require_no_thread_token(handle);
    FILETIME creation{}, ignored_exit{}, kernel{}, user{};
    const bool read = GetThreadTimes(handle, &creation, &ignored_exit, &kernel, &user) != FALSE;
    const auto error = read ? ERROR_SUCCESS : GetLastError();
    if (checkpoint && read) {
        const auto point = "broker_native_initial_times_read." + std::to_string(id);
        (*checkpoint)(point.c_str());
    }
    std::optional<DWORD> waited;
    DWORD wait_error = ERROR_SUCCESS;
    if (read && census_time_value(creation)) {
        waited = WaitForSingleObject(handle, 0);
        if (*waited == WAIT_FAILED) wait_error = GetLastError();
    }
    if (!read || !census_time_value(creation) || waited != static_cast<DWORD>(WAIT_TIMEOUT))
        refuse_thread_observation("SCM broker pending thread is unavailable or exited", handle, id, round,
            "pending_full_policy_read", read, error, creation, waited, wait_error, original, checkpoint);
    auto facts = object_security(handle);
    require(usk::json::canonical(Value(facts)) == usk::json::canonical(Value(object_security(handle))),
        "SCM broker pending thread security changed during readback");
    facts.emplace("thread_id", Value(static_cast<std::uint64_t>(id)));
    facts.emplace("creation_time", Value(hex64(census_time_value(creation))));
    facts.emplace("thread_impersonating", Value(false));
    require_no_thread_token(handle);
    FILETIME repeated{}, repeated_exit{};
    require(GetProcessIdOfThread(handle) == GetCurrentProcessId() && GetThreadId(handle) == id &&
        GetThreadTimes(handle, &repeated, &repeated_exit, &kernel, &user) && CompareFileTime(&creation, &repeated) == 0 &&
        WaitForSingleObject(handle, 0) == WAIT_TIMEOUT, "SCM broker pending thread ended or changed before full admission");
    Value result(std::move(facts));
    if (original) require(usk::json::canonical(result) == usk::json::canonical(*original),
        "SCM broker pending stored thread security changed across readback");
    return result;
}
Value broker_partition(const BrokerOriginalThreads& originals, const std::map<DWORD, Value>& pending,
    const std::vector<DWORD>& live) {
    auto admitted = originals.baseline;
    Value::Array all, observed, retired;
    auto facts = originals.facts;
    facts.insert(pending.begin(), pending.end());
    for (const auto& item : facts) {
        all.push_back(item.second);
        if (std::binary_search(live.begin(), live.end(), item.first)) observed.push_back(item.second);
    }
    for (const auto& item : originals.retired) retired.push_back(item.second);
    admitted.as_object().at("threads") = Value(std::move(all));
    auto result = originals.baseline;
    result.as_object().at("schema") = Value("usk.publisher_broker_worker_security.v1");
    result.as_object().at("scope") = Value("completed_policy_original_native_custody_and_pending_additions");
    result.as_object().at("threads") = Value(std::move(observed));
    result.as_object().emplace("admitted_baseline", std::move(admitted));
    result.as_object().emplace("retired_threads", Value(std::move(retired)));
    return result;
}
void pin_broker_originals(BrokerOriginalThreads& originals, const PublisherWorkerTokenContext& context) {
    // Move original handles out of the successful native sampler. They remain
    // owned locally during full bound validation and allocation; no reopen.
    ThreadHandles retained;
    auto baseline = observe_worker_security(true, nullptr, &retained);
    require_publisher_worker_security(baseline, context);
    std::map<DWORD, Value> facts;
    for (const auto& row : baseline.at("threads").as_array()) facts.emplace(static_cast<DWORD>(row.at("thread_id").as_unsigned()), row);
    originals.baseline = std::move(baseline);
    originals.facts = std::move(facts);
    originals.handles = std::move(retained);
    originals.previous = broker_partition(originals, {}, handle_ids(originals.handles));
    require_publisher_broker_worker_security(originals.previous, context);
}
Value sample_broker_originals(BrokerOriginalThreads& originals, const PublisherWorkerTokenContext& context,
    const std::function<void(const char*)>* checkpoint) {
    require(!originals.failed && GetCurrentProcessId() == originals.baseline.at("process_id").as_unsigned() &&
        GetCurrentThreadId() == originals.baseline.at("current_thread_id").as_unsigned(),
        "SCM broker original lifetime owner failed or execution context changed");
    try {
        HANDLE raw = nullptr;
        require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | READ_CONTROL, &raw), "SCM broker primary security unavailable");
        Handle token(raw);
        const auto before = statistics(token.get());
        const auto primary = read_primary_security(token.get(), before);
        require(usk::json::canonical(Value(primary)) == usk::json::canonical(originals.baseline.at("primary_token")),
            "SCM broker frozen primary token or defaults changed");
        ThreadHandles pending;
        std::map<DWORD, Value> pending_facts;
        auto acquisition = native_broker_threads({}, 0, "initial_acquisition", checkpoint, &originals);
        for (unsigned round = 0; round != 4; ++round) {
            for (auto& item : acquisition.handles) {
                if (originals.handles.count(item.first)) { (void)originals.read(item.first, item.second->get()); continue; }
                if (pending.count(item.first)) { require_same_thread_object(pending.at(item.first)->get(), item.second->get()); continue; }
                require(originals.handles.size() + pending.size() < 4096, "SCM broker total original provenance exceeds bound");
                auto facts = read_pending_broker_thread(item.second->get(), item.first, nullptr, round, checkpoint);
                pending_facts.emplace(item.first, std::move(facts));
                pending.emplace(item.first, std::move(item.second));
            }
            if (checkpoint) (*checkpoint)("broker_native_before_thread_readback");
            std::vector<DWORD> live;
            for (const auto& item : originals.handles) if (originals.read(item.first)) live.push_back(item.first);
            for (const auto& item : pending) {
                (void)read_pending_broker_thread(item.second->get(), item.first, &pending_facts.at(item.first), round, checkpoint);
                live.push_back(item.first);
            }
            std::sort(live.begin(), live.end());
            if (checkpoint) (*checkpoint)("broker_native_before_final_census");
            auto final = native_broker_threads(acquisition.independent_after, round, "final_population_census", checkpoint, &originals);
            const auto ids = handle_ids(final.handles);
            // Pending handles/facts remain original throughout every walk.
            // A per-thread partial read never grants a retirement exception.
            for (const auto& item : pending) {
                require(final.handles.count(item.first), "SCM broker lost a pending thread before completed policy admission");
                require_same_thread_object(item.second->get(), final.handles.at(item.first)->get());
                (void)read_pending_broker_thread(item.second->get(), item.first, &pending_facts.at(item.first), round, checkpoint);
            }
            std::vector<DWORD> repeated_live;
            for (const auto& item : originals.handles) if (originals.read(item.first)) repeated_live.push_back(item.first);
            for (const auto& item : pending) repeated_live.push_back(item.first);
            std::sort(repeated_live.begin(), repeated_live.end());
            require_primary_unchanged(token.get(), before, primary);
            if (ids == repeated_live && final.independent_after == ids && live == repeated_live) {
                auto result = broker_partition(originals, pending_facts, repeated_live);
                require_publisher_broker_worker_security(result, context);
                require_publisher_broker_worker_security_continuity(originals.previous, result);
                auto previous = result;
                // No fallible proof/allocation follows admission. Node transfer
                // preserves each FIRST original native handle and full facts.
                originals.handles.merge(pending);
                originals.facts.merge(pending_facts);
                originals.previous = std::move(previous);
                return result;
            }
            // Only positive old-object retirement or still-pending additions
            // can extend this successful read, within the same four rounds.
            for (const auto id : repeated_live)
                require(std::binary_search(ids.begin(), ids.end(), id), "SCM broker live original absent from native walk");
            acquisition = std::move(final);
        }
        throw std::runtime_error("SCM broker lifetime population did not settle within its observation bound");
    } catch (...) { originals.failed = true; throw; }
}
} // namespace
std::vector<DWORD> detail::parse_publisher_system_thread_census(const std::uint8_t* bytes,
    std::size_t size, DWORD current_process, DWORD current_thread) {
    require(bytes && size >= sizeof(SYSTEM_PROCESS_INFORMATION) && size <= 16u * 1024u * 1024u &&
        current_process && current_thread, "publisher worker independent census buffer invalid");
    std::vector<DWORD> result;
    std::size_t offset = 0, processes = 0;
    bool found = false;
    for (;;) {
        require(++processes <= 65536u && size - offset >= sizeof(SYSTEM_PROCESS_INFORMATION),
            "publisher worker independent census process header truncated");
        SYSTEM_PROCESS_INFORMATION process{};
        std::memcpy(&process, bytes + offset, sizeof(process));
        const auto extent = process.NextEntryOffset ? static_cast<std::size_t>(process.NextEntryOffset) : size - offset;
        require(extent >= sizeof(process) && extent <= size - offset &&
            (!process.NextEntryOffset || process.NextEntryOffset % alignof(SYSTEM_PROCESS_INFORMATION) == 0) &&
            process.NumberOfThreads <= (extent - sizeof(process)) / sizeof(SYSTEM_THREAD_INFORMATION),
            "publisher worker independent census process/thread extent invalid");
        if (reinterpret_cast<std::uintptr_t>(process.UniqueProcessId) == current_process) {
            require(!found && process.NumberOfThreads && process.NumberOfThreads <= 4096u,
                "publisher worker independent census process repeated or thread bound invalid");
            found = true;
            for (ULONG index = 0; index != process.NumberOfThreads; ++index) {
                SYSTEM_THREAD_INFORMATION thread{};
                std::memcpy(&thread, bytes + offset + sizeof(process) +
                    static_cast<std::size_t>(index) * sizeof(thread), sizeof(thread));
                const auto id = reinterpret_cast<std::uintptr_t>(thread.ClientId.UniqueThread);
                require(reinterpret_cast<std::uintptr_t>(thread.ClientId.UniqueProcess) == current_process &&
                    id && id <= MAXDWORD, "publisher worker independent census thread identity invalid");
                result.push_back(static_cast<DWORD>(id));
            }
        }
        if (!process.NextEntryOffset) break;
        offset += extent;
    }
    std::sort(result.begin(), result.end());
    require(found && !result.empty() && std::adjacent_find(result.begin(), result.end()) == result.end() &&
        std::binary_search(result.begin(), result.end(), current_thread),
        "publisher worker current thread absent or population duplicated");
    return result;
}
struct PublisherBrokerWorkerSecurity::Impl { BrokerOriginalThreads originals; };
std::vector<DWORD> detail::observe_publisher_system_thread_census_for_test() { return thread_ids(); }
PublisherBrokerWorkerSecurity::PublisherBrokerWorkerSecurity(const PublisherServiceObservation& service)
    : impl_(std::make_unique<Impl>()) {
    require(service.process_id == GetCurrentProcessId(), "SCM broker lifetime context is another process");
    pin_broker_originals(impl_->originals, PublisherWorkerTokenContext{service.process_id, service.service_sid, service.token});
}
PublisherBrokerWorkerSecurity::~PublisherBrokerWorkerSecurity() = default;
Value PublisherBrokerWorkerSecurity::observe_current(const PublisherServiceObservation& service) {
    return sample_broker_originals(impl_->originals,
        PublisherWorkerTokenContext{service.process_id, service.service_sid, service.token}, nullptr);
}
struct detail::BrokerWorkerSecurityTestOwner { BrokerOriginalThreads originals; PublisherWorkerTokenContext context; };
std::shared_ptr<detail::BrokerWorkerSecurityTestOwner> detail::pin_broker_worker_security_for_test() {
    auto result = std::make_shared<BrokerWorkerSecurityTestOwner>();
    const auto actual = observe_current_publisher_token();
    result->context = PublisherWorkerTokenContext{GetCurrentProcessId(), actual.process_user_sid, actual};
    pin_broker_originals(result->originals, result->context);
    return result;
}
Value detail::observe_broker_worker_security_for_test(BrokerWorkerSecurityTestOwner& owner,
    const std::function<void(const char*)>& checkpoint) {
    return sample_broker_originals(owner.originals, owner.context, &checkpoint);
}
void detail::require_broker_retired_census_binding_for_test(BrokerWorkerSecurityTestOwner& owner,
    DWORD id, HANDLE object) {
    std::map<DWORD, HANDLE> native;
    if (object) native.emplace(id, object);
    require_broker_census_binding(owner.originals, {id}, native);
}
Value observe_current_publisher_worker_security() {
    return observe_worker_security(false);
}
Value observe_current_publisher_broker_worker_security(const PublisherServiceObservation& service) {
    require(service.process_id == GetCurrentProcessId(), "SCM broker worker security context is another process");
    try {
        auto result = observe_worker_security(true);
        require_publisher_worker_security(result, service);
        return result;
    } catch (const std::exception& error) {
        throw std::runtime_error("SCM broker current worker security observation refused: process=" +
            std::to_string(GetCurrentProcessId()) + " thread=" + std::to_string(GetCurrentThreadId()) +
            "; cause=" + error.what());
    }
}
Value detail::observe_publisher_broker_worker_security_for_test(const std::function<void(const char*)>& checkpoint) {
    return observe_worker_security(true, &checkpoint);
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
    std::optional<Value> read_original(HANDLE handle, const Value& original, Value* retirement = nullptr) const {
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
        if (state == WAIT_OBJECT_0) {
            require_retired();
            if (retirement) *retirement = Value(Value::Object{{"thread_id", original.at("thread_id")},
                {"creation_time", original.at("creation_time")},
                {"exit_time", Value(hex64((static_cast<std::uint64_t>(exit.dwHighDateTime) << 32) | exit.dwLowDateTime))}});
            return std::nullopt;
        }
        require_no_thread_token(handle);
        return Value(std::move(facts));
    }
    Value observe_current(const std::function<void(const char*)>& checkpoint,
        const std::string& failure_context = {}, bool include_retirement = false) const {
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
            Value::Array retired;
            std::vector<DWORD> live_ids;
            for (const auto& item : originals) {
                Value retirement;
                auto facts = read_original(threads.at(item.first)->get(), *item.second, &retirement);
                if (facts) {
                    require(std::binary_search(first_ids.begin(), first_ids.end(), item.first),
                        "publisher maintenance live original absent from native population");
                    live_ids.push_back(item.first); observed.push_back(std::move(*facts));
                } else retired.push_back(std::move(retirement));
            }
            if (checkpoint) checkpoint("after_live_readback");
            const auto final_ids = thread_ids();
            require_known_ids(final_ids, "final_population_snapshot", round);
            require(std::includes(live_ids.begin(), live_ids.end(), final_ids.begin(), final_ids.end()),
                "publisher maintenance native population contradicts retained original retirement");
            bool retired_after_readback = false;
            Value::Array repeated_retired;
            for (const auto& item : originals) {
                Value retirement;
                const auto repeated = read_original(threads.at(item.first)->get(), *item.second, &retirement);
                const bool was_live = std::binary_search(live_ids.begin(), live_ids.end(), item.first);
                if (repeated) {
                    require(was_live && std::binary_search(final_ids.begin(), final_ids.end(), item.first),
                        "publisher maintenance live original absent from native population");
                } else {
                    repeated_retired.push_back(std::move(retirement));
                    if (was_live) retired_after_readback = true;
                }
            }
            require_primary_unchanged(token.get(), before, primary);
            require_execution();
            if (retired_after_readback) continue;
            require(usk::json::canonical(Value(retired)) == usk::json::canonical(Value(repeated_retired)),
                "publisher original-held retirement evidence changed during readback");
            require(final_ids == live_ids,
                "publisher maintenance thread population changed without proved original retirement");
            Value result(Value::Object{{"schema", baseline.at("schema")}, {"scope", baseline.at("scope")},
                {"process_id", Value(static_cast<std::uint64_t>(GetCurrentProcessId()))},
                {"current_thread_id", Value(static_cast<std::uint64_t>(GetCurrentThreadId()))},
                {"primary_token", Value(std::move(primary))}, {"threads", Value(std::move(observed))}});
            if (include_retirement) {
                result.as_object().at("schema") = Value("usk.publisher_worker_security.v2");
                result.as_object().at("scope") = Value("original_pinned_token_defaults_and_native_thread_retirement_partition");
                result.as_object().emplace("original_baseline", baseline);
                result.as_object().emplace("retired_threads", Value(std::move(retired)));
            }
            return result;
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
Value PublisherWorkerSecurityContinuity::observe_current_with_retirement(const std::string& failure_context) const {
    return impl_->observe_current({}, failure_context, true);
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
    if (value.at("schema").as_string() == "usk.publisher_worker_security.v2") {
        require(value.as_object().size() == 8 && value.at("scope").as_string() ==
            "original_pinned_token_defaults_and_native_thread_retirement_partition",
            "publisher retirement observation closed schema differs");
        const auto& baseline = value.at("original_baseline");
        require(baseline.at("schema").as_string() == "usk.publisher_worker_security.v1",
            "publisher retirement baseline is not the original closed snapshot");
        require_publisher_worker_security(baseline, worker);
        auto live = value;
        live.as_object().erase("original_baseline");
        live.as_object().erase("retired_threads");
        live.as_object().at("schema") = baseline.at("schema");
        live.as_object().at("scope") = baseline.at("scope");
        require_publisher_worker_security(live, worker);
        for (const auto* field : {"process_id", "current_thread_id", "primary_token"})
            require(usk::json::canonical(live.at(field)) == usk::json::canonical(baseline.at(field)),
                "publisher retirement changed original non-thread security facts");
        std::map<std::uint64_t, const Value*> originals;
        for (const auto& thread : baseline.at("threads").as_array())
            originals.emplace(thread.at("thread_id").as_unsigned(), &thread);
        std::set<std::uint64_t> partition;
        for (const auto& thread : live.at("threads").as_array()) {
            const auto id = thread.at("thread_id").as_unsigned();
            require(originals.count(id) && partition.insert(id).second &&
                usk::json::canonical(thread) == usk::json::canonical(*originals.at(id)),
                "publisher live partition added or changed an original thread");
        }
        const auto& retired = value.at("retired_threads").as_array();
        require(retired.size() <= originals.size(), "publisher retirement evidence exceeds original population");
        std::uint64_t previous = 0;
        for (const auto& thread : retired) {
            const auto id = thread.at("thread_id").as_unsigned();
            const auto& birth = thread.at("creation_time").as_string();
            const auto& exit = thread.at("exit_time").as_string();
            require(thread.as_object().size() == 3 && id > previous && originals.count(id) &&
                id != live.at("current_thread_id").as_unsigned() && partition.insert(id).second &&
                birth == originals.at(id)->at("creation_time").as_string() && exit.size() == 16 &&
                exit != "0000000000000000" && exit >= birth &&
                std::all_of(exit.begin(), exit.end(), [](char ch) {
                    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
                }), "publisher original retirement identity, native exit or partition differs");
            previous = id;
        }
        require(partition.size() == originals.size(), "publisher original thread partition is incomplete");
        return;
    }
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
void require_publisher_broker_worker_security(const Value& value, const PublisherWorkerTokenContext& worker) {
    require(value.as_object().size() == 8 && value.at("schema").as_string() == "usk.publisher_broker_worker_security.v1" &&
        value.at("scope").as_string() == "completed_policy_original_native_custody_and_pending_additions",
        "SCM broker lifetime closed schema differs");
    // Reuse the complete stored-policy and partition DATA checks. This does
    // not turn a growing broker admission history into child native custody.
    auto partition = value;
    partition.as_object().at("schema") = Value("usk.publisher_worker_security.v2");
    partition.as_object().at("scope") = Value("original_pinned_token_defaults_and_native_thread_retirement_partition");
    partition.as_object().emplace("original_baseline", partition.at("admitted_baseline"));
    partition.as_object().erase("admitted_baseline");
    require_publisher_worker_security(partition, worker);
}
void require_publisher_broker_worker_security_continuity(const Value& earlier, const Value& later) {
    require(earlier.at("schema").as_string() == "usk.publisher_broker_worker_security.v1" &&
        later.at("schema").as_string() == earlier.at("schema").as_string(), "SCM broker lifetime version changed");
    for (const auto* key : {"scope", "process_id", "current_thread_id", "primary_token"})
        require(usk::json::canonical(earlier.at(key)) == usk::json::canonical(later.at(key)),
            "SCM broker frozen lifetime context changed");
    std::map<std::uint64_t, const Value*> admitted, retired;
    for (const auto& row : later.at("admitted_baseline").at("threads").as_array())
        require(admitted.emplace(row.at("thread_id").as_unsigned(), &row).second, "SCM broker repeated admitted identity");
    for (const auto& row : earlier.at("admitted_baseline").at("threads").as_array())
        require(admitted.count(row.at("thread_id").as_unsigned()) &&
            usk::json::canonical(row) == usk::json::canonical(*admitted.at(row.at("thread_id").as_unsigned())),
            "SCM broker admitted original disappeared or changed");
    for (const auto& row : later.at("retired_threads").as_array())
        require(retired.emplace(row.at("thread_id").as_unsigned(), &row).second, "SCM broker repeated retired identity");
    for (const auto& row : earlier.at("retired_threads").as_array())
        require(retired.count(row.at("thread_id").as_unsigned()) &&
            usk::json::canonical(row) == usk::json::canonical(*retired.at(row.at("thread_id").as_unsigned())),
            "SCM broker admitted retirement disappeared, revived or changed");
}
void require_publisher_worker_security_continuity(const Value& earlier, const Value& later) {
    if (earlier.at("schema").as_string() != "usk.publisher_worker_security.v2") {
        require(usk::json::canonical(earlier) == usk::json::canonical(later),
            "publisher legacy token/default/thread security changed");
        return;
    }
    require(later.at("schema").as_string() == "usk.publisher_worker_security.v2",
        "publisher original retirement provenance disappeared");
    for (const auto* field : {"schema", "scope", "process_id", "current_thread_id", "primary_token", "original_baseline"})
        require(usk::json::canonical(earlier.at(field)) == usk::json::canonical(later.at(field)),
            "publisher frozen original security binding changed");
    std::map<std::uint64_t, const Value*> retired;
    for (const auto& thread : later.at("retired_threads").as_array())
        require(retired.emplace(thread.at("thread_id").as_unsigned(), &thread).second,
            "publisher repeated retirement identity");
    for (const auto& thread : earlier.at("retired_threads").as_array()) {
        const auto id = thread.at("thread_id").as_unsigned();
        require(retired.count(id) && usk::json::canonical(thread) == usk::json::canonical(*retired.at(id)),
            "publisher original retirement disappeared, revived or changed exit");
    }
}
} // namespace usk::platform::windows
#endif
