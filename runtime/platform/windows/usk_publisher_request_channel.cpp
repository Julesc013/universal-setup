// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_request_channel.h"
#if defined(_WIN32)
#include <sddl.h>
#include <aclapi.h>
#include "usk_publisher_token_observation.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_handle_observation.h"
#include "usk_effect_dispatch.h"
#include "usk_json.h"
#include <algorithm>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <vector>
namespace usk::platform::windows {
namespace {
constexpr DWORD request_limit = 1024u * 1024u;
constexpr DWORD response_limit = 4u * 1024u * 1024u;
constexpr DWORD client_access = FILE_READ_DATA | FILE_WRITE_DATA |
    FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE v) : value(v) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
struct ServiceHandle {
    SC_HANDLE value;
    explicit ServiceHandle(SC_HANDLE v) : value(v) {}
    ~ServiceHandle() { if (value) CloseServiceHandle(value); }
};
struct LocalBuffer {
    void* value = nullptr;
    ~LocalBuffer() { if (value) LocalFree(value); }
};
ULONGLONG deadline(DWORD milliseconds) {
    if (!milliseconds || milliseconds > 120000) throw std::runtime_error("invalid publisher transport timeout");
    return GetTickCount64() + milliseconds;
}
DWORD remaining(ULONGLONG until) {
    const auto now = GetTickCount64();
    return now >= until ? 0 : static_cast<DWORD>(until - now);
}
void require_request_not_cancelled(const PublisherRequestOptions& options,
    const std::string& inspection_reference) {
    if (!options.cancel_event) return;
    const DWORD result = WaitForSingleObject(options.cancel_event, 0);
    if (result == WAIT_OBJECT_0)
        throw usk::base::EffectRequestNotDispatched(
            usk::base::EffectRequestNotDispatched::Reason::operation_cancelled, inspection_reference);
    if (result != WAIT_TIMEOUT) throw std::runtime_error("publisher cancellation event unavailable");
}
std::wstring canonical_sid(const std::wstring& value) {
    LocalBuffer sid, text;
    if (value.empty() || value.size() > 184 ||
        !ConvertStringSidToSidW(value.c_str(), &sid.value) || !IsValidSid(sid.value) ||
        !ConvertSidToStringSidW(sid.value, reinterpret_cast<LPWSTR*>(&text.value))) {
        throw std::runtime_error("publisher transport SID is invalid");
    }
    return static_cast<wchar_t*>(text.value);
}
struct Io {
    Handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    OVERLAPPED overlapped{};
    Io() {
        if (!event.value) throw std::runtime_error("publisher transport event unavailable");
        overlapped.hEvent = event.value;
    }
    DWORD finish(HANDLE file, BOOL started, HANDLE stop, ULONGLONG until,
        DWORD immediate_error) {
        if (!started && immediate_error != ERROR_IO_PENDING) {
            throw std::runtime_error("publisher transport message failed; Win32 " + std::to_string(immediate_error));
        }
        HANDLE waits[2] = {event.value, stop};
        const DWORD result = started ? WAIT_OBJECT_0 :
            WaitForMultipleObjects(stop ? 2 : 1, waits, FALSE, remaining(until));
        DWORD bytes = 0;
        if (result != WAIT_OBJECT_0) {
            CancelIoEx(file, &overlapped);
            // Do not release the OVERLAPPED storage until cancellation completes.
            GetOverlappedResult(file, &overlapped, &bytes, TRUE);
            throw std::runtime_error("publisher transport cancelled or timed out");
        }
        if (!GetOverlappedResult(file, &overlapped, &bytes, FALSE)) {
            throw std::runtime_error("publisher transport message incomplete; Win32 " + std::to_string(GetLastError()));
        }
        return bytes;
    }
};
std::string read_message(HANDLE pipe, DWORD limit, HANDLE stop, ULONGLONG until) {
    std::vector<char> bytes(limit + 1u);
    Io io;
    const BOOL started = ReadFile(pipe, bytes.data(), static_cast<DWORD>(bytes.size()), nullptr, &io.overlapped);
    const DWORD error = started ? ERROR_SUCCESS : GetLastError();
    const DWORD read = io.finish(pipe, started, stop, until, error);
    if (!read || read > limit) throw std::runtime_error("publisher transport message exceeds bound or is empty");
    return std::string(bytes.data(), read);
}
void write_message(HANDLE pipe, const std::string& bytes, DWORD limit, HANDLE stop, ULONGLONG until) {
    if (bytes.empty() || bytes.size() > limit) throw std::runtime_error("publisher transport message exceeds bound or is empty");
    Io io;
    const BOOL started = WriteFile(pipe, bytes.data(), static_cast<DWORD>(bytes.size()), nullptr, &io.overlapped);
    const DWORD error = started ? ERROR_SUCCESS : GetLastError();
    if (io.finish(pipe, started, stop, until, error) != bytes.size()) {
        throw std::runtime_error("publisher transport partial message");
    }
}
std::string sid_text(PSID sid) {
    LocalBuffer rendered;
    if (!sid || !IsValidSid(sid) || !ConvertSidToStringSidW(sid, reinterpret_cast<LPWSTR*>(&rendered.value)))
        throw std::runtime_error("authenticated client SID is unavailable");
    const std::wstring wide(static_cast<wchar_t*>(rendered.value));
    std::string text;
    text.reserve(wide.size());
    for (const wchar_t ch : wide) {
        if (ch > 0x7f) throw std::runtime_error("authenticated client SID is not ASCII");
        text.push_back(static_cast<char>(ch));
    }
    return text;
}
std::uint64_t luid_value(const LUID& value) {
    return (static_cast<std::uint64_t>(static_cast<std::uint32_t>(value.HighPart)) << 32u) | value.LowPart;
}
std::vector<unsigned char> token_bytes(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    DWORD needed = 0;
    if (GetTokenInformation(token, kind, nullptr, 0, &needed) || GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        needed == 0 || needed > 65536)
        throw std::runtime_error("authenticated client token size is unavailable or exceeds its bound");
    std::vector<unsigned char> bytes(needed);
    DWORD returned = 0;
    if (!GetTokenInformation(token, kind, bytes.data(), needed, &returned) || returned != needed)
        throw std::runtime_error("authenticated client token changed during observation");
    return bytes;
}
usk::json::Value client_token_facts(HANDLE token, ULONG process_id) {
    using usk::json::Value;
    const auto user = token_bytes(token, TokenUser);
    const auto statistics = token_bytes(token, TokenStatistics);
    const auto level = token_bytes(token, TokenImpersonationLevel);
    if (user.size() < sizeof(TOKEN_USER) || statistics.size() != sizeof(TOKEN_STATISTICS) ||
        level.size() != sizeof(SECURITY_IMPERSONATION_LEVEL) || process_id == 0)
        throw std::runtime_error("authenticated client token layout differs");
    const auto& stats = *reinterpret_cast<const TOKEN_STATISTICS*>(statistics.data());
    const auto impersonation = *reinterpret_cast<const SECURITY_IMPERSONATION_LEVEL*>(level.data());
    if (stats.TokenType != TokenImpersonation || impersonation < SecurityIdentification)
        throw std::runtime_error("authenticated client token is not an identification token");
    const auto groups = [&](TOKEN_INFORMATION_CLASS kind) {
        const auto bytes = token_bytes(token, kind);
        if (bytes.size() < sizeof(DWORD))
            throw std::runtime_error("authenticated client group layout differs");
        const auto* values = reinterpret_cast<const TOKEN_GROUPS*>(bytes.data());
        if (values->GroupCount == 0) return Value(Value::Array{});
        if (bytes.size() < offsetof(TOKEN_GROUPS, Groups))
            throw std::runtime_error("authenticated client group array is truncated");
        if (values->GroupCount > 1024 || values->GroupCount >
            (bytes.size() - offsetof(TOKEN_GROUPS, Groups)) / sizeof(SID_AND_ATTRIBUTES))
            throw std::runtime_error("authenticated client group count exceeds its bound");
        Value::Array result;
        for (DWORD index = 0; index < values->GroupCount; ++index)
            result.emplace_back(Value::Object{{"sid", Value(sid_text(values->Groups[index].Sid))},
                {"attributes", Value(static_cast<std::uint64_t>(values->Groups[index].Attributes))}});
        return Value(std::move(result));
    };
    const auto privileges = token_bytes(token, TokenPrivileges);
    if (privileges.size() < offsetof(TOKEN_PRIVILEGES, Privileges))
        throw std::runtime_error("authenticated client privilege layout differs");
    const auto* values = reinterpret_cast<const TOKEN_PRIVILEGES*>(privileges.data());
    if (values->PrivilegeCount > 256 || values->PrivilegeCount >
        (privileges.size() - offsetof(TOKEN_PRIVILEGES, Privileges)) / sizeof(LUID_AND_ATTRIBUTES))
        throw std::runtime_error("authenticated client privilege count exceeds its bound");
    Value::Array privilege_values;
    for (DWORD index = 0; index < values->PrivilegeCount; ++index)
        privilege_values.emplace_back(Value::Object{{"luid", Value(luid_value(values->Privileges[index].Luid))},
            {"attributes", Value(static_cast<std::uint64_t>(values->Privileges[index].Attributes))}});
    return Value(Value::Object{{"schema", Value("usk.publisher_authenticated_client_observation.v1")},
        {"scope", Value("held_authenticated_identification_token")},
        {"captured_process_id", Value(static_cast<std::uint64_t>(process_id))},
        {"user_sid", Value(sid_text(reinterpret_cast<const TOKEN_USER*>(user.data())->User.Sid))},
        {"token_type", Value(static_cast<std::uint64_t>(stats.TokenType))},
        {"impersonation_level", Value(static_cast<std::uint64_t>(impersonation))},
        {"token_id", Value(luid_value(stats.TokenId))},
        {"authentication_id", Value(luid_value(stats.AuthenticationId))},
        {"modified_id", Value(luid_value(stats.ModifiedId))},
        {"groups", groups(TokenGroups)}, {"restricted_sids", groups(TokenRestrictedSids)},
        {"privileges", Value(std::move(privilege_values))}});
}
HANDLE require_caller(HANDLE pipe, const std::wstring& expected) {
    if (!ImpersonateNamedPipeClient(pipe)) throw std::runtime_error("publisher caller identification failed");
    struct Revert {
        ~Revert() {
            if (!RevertToSelf()) {
                TerminateProcess(GetCurrentProcess(), ERROR_ACCESS_DENIED);
                std::terminate();
            }
        }
    } revert;
    HANDLE raw = nullptr;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
        throw std::runtime_error("publisher caller token unavailable");
    }
    Handle token(raw);
    DWORD size = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
    if (!size || size > 4096) throw std::runtime_error("publisher caller token size invalid");
    std::vector<unsigned char> user(size);
    SECURITY_IMPERSONATION_LEVEL level{};
    DWORD level_size = 0;
    if (!GetTokenInformation(token.value, TokenUser, user.data(), size, &size) ||
        !GetTokenInformation(token.value, TokenImpersonationLevel, &level, sizeof(level), &level_size) ||
        level < SecurityIdentification) throw std::runtime_error("publisher caller token cannot identify user");
    LocalBuffer observed;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid,
            reinterpret_cast<LPWSTR*>(&observed.value)) ||
        expected != static_cast<wchar_t*>(observed.value)) {
        throw std::runtime_error("publisher caller differs from admitted user");
    }
    if (observe_publisher_noninheritable_handle_flags(token.value) != 0)
        throw std::runtime_error("authenticated client token handle is inheritable");
    token.value = nullptr;
    return raw;
}
DWORD service_process(SC_HANDLE service) {
    SERVICE_STATUS_PROCESS status{};
    DWORD size = 0;
    SERVICE_SID_INFO sid{};
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<BYTE*>(&status), sizeof(status), &size) ||
        status.dwServiceType != SERVICE_WIN32_OWN_PROCESS ||
        status.dwCurrentState != SERVICE_RUNNING || !status.dwProcessId ||
        !QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO,
            reinterpret_cast<BYTE*>(&sid), sizeof(sid), &size) || sid.dwServiceSidType != SERVICE_SID_TYPE_RESTRICTED) {
        throw std::runtime_error("publisher server is not a live own-process restricted service");
    }
    return status.dwProcessId;
}
DWORD await_service_process(SC_HANDLE service, ULONGLONG until,
    const PublisherRequestOptions& options, const std::string& inspection_reference) {
    SERVICE_SID_INFO sid{};
    DWORD size = 0;
    if (!QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO,
            reinterpret_cast<BYTE*>(&sid), sizeof(sid), &size) ||
        sid.dwServiceSidType != SERVICE_SID_TYPE_RESTRICTED) {
        throw std::runtime_error("publisher server is not a restricted service");
    }
    while (true) {
        require_request_not_cancelled(options, inspection_reference);
        SERVICE_STATUS_PROCESS status{};
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&status), sizeof(status), &size) ||
            status.dwServiceType != SERVICE_WIN32_OWN_PROCESS) {
            throw std::runtime_error("publisher server is not an own-process service");
        }
        if (status.dwCurrentState == SERVICE_RUNNING) {
            if (!remaining(until)) throw std::runtime_error("publisher server startup timed out");
            return service_process(service);
        }
        if (status.dwCurrentState != SERVICE_START_PENDING) {
            throw std::runtime_error("publisher server stopped before becoming ready");
        }
        const DWORD wait = std::min<DWORD>(remaining(until), 20);
        if (!wait) throw std::runtime_error("publisher server startup timed out");
        Sleep(wait);
    }
}
}
std::wstring publisher_request_pipe_name(const std::wstring& service_name) {
    if (service_name.empty() || service_name.size() > 80) throw std::runtime_error("publisher service name invalid");
    for (const auto ch : service_name) {
        if (!((ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z') ||
            (ch >= L'0' && ch <= L'9') || ch == L'_' || ch == L'-')) {
            throw std::runtime_error("publisher service name invalid");
        }
    }
    return L"\\\\.\\pipe\\USK-Publisher-" + service_name;
}
std::string publisher_request_inspection_reference(const std::wstring& service_name) {
    const auto name = publisher_request_pipe_name(service_name);
    std::string canonical;
    canonical.reserve(name.size());
    for (const auto ch : name)
        canonical.push_back(static_cast<char>(ch >= L'a' && ch <= L'z' ? ch - L'a' + L'A' : ch));
    return "usk.operation-inspection.v1:" + usk::json::sha256_canonical(usk::json::Value(canonical));
}
HANDLE connect_publisher_request_endpoint(const std::wstring& service_name,
    DWORD timeout_ms, const PublisherRequestOptions& options) {
    const auto until = deadline(timeout_ms);
    if (options.conflict_wait_milliseconds > publisher_request_max_conflict_wait_milliseconds)
        throw std::invalid_argument("publisher contention wait exceeds bound");
    const auto name = publisher_request_pipe_name(service_name);
    const auto inspection_reference = publisher_request_inspection_reference(service_name);
    ULONGLONG conflict_until = 0;
    const auto conflict = [&] {
        throw usk::base::EffectRequestNotDispatched(
            usk::base::EffectRequestNotDispatched::Reason::operation_conflict, inspection_reference);
    };
    while (true) {
        require_request_not_cancelled(options, inspection_reference);
        if (conflict_until && !remaining(conflict_until)) conflict();
        if (!remaining(until)) {
            if (conflict_until) conflict();
            throw std::runtime_error("publisher endpoint connection timed out before dispatch");
        }
        const HANDLE raw = CreateFileW(name.c_str(), client_access, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (raw != INVALID_HANDLE_VALUE) {
            try { require_request_not_cancelled(options, inspection_reference); }
            catch (...) { CloseHandle(raw); throw; }
            return raw;
        }
        const DWORD error = GetLastError();
        if (error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND)
            throw std::runtime_error("publisher endpoint refused connection before dispatch");
        if (error == ERROR_PIPE_BUSY) {
            if (!options.conflict_wait_milliseconds) conflict();
            if (!conflict_until)
                conflict_until = std::min<ULONGLONG>(until,
                    GetTickCount64() + options.conflict_wait_milliseconds);
        }
        const DWORD wait = std::min<DWORD>(10,
            remaining(conflict_until ? conflict_until : until));
        if (!wait) continue;
        // WaitNamedPipe returns immediately for an absent pipe. A separate
        // bounded pause prevents spinning while ServiceMain creates its endpoint.
        if (error == ERROR_FILE_NOT_FOUND) {
            if (options.cancel_event) WaitForSingleObject(options.cancel_event, wait);
            else Sleep(wait);
        } else {
            WaitNamedPipeW(name.c_str(), wait);
        }
    }
}
struct PublisherRequestChannel::State {
    Handle pipe;
    Handle client_token{nullptr};
    ULONG client_process_id = 0;
    usk::json::Value client_facts;
    std::wstring caller_sid;
    HANDLE stop;
    ULONGLONG until;
    bool receive_started = false, received = false, replied = false;
    State(HANDLE p, std::wstring sid, HANDLE event, ULONGLONG end)
        : pipe(p), caller_sid(std::move(sid)), stop(event), until(end) {}
};
PublisherRequestChannel::PublisherRequestChannel(const std::wstring& service_name,
    const std::wstring& service_sid, const std::wstring& caller_sid, HANDLE stop, DWORD timeout_ms) {
    const auto until = deadline(timeout_ms);
    const auto name = publisher_request_pipe_name(service_name);
    const auto caller = canonical_sid(caller_sid);
    const auto service = canonical_sid(service_sid);
    if (service.compare(0, 9, L"S-1-5-80-") != 0) throw std::runtime_error("publisher transport requires service SID");
    // FILE_GENERIC_WRITE includes FILE_CREATE_PIPE_INSTANCE. The caller gets
    // only individual data/attribute rights, never that alias or WRITE_DAC.
    const std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;" + service +
        L")(A;;0x00120183;;;" + caller + L")";
    LocalBuffer descriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
        &descriptor.value, nullptr)) throw std::runtime_error("publisher transport descriptor unavailable");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.value, FALSE};
    HANDLE pipe = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
        PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, &attributes);
    if (pipe == INVALID_HANDLE_VALUE) throw std::runtime_error("publisher exclusive request endpoint unavailable");
    Handle pending(pipe);
    state_ = std::make_unique<State>(pipe, caller, stop, until);
    pending.value = nullptr;
}
PublisherRequestChannel::~PublisherRequestChannel() = default;
std::string PublisherRequestChannel::receive() {
    auto& state = *state_;
    if (state.receive_started) throw std::runtime_error("publisher endpoint accepts one request");
    state.receive_started = true;
    if (state.stop && WaitForSingleObject(state.stop,0)==WAIT_OBJECT_0) throw std::runtime_error("publisher transport cancelled");
    Io io;
    const BOOL connected = ConnectNamedPipe(state.pipe.value, &io.overlapped);
    const DWORD error = connected ? ERROR_SUCCESS : GetLastError();
    if (!connected && error == ERROR_PIPE_CONNECTED) SetEvent(io.event.value);
    else io.finish(state.pipe.value, connected, state.stop, state.until, error);
    auto request = read_message(state.pipe.value, request_limit, state.stop, state.until);
    state.client_token.value = require_caller(state.pipe.value, state.caller_sid);
    if (!GetNamedPipeClientProcessId(state.pipe.value, &state.client_process_id) || !state.client_process_id)
        throw std::runtime_error("authenticated pipe client process is unavailable");
    state.client_facts = client_token_facts(state.client_token.value, state.client_process_id);
    if (state.stop && WaitForSingleObject(state.stop,0)==WAIT_OBJECT_0) throw std::runtime_error("publisher transport cancelled");
    state.received = true;
    return request;
}
usk::json::Value PublisherRequestChannel::observe_authenticated_object_access(HANDLE object) const {
    using usk::json::Value;
    const auto& state = *state_;
    if (!state.received || state.replied || !state.client_token.value || !object || object == INVALID_HANDLE_VALUE)
        throw std::runtime_error("authenticated access observation requires the active request and held object");
    const auto before_client = client_token_facts(state.client_token.value, state.client_process_id);
    if (usk::json::canonical(before_client) != usk::json::canonical(state.client_facts))
        throw std::runtime_error("authenticated client token changed since admission");
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!GetFileInformationByHandleEx(object, FileAttributeTagInfo, &attributes, sizeof(attributes)))
        throw std::runtime_error("authenticated access object type is unavailable");
    const bool directory = (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    const auto before = directory ? observe_publisher_directory_handle(object) : observe_publisher_file_handle(object);
    LocalBuffer descriptor;
    PSID owner = nullptr, group = nullptr;
    PACL dacl = nullptr;
    if (GetSecurityInfo(object, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION, &owner, &group, &dacl, nullptr,
        reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.value)) != ERROR_SUCCESS ||
        !descriptor.value || !IsValidSecurityDescriptor(descriptor.value) || !group || !IsValidSid(group) ||
        !dacl || !IsValidAcl(dacl) || sid_text(owner) != before.owner_sid || dacl->AceCount != before.dacl_aces.size())
        throw std::runtime_error("fresh effective-access descriptor differs from held object security");
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void* raw = nullptr;
        if (!GetAce(dacl, index, &raw) || !raw)
            throw std::runtime_error("fresh effective-access descriptor ACE is unavailable");
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        const auto& expected = before.dacl_aces[index];
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            ace->Header.AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8u ||
            ace->Header.AceType != expected.type || ace->Header.AceFlags != expected.flags ||
            ace->Mask != expected.access_mask)
            throw std::runtime_error("fresh effective-access descriptor ACE differs from held object security");
        const auto* sid_bytes = reinterpret_cast<const unsigned char*>(&ace->SidStart);
        const auto sid_room = ace->Header.AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart);
        if (sid_bytes[1] > SID_MAX_SUB_AUTHORITIES || 8u + 4u * sid_bytes[1] > sid_room ||
            sid_text(const_cast<DWORD*>(&ace->SidStart)) != expected.sid)
            throw std::runtime_error("fresh effective-access descriptor ACE differs from held object security");
    }
    const DWORD length = GetSecurityDescriptorLength(descriptor.value);
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    if (length < SECURITY_DESCRIPTOR_MIN_LENGTH || length > 65536 ||
        !GetSecurityDescriptorControl(descriptor.value, &control, &revision) || (control & SE_SELF_RELATIVE) == 0)
        throw std::runtime_error("fresh effective-access descriptor exceeds its bound");
    static constexpr char hex[] = "0123456789abcdef";
    const auto* bytes = static_cast<const unsigned char*>(descriptor.value);
    std::string descriptor_hex;
    descriptor_hex.reserve(static_cast<std::size_t>(length) * 2u);
    for (DWORD index = 0; index < length; ++index) {
        descriptor_hex.push_back(hex[bytes[index] >> 4u]);
        descriptor_hex.push_back(hex[bytes[index] & 15u]);
    }
    Value::Object checks;
    const std::vector<std::pair<std::string, DWORD>> rights{{"write_or_add_file", FILE_WRITE_DATA},
        {"append_or_add_directory", FILE_APPEND_DATA}, {"write_ea", FILE_WRITE_EA},
        {"delete_child", FILE_DELETE_CHILD}, {"write_attributes", FILE_WRITE_ATTRIBUTES},
        {"delete", DELETE}, {"write_dac", WRITE_DAC}, {"write_owner", WRITE_OWNER},
        {"maximum_allowed", MAXIMUM_ALLOWED}};
    for (const auto& [name, requested] : rights) {
        GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
        std::vector<unsigned char> privilege_storage(sizeof(PRIVILEGE_SET) + 16u * sizeof(LUID_AND_ATTRIBUTES));
        DWORD privilege_length = static_cast<DWORD>(privilege_storage.size()), granted = 0;
        BOOL allowed = FALSE;
        const auto run = [&] { return AccessCheck(descriptor.value, state.client_token.value, requested, &mapping,
            reinterpret_cast<PRIVILEGE_SET*>(privilege_storage.data()), &privilege_length, &granted, &allowed); };
        if (!run()) {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || privilege_length < sizeof(PRIVILEGE_SET) ||
                privilege_length > 65536)
                throw std::runtime_error("fresh authenticated AccessCheck failed");
            privilege_storage.resize(privilege_length);
            if (!run()) throw std::runtime_error("fresh authenticated AccessCheck retry failed");
        }
        checks.emplace(name, Value(Value::Object{{"requested", Value(static_cast<std::uint64_t>(requested))},
            {"allowed", Value(allowed != FALSE)}, {"granted", Value(static_cast<std::uint64_t>(granted))}}));
    }
    // Group and API control flags are not in the native object observation.
    // Bracket the actual returned descriptor too; never reconstruct its bytes
    // or copy stored protection flags into this API's representation.
    LocalBuffer descriptor_after;
    if (GetSecurityInfo(object, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr,
        reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor_after.value)) != ERROR_SUCCESS ||
        !descriptor_after.value || !IsValidSecurityDescriptor(descriptor_after.value) ||
        GetSecurityDescriptorLength(descriptor_after.value) != length ||
        std::memcmp(descriptor.value, descriptor_after.value, length) != 0)
        throw std::runtime_error("held descriptor changed across authenticated access collection");
    const auto after = directory ? observe_publisher_directory_handle(object) : observe_publisher_file_handle(object);
    if (usk::json::canonical(publisher_handle_observation_json(before)) !=
            usk::json::canonical(publisher_handle_observation_json(after)) ||
        usk::json::canonical(before_client) !=
            usk::json::canonical(client_token_facts(state.client_token.value, state.client_process_id)))
        throw std::runtime_error("authenticated token or held object changed across access collection");
    return Value(Value::Object{{"schema", Value("usk.publisher_authenticated_object_access.v1")},
        {"scope", Value("fresh_held_authenticated_token_and_file_descriptor")},
        {"client", before_client}, {"native_object", publisher_handle_observation_json(before)},
        {"descriptor_api", Value("GetSecurityInfo:SE_FILE_OBJECT:OWNER_GROUP_DACL")},
        {"descriptor_hex", Value(descriptor_hex)}, {"observed_group_sid", Value(sid_text(group))},
        {"checks", Value(std::move(checks))}});
}
void PublisherRequestChannel::reply(const std::string& response) {
    auto& state = *state_;
    if (!state.received || state.replied) throw std::runtime_error("publisher endpoint response state invalid");
    write_message(state.pipe.value, response, response_limit, state.stop, state.until);
    state.replied = true;
}
void PublisherRequestChannel::wait_for_client_disconnect() noexcept {
    try {
        if (!state_ || !state_->replied) return;
        auto& state = *state_;
        DWORD mode = PIPE_READMODE_BYTE;
        if (!SetNamedPipeHandleState(state.pipe.value, &mode, nullptr, nullptr)) {
            // Preserve the reply long enough for a slow client even if this
            // handle cannot switch modes; never treat setup failure as leave.
            if (state.stop) WaitForSingleObject(state.stop, 120000);
            else Sleep(120000);
            return;
        }
        const ULONGLONG until = deadline(120000);
        char ignored[4096];
        while (remaining(until)) {
            Io io;
            const BOOL started = ReadFile(state.pipe.value, ignored,
                static_cast<DWORD>(sizeof(ignored)), nullptr, &io.overlapped);
            const DWORD error = started ? ERROR_SUCCESS : GetLastError();
            // Extra client bytes never authorize a second request or permit
            // early pipe closure. One absolute deadline bounds all draining.
            // A successful zero-byte read can be an empty client message,
            // not a disconnect. Broken pipe is reported as a read error.
            (void)io.finish(state.pipe.value, started, state.stop, until, error);
            Sleep(1);
        }
    } catch (...) {
        // The terminal reply is already written. Departure, cancellation,
        // timeout and broken-pipe outcomes cannot change the operation result.
    }
}
void require_publisher_response_binding(const std::wstring& service_name,
    const std::string& request, const std::string& response, DWORD expected_process_id) {
    usk::json::ParseLimits limits;
    limits.max_bytes = response_limit;
    limits.max_string_bytes = response_limit / 2u;
    const auto observed = usk::json::parse(response, limits);
    limits.max_bytes = request_limit;
    limits.max_string_bytes = request_limit / 2u;
    const auto submitted = usk::json::parse(request, limits);
    const std::string schema = submitted.at("schema").as_string();
    std::string expected_service;
    expected_service.reserve(service_name.size());
    for (const wchar_t ch : service_name) {
        if (ch < 0x20 || ch > 0x7e) {
            throw std::runtime_error("publisher service name is not ASCII");
        }
        expected_service.push_back(static_cast<char>(ch));
    }
    if (schema == "usk.publisher_capability_request.v2" || schema == "usk.publisher_capability_request.v3") {
        const auto& request_id = submitted.at("request_id").as_string();
        if (submitted.as_object().size() != 2 || request_id.empty() || request_id.size() > 128 ||
            request_id.find_first_not_of(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != std::string::npos ||
            observed.as_object().size() != 8 ||
            observed.at("schema").as_string() != "usk.publisher_service_capability_observation.v1" ||
            observed.at("status").as_string() != "observed" ||
            observed.at("request_id").as_string() != request_id ||
            observed.at("service_name").as_string() != expected_service ||
            observed.at("service_sid").as_string().empty() ||
            observed.at("process_id").as_unsigned() == 0 ||
            observed.at("process_id").as_unsigned() > 0xffffffffu ||
            (expected_process_id != 0 && observed.at("process_id").as_unsigned() != expected_process_id) ||
            observed.at("registered_admission").type() != usk::json::Value::Type::object ||
            observed.at("capability_observation").type() != usk::json::Value::Type::object ||
            observed.at("capability_observation").at("schema").as_string() !=
                (schema == "usk.publisher_capability_request.v3" ? "usk.publisher_capability.v3" : "usk.publisher_capability.v2")) {
            throw std::runtime_error("publisher service observation differs from request or live server");
        }
        // The command validator checks the complete admission/capability leaves
        // before exposing them. Transport admission never grants authority.
        return;
    }
    if (observed.at("schema").as_string() !=
            "usk.publisher_lab_service_observation.v1") {
        throw std::runtime_error("publisher response schema differs");
    }
    const std::string status = observed.at("status").as_string();
    const bool completed_drift_report = status == "failed" &&
        observed.contains("verify_response");
    if (status == "recovery_required" ||
        (status == "failed" && !completed_drift_report)) return;
    if (status != "pass" && !completed_drift_report) {
        throw std::runtime_error("publisher response status differs");
    }

    if (observed.contains("service_name")) {
        if (observed.at("service_name").as_string() != expected_service) {
            throw std::runtime_error("publisher response service identity differs");
        }
    } else if (schema != "usk.publisher_installed_verify_request.v1") {
        throw std::runtime_error("publisher response service identity is absent");
    }

    if (schema == "usk.repair_apply_request.v1" || schema == "usk.move_apply_request.v1" ||
        schema == "usk.uninstall_apply_request.v1" || schema == "usk.publisher_maintenance_recovery_request.v1") {
        const bool recovery = schema == "usk.publisher_maintenance_recovery_request.v1";
        const std::string operation = recovery ? submitted.at("operation").as_string() :
            schema == "usk.repair_apply_request.v1" ? "repair" :
            schema == "usk.move_apply_request.v1" ? "move" : "uninstall";
        if (recovery && (submitted.as_object().size() != 4 ||
            (operation != "repair" && operation != "move" && operation != "uninstall")))
            throw std::runtime_error("publisher maintenance recovery selector differs");
        const auto install_id = recovery ? submitted.at("install_id").as_string() :
            submitted.at("plan_request").at("install_id").as_string();
        const auto& public_response = observed.at(recovery ? "recovery_response" : "apply_response");
        const auto& report = public_response.at("payload");
        auto digest_body = report;
        digest_body.as_object().erase("report_digest");
        const auto& admission = observed.at("registered_admission");
        const auto report_status = report.at("status").as_string();
        const bool completed = recovery ? report_status == "completed" : operation == "move" ? report_status == "new_committed_old_retained" :
            (report_status == "completed" || (operation == "uninstall" && report_status == "retained_foreign_content"));
        if (observed.as_object().size() != 12 || status != "pass" || !completed ||
            observed.at("request_sha256").as_string() != usk::json::sha256_canonical(submitted) ||
            observed.at("operation").as_string() != operation ||
            observed.at("install_id").as_string() != install_id ||
            observed.at("transaction_id").as_string() != submitted.at("transaction_id").as_string() ||
            observed.at("process_id").as_unsigned() == 0 || observed.at("process_id").as_unsigned() > 0xffffffffu ||
            (expected_process_id && observed.at("process_id").as_unsigned() != expected_process_id) ||
            observed.at("service_sid").as_string().empty() ||
            observed.at("operation_admission").type() != usk::json::Value::Type::object ||
            admission.at("schema").as_string() != "usk.publisher_registered_admission_observation.v1" ||
            admission.at("service_name").as_string() != expected_service ||
            admission.at("service_sid").as_string() != observed.at("service_sid").as_string() ||
            admission.at("process_id").as_unsigned() != observed.at("process_id").as_unsigned() ||
            public_response.at("schema").as_string() != "usk.command_response.v1" ||
            public_response.at("status").as_string() != "ok" ||
            report.at("schema").as_string() != (recovery ? "usk.maintenance_recovery_report.v1" : "usk." + operation + "_report.v1") ||
            report.at("install_id").as_string() != install_id ||
            report.at("transaction_id").as_string() != submitted.at("transaction_id").as_string() ||
            (!recovery && report.at("plan_id").as_string() != submitted.at("plan_request").at("plan_id").as_string()) ||
            report.at("report_id").as_string() != (recovery ? "recovery." : "") + operation + "." + submitted.at("transaction_id").as_string() ||
            report.at("report_digest").as_string() != usk::json::sha256_canonical(digest_body) ||
            (!recovery && report.at("completed_at").as_string() != submitted.at("applied_at").as_string()))
            throw std::runtime_error("publisher completed maintenance differs from request or live server");
        if (recovery) {
            if (report.as_object().size() != 13 || report.at("operation").as_string() != operation ||
                report.at("plan_id").as_string().empty() || report.at("recorded_at").as_string().empty())
                throw std::runtime_error("publisher maintenance recovery result differs from original context");
            for (const auto field : {"plan_digest", "transaction_snapshot_sha256", "effect_history_sha256", "source_digest"}) {
                const auto& digest = report.at(field).as_string();
                if (digest.size() != 64 || digest.find_first_not_of("0123456789abcdef") != std::string::npos)
                    throw std::runtime_error("publisher maintenance recovery result binding is absent");
            }
        }
        return;
    }
    if (schema == "usk.install_local_apply_request.v1" ||
        schema == "usk.publisher_recovery_request.v1") {
        if (status != "pass") {
            throw std::runtime_error("publisher installation has a nonterminal success shape");
        }
        const std::string install_id = schema == "usk.install_local_apply_request.v1" ?
            submitted.at("plan_request").at("install_id").as_string() :
            submitted.at("install_id").as_string();
        // A retry of the original apply request completes through the same
        // source-free replay as an explicit recovery request. Exactly one
        // completed public result may identify this terminal observation.
        const bool direct = observed.at("apply_response").type() !=
            usk::json::Value::Type::null_value;
        const bool replayed = observed.at("recovery_installed_response").type() !=
            usk::json::Value::Type::null_value;
        if (direct == replayed ||
            (schema == "usk.publisher_recovery_request.v1" && direct)) {
            throw std::runtime_error("publisher completed installation result is ambiguous");
        }
        const auto& public_response = observed.at(direct ?
            "apply_response" : "recovery_installed_response");
        const auto& installed = public_response.at("payload");
        if (public_response.at("schema").as_string() != "usk.command_response.v1" ||
            public_response.at("status").as_string() != "ok" ||
            installed.at("schema").as_string() != "usk.installed_state.v1" ||
            installed.at("lifecycle_status").as_string() != "installed" ||
            installed.at("install_id").as_string() != install_id ||
            installed.at("transaction_id").as_string() !=
                submitted.at("transaction_id").as_string() ||
            (schema == "usk.install_local_apply_request.v1" &&
             installed.at("created_at").as_string() !=
                submitted.at("applied_at").as_string())) {
            throw std::runtime_error("publisher completed installation differs from request");
        }
        return;
    }
    if (schema == "usk.publisher_installed_verify_request.v1") {
        const auto& public_response = observed.at("verify_response");
        const auto& report = public_response.at("payload");
        if (observed.at("transaction_id").as_string() !=
                submitted.at("transaction_id").as_string() ||
            public_response.at("schema").as_string() != "usk.command_response.v1" ||
            public_response.at("status").as_string() != "ok" ||
            report.at("schema").as_string() != "usk.verification_report.v1" ||
            (status == "pass" ? report.at("status").as_string() != "pass" :
                (report.at("status").as_string() != "fail" &&
                 report.at("status").as_string() != "warn" &&
                 report.at("status").as_string() != "unknown")) ||
            report.at("install_id").as_string() !=
                submitted.at("install_id").as_string() ||
            report.at("report_id").as_string() !=
                submitted.at("report_id").as_string() ||
            report.at("verified_at").as_string() !=
                submitted.at("verified_at").as_string() ||
            report.at("report_digest").as_string() !=
                observed.at("bound_report_digest").as_string()) {
            throw std::runtime_error("publisher completed verification differs from request");
        }
        return;
    }
    throw std::runtime_error("publisher success has no admitted request schema");
}

std::string submit_publisher_request(const std::wstring& service_name,
    const std::string& request, DWORD timeout_ms,
    const std::wstring& expected_process_image, const PublisherRequestOptions& options) {
    bool write_attempted = false;
    try {
    const auto until = deadline(timeout_ms);
    if (options.conflict_wait_milliseconds > publisher_request_max_conflict_wait_milliseconds)
        throw std::invalid_argument("publisher contention wait exceeds bound");
    const auto inspection_reference = publisher_request_inspection_reference(service_name);
    require_request_not_cancelled(options, inspection_reference);
    if (request.empty() || request.size() > request_limit) throw std::runtime_error("publisher request exceeds bound or is empty");
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.value) throw std::runtime_error("publisher SCM unavailable");
    ServiceHandle service(OpenServiceW(manager.value, service_name.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
    if (!service.value) throw std::runtime_error("publisher service unavailable");
    // StartServiceW returns while ServiceMain may still be START_PENDING.
    // Wait only for that transition, before opening or writing the pipe.
    const auto expected = await_service_process(service.value, until, options, inspection_reference);
    Handle process(nullptr);
    while (!process.value) {
        require_request_not_cancelled(options, inspection_reference);
        process.value = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, expected);
        if (process.value) break;
        const DWORD error = GetLastError();
        // RUNNING precedes the service-side consumer query grant. A standard
        // caller may arrive during that admission window. Wait only for that
        // grant, under the original deadline and unchanged live SCM identity.
        if (error != ERROR_ACCESS_DENIED || service_process(service.value) != expected ||
            !remaining(until)) throw std::runtime_error("publisher process unavailable");
        Sleep(std::min<DWORD>(remaining(until), 10));
    }
    if (WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT ||
        service_process(service.value) != expected) throw std::runtime_error("publisher process unavailable");
    require_request_not_cancelled(options, inspection_reference);
    if (!remaining(until)) throw std::runtime_error("publisher endpoint request deadline expired");
    Handle pipe(connect_publisher_request_endpoint(service_name, remaining(until), options));
    ULONG observed = 0;
    if (!GetNamedPipeServerProcessId(pipe.value, &observed) || observed != expected ||
        WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT || service_process(service.value) != expected) {
        throw std::runtime_error("publisher pipe server differs from live service");
    }
    if (!expected_process_image.empty()) {
        std::wstring image(32768, L'\0');
        DWORD size = static_cast<DWORD>(image.size());
        if (!QueryFullProcessImageNameW(process.value, 0, image.data(), &size) || size == 0)
            throw std::runtime_error("publisher process image is unavailable");
        image.resize(size);
        if (CompareStringOrdinal(image.c_str(), -1, expected_process_image.c_str(), -1, TRUE) != CSTR_EQUAL)
            throw std::runtime_error("publisher process image differs from admitted executable");
    }
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(pipe.value, &mode, nullptr, nullptr)) throw std::runtime_error("publisher endpoint message mode unavailable");
    if (!remaining(until)) throw std::runtime_error("publisher endpoint ready after request deadline");
    require_request_not_cancelled(options, inspection_reference);
        // Even a cancelled/partial first write may have reached the worker.
        write_attempted = true;
        write_message(pipe.value, request, request_limit, options.cancel_event, until);
        const std::string response = read_message(pipe.value, response_limit, options.cancel_event, until);
        require_publisher_response_binding(service_name, request, response, expected);
        return response;
    } catch (const usk::base::EffectRequestNotDispatched&) {
        if (write_attempted) throw PublisherRequestOutcomeUnknown("request dispatch was attempted");
        throw;
    } catch(const std::exception& error) {
        if (write_attempted) throw PublisherRequestOutcomeUnknown(error.what());
        // Preserve the legacy raw candidate's generic failure ceiling. The
        // registered wrapper may classify this concrete pre-write exception.
        throw;
    }
}
void admit_current_publisher_client_observer(const std::wstring& service_name,
    const std::wstring& consumer_sid) {
    // Refuse before any security effect unless SCM and our current restricted
    // token independently identify the actual own-process SYSTEM service.
    const auto service = observe_current_restricted_publisher_service(service_name);
    std::string sid_ascii;
    for (const auto ch : consumer_sid) {
        if (ch > 0x7f) throw std::runtime_error("consumer SID is not ASCII");
        sid_ascii.push_back(static_cast<char>(ch));
    }
    require_publisher_consumer_sid(sid_ascii);
    const auto canonical = canonical_sid(consumer_sid);
    if (canonical != consumer_sid) throw std::runtime_error("noncanonical consumer SID");
    LocalBuffer reader, before, after, updated, service_owner, owner_text;
    if (!ConvertStringSidToSidW(consumer_sid.c_str(), &reader.value))
        throw std::runtime_error("consumer SID unavailable");
    const std::wstring service_sid(service.service_sid.begin(), service.service_sid.end());
    if (!ConvertStringSidToSidW(service_sid.c_str(), &service_owner.value))
        throw std::runtime_error("observed service owner SID unavailable");
    PSID owner = nullptr;
    PACL dacl = nullptr;
    const auto security_status = GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr,
        &dacl, nullptr, reinterpret_cast<PSECURITY_DESCRIPTOR*>(&before.value));
    std::string observed_owner = "unavailable";
    if (security_status == ERROR_SUCCESS && owner &&
        ConvertSidToStringSidW(owner, reinterpret_cast<LPWSTR*>(&owner_text.value))) {
        const auto* p = static_cast<const wchar_t*>(owner_text.value);
        observed_owner.clear();
        for (; *p; ++p) {
            if (*p > 0x7f) throw std::runtime_error("process owner SID is not ASCII");
            observed_owner.push_back(static_cast<char>(*p));
        }
    }
    const auto logon_owner_matches = std::count_if(service.token.process_groups.begin(),
        service.token.process_groups.end(), [&](const ObservedTokenGroup& group) {
            return group.sid == observed_owner &&
                (group.attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID;
        });
    if (security_status != ERROR_SUCCESS ||
        !owner || !dacl || !IsValidAcl(dacl) ||
        (!IsWellKnownSid(owner, WinLocalSystemSid) &&
         !IsWellKnownSid(owner, WinBuiltinAdministratorsSid) &&
         !EqualSid(owner, service_owner.value) && logon_owner_matches != 1) ||
        logon_owner_matches > 1) {
        throw std::runtime_error("current publisher process security unavailable; win32=" +
            std::to_string(security_status) + "; system_owner=" +
            std::to_string(owner && IsWellKnownSid(owner, WinLocalSystemSid)) +
            "; administrators_owner=" +
            std::to_string(owner && IsWellKnownSid(owner, WinBuiltinAdministratorsSid)) +
            "; service_owner=" + std::to_string(owner && EqualSid(owner, service_owner.value)) +
            "; token_logon_owner_matches=" + std::to_string(logon_owner_matches) +
            "; observed_owner=" + observed_owner);
    }
    constexpr DWORD observer_access = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
    auto ace_bytes = [](PACL acl) {
        std::vector<std::vector<unsigned char>> result;
        for (DWORD i = 0; i < acl->AceCount; ++i) {
            void* raw = nullptr;
            if (!GetAce(acl, i, &raw)) throw std::runtime_error("process ACE unavailable");
            auto* header = static_cast<ACE_HEADER*>(raw);
            const auto* bytes = static_cast<const unsigned char*>(raw);
            result.emplace_back(bytes, bytes + header->AceSize);
        }
        return result;
    };
    auto expected = ace_bytes(dacl);
    for (const auto& bytes : expected) {
        const auto* header = reinterpret_cast<const ACE_HEADER*>(bytes.data());
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_DENIED_ACE_TYPE) {
            const auto* ace = reinterpret_cast<const ACCESS_ALLOWED_ACE*>(bytes.data());
            if (EqualSid(const_cast<DWORD*>(&ace->SidStart), reader.value))
                throw std::runtime_error("consumer process ACE already present");
        }
    }
    EXPLICIT_ACCESSW access{};
    access.grfAccessPermissions = observer_access;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = static_cast<LPWSTR>(reader.value);
    if (SetEntriesInAclW(1, &access, dacl, reinterpret_cast<PACL*>(&updated.value)) != ERROR_SUCCESS)
        throw std::runtime_error("consumer process descriptor unavailable");
    auto desired = ace_bytes(static_cast<PACL>(updated.value));
    auto preserved = desired;
    unsigned readers = 0;
    for (auto it = preserved.begin(); it != preserved.end();) {
        const auto* header = reinterpret_cast<const ACE_HEADER*>(it->data());
        const auto* ace = reinterpret_cast<const ACCESS_ALLOWED_ACE*>(it->data());
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE &&
            EqualSid(const_cast<DWORD*>(&ace->SidStart), reader.value)) {
            if (header->AceFlags || ace->Mask != observer_access)
                throw std::runtime_error("consumer process rights exceed identity observation");
            ++readers; it = preserved.erase(it);
        } else ++it;
    }
    std::sort(expected.begin(), expected.end());
    std::sort(preserved.begin(), preserved.end());
    if (readers != 1 || preserved != expected)
        throw std::runtime_error("consumer process descriptor changes existing access");
    if (SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, static_cast<PACL>(updated.value), nullptr) != ERROR_SUCCESS)
        throw std::runtime_error("consumer process observation admission failed");
    PSID actual_owner = nullptr;
    PACL actual = nullptr;
    if (GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &actual_owner, nullptr,
        &actual, nullptr, reinterpret_cast<PSECURITY_DESCRIPTOR*>(&after.value)) != ERROR_SUCCESS ||
        !actual_owner || !EqualSid(owner, actual_owner) || !actual || !IsValidAcl(actual))
        throw std::runtime_error("consumer process admission readback unavailable");
    auto observed = ace_bytes(actual);
    std::sort(desired.begin(), desired.end());
    std::sort(observed.begin(), observed.end());
    if (desired != observed) throw std::runtime_error("consumer process admission readback differs");
}
}
#endif
