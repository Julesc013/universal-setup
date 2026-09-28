// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_request_channel.h"
#if defined(_WIN32)
#include <sddl.h>
#include <aclapi.h>
#include "usk_publisher_token_observation.h"
#include "usk_publisher_security_descriptor.h"
#include <algorithm>
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
void require_caller(HANDLE pipe, const std::wstring& expected) {
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
struct PublisherRequestChannel::State {
    Handle pipe;
    std::wstring caller_sid;
    HANDLE stop;
    ULONGLONG until;
    bool received = false, replied = false;
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
    if (state.received) throw std::runtime_error("publisher endpoint accepts one request");
    if (state.stop && WaitForSingleObject(state.stop,0)==WAIT_OBJECT_0) throw std::runtime_error("publisher transport cancelled");
    Io io;
    const BOOL connected = ConnectNamedPipe(state.pipe.value, &io.overlapped);
    const DWORD error = connected ? ERROR_SUCCESS : GetLastError();
    if (!connected && error == ERROR_PIPE_CONNECTED) SetEvent(io.event.value);
    else io.finish(state.pipe.value, connected, state.stop, state.until, error);
    auto request = read_message(state.pipe.value, request_limit, state.stop, state.until);
    require_caller(state.pipe.value, state.caller_sid);
    if (state.stop && WaitForSingleObject(state.stop,0)==WAIT_OBJECT_0) throw std::runtime_error("publisher transport cancelled");
    state.received = true;
    return request;
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
        char unexpected = 0;
        Io io;
        const BOOL started = ReadFile(state.pipe.value, &unexpected, 1, nullptr,
            &io.overlapped);
        const DWORD error = started ? ERROR_SUCCESS : GetLastError();
        // A peer close normally completes the read with ERROR_BROKEN_PIPE.
        // Extra input is ignored: this channel admits exactly one request.
        // A stopped or unresponsive client cannot retain the service forever.
        (void)io.finish(state.pipe.value, started, state.stop,
            deadline(120000), error);
    } catch (...) {
        // The terminal reply is already written. Departure, cancellation,
        // timeout and broken-pipe outcomes cannot change the operation result.
    }
}
std::string submit_publisher_request(const std::wstring& service_name,
    const std::string& request, DWORD timeout_ms) {
    const auto until = deadline(timeout_ms);
    const auto name = publisher_request_pipe_name(service_name);
    if (request.empty() || request.size() > request_limit) throw std::runtime_error("publisher request exceeds bound or is empty");
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.value) throw std::runtime_error("publisher SCM unavailable");
    ServiceHandle service(OpenServiceW(manager.value, service_name.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
    if (!service.value) throw std::runtime_error("publisher service unavailable");
    const auto expected = service_process(service.value);
    Handle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, expected));
    if (!process.value || WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT) throw std::runtime_error("publisher process unavailable");
    HANDLE raw = INVALID_HANDLE_VALUE;
    do {
        raw = CreateFileW(name.c_str(), client_access, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (raw != INVALID_HANDLE_VALUE) break;
        const DWORD error = GetLastError();
        if (error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND) throw std::runtime_error("publisher endpoint refused connection");
        if (!remaining(until)) throw std::runtime_error("publisher endpoint connection timed out");
        WaitNamedPipeW(name.c_str(), std::min<DWORD>(remaining(until), 100));
        if (error == ERROR_FILE_NOT_FOUND) Sleep(std::min<DWORD>(remaining(until), 10));
    } while (remaining(until));
    if (raw == INVALID_HANDLE_VALUE) throw std::runtime_error("publisher endpoint connection timed out");
    Handle pipe(raw);
    ULONG observed = 0;
    if (!GetNamedPipeServerProcessId(pipe.value, &observed) || observed != expected ||
        WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT || service_process(service.value) != expected) {
        throw std::runtime_error("publisher pipe server differs from live service");
    }
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(pipe.value, &mode, nullptr, nullptr)) throw std::runtime_error("publisher endpoint message mode unavailable");
    try {
        write_message(pipe.value, request, request_limit, nullptr, until);
        return read_message(pipe.value, response_limit, nullptr, until);
    } catch(const std::exception& error) {
        throw PublisherRequestOutcomeUnknown(error.what());
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
