// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_effect_worker_custody_internal.h"
#if defined(_WIN32)
#include "usk_publisher_token_observation.h"
#include "usk_sha256.h"
#include <bcrypt.h>
#include <sddl.h>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace usk::platform::windows {
namespace {
using usk::json::Value;
constexpr DWORD packet_limit = 4u * 1024u * 1024u;
constexpr DWORD peer_process_access = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
// At most one active/unknown transport per process. An unknown owner's retained
// raw allocation intentionally has no C++ exit destructor: pending native I/O
// storage lives until OS process teardown, and cannot be reused by a new owner.
std::atomic<void*> active_wire{nullptr};
void require(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
}
struct Handle {
    HANDLE value = nullptr;
    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    void reset(HANDLE handle = nullptr) noexcept {
        if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
        value = handle;
    }
};
struct LocalMemory {
    void* value = nullptr;
    ~LocalMemory() { if (value) LocalFree(value); }
};
std::uint64_t birth(HANDLE process) {
    FILETIME created{}, exited{}, kernel{}, user{};
    require(GetProcessTimes(process, &created, &exited, &kernel, &user) != FALSE,
        "effect transport process birth is unavailable");
    return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}
std::wstring image_path(HANDLE process) {
    std::vector<wchar_t> path(32768);
    DWORD length = static_cast<DWORD>(path.size());
    require(QueryFullProcessImageNameW(process, 0, path.data(), &length) != FALSE &&
        length && length < path.size(), "effect transport process image is unavailable");
    return std::wstring(path.data(), length);
}
std::string hex64(std::uint64_t value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result(16, '0');
    for (std::size_t index = result.size(); index != 0; --index) {
        result[index - 1] = digits[value & 15u];
        value >>= 4;
    }
    return result;
}
std::string request_digest(const std::string& request) {
    usk::base::Sha256 digest;
    digest.update(reinterpret_cast<const unsigned char*>(request.data()), request.size());
    return digest.finish();
}
void require_same_image(const usk::base::StableFile& first, const usk::base::StableFile& second) {
    first.verify_unchanged();
    second.verify_unchanged();
    const auto& a = first.identity();
    const auto& b = second.identity();
    require(a.volume_id == b.volume_id && a.file_id == b.file_id &&
        a.size_bytes == b.size_bytes && a.modified_time_ns == b.modified_time_ns &&
        a.link_count == b.link_count && first.sha256_hex() == second.sha256_hex(),
        "effect transport does not hold the original executable image");
}
Value image_value(const usk::base::StableFile& image) {
    const auto& identity = image.identity();
    return Value(Value::Object{{"volume_id", Value(identity.volume_id)},
        {"file_id", Value(identity.file_id)}, {"size_bytes", Value(identity.size_bytes)},
        {"sha256", Value(image.sha256_hex())}});
}
void require_canonical_sid(const std::wstring& text) {
    LocalMemory sid, canonical;
    require(!text.empty() && text.size() <= 184 &&
        ConvertStringSidToSidW(text.c_str(), &sid.value) && IsValidSid(sid.value) &&
        ConvertSidToStringSidW(sid.value, reinterpret_cast<LPWSTR*>(&canonical.value)) &&
        text == static_cast<const wchar_t*>(canonical.value), "effect transport custody SID differs");
}
struct Attributes {
    LocalMemory descriptor;
    SECURITY_ATTRIBUTES value{sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE};
    Attributes(const std::wstring& owner, const std::wstring& sid) {
        require_canonical_sid(owner);
        require_canonical_sid(sid);
        // Custody mechanism, not a service admission predicate. Production
        // supplies its actually admitted restricted service SID; ordinary
        // controls can use their own actual user SID without effect authority.
        const auto sddl = L"O:" + owner + L"G:" + owner + L"D:P(A;;GA;;;SY)(A;;GA;;;" +
            owner + L")" + (sid == owner || sid == L"S-1-5-18" ? L"" : L"(A;;GA;;;" + sid + L")");
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),
            SDDL_REVISION_1, reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.value), nullptr) != FALSE,
            "effect transport private descriptor is unavailable");
        value.lpSecurityDescriptor = descriptor.value;
    }
};
std::wstring private_pipe_name() {
    std::array<unsigned char, 16> nonce{};
    require(BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0, "effect transport native random source is unavailable");
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring name = L"\\\\.\\pipe\\usk.effect.custody.";
    for (const auto ch : nonce) { name.push_back(digits[ch >> 4]); name.push_back(digits[ch & 15]); }
    return name;
}
std::vector<wchar_t> environment() {
    std::vector<wchar_t> path(32768);
    const auto length = GetWindowsDirectoryW(path.data(), static_cast<UINT>(path.size()));
    require(length && length < path.size(), "effect transport native Windows directory is unavailable");
    const std::wstring windows(path.data(), length);
    // No inherited provider/plugin/search-path/compatibility configuration.
    std::vector<wchar_t> result;
    for (const auto& entry : {L"PATH=" + windows + L"\\System32", L"SystemRoot=" + windows, L"windir=" + windows}) {
        result.insert(result.end(), entry.begin(), entry.end());
        result.push_back(L'\0');
    }
    result.push_back(L'\0');
    return result;
}
HANDLE parse_handle(const wchar_t* text) {
    require(text && *text && std::wcslen(text) <= 20, "effect transport inherited handle grammar differs");
    std::uint64_t number = 0;
    for (const wchar_t* cursor = text; *cursor; ++cursor) {
        require(*cursor >= L'0' && *cursor <= L'9' &&
            number <= (std::numeric_limits<std::uint64_t>::max() - (*cursor - L'0')) / 10,
            "effect transport inherited handle grammar differs");
        number = number * 10 + static_cast<std::uint64_t>(*cursor - L'0');
    }
    require(number && number < std::numeric_limits<std::uintptr_t>::max(),
        "effect transport inherited handle is outside the native bound");
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(number));
}
void inherit_query_handle(HANDLE source, DWORD access, Handle& destination) {
    HANDLE copied = nullptr;
    require(DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &copied,
        access, TRUE, 0) != FALSE, "effect transport query-only inheritance handle is unavailable");
    destination.reset(copied);
}
struct Wire {
    struct PendingIo {
        Handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        OVERLAPPED overlapped{};
        std::vector<unsigned char> buffer;
        bool retirement_attempted = false;
        DWORD retirement_error = ERROR_SUCCESS;
        explicit PendingIo(DWORD size) : buffer(size) {
            require(event.value != nullptr, "effect transport I/O event is unavailable");
            overlapped.hEvent = event.value;
        }
    };
    Handle pipe, peer, cancel;
    std::unique_ptr<PendingIo> pending;
    std::unique_ptr<usk::base::StableFile> image;
    DWORD peer_id = 0;
    std::uint64_t peer_birth = 0, sent = 0, received = 0;
    std::wstring peer_image_path;
    std::string binding;
    bool failed = false;
    bool claimed = false;
    void claim() {
        void* empty = nullptr;
        require(active_wire.compare_exchange_strong(empty, this),
            "effect transport already has an active or closure-unknown owner in this process");
        claimed = true;
    }
    void release_claim() noexcept {
        if (!claimed) return;
        void* original = this;
        if (active_wire.compare_exchange_strong(original, nullptr)) claimed = false;
    }
    DWORD finish_pending(DWORD milliseconds, DWORD& transferred) noexcept {
        if (!pending) return ERROR_SUCCESS;
        if (GetOverlappedResultEx(pipe.value, &pending->overlapped, &transferred, milliseconds, FALSE))
            return ERROR_SUCCESS;
        return GetLastError();
    }
    static bool terminal_status(DWORD error) noexcept {
        return error == ERROR_SUCCESS || error == ERROR_OPERATION_ABORTED || error == ERROR_BROKEN_PIPE ||
            error == ERROR_NO_DATA || error == ERROR_PIPE_NOT_CONNECTED || error == ERROR_HANDLE_EOF;
    }
    bool retire_pending(DWORD milliseconds, DWORD& error) noexcept {
        if (!pending) { error = ERROR_SUCCESS; return true; }
        if (pending->retirement_attempted) { error = pending->retirement_error; return false; }
        // CancelIoEx only requests cancellation. A bounded native completion
        // observation must positively retire the original OVERLAPPED/buffer.
        pending->retirement_attempted = true;
        CancelIoEx(pipe.value, &pending->overlapped);
        DWORD ignored = 0;
        error = finish_pending(milliseconds, ignored);
        pending->retirement_error = error;
        if (!terminal_status(error)) return false;
        pending.reset();
        return true;
    }
    void require_peer() const {
        require(!failed && peer.value && WaitForSingleObject(peer.value, 0) == WAIT_TIMEOUT &&
            GetProcessId(peer.value) == peer_id && birth(peer.value) == peer_birth &&
            image_path(peer.value) == peer_image_path,
            "effect transport original peer is not live with its held native identity");
        image->verify_unchanged();
    }
    void bytes(bool write, unsigned char* data, DWORD length, ULONGLONG until) {
        while (length) {
            require(!pending, "effect transport has an unretired native request");
            pending = std::make_unique<PendingIo>(length);
            if (write) std::memcpy(pending->buffer.data(), data, length);
            const BOOL started = write ? WriteFile(pipe.value, pending->buffer.data(), length, nullptr,
                &pending->overlapped) : ReadFile(pipe.value, pending->buffer.data(), length, nullptr,
                    &pending->overlapped);
            const DWORD error = started ? ERROR_SUCCESS : GetLastError();
            if (!started && error != ERROR_IO_PENDING) {
                // No operation was issued; this storage is not pending.
                pending.reset();
                throw std::runtime_error("effect transport native I/O failed; Win32 " + std::to_string(error));
            }
            HANDLE waits[] = {pending->event.value, peer.value, cancel.value};
            const auto now = GetTickCount64();
            const DWORD remaining = now >= until ? 0 : static_cast<DWORD>(until - now);
            const auto waited = started ? WAIT_OBJECT_0 : WaitForMultipleObjects(3, waits, FALSE, remaining);
            DWORD transferred = 0;
            if (waited != WAIT_OBJECT_0) {
                DWORD retirement_error = ERROR_SUCCESS;
                const bool retired = retire_pending(10000, retirement_error);
                throw std::runtime_error("effect transport stopped, peer ended or native I/O deadline elapsed; "
                    "wait=" + std::to_string(waited) + " io_retired=" + std::to_string(retired) +
                    " retirement_error=" + std::to_string(retirement_error));
            }
            const auto completion_error = finish_pending(0, transferred);
            if (completion_error != ERROR_SUCCESS || !transferred || transferred > length) {
                if (terminal_status(completion_error)) pending.reset();
                throw std::runtime_error("effect transport native I/O completion differs; Win32 " +
                    std::to_string(completion_error));
            }
            if (!write) std::memcpy(data, pending->buffer.data(), transferred);
            pending.reset();
            data += transferred;
            length -= transferred;
        }
    }
    ULONGLONG deadline(DWORD timeout) const {
        require(timeout && timeout <= 120000, "effect transport deadline exceeds its bound");
        require_peer();
        require(WaitForSingleObject(cancel.value, 0) == WAIT_TIMEOUT,
            "effect transport cancellation is signaled or unavailable");
        return GetTickCount64() + timeout;
    }
    void send(const Value& body, DWORD timeout) {
        try {
            const auto until = deadline(timeout);
            require(sent != std::numeric_limits<std::uint64_t>::max(), "effect transport sequence exhausted");
            const Value sequence(sent + 1), binding_value(binding);
            const auto packet = usk::json::canonical_object({
                {"sequence", std::cref(sequence)}, {"binding_sha256", std::cref(binding_value)},
                {"body", std::cref(body)}});
            require(!packet.empty() && packet.size() <= packet_limit, "effect transport packet exceeds its bound");
            const auto size = static_cast<DWORD>(packet.size());
            std::array<unsigned char, 4> header{{static_cast<unsigned char>(size),
                static_cast<unsigned char>(size >> 8), static_cast<unsigned char>(size >> 16),
                static_cast<unsigned char>(size >> 24)}};
            bytes(true, header.data(), static_cast<DWORD>(header.size()), until);
            bytes(true, reinterpret_cast<unsigned char*>(const_cast<char*>(packet.data())), size, until);
            require_peer();
            ++sent;
        } catch (...) { failed = true; throw; }
    }
    Value receive(DWORD timeout) {
        try {
            const auto until = deadline(timeout);
            require(received != std::numeric_limits<std::uint64_t>::max(), "effect transport sequence exhausted");
            std::array<unsigned char, 4> header{};
            bytes(false, header.data(), static_cast<DWORD>(header.size()), until);
            const DWORD size = static_cast<DWORD>(header[0]) | (static_cast<DWORD>(header[1]) << 8) |
                (static_cast<DWORD>(header[2]) << 16) | (static_cast<DWORD>(header[3]) << 24);
            require(size && size <= packet_limit, "effect transport received length exceeds its bound");
            std::string packet(size, '\0');
            bytes(false, reinterpret_cast<unsigned char*>(packet.data()), size, until);
            usk::json::ParseLimits limits;
            limits.max_bytes = packet_limit;
            limits.max_string_bytes = packet_limit;
            auto parsed = usk::json::parse(packet, limits);
            require(parsed.as_object().size() == 3 && parsed.at("sequence").as_unsigned() == received + 1 &&
                parsed.at("binding_sha256").as_string() == binding,
                "effect transport exact request binding or sequence differs");
            require_peer();
            ++received;
            return std::move(parsed.as_object().at("body"));
        } catch (...) { failed = true; throw; }
    }
    Value observation() const {
        require_peer();
        Value::Object fields;
        fields.emplace("schema", Value("usk.publisher_effect_transport_custody.v1"));
        fields.emplace("authority", Value("none"));
        fields.emplace("current_process_id", Value(static_cast<std::uint64_t>(GetCurrentProcessId())));
        fields.emplace("current_process_birth", Value(hex64(birth(GetCurrentProcess()))));
        fields.emplace("peer_process_id", Value(static_cast<std::uint64_t>(peer_id)));
        fields.emplace("peer_process_birth", Value(hex64(peer_birth)));
        fields.emplace("image", image_value(*image));
        fields.emplace("request_sha256", Value(binding));
        return Value(std::move(fields));
    }
    void require_record_chunk_custody(const Value& original) const {
        require_peer();
        const auto& expected_image = original.at("image");
        const auto& identity = image->identity();
        require(original.as_object().size() == 8u && expected_image.as_object().size() == 4u &&
            original.at("schema").as_string() == "usk.publisher_effect_transport_custody.v1" &&
            original.at("authority").as_string() == "none" &&
            original.at("current_process_id").as_unsigned() == GetCurrentProcessId() &&
            original.at("current_process_birth").as_string() == hex64(birth(GetCurrentProcess())) &&
            original.at("peer_process_id").as_unsigned() == peer_id &&
            original.at("peer_process_birth").as_string() == hex64(peer_birth) &&
            original.at("request_sha256").as_string() == binding &&
            expected_image.at("volume_id").as_string() == identity.volume_id &&
            expected_image.at("file_id").as_string() == identity.file_id &&
            expected_image.at("size_bytes").as_unsigned() == identity.size_bytes,
            "effect record chunk original native custody identity changed");
        // The original is this scope's actual full observation, not supplied
        // data or a cached validation result. Image bytes are freshly hashed
        // at the complete scope endpoints. Intermediate chunks retain fresh
        // held/path metadata, peer liveness/birth/path and actual token checks;
        // they do not claim another image-content sample.
        require_peer();
    }
    std::string canonical_request;
    PublisherTokenObservation peer_primary_token() const {
        require_peer();
        auto token = observe_held_publisher_process_token(peer.value);
        require_peer();
        return token;
    }
};
struct AttributeList {
    std::vector<unsigned char> storage;
    PPROC_THREAD_ATTRIBUTE_LIST value = nullptr;
    ~AttributeList() { if (value) DeleteProcThreadAttributeList(value); }
    HANDLE job_value = nullptr;
    void initialize(const std::array<HANDLE, 3>& handles, HANDLE job) {
        SIZE_T size = 0;
        require(!InitializeProcThreadAttributeList(nullptr, 2, 0, &size) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER && size && size <= 65536,
            "effect transport explicit inheritance list size differs");
        storage.resize(size);
        value = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        if (!InitializeProcThreadAttributeList(value, 2, 0, &size)) {
            value = nullptr;
            throw std::runtime_error("effect transport explicit inheritance list is unavailable");
        }
        require(UpdateProcThreadAttribute(value, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            const_cast<HANDLE*>(handles.data()), sizeof(handles), nullptr, nullptr) != FALSE,
            "effect transport explicit inheritance list failed");
        job_value = job;
        require(UpdateProcThreadAttribute(value, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
            &job_value, sizeof(job_value), nullptr, nullptr) != FALSE,
            "effect transport job-at-creation attribute failed");
    }
};
void bind_peer(Wire& wire, HANDLE process, const usk::base::StableFile& original) {
    HANDLE query = nullptr;
    require(DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &query,
        peer_process_access, FALSE, 0) != FALSE, "effect transport held peer identity is unavailable");
    wire.peer.reset(query);
    wire.peer_id = GetProcessId(query);
    wire.peer_birth = birth(query);
    wire.peer_image_path = image_path(query);
    wire.image = std::make_unique<usk::base::StableFile>(wire.peer_image_path);
    require_same_image(original, *wire.image);
    wire.require_peer();
}
} // namespace

struct PublisherEffectWorkerCustody::State {
    // Close the sole job before releasing any held image/peer/transport state.
    Handle job;
    Handle launch_process, launch_thread;
    Wire wire;
    bool closure_attempted = false;
    PublisherEffectWorkerClosure closure;
    PublisherEffectWorkerClosure close(DWORD timeout) noexcept {
        if (closure_attempted) return closure;
        closure_attempted = true;
        wire.failed = true;
        const auto until = GetTickCount64() + timeout;
        const auto remaining = [&]() {
            const auto now = GetTickCount64();
            return now >= until ? DWORD{0} : static_cast<DWORD>(until - now);
        };
        if (!job.value) closure.job_closed = true;
        else if (CloseHandle(job.value)) {
            closure.job_closed = true;
            job.value = nullptr; // Clear only after the actual close succeeded.
        } else closure.job_close_error = GetLastError();
        if (!launch_process.value) {
            closure.child_ended = true;
            closure.child_wait_result = WAIT_OBJECT_0;
        } else {
            closure.child_wait_result = WaitForSingleObject(launch_process.value, remaining());
            closure.child_ended = closure.child_wait_result == WAIT_OBJECT_0;
        }
        closure.io_retired = wire.retire_pending(remaining(), closure.io_retirement_error);
        if (closure.confirmed()) wire.release_claim();
        return closure;
    }
    void require_job() const {
        wire.require_peer();
        struct ProcessList { DWORD assigned, listed; ULONG_PTR process; } processes{};
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        const auto limits_read = QueryInformationJobObject(job.value, JobObjectExtendedLimitInformation,
            &limits, sizeof(limits), nullptr);
        const auto limits_error = limits_read ? ERROR_SUCCESS : GetLastError();
        const auto processes_read = QueryInformationJobObject(job.value, JobObjectBasicProcessIdList,
            &processes, sizeof(processes), nullptr);
        const auto processes_error = processes_read ? ERROR_SUCCESS : GetLastError();
        if (!(limits_read &&
            limits.BasicLimitInformation.LimitFlags ==
                (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS) &&
            limits.BasicLimitInformation.ActiveProcessLimit == 1 &&
            processes_read && processes.assigned == 1 && processes.listed == 1 &&
            processes.process == wire.peer_id))
            throw std::runtime_error("effect transport original owned job does not contain exactly its live child; "
                "limits_error=" + std::to_string(limits_error) + " flags=" +
                std::to_string(limits.BasicLimitInformation.LimitFlags) + " active_limit=" +
                std::to_string(limits.BasicLimitInformation.ActiveProcessLimit) + " list_error=" +
                std::to_string(processes_error) + " assigned=" + std::to_string(processes.assigned) +
                " listed=" + std::to_string(processes.listed) + " observed_pid=" +
                std::to_string(processes.process) + " expected_pid=" + std::to_string(wire.peer_id));
    }
};

PublisherEffectWorkerCustody::PublisherEffectWorkerCustody(const usk::base::StableFile& original,
    const std::wstring& sid, const std::string& request, HANDLE cancel) : state_(std::make_unique<State>()) {
    try {
    state_->wire.claim();
    require(!request.empty() && request.size() <= 1024u * 1024u &&
        usk::json::canonical(usk::json::parse(request)) == request,
        "effect transport requires bounded canonical request bytes");
    original.verify_unchanged();
    const auto path = original.path();
    require(path.is_absolute() && path.lexically_normal() == path &&
        path.wstring().find_first_of(L"\"\r\n") == std::wstring::npos,
        "effect transport executable path grammar differs");
    const auto token = observe_current_publisher_token();
    require(!token.current_thread_impersonating, "effect transport launcher is impersonating");
    const std::wstring owner(token.process_user_sid.begin(), token.process_user_sid.end());
    Attributes attributes(owner, sid);
    auto& state = *state_;
    state.wire.binding = request_digest(request);
    state.job.reset(CreateJobObjectW(&attributes.value, nullptr));
    require(state.job.value != nullptr, "effect transport private job is unavailable");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    require(SetInformationJobObject(state.job.value, JobObjectExtendedLimitInformation,
        &limits, sizeof(limits)) != FALSE, "effect transport private job limits are unavailable");
    const auto pipe_name = private_pipe_name();
    state.wire.pipe.reset(CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_DUPLEX |
        FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
        PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, &attributes.value));
    require(state.wire.pipe.value != INVALID_HANDLE_VALUE, "effect transport private pipe is unavailable");
    state.wire.pending = std::make_unique<Wire::PendingIo>(0);
    const auto started = ConnectNamedPipe(state.wire.pipe.value, &state.wire.pending->overlapped);
    const auto connect_error = started ? ERROR_SUCCESS : GetLastError();
    if (started || connect_error != ERROR_IO_PENDING) {
        // No asynchronous operation is outstanding on these outcomes.
        state.wire.pending.reset();
        throw std::runtime_error("effect transport private connection did not pend");
    }
    attributes.value.bInheritHandle = TRUE;
    Handle child_pipe(CreateFileW(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
        &attributes.value, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr));
    DWORD connection_bytes = 0;
    const auto connection_error = child_pipe.value == INVALID_HANDLE_VALUE ? ERROR_PIPE_NOT_CONNECTED :
        state.wire.finish_pending(10000, connection_bytes);
    if (connection_error != ERROR_SUCCESS) {
        throw std::runtime_error("effect transport private connection failed");
    }
    state.wire.pending.reset();
    Handle parent_query, child_cancel, owned_cancel;
    inherit_query_handle(GetCurrentProcess(), peer_process_access, parent_query);
    if (!cancel) {
        owned_cancel.reset(CreateEventW(&attributes.value, TRUE, FALSE, nullptr));
        require(owned_cancel.value != nullptr, "effect transport private cancellation event is unavailable");
        cancel = owned_cancel.value;
    }
    inherit_query_handle(cancel, SYNCHRONIZE, child_cancel);
    inherit_query_handle(cancel, SYNCHRONIZE, state.wire.cancel);
    require(SetHandleInformation(state.wire.cancel.value, HANDLE_FLAG_INHERIT, 0) != FALSE,
        "effect transport parent cancellation handle inheritance differs");
    const std::array<HANDLE, 3> inherited{{child_pipe.value, parent_query.value, child_cancel.value}};
    AttributeList list;
    list.initialize(inherited, state.job.value);
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = list.value;
    auto command = L"\"" + path.wstring() + L"\" " + publisher_effect_worker_transport_switch;
    for (const auto handle : inherited) command += L" " +
        std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
    auto child_environment = environment();
    PROCESS_INFORMATION information{};
    attributes.value.bInheritHandle = FALSE;
    require(CreateProcessW(path.c_str(), command.data(), &attributes.value, &attributes.value, TRUE,
        CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
        child_environment.data(), path.parent_path().c_str(), &startup.StartupInfo, &information) != FALSE,
        "effect transport suspended child creation failed");
    state.launch_process.reset(information.hProcess);
    state.launch_thread.reset(information.hThread);
    state.closure.child_process_id = information.dwProcessId;
    state.closure.child_process_birth = birth(state.launch_process.value);
    // The job-list creation attribute already contains this suspended child.
    // No independent create-then-assign window and no unassigned fallback.
        bind_peer(state.wire, state.launch_process.value, original);
        state.require_job();
        original.verify_unchanged();
        require(ResumeThread(state.launch_thread.value) == 1, "effect transport original suspended thread did not resume");
        child_pipe.reset();
        parent_query.reset();
        child_cancel.reset();
        state.wire.canonical_request = request;
        state.wire.send(Value(Value::Object{{"schema", Value("usk.publisher_effect_transport_start.v1")},
            {"parent_process_id", Value(static_cast<std::uint64_t>(GetCurrentProcessId()))},
            {"parent_process_birth", Value(hex64(birth(GetCurrentProcess())))},
            {"child_process_id", Value(static_cast<std::uint64_t>(state.wire.peer_id))},
            {"child_process_birth", Value(hex64(state.wire.peer_birth))},
            {"image", image_value(*state.wire.image)}, {"canonical_request", Value(request)}}), 10000);
        const auto ready = state.wire.receive(10000);
        require(ready.as_object().size() == 2 && ready.at("schema").as_string() ==
            "usk.publisher_effect_transport_ready.v1", "effect transport child ready schema differs");
        auto expected = state.wire.observation();
        expected.as_object().at("current_process_id") = Value(static_cast<std::uint64_t>(state.wire.peer_id));
        expected.as_object().at("current_process_birth") = Value(hex64(state.wire.peer_birth));
        expected.as_object().at("peer_process_id") = Value(static_cast<std::uint64_t>(GetCurrentProcessId()));
        expected.as_object().at("peer_process_birth") = Value(hex64(birth(GetCurrentProcess())));
        require(usk::json::canonical(ready.at("custody")) == usk::json::canonical(expected),
            "effect transport child ready identity differs");
        state.require_job();
    } catch (...) {
        const auto primary = std::current_exception();
        const auto closure = state_->close(10000);
        if (!closure.confirmed()) {
            state_.release(); // Retained once, with the process-wide claim latched.
            throw PublisherEffectWorkerClosureUnknown(closure, primary);
        }
        throw;
    }
}
PublisherEffectWorkerCustody::~PublisherEffectWorkerCustody() {
    if (state_ && !state_->close(10000).confirmed()) state_.release();
}
PublisherEffectWorkerClosure PublisherEffectWorkerCustody::close(DWORD timeout) {
    require(timeout <= 120000, "effect transport closure deadline exceeds its bound");
    return state_->close(timeout);
}
void PublisherEffectWorkerCustody::send(const Value& body, DWORD timeout) {
    state_->require_job();
    state_->wire.send(body, timeout);
    state_->require_job();
}
Value PublisherEffectWorkerCustody::receive(DWORD timeout) {
    state_->require_job();
    auto body = state_->wire.receive(timeout);
    state_->require_job();
    return body;
}
Value PublisherEffectWorkerCustody::observation() const {
    state_->require_job();
    auto result = state_->wire.observation();
    result.as_object().emplace("owned_job_active_process_limit", Value(std::uint64_t{1}));
    result.as_object().emplace("owned_job_kill_on_close", Value(true));
    return result;
}
PublisherTokenObservation PublisherEffectWorkerCustody::peer_primary_token() const {
    state_->require_job();
    auto token = state_->wire.peer_primary_token();
    state_->require_job();
    return token;
}
bool PublisherEffectWorkerCustody::wait_for_exit(DWORD timeout, DWORD& code) const {
    require(timeout <= 120000, "effect transport exit wait exceeds its bound");
    const auto result = WaitForSingleObject(state_->wire.peer.value, timeout);
    if (result == WAIT_TIMEOUT) return false;
    require(result == WAIT_OBJECT_0 && GetExitCodeProcess(state_->wire.peer.value, &code),
        "effect transport original child exit is unavailable");
    return true;
}
const std::string& PublisherEffectWorkerCustody::canonical_request() const {
    state_->require_job();
    state_->wire.require_peer();
    return state_->wire.canonical_request;
}

struct PublisherEffectWorkerPeer::State { Wire wire; };
bool PublisherEffectWorkerPeer::await_parent_retirement(DWORD timeout) const {
    require(timeout <= 120000, "effect terminal parent wait exceeds its bound");
    state_->wire.require_peer();
    const auto result = WaitForSingleObject(state_->wire.peer.value, timeout);
    require(result == WAIT_TIMEOUT || result == WAIT_OBJECT_0, "effect terminal original parent wait is unavailable");
    return result == WAIT_OBJECT_0;
}
PublisherEffectWorkerPeer::PublisherEffectWorkerPeer(int argc, wchar_t** argv) : state_(std::make_unique<State>()) {
    try {
    state_->wire.claim();
    require(argc == 5 && argv && argv[1] && std::wstring(argv[1]) == publisher_effect_worker_transport_switch,
        "effect transport private entry grammar differs");
    const std::array<HANDLE, 3> inherited{{parse_handle(argv[2]), parse_handle(argv[3]), parse_handle(argv[4])}};
    require(inherited[0] != inherited[1] && inherited[0] != inherited[2] && inherited[1] != inherited[2],
        "effect transport inherited handles alias");
    auto& wire = state_->wire;
    wire.pipe.reset(inherited[0]);
    wire.peer.reset(inherited[1]);
    wire.cancel.reset(inherited[2]);
    for (const auto handle : inherited) require(SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) != FALSE,
        "effect transport inherited handle could not be made private");
    ULONG server_id = 0;
    DWORD flags = 0;
    require(GetFileType(wire.pipe.value) == FILE_TYPE_PIPE &&
        GetNamedPipeInfo(wire.pipe.value, &flags, nullptr, nullptr, nullptr) && !(flags & PIPE_SERVER_END) &&
        GetNamedPipeServerProcessId(wire.pipe.value, &server_id) && server_id &&
        GetProcessId(wire.peer.value) == server_id && server_id != GetCurrentProcessId(),
        "effect transport pipe server is not its original held parent process");
    wire.peer_id = server_id;
    wire.peer_birth = birth(wire.peer.value);
    wire.peer_image_path = image_path(wire.peer.value);
    wire.image = std::make_unique<usk::base::StableFile>(image_path(GetCurrentProcess()));
    usk::base::StableFile parent_image(wire.peer_image_path);
    require_same_image(parent_image, *wire.image);
    wire.require_peer();
    // Only the first frame may introduce the request binding. All subsequent
    // frames must repeat it with independent monotonic directional sequences.
    const auto until = wire.deadline(10000);
    std::array<unsigned char, 4> header{};
    wire.bytes(false, header.data(), static_cast<DWORD>(header.size()), until);
    const DWORD size = static_cast<DWORD>(header[0]) | (static_cast<DWORD>(header[1]) << 8) |
        (static_cast<DWORD>(header[2]) << 16) | (static_cast<DWORD>(header[3]) << 24);
    require(size && size <= packet_limit, "effect transport initial packet exceeds its bound");
    std::string bytes(size, '\0');
    wire.bytes(false, reinterpret_cast<unsigned char*>(bytes.data()), size, until);
    usk::json::ParseLimits limits;
    limits.max_bytes = packet_limit;
    limits.max_string_bytes = packet_limit;
    const auto packet = usk::json::parse(bytes, limits);
    require(packet.as_object().size() == 3 && packet.at("sequence").as_unsigned() == 1,
        "effect transport initial sequence differs");
    const auto& initial = packet.at("body");
    require(initial.as_object().size() == 7 && initial.at("schema").as_string() ==
        "usk.publisher_effect_transport_start.v1" && initial.at("parent_process_id").as_unsigned() == wire.peer_id &&
        initial.at("parent_process_birth").as_string() == hex64(wire.peer_birth) &&
        initial.at("child_process_id").as_unsigned() == GetCurrentProcessId() &&
        initial.at("child_process_birth").as_string() == hex64(birth(GetCurrentProcess())) &&
        usk::json::canonical(initial.at("image")) == usk::json::canonical(image_value(*wire.image)),
        "effect transport initial native process/image binding differs");
    const auto& request = initial.at("canonical_request").as_string();
    require(!request.empty() && request.size() <= 1024u * 1024u &&
        usk::json::canonical(usk::json::parse(request)) == request,
        "effect transport initial request is not bounded canonical bytes");
    wire.binding = request_digest(request);
    wire.canonical_request = request;
    require(packet.at("binding_sha256").as_string() == wire.binding,
        "effect transport initial exact request digest differs");
    wire.received = 1;
    wire.require_peer();
    require(GetNamedPipeServerProcessId(wire.pipe.value, &server_id) && server_id == wire.peer_id,
        "effect transport original pipe server changed");
    wire.send(Value(Value::Object{{"schema", Value("usk.publisher_effect_transport_ready.v1")},
        {"custody", wire.observation()}}), 10000);
    } catch (...) {
        const auto primary = std::current_exception();
        DWORD error = ERROR_SUCCESS;
        if (!state_->wire.retire_pending(10000, error)) {
            state_.release();
            PublisherEffectWorkerClosure closure;
            closure.job_closed = true; // This peer never owns a job/child.
            closure.child_ended = true;
            closure.io_retirement_error = error;
            throw PublisherEffectWorkerClosureUnknown(closure, primary);
        }
        state_->wire.release_claim();
        throw;
    }
}
PublisherEffectWorkerPeer::~PublisherEffectWorkerPeer() {
    DWORD error = ERROR_SUCCESS;
    if (!state_->wire.retire_pending(10000, error)) state_.release();
    else state_->wire.release_claim();
}
void PublisherEffectWorkerPeer::send(const Value& body, DWORD timeout) { state_->wire.send(body, timeout); }
Value PublisherEffectWorkerPeer::receive(DWORD timeout) { return state_->wire.receive(timeout); }
Value PublisherEffectWorkerPeer::observation() const { return state_->wire.observation(); }
void PublisherEffectWorkerPeer::require_record_chunk_custody(const Value& original) const {
    state_->wire.require_record_chunk_custody(original);
}
PublisherTokenObservation PublisherEffectWorkerPeer::peer_primary_token() const { return state_->wire.peer_primary_token(); }
const std::string& PublisherEffectWorkerPeer::canonical_request() const {
    state_->wire.require_peer();
    return state_->wire.canonical_request;
}
HANDLE PublisherEffectWorkerPeer::cancellation_observer() const {
    state_->wire.require_peer();
    return state_->wire.cancel.value;
}
namespace {
std::string closure_failure_text(const std::exception_ptr& primary) {
    std::string message = "effect transport closure unknown; original failure: ";
    try { if (primary) std::rethrow_exception(primary); }
    catch (const std::exception& error) { return message + error.what(); }
    catch (...) { return message + "non-standard exception"; }
    return message + "unavailable";
}
}
PublisherEffectWorkerClosureUnknown::PublisherEffectWorkerClosureUnknown(
    const PublisherEffectWorkerClosure& closure, std::exception_ptr primary) :
    std::runtime_error(closure_failure_text(primary)), closure_(closure), primary_(std::move(primary)) {}
} // namespace usk::platform::windows
#endif
