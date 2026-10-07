// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_effect_worker_custody_internal.h"
#include "usk_publisher_token_observation.h"
#include <chrono>
#include <array>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <thread>

using usk::json::Value;
using namespace usk::platform::windows;
namespace {
void require(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
}
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE raw) : value(raw) {
        require(value && value != INVALID_HANDLE_VALUE, "native control handle unavailable");
    }
    ~Handle() { CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
template<class F> void refuses(F action) {
    bool refused = false;
    try { action(); } catch (const std::exception&) { refused = true; }
    require(refused, "unsafe transport input/state was accepted");
}
std::wstring current_image() {
    wchar_t path[32768]{};
    DWORD length = static_cast<DWORD>(std::size(path));
    require(QueryFullProcessImageNameW(GetCurrentProcess(), 0, path, &length) && length &&
        length < std::size(path), "native control image unavailable");
    return std::wstring(path, length);
}
std::wstring own_sid() {
    const auto token = observe_current_publisher_token();
    return std::wstring(token.process_user_sid.begin(), token.process_user_sid.end());
}
std::string request() {
    return usk::json::canonical(Value(Value::Object{{"schema", Value("ordinary_transport_control")},
        {"effects_authorized", Value(false)}}));
}
std::uint64_t process_birth(HANDLE process) {
    FILETIME created{}, exited{}, kernel{}, user{};
    require(GetProcessTimes(process, &created, &exited, &kernel, &user) != FALSE,
        "held control process birth unavailable");
    return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}
struct OwnerReport { DWORD pid, reserved; std::uint64_t birth; };
int loss_owner(const wchar_t* handle_text) {
    // Closed ordinary fixture grammar; this entry exists only in the smoke
    // executable and carries no registered admission or publisher effects.
    std::uint64_t number = 0;
    for (const wchar_t* cursor = handle_text; *cursor; ++cursor) {
        require(*cursor >= L'0' && *cursor <= L'9' &&
            number <= (std::numeric_limits<std::uint64_t>::max() - (*cursor - L'0')) / 10,
            "owner-loss observer handle grammar differs");
        number = number * 10 + static_cast<std::uint64_t>(*cursor - L'0');
    }
    require(number && number < std::numeric_limits<std::uintptr_t>::max(),
        "owner-loss observer handle is outside the native bound");
    Handle output(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(number)));
    require(SetHandleInformation(output.value, HANDLE_FLAG_INHERIT, 0) != FALSE,
        "owner-loss observer handle did not become private");
    usk::base::StableFile image(current_image());
    PublisherEffectWorkerCustody custody(image, own_sid(), request());
    custody.send(Value(Value::Object{{"action", Value("wait")}}), 10000);
    require(custody.receive(10000).as_string() == "waiting", "owner-loss child not ready");
    const auto observed = custody.observation();
    Handle actual_child(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE,
        static_cast<DWORD>(observed.at("peer_process_id").as_unsigned())));
    const OwnerReport report{GetProcessId(actual_child.value), 0, process_birth(actual_child.value)};
    DWORD written = 0;
    require(WriteFile(output.value, &report, sizeof(report), &written, nullptr) && written == sizeof(report),
        "owner-loss native observer report failed");
    Handle wait(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    WaitForSingleObject(wait.value, INFINITE); // Original owner is genuinely killed by its held parent.
    return 2;
}
void owner_death_control(const usk::base::StableFile& image) {
    SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE read_raw = nullptr, write_raw = nullptr;
    require(CreatePipe(&read_raw, &write_raw, &inherit, 4096) != FALSE,
        "owner-loss observer pipe unavailable");
    Handle reader(read_raw), writer(write_raw);
    require(SetHandleInformation(reader.value, HANDLE_FLAG_INHERIT, 0) != FALSE,
        "owner-loss observer reader inheritance differs");
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    require(GetLastError() == ERROR_INSUFFICIENT_BUFFER && size && size < 65536,
        "owner-loss explicit observer list size unavailable");
    std::vector<unsigned char> bytes(size);
    auto* attributes = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(bytes.data());
    require(InitializeProcThreadAttributeList(attributes, 1, 0, &size) != FALSE,
        "owner-loss explicit observer list unavailable");
    struct AttributeCloser {
        PPROC_THREAD_ATTRIBUTE_LIST value;
        ~AttributeCloser() { DeleteProcThreadAttributeList(value); }
    } closer{attributes};
    require(UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        &writer.value, sizeof(writer.value), nullptr, nullptr) != FALSE,
        "owner-loss explicit observer inheritance unavailable");
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes;
    const auto executable = image.path().wstring();
    auto command = L"\"" + executable + L"\" --ordinary-custody-owner-loss " +
        std::to_wstring(reinterpret_cast<std::uintptr_t>(writer.value));
    PROCESS_INFORMATION information{};
    require(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
        DETACHED_PROCESS | EXTENDED_STARTUPINFO_PRESENT, nullptr, image.path().parent_path().c_str(),
        &startup.StartupInfo, &information) != FALSE, "original owner-loss process unavailable");
    Handle owner(information.hProcess), thread(information.hThread);
    struct OwnerCloser {
        HANDLE process;
        ~OwnerCloser() {
            if (WaitForSingleObject(process, 0) == WAIT_TIMEOUT) {
                TerminateProcess(process, ERROR_PROCESS_ABORTED);
                WaitForSingleObject(process, 10000);
            }
        }
    } owner_closer{owner.value};
    const auto original_birth = process_birth(owner.value);
    const auto until = GetTickCount64() + 10000;
    DWORD available = 0;
    while (available < sizeof(OwnerReport)) {
        require(PeekNamedPipe(reader.value, nullptr, 0, nullptr, &available, nullptr) &&
            GetTickCount64() < until && WaitForSingleObject(owner.value, 0) == WAIT_TIMEOUT,
            "original owner-loss process did not supply its native child identity");
        if (available < sizeof(OwnerReport)) Sleep(10);
    }
    OwnerReport report{};
    DWORD read = 0;
    require(ReadFile(reader.value, &report, sizeof(report), &read, nullptr) && read == sizeof(report) &&
        report.reserved == 0 && report.pid && report.pid != GetCurrentProcessId() &&
        report.pid != GetProcessId(owner.value), "original owner-loss child report differs");
    Handle held_child(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, report.pid));
    require(WaitForSingleObject(held_child.value, 0) == WAIT_TIMEOUT &&
        process_birth(held_child.value) == report.birth && process_birth(owner.value) == original_birth,
        "owner-loss live original native process births differ");
    image.verify_unchanged();
    require(TerminateProcess(owner.value, ERROR_PROCESS_ABORTED) &&
        WaitForSingleObject(owner.value, 10000) == WAIT_OBJECT_0 &&
        WaitForSingleObject(held_child.value, 10000) == WAIT_OBJECT_0,
        "genuine original owner death did not end its held job-owned child");
}
int child(int argc, wchar_t** argv) {
    PublisherEffectWorkerPeer peer(argc, argv);
    for (;;) {
        const auto body = peer.receive(10000);
        const auto action = body.at("action").as_string();
        if (action == "echo") peer.send(Value(Value::Object{{"echo", body.at("value")},
            {"custody", peer.observation()}}), 10000);
        else if (action == "wait") {
            peer.send(Value("waiting"), 10000);
            try { (void)peer.receive(10000); }
            catch (const std::exception&) { return 0; }
            throw std::runtime_error("waiting control unexpectedly received another packet");
        } else if (action == "sentinel") {
            const auto handle = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(
                body.at("handle").as_unsigned()));
            BY_HANDLE_FILE_INFORMATION information{};
            const bool observed = GetFileInformationByHandle(handle, &information) != FALSE;
            const bool inherited_same_file = observed &&
                information.dwVolumeSerialNumber == body.at("volume_serial").as_unsigned() &&
                information.nFileIndexHigh == body.at("file_id_high").as_unsigned() &&
                information.nFileIndexLow == body.at("file_id_low").as_unsigned();
            peer.send(Value(inherited_same_file), 10000);
        } else throw std::runtime_error("ordinary control action differs");
    }
}
void controls(const usk::base::StableFile& image, const std::wstring& sid) {
    wchar_t directory[32768]{}, temporary[32768]{};
    const auto count = GetTempPathW(static_cast<DWORD>(std::size(directory)), directory);
    require(count && count < std::size(directory) &&
        GetTempFileNameW(directory, L"usk", 0, temporary), "owned ordinary sentinel path unavailable");
    SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    Handle sentinel(CreateFileW(temporary, GENERIC_READ | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &inherit, OPEN_EXISTING,
        FILE_FLAG_DELETE_ON_CLOSE, nullptr));
    BY_HANDLE_FILE_INFORMATION file{};
    require(GetFileInformationByHandle(sentinel.value, &file) != FALSE, "sentinel identity unavailable");
    Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    HANDLE child_query = nullptr;
    {
        PublisherEffectWorkerCustody custody(image, sid, request(), stop.value);
        const auto observed = custody.observation();
        require(observed.at("authority").as_string() == "none" &&
            observed.at("current_process_id").as_unsigned() == GetCurrentProcessId() &&
            observed.at("peer_process_id").as_unsigned() != GetCurrentProcessId() &&
            observed.at("owned_job_active_process_limit").as_unsigned() == 1,
            "ordinary transport custody identities differ");
        child_query = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
            static_cast<DWORD>(observed.at("peer_process_id").as_unsigned()));
        require(child_query != nullptr, "independent query-only original child unavailable");
        refuses([&] { PublisherEffectWorkerCustody second(image, sid, request()); });
        require(custody.observation().at("peer_process_id").as_unsigned() == observed.at("peer_process_id").as_unsigned(),
            "refused second launch released the original process-wide custody owner");
        custody.send(Value(Value::Object{{"action", Value("echo")}, {"value", Value("exact payload")}}), 10000);
        const auto reply = custody.receive(10000);
        require(reply.at("echo").as_string() == "exact payload" &&
            reply.at("custody").at("peer_process_id").as_unsigned() == GetCurrentProcessId() &&
            reply.at("custody").at("current_process_id").as_unsigned() == observed.at("peer_process_id").as_unsigned() &&
            reply.at("custody").at("request_sha256").as_string() == observed.at("request_sha256").as_string(),
            "native connected child did not retain its exact peer/request binding");
        custody.send(Value(Value::Object{{"action", Value("sentinel")},
            {"handle", Value(static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(sentinel.value)))},
            {"volume_serial", Value(static_cast<std::uint64_t>(file.dwVolumeSerialNumber))},
            {"file_id_high", Value(static_cast<std::uint64_t>(file.nFileIndexHigh))},
            {"file_id_low", Value(static_cast<std::uint64_t>(file.nFileIndexLow))}}), 10000);
        require(!custody.receive(10000).as_boolean(), "unlisted native inheritable file leaked into the child");
        custody.send(Value(Value::Object{{"action", Value("wait")}}), 10000);
        require(custody.receive(10000).as_string() == "waiting", "child did not enter its owned wait");
        const auto closed = custody.close(10000);
        require(closed.confirmed() && closed.child_process_id == observed.at("peer_process_id").as_unsigned() &&
            closed.child_process_birth == process_birth(child_query),
            "explicit bounded closure did not confirm the original held child");
        require(custody.close(0).confirmed(), "confirmed closure was not latched");
        refuses([&] { (void)custody.observation(); });
    }
    Handle ended_child(child_query);
    require(WaitForSingleObject(ended_child.value, 10000) == WAIT_OBJECT_0,
        "closing the sole noninherited job did not end its original child");
    {
        ResetEvent(stop.value);
        PublisherEffectWorkerCustody custody(image, sid, request(), stop.value);
        custody.send(Value(Value::Object{{"action", Value("wait")}}), 10000);
        require(custody.receive(10000).as_string() == "waiting", "cancellation control was not ready");
        std::thread signal([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            SetEvent(stop.value);
        });
        refuses([&] { (void)custody.receive(5000); });
        signal.join();
        DWORD code = STILL_ACTIVE;
        require(custody.wait_for_exit(10000, code) && code == 0,
            "native cancellation did not release the child's pending overlapped read");
        ResetEvent(stop.value);
        refuses([&] { custody.send(Value("after failed read")); });
    }
    {
        PublisherEffectWorkerCustody custody(image, sid, request());
        custody.send(Value(Value::Object{{"action", Value("wait")}}), 10000);
        require(custody.receive(10000).as_string() == "waiting", "deadline control was not ready");
        refuses([&] { (void)custody.receive(100); });
        refuses([&] { custody.send(Value("after native deadline")); });
        require(custody.close(10000).confirmed(), "cancelled deadline I/O did not retire before native closure");
    }
    {
        PublisherEffectWorkerCustody custody(image, sid, request());
        refuses([&] { custody.send(Value(std::string(4u * 1024u * 1024u, 'x'))); });
        refuses([&] { custody.send(Value("after oversized packet")); });
    }
    refuses([&] { PublisherEffectWorkerCustody custody(image, sid, "{ \"noncanonical\":true}"); });
    wchar_t executable[] = L"ordinary";
    wchar_t option[] = L"--usk-private-effect-worker-transport-v1";
    wchar_t invalid[] = L"18446744073709551615";
    wchar_t* malformed[] = {executable, option, invalid, invalid, invalid};
    refuses([&] { PublisherEffectWorkerPeer peer(5, malformed); });
}
} // namespace
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc > 1 && std::wstring(argv[1]) == publisher_effect_worker_transport_switch) return child(argc, argv);
        if (argc == 3 && std::wstring(argv[1]) == L"--ordinary-custody-owner-loss") return loss_owner(argv[2]);
        usk::base::StableFile image(current_image());
        controls(image, own_sid());
        owner_death_control(image);
        std::cout << "Native private child custody, exact transport, explicit inheritance, job closure, genuine owner death and cancellation: PASS; no effect admission\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
