// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_request_channel.h"
#include "usk_publisher_execution_observation.h"
#include "usk_publisher_tree_observation.h"
#include "usk_effect_dispatch.h"
#include "usk_json.h"
#if defined(_WIN32)
#include <sddl.h>
#include <atomic>
#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>
using usk::platform::windows::PublisherRequestChannel;
namespace {
void require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
template<class Action> void refuses(Action action) {
    bool refused=false;
    try { action(); } catch (const std::exception&) { refused=true; }
    require(refused,"required refusal absent");
}
std::string replaced(std::string source, const std::string& from, const std::string& to) {
    const auto position = source.find(from);
    require(position != std::string::npos, "test replacement token absent");
    source.replace(position, from.size(), to);
    return source;
}
void test_terminal_response_binding() {
    using usk::platform::windows::require_publisher_response_binding;
    const std::wstring service = L"USK_PUB_0123456789abcdef0123456789abcdef";
    const std::string apply_request = R"({"schema":"usk.install_local_apply_request.v1","transaction_id":"tx.apply","applied_at":"2026-09-29T15:06:00Z","plan_request":{"install_id":"install.one"}})";
    const std::string installed_response = R"({"schema":"usk.command_response.v1","status":"ok","payload":{"schema":"usk.installed_state.v1","lifecycle_status":"installed","install_id":"install.one","transaction_id":"tx.apply","created_at":"2026-09-29T15:06:00Z"}})";
    const std::string response_prefix = R"({"schema":"usk.publisher_lab_service_observation.v1","status":"pass","service_name":"USK_PUB_0123456789abcdef0123456789abcdef",)";
    const std::string apply_response = response_prefix +
        "\"apply_response\":" + installed_response +
        ",\"recovery_installed_response\":null}";
    const std::string apply_reentry_response = response_prefix +
        "\"apply_response\":null,\"recovery_installed_response\":" +
        installed_response + "}";
    require_publisher_response_binding(service, apply_request, apply_response);
    require_publisher_response_binding(service, apply_request, apply_reentry_response);
    refuses([&] { require_publisher_response_binding(service, apply_request,
        replaced(apply_response, "\"transaction_id\":\"tx.apply\"", "\"transaction_id\":\"other\"")); });
    refuses([&] { require_publisher_response_binding(service, apply_request,
        replaced(apply_response, "\"install_id\":\"install.one\"", "\"install_id\":\"other\"")); });
    refuses([&] { require_publisher_response_binding(service, apply_request,
        replaced(apply_response, "\"created_at\":\"2026-09-29T15:06:00Z\"",
            "\"created_at\":\"2026-09-29T15:06:01Z\"")); });
    refuses([&] { require_publisher_response_binding(service, apply_request,
        replaced(apply_response, "\"service_name\":\"USK_PUB_0123456789abcdef0123456789abcdef\"",
            "\"service_name\":\"USK_PUB_ffffffffffffffffffffffffffffffff\"")); });
    refuses([&] { require_publisher_response_binding(service, apply_request,
        replaced(apply_response, "\"apply_response\":{", "\"apply_response\":null,\"unused\":{") ); });
    refuses([&] { require_publisher_response_binding(service, apply_request,
        replaced(apply_response, "\"recovery_installed_response\":null",
            "\"recovery_installed_response\":" + installed_response)); });

    const std::string recovery_request = R"({"schema":"usk.publisher_recovery_request.v1","install_id":"install.one","transaction_id":"tx.apply"})";
    const std::string recovery_response = apply_reentry_response;
    require_publisher_response_binding(service, recovery_request, recovery_response);
    refuses([&] { require_publisher_response_binding(service, recovery_request,
        replaced(recovery_response, "\"transaction_id\":\"tx.apply\"", "\"transaction_id\":\"stale\"")); });

    const std::string verify_request = R"({"schema":"usk.publisher_installed_verify_request.v1","install_id":"install.one","transaction_id":"tx.apply","report_id":"report.one","verified_at":"2026-09-29T15:08:00Z"})";
    const std::string verify_response = R"({"schema":"usk.publisher_lab_service_observation.v1","status":"pass","transaction_id":"tx.apply","bound_report_digest":"digest.one","verify_response":{"schema":"usk.command_response.v1","status":"ok","payload":{"schema":"usk.verification_report.v1","status":"pass","install_id":"install.one","report_id":"report.one","verified_at":"2026-09-29T15:08:00Z","report_digest":"digest.one"}}})";
    require_publisher_response_binding(service, verify_request, verify_response);
    refuses([&] { require_publisher_response_binding(service, verify_request,
        replaced(verify_response, "\"report_id\":\"report.one\"", "\"report_id\":\"other\"")); });
    refuses([&] { require_publisher_response_binding(service, verify_request,
        replaced(verify_response, "\"verified_at\":\"2026-09-29T15:08:00Z\"",
            "\"verified_at\":\"2026-09-29T15:09:00Z\"")); });
    refuses([&] { require_publisher_response_binding(service, verify_request,
        replaced(verify_response, "\"report_digest\":\"digest.one\"", "\"report_digest\":\"other\"")); });
    const std::string drift_response = replaced(replaced(verify_response,
        "\"status\":\"pass\",\"transaction_id\"", "\"status\":\"failed\",\"transaction_id\""),
        "\"schema\":\"usk.verification_report.v1\",\"status\":\"pass\"",
        "\"schema\":\"usk.verification_report.v1\",\"status\":\"fail\"");
    require_publisher_response_binding(service, verify_request, drift_response);
    refuses([&] { require_publisher_response_binding(service, verify_request,
        replaced(drift_response, "\"install_id\":\"install.one\"", "\"install_id\":\"other\"")); });
    require_publisher_response_binding(service, apply_request,
        R"({"schema":"usk.publisher_lab_service_observation.v1","status":"recovery_required","error":"retained"})");
    require_publisher_response_binding(service, verify_request,
        R"({"schema":"usk.publisher_lab_service_observation.v1","status":"failed","error":"verify refused"})");
}
void test_maintenance_response_binding() {
    using usk::json::Value;
    using usk::platform::windows::require_publisher_response_binding;
    const std::string name = "USK_PUB_0123456789abcdef0123456789abcdef";
    const std::wstring service(name.begin(), name.end());
    for (const std::string operation : {"repair", "move", "uninstall"}) {
        const Value request(Value::Object{{"schema", Value("usk." + operation + "_apply_request.v1")},
            {"transaction_id", Value("tx.one")}, {"applied_at", Value("2026-10-06T07:00:00Z")},
            {"plan_request", Value(Value::Object{{"install_id", Value("install.one")}, {"plan_id", Value("plan.one")}})}});
        Value report(Value::Object{{"schema", Value("usk." + operation + "_report.v1")},
            {"status", Value(operation == "move" ? "new_committed_old_retained" : "completed")},
            {"install_id", Value("install.one")}, {"plan_id", Value("plan.one")}, {"transaction_id", Value("tx.one")},
            {"report_id", Value(operation + ".tx.one")}, {"completed_at", Value("2026-10-06T07:00:00Z")}});
        report.as_object().emplace("report_digest", Value(usk::json::sha256_canonical(report)));
        Value response(Value::Object{{"schema", Value("usk.publisher_lab_service_observation.v1")}, {"status", Value("pass")},
            {"request_sha256", Value(usk::json::sha256_canonical(request))}, {"operation", Value(operation)},
            {"install_id", Value("install.one")}, {"transaction_id", Value("tx.one")}, {"service_name", Value(name)},
            {"service_sid", Value("S-1-5-80-1-2-3-4-5")}, {"process_id", Value(std::uint64_t{123})},
            {"operation_admission", Value(Value::Object{})},
            {"registered_admission", Value(Value::Object{{"schema", Value("usk.publisher_registered_admission_observation.v1")},
                {"service_name", Value(name)}, {"service_sid", Value("S-1-5-80-1-2-3-4-5")}, {"process_id", Value(std::uint64_t{123})}})},
            {"apply_response", Value(Value::Object{{"schema", Value("usk.command_response.v1")}, {"status", Value("ok")}, {"payload", report}})}});
        const auto encoded_request = usk::json::canonical(request);
        require_publisher_response_binding(service, encoded_request, usk::json::canonical(response), 123);
        refuses([&] { require_publisher_response_binding(service, encoded_request, usk::json::canonical(response), 124); });
        for (const auto field : {"request_sha256", "operation", "install_id", "transaction_id", "service_name", "service_sid"}) {
            auto wrong = response;
            wrong.as_object().at(field) = Value("substituted");
            refuses([&] { require_publisher_response_binding(service, encoded_request, usk::json::canonical(wrong), 123); });
        }
        for (const auto field : {"schema", "status", "install_id", "transaction_id", "plan_id", "completed_at", "report_id", "report_digest"}) {
            auto wrong = response;
            wrong.as_object().at("apply_response").as_object().at("payload").as_object().at(field) = Value("substituted");
            refuses([&] { require_publisher_response_binding(service, encoded_request, usk::json::canonical(wrong), 123); });
        }
        auto wrong = response;
        wrong.as_object().at("registered_admission").as_object().at("process_id") = Value(std::uint64_t{124});
        refuses([&] { require_publisher_response_binding(service, encoded_request, usk::json::canonical(wrong), 123); });
        wrong = response;
        wrong.as_object().emplace("recovery_installed_response", Value());
        refuses([&] { require_publisher_response_binding(service, encoded_request, usk::json::canonical(wrong), 123); });
        const Value recovery(Value::Object{{"schema", Value("usk.publisher_maintenance_recovery_request.v1")},
            {"operation", Value(operation)}, {"install_id", Value("install.one")}, {"transaction_id", Value("tx.one")}});
        Value recovered_report(Value::Object{{"schema", Value("usk.maintenance_recovery_report.v1")}, {"status", Value("completed")},
            {"operation", Value(operation)}, {"install_id", Value("install.one")}, {"transaction_id", Value("tx.one")},
            {"plan_id", Value("plan.one")}, {"plan_digest", Value(std::string(64, 'a'))},
            {"transaction_snapshot_sha256", Value(std::string(64, 'b'))}, {"effect_history_sha256", Value(std::string(64, 'c'))},
            {"source_digest", Value(std::string(64, 'd'))}, {"recorded_at", Value("2026-10-06T07:00:00Z")},
            {"report_id", Value("recovery." + operation + ".tx.one")}});
        recovered_report.as_object().emplace("report_digest", Value(usk::json::sha256_canonical(recovered_report)));
        auto recovered = response;
        recovered.as_object().erase("apply_response");
        recovered.as_object().at("request_sha256") = Value(usk::json::sha256_canonical(recovery));
        recovered.as_object().emplace("recovery_response", Value(Value::Object{
            {"schema", Value("usk.command_response.v1")}, {"status", Value("ok")}, {"payload", recovered_report}}));
        const auto encoded_recovery = usk::json::canonical(recovery);
        require_publisher_response_binding(service, encoded_recovery, usk::json::canonical(recovered), 123);
        refuses([&] { require_publisher_response_binding(service, encoded_request, usk::json::canonical(recovered), 123); });
        refuses([&] { require_publisher_response_binding(service, encoded_recovery, usk::json::canonical(response), 123); });
        for (const auto field : {"operation", "plan_digest", "transaction_snapshot_sha256", "effect_history_sha256", "source_digest"}) {
            auto invalid_report = recovered_report;
            invalid_report.as_object().erase("report_digest");
            invalid_report.as_object().at(field) = Value("substituted");
            invalid_report.as_object().emplace("report_digest", Value(usk::json::sha256_canonical(invalid_report)));
            wrong = recovered;
            wrong.as_object().at("recovery_response").as_object().at("payload") = invalid_report;
            refuses([&] { require_publisher_response_binding(service, encoded_recovery, usk::json::canonical(wrong), 123); });
        }
    }
}
void test_service_observation_transport_binding() {
    using usk::platform::windows::require_publisher_response_binding;
    const std::wstring service = L"USK_PUB_0123456789abcdef0123456789abcdef";
    const std::string request = R"({"schema":"usk.publisher_capability_request.v2","request_id":"observe.one"})";
    // These leaf objects exercise transport binding only. The command validator
    // separately requires the complete capability and admission contracts.
    const std::string response = R"({"schema":"usk.publisher_service_capability_observation.v1","status":"observed","request_id":"observe.one","service_name":"USK_PUB_0123456789abcdef0123456789abcdef","service_sid":"S-1-5-80-1-2-3-4-5","process_id":123,"registered_admission":{},"capability_observation":{"schema":"usk.publisher_capability.v2"}})";
    require_publisher_response_binding(service, request, response);
    require_publisher_response_binding(service, request, response, 123);
    const auto v3_request = replaced(request, "request.v2", "request.v3");
    const auto v3_response = replaced(response, "capability.v2", "capability.v3");
    require_publisher_response_binding(service, v3_request, v3_response, 123);
    refuses([&] { require_publisher_response_binding(service, v3_request, response, 123); });
    refuses([&] { require_publisher_response_binding(service, request, v3_response, 123); });
    refuses([&] { require_publisher_response_binding(service, request, response, 124); });
    refuses([&] { require_publisher_response_binding(service, request,
        replaced(response, "observe.one", "observe.stale")); });
    refuses([&] { require_publisher_response_binding(service, request,
        replaced(response, "USK_PUB_0123456789abcdef0123456789abcdef", "USK_PUB_ffffffffffffffffffffffffffffffff")); });
    refuses([&] { require_publisher_response_binding(service, request,
        replaced(response, "\"status\":\"observed\"", "\"status\":\"pass\"")); });
    refuses([&] { require_publisher_response_binding(service, request,
        replaced(response, "usk.publisher_service_capability_observation.v1", "usk.publisher_lab_service_observation.v1")); });
    refuses([&] { require_publisher_response_binding(service, request,
        replaced(response, "\"process_id\":123", "\"process_id\":0")); });
    refuses([&] { require_publisher_response_binding(service, request,
        replaced(response, "\"process_id\":123", "\"process_id\":4294967296")); });
    refuses([&] { require_publisher_response_binding(service, request,
        replaced(response, "\"process_id\":123", "\"process_id\":123.0")); });
    refuses([&] { require_publisher_response_binding(service, request,
        replaced(response, "S-1-5-80-1-2-3-4-5", "")); });
    refuses([&] { require_publisher_response_binding(service, request,
        replaced(response, "\"registered_admission\":{}", "\"registered_admission\":null")); });
    refuses([&] { require_publisher_response_binding(service, request,
        replaced(response, "\"capability_observation\":{", "\"extra\":true,\"capability_observation\":{")); });
    refuses([&] { require_publisher_response_binding(service,
        R"({"schema":"usk.install_local_apply_request.v1","transaction_id":"tx.apply","plan_request":{"install_id":"install.one"}})", response); });
    refuses([&] { require_publisher_response_binding(service,
        replaced(request, "\"request_id\":\"observe.one\"", "\"request_id\":\"observe.one\",\"extra\":true"), response); });
}
struct OwnedHandle {
    HANDLE value;
    explicit OwnedHandle(HANDLE handle) : value(handle) {}
    ~OwnedHandle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
};
void test_endpoint_acquisition(const std::wstring& name, const std::wstring& sid,
    const std::wstring& service_sid) {
    using namespace usk::platform::windows;
    using Refusal = usk::base::EffectRequestNotDispatched;
    const auto reference = publisher_request_inspection_reference(name);
    auto lower = name;
    for (auto& ch : lower) if (ch >= L'A' && ch <= L'Z') ch = ch - L'A' + L'a';
    require(reference == publisher_request_inspection_reference(lower) &&
        reference != publisher_request_inspection_reference(name + L"_other"),
        "endpoint reference does not preserve its canonical scope");
    auto channel = std::make_unique<PublisherRequestChannel>(name, service_sid, sid, nullptr, 2000);
    OwnedHandle first(connect_publisher_request_endpoint(name, 2000));
    require(first.value != INVALID_HANDLE_VALUE, "first owned endpoint connection absent");
    const auto expect_refusal = [&](const char* label, const PublisherRequestOptions& options, Refusal::Reason expected) {
        bool refused = false;
        const auto call_began = GetTickCount64();
        try { OwnedHandle unexpected(connect_publisher_request_endpoint(name, 1000, options)); }
        catch (const Refusal& error) {
            refused = error.reason() == expected && error.inspection_reference() == reference;
            if (!refused) {
                std::cerr << "endpoint " << label << ": expected reason " << static_cast<int>(expected)
                    << ", actual reason " << static_cast<int>(error.reason())
                    << ", scope matches " << (error.inspection_reference() == reference)
                    << ", elapsed milliseconds " << GetTickCount64() - call_began << '\n';
            }
        } catch (const std::exception& error) {
            std::cerr << "endpoint " << label << ": unexpected generic refusal after "
                << GetTickCount64() - call_began << " milliseconds: " << error.what() << '\n';
            throw;
        }
        require(refused, "endpoint refusal lost its actual reason or scope reference");
        DWORD available = 99;
        require(PeekNamedPipe(first.value, nullptr, 0, nullptr, &available, nullptr) && available == 0,
            "refusal disturbed the existing empty connection");
    };
    const auto began = GetTickCount64();
    expect_refusal("fail_fast", {}, Refusal::Reason::operation_conflict);
    require(GetTickCount64() - began < 500, "default endpoint conflict was not fail-fast");
    PublisherRequestOptions timed;
    timed.conflict_wait_milliseconds = 60;
    const auto timed_begin = GetTickCount64();
    expect_refusal("deadline", timed, Refusal::Reason::operation_conflict);
    require(GetTickCount64() - timed_begin >= 60 && GetTickCount64() - timed_begin < 1000,
        "endpoint conflict ignored its bounded deadline");
    OwnedHandle cancel(CreateEventW(nullptr, TRUE, TRUE, nullptr));
    require(cancel.value != nullptr, "endpoint cancellation event absent");
    PublisherRequestOptions cancelled;
    cancelled.cancel_event = cancel.value;
    cancelled.conflict_wait_milliseconds = 1000;
    expect_refusal("ready_cancel", cancelled, Refusal::Reason::operation_cancelled);
    require(ResetEvent(cancel.value) != FALSE, "endpoint cancellation reset failed");
    std::exception_ptr cancellation_failure;
    std::atomic<bool> started{false};
    std::thread waiting([&] {
        try { started.store(true); expect_refusal("async_cancel", cancelled, Refusal::Reason::operation_cancelled); }
        catch (...) { cancellation_failure = std::current_exception(); }
    });
    while (!started.load()) Sleep(1);
    Sleep(20);
    const bool signalled = SetEvent(cancel.value) != FALSE;
    waiting.join();
    require(signalled, "endpoint cancellation signal failed");
    if (cancellation_failure) std::rethrow_exception(cancellation_failure);
    // Deadline/cancellation leave the existing connection owned. A waiting
    // contender succeeds only after the fixture owner creates a new endpoint.
    PublisherRequestOptions bounded_wait;
    bounded_wait.conflict_wait_milliseconds = 1000;
    std::exception_ptr connection_failure;
    std::atomic<bool> connected{false};
    started.store(false);
    std::thread contender([&] {
        try {
            started.store(true);
            OwnedHandle connection(connect_publisher_request_endpoint(name, 2000, bounded_wait));
            connected.store(connection.value != INVALID_HANDLE_VALUE);
        } catch (...) { connection_failure = std::current_exception(); }
    });
    while (!started.load()) Sleep(1);
    Sleep(20);
    const bool closed = CloseHandle(first.value) != FALSE;
    first.value = INVALID_HANDLE_VALUE;
    channel.reset();
    try { channel = std::make_unique<PublisherRequestChannel>(name, service_sid, sid, nullptr, 2000); }
    catch (...) { contender.join(); throw; }
    contender.join();
    require(closed, "owned endpoint release failed");
    if (connection_failure) std::rethrow_exception(connection_failure);
    require(connected.load(), "bounded contender did not connect to the fresh owned endpoint");
    PublisherRequestChannel ready(name + L"_ready", service_sid, sid, nullptr, 2000);
    require(SetEvent(cancel.value) != FALSE, "ready cancellation signal failed");
    bool ready_cancelled = false;
    try { OwnedHandle unexpected(connect_publisher_request_endpoint(name + L"_ready", 1000, cancelled)); }
    catch (const Refusal& error) { ready_cancelled = error.reason() == Refusal::Reason::operation_cancelled; }
    require(ready_cancelled, "available endpoint overrode ready cancellation");
    auto excessive = bounded_wait;
    excessive.conflict_wait_milliseconds = publisher_request_max_conflict_wait_milliseconds + 1;
    refuses([&] { OwnedHandle unexpected(connect_publisher_request_endpoint(name, 1000, excessive)); });
    bool generic_missing = false;
    try { OwnedHandle unexpected(connect_publisher_request_endpoint(name + L"_missing", 25)); }
    catch (const Refusal&) { throw std::runtime_error("generic missing endpoint became typed admission"); }
    catch (const std::runtime_error&) { generic_missing = true; }
    require(generic_missing, "generic missing endpoint control did not fail");
}
std::wstring current_sid() {
    HANDLE token=nullptr;
    require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)!=FALSE,"process token unavailable");
    DWORD size=0;
    GetTokenInformation(token,TokenUser,nullptr,0,&size);
    std::vector<unsigned char> bytes(size);
    const bool okay=GetTokenInformation(token,TokenUser,bytes.data(),size,&size)!=FALSE;
    CloseHandle(token);
    require(okay,"process user unavailable");
    LPWSTR text=nullptr;
    require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid,&text)!=FALSE,"user SID unavailable");
    const std::wstring value(text);
    LocalFree(text);
    return value;
}
class OwnedAccessDirectory {
public:
    explicit OwnedAccessDirectory(const std::wstring& sid, bool full_access = false) {
        static std::atomic<unsigned> sequence{0};
        path_ = std::filesystem::temp_directory_path() /
            (L"usk-authenticated-access-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(sequence.fetch_add(1)));
        const std::wstring sddl = L"O:" + sid + L"D:P(A;;" +
            (full_access ? L"FA" : L"0x001300a9") + L";;;" + sid + L")";
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
            &descriptor, nullptr) != FALSE, "owned access descriptor unavailable");
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
        const bool created = CreateDirectoryW(path_.c_str(), &attributes) != FALSE;
        LocalFree(descriptor);
        require(created, "owned access directory creation failed");
        created_ = true;
        handle_ = CreateFileW(path_.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) {
            RemoveDirectoryW(path_.c_str());
            created_ = false;
            throw std::runtime_error("owned access directory handle unavailable");
        }
    }
    ~OwnedAccessDirectory() {
        if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
        if (created_) RemoveDirectoryW(path_.c_str());
    }
    OwnedAccessDirectory(const OwnedAccessDirectory&) = delete;
    OwnedAccessDirectory& operator=(const OwnedAccessDirectory&) = delete;
    HANDLE get() const { return handle_; }
    const std::filesystem::path& path() const { return path_; }
private:
    std::filesystem::path path_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    bool created_ = false;
};
class OwnedAccessFile {
public:
    explicit OwnedAccessFile(const std::filesystem::path& path) : path_(path) {
        HANDLE file = CreateFileW(path_.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        require(file != INVALID_HANDLE_VALUE, "owned access file creation failed");
        created_ = true;
        DWORD written = 0;
        const bool okay = WriteFile(file, "abc", 3, &written, nullptr) != FALSE && written == 3;
        const bool closed = CloseHandle(file) != FALSE;
        if (!okay || !closed) {
            DeleteFileW(path_.c_str());
            created_ = false;
            throw std::runtime_error("owned access file write failed");
        }
    }
    ~OwnedAccessFile() { if (created_) DeleteFileW(path_.c_str()); }
    OwnedAccessFile(const OwnedAccessFile&) = delete;
    OwnedAccessFile& operator=(const OwnedAccessFile&) = delete;
private:
    std::filesystem::path path_;
    bool created_ = false;
};
std::thread raw_client(const std::wstring& name, const std::string& message,
    std::string& response, std::exception_ptr& failure,
    bool send_extra = false) {
    return std::thread([&,name,message,send_extra] {
        try {
            const auto pipe_name=usk::platform::windows::publisher_request_pipe_name(name);
            HANDLE pipe=CreateFileW(pipe_name.c_str(), FILE_READ_DATA|FILE_WRITE_DATA|
                FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE,
                0,nullptr,OPEN_EXISTING,SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
            require(pipe!=INVALID_HANDLE_VALUE,"raw client connection denied");
            DWORD mode=PIPE_READMODE_MESSAGE, transferred=0;
            const bool configured=SetNamedPipeHandleState(pipe,&mode,nullptr,nullptr)!=FALSE;
            const bool written=configured && WriteFile(pipe,message.data(),static_cast<DWORD>(message.size()),&transferred,nullptr)!=FALSE;
            if (written && send_extra) {
                constexpr char extra[] = "no-second-request";
                require(WriteFile(pipe,extra,0,&transferred,nullptr)!=FALSE &&
                    transferred==0,"empty extra client message failed");
                require(WriteFile(pipe,extra,sizeof(extra)-1,&transferred,nullptr)!=FALSE &&
                    transferred==sizeof(extra)-1,"extra client message failed");
                Sleep(75);
            }
            char bytes[128]{};
            const bool read=written && ReadFile(pipe,bytes,sizeof(bytes),&transferred,nullptr)!=FALSE;
            CloseHandle(pipe);
            require(read,"raw client response absent");
            response.assign(bytes,transferred);
        } catch (...) { failure=std::current_exception(); }
    });
}
}
int main(int argc, char** argv) {
    try {
        test_terminal_response_binding();
        test_service_observation_transport_binding();
        test_maintenance_response_binding();
        if (argc == 2 && std::string(argv[1]) == "--response-binding-smoke") return 0;
        const auto name=L"USK_transport_test_"+std::to_wstring(GetCurrentProcessId());
        const auto sid=current_sid();
        const std::wstring service_sid=L"S-1-5-80-1-2-3-4-5";
        test_endpoint_acquisition(name + L"_acquisition", sid, service_sid);
        std::string response;
        std::exception_ptr client_failure;
        auto channel=std::make_unique<PublisherRequestChannel>(name,service_sid,sid,nullptr,2000);
        refuses([&] { (void)channel->observe_authenticated_object_access(INVALID_HANDLE_VALUE); });
        refuses([&] { PublisherRequestChannel duplicate(name,service_sid,sid,nullptr); });
        auto client=raw_client(name,"{\"reviewed\":true}",response,client_failure,true);
        try {
            require(channel->receive()=="{\"reviewed\":true}","request bytes changed");
            HANDLE token=nullptr;
            require(!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&token) &&
                GetLastError()==ERROR_NO_TOKEN,"caller impersonation retained");
            OwnedAccessDirectory directory(sid);
            const auto access = channel->observe_authenticated_object_access(directory.get());
            const auto& observed_sid = access.at("client").at("user_sid").as_string();
            require(access.at("schema").as_string() == "usk.publisher_authenticated_object_access.v1" &&
                std::wstring(observed_sid.begin(), observed_sid.end()) == sid &&
                access.at("client").at("captured_process_id").as_unsigned() == GetCurrentProcessId() &&
                access.at("client").at("token_type").as_unsigned() == TokenImpersonation,
                "authenticated access identity differs from actual pipe client");
            require(!access.at("checks").at("write_or_add_file").at("allowed").as_boolean() &&
                access.at("checks").at("write_or_add_file").at("granted").as_unsigned() == 0 &&
                access.at("checks").at("delete").at("allowed").as_boolean() &&
                access.at("checks").at("delete").at("granted").as_unsigned() == DELETE,
                "actual authenticated access check lost allowed/denied distinction");
            const auto client_facts = access.at("client");
            const auto native_object = access.at("native_object");
            using namespace usk::platform::windows;
            const auto empty_tree = observe_publisher_tree(directory.get());
            const auto empty_access = observe_publisher_authenticated_descendant_access(
                directory.get(), empty_tree, *channel, client_facts);
            require(empty_access.at("objects").as_array().empty(), "empty authenticated closure gained descendants");
            auto wrong_client = client_facts;
            wrong_client.as_object().at("token_id") = usk::json::Value(std::uint64_t{0});
            refuses([&] { (void)observe_publisher_authenticated_descendant_access(
                directory.get(), empty_tree, *channel, wrong_client); });
            OwnedAccessDirectory writable(sid, true);
            OwnedAccessFile file(writable.path() / L"payload.bin");
            const auto file_tree = observe_publisher_tree(writable.get());
            const auto file_access = observe_publisher_authenticated_descendant_access(
                writable.get(), file_tree, *channel, client_facts);
            require(file_access.at("objects").as_array().size() == 1 &&
                file_access.at("objects").as_array().front().at("relative_path").as_string() == "payload.bin" &&
                file_access.at("objects").as_array().front().at("authenticated_access").at("checks")
                    .at("write_or_add_file").at("allowed").as_boolean(),
                "actual owned-file descriptor access lost the granted mutation control");
            auto incomplete_tree = file_tree;
            incomplete_tree.descendants.clear();
            refuses([&] { (void)observe_publisher_authenticated_descendant_access(
                writable.get(), incomplete_tree, *channel, client_facts); });
            auto compact = access;
            compact.as_object().erase("client");
            compact.as_object().erase("native_object");
            compact.as_object().emplace("client_sha256", usk::json::Value(usk::json::sha256_canonical(client_facts)));
            compact.as_object().emplace("native_object_sha256", usk::json::Value(usk::json::sha256_canonical(native_object)));
            using usk::platform::windows::require_publisher_authenticated_object_access;
            require_publisher_authenticated_object_access(compact, client_facts, native_object);
            auto invalid = compact;
            invalid.as_object().at("descriptor_hex") = usk::json::Value("0100000000000000000000000000000000000000");
            refuses([&] { require_publisher_authenticated_object_access(invalid, client_facts, native_object); });
            invalid = compact;
            invalid.as_object().at("client_sha256") = usk::json::Value(std::string(64, '0'));
            refuses([&] { require_publisher_authenticated_object_access(invalid, client_facts, native_object); });
            invalid = compact;
            invalid.as_object().at("checks").as_object().at("delete").as_object().at("allowed") = usk::json::Value(false);
            refuses([&] { require_publisher_authenticated_object_access(invalid, client_facts, native_object); });
            invalid = compact;
            invalid.as_object().at("observed_group_sid") = usk::json::Value(
                compact.at("observed_group_sid").as_string() == "S-1-5-18" ? "S-1-5-32-545" : "S-1-5-18");
            refuses([&] { require_publisher_authenticated_object_access(invalid, client_facts, native_object); });
            refuses([&] { (void)channel->observe_authenticated_object_access(INVALID_HANDLE_VALUE); });
            refuses([&] { channel->receive(); });
            channel->reply("completed");
            refuses([&] { (void)observe_publisher_authenticated_descendant_access(
                writable.get(), file_tree, *channel, client_facts); });
            refuses([&] { (void)channel->observe_authenticated_object_access(directory.get()); });
            refuses([&] { channel->reply("duplicate"); });
            channel->wait_for_client_disconnect();
        } catch (...) { channel.reset(); client.join(); throw; }
        channel.reset();
        client.join();
        if(client_failure) std::rethrow_exception(client_failure);
        require(response=="completed","response bytes changed");
        HANDLE stop=CreateEventW(nullptr,TRUE,TRUE,nullptr);
        require(stop!=nullptr,"stop event unavailable");
        { PublisherRequestChannel stopped(name,service_sid,sid,stop,2000);
          refuses([&] { stopped.receive(); }); }
        CloseHandle(stop);
        { PublisherRequestChannel timed(name,service_sid,sid,nullptr,25);
          refuses([&] { timed.receive(); }); }
        { auto oversized=std::make_unique<PublisherRequestChannel>(name,service_sid,sid,nullptr,2000);
          auto large_client=raw_client(name,std::string(1024u*1024u+2u,'x'),response,client_failure);
          try { refuses([&] { oversized->receive(); }); }
          catch (...) { oversized.reset(); large_client.join(); throw; }
          // Closing the server releases a possibly blocked client writer.
          oversized.reset(); large_client.join(); }
        { PublisherRequestChannel denied(name,service_sid,L"S-1-5-21-1-2-3-500",nullptr,25);
          bool generic_denied = false;
          try { OwnedHandle unexpected(usk::platform::windows::connect_publisher_request_endpoint(name, 25)); }
          catch (const usk::base::EffectRequestNotDispatched&) {
              throw std::runtime_error("generic denied endpoint became typed admission");
          }
          catch (const std::runtime_error&) { generic_denied = true; }
          require(generic_denied, "generic denied endpoint control did not fail");
          HANDLE raw=CreateFileW(usk::platform::windows::publisher_request_pipe_name(name).c_str(),
              FILE_READ_DATA|FILE_WRITE_DATA,0,nullptr,OPEN_EXISTING,0,nullptr);
          if(raw!=INVALID_HANDLE_VALUE) CloseHandle(raw);
          require(raw==INVALID_HANDLE_VALUE && GetLastError()==ERROR_ACCESS_DENIED,
              "unadmitted user connected to endpoint"); }
        // No service named by this process exists: the client must reject an
        // impostor pipe before it sends the request, even when its name matches.
        { PublisherRequestChannel impostor(name,service_sid,sid,nullptr,25);
          refuses([&] { usk::platform::windows::submit_publisher_request(name,"{}",25); }); }
        refuses([&] { usk::platform::windows::publisher_request_pipe_name(L"bad\\remote"); });
        // A non-service process cannot use admission to mutate its process ACL.
        refuses([&] { usk::platform::windows::admit_current_publisher_client_observer(
            name, L"S-1-5-21-1-2-3-1001"); });
        std::cout << "publisher request authentication, bounds, cancellation and exclusive endpoint passed\n";
        return 0;
    } catch(const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
#endif
