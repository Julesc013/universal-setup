// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_request_channel.h"
#if defined(_WIN32)
#include <sddl.h>
#include <atomic>
#include <exception>
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
    const std::string apply_request = R"({"schema":"usk.install_local_apply_request.v1","transaction_id":"tx.apply","plan_request":{"install_id":"install.one"}})";
    const std::string apply_response = R"({"schema":"usk.publisher_lab_service_observation.v1","status":"pass","service_name":"USK_PUB_0123456789abcdef0123456789abcdef","apply_response":{"schema":"usk.command_response.v1","status":"ok","payload":{"schema":"usk.installed_state.v1","lifecycle_status":"installed","install_id":"install.one","transaction_id":"tx.apply"}}})";
    require_publisher_response_binding(service, apply_request, apply_response);
    refuses([&] { require_publisher_response_binding(service, apply_request,
        replaced(apply_response, "\"transaction_id\":\"tx.apply\"", "\"transaction_id\":\"other\"")); });
    refuses([&] { require_publisher_response_binding(service, apply_request,
        replaced(apply_response, "\"install_id\":\"install.one\"", "\"install_id\":\"other\"")); });
    refuses([&] { require_publisher_response_binding(service, apply_request,
        replaced(apply_response, "\"service_name\":\"USK_PUB_0123456789abcdef0123456789abcdef\"",
            "\"service_name\":\"USK_PUB_ffffffffffffffffffffffffffffffff\"")); });
    refuses([&] { require_publisher_response_binding(service, apply_request,
        replaced(apply_response, "\"apply_response\":{", "\"apply_response\":null,\"unused\":{") ); });

    const std::string recovery_request = R"({"schema":"usk.publisher_recovery_request.v1","install_id":"install.one","transaction_id":"tx.apply"})";
    const std::string recovery_response = replaced(apply_response,
        "\"apply_response\"", "\"recovery_installed_response\"");
    require_publisher_response_binding(service, recovery_request, recovery_response);
    refuses([&] { require_publisher_response_binding(service, recovery_request,
        replaced(recovery_response, "\"transaction_id\":\"tx.apply\"", "\"transaction_id\":\"stale\"")); });

    const std::string verify_request = R"({"schema":"usk.publisher_installed_verify_request.v1","install_id":"install.one","transaction_id":"tx.apply","report_id":"report.one"})";
    const std::string verify_response = R"({"schema":"usk.publisher_lab_service_observation.v1","status":"pass","transaction_id":"tx.apply","bound_report_digest":"digest.one","verify_response":{"schema":"usk.command_response.v1","status":"ok","payload":{"schema":"usk.verification_report.v1","status":"pass","install_id":"install.one","report_id":"report.one","report_digest":"digest.one"}}})";
    require_publisher_response_binding(service, verify_request, verify_response);
    refuses([&] { require_publisher_response_binding(service, verify_request,
        replaced(verify_response, "\"report_id\":\"report.one\"", "\"report_id\":\"other\"")); });
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
int main() {
    try {
        test_terminal_response_binding();
        const auto name=L"USK_transport_test_"+std::to_wstring(GetCurrentProcessId());
        const auto sid=current_sid();
        const std::wstring service_sid=L"S-1-5-80-1-2-3-4-5";
        std::string response;
        std::exception_ptr client_failure;
        auto channel=std::make_unique<PublisherRequestChannel>(name,service_sid,sid,nullptr,2000);
        refuses([&] { PublisherRequestChannel duplicate(name,service_sid,sid,nullptr); });
        auto client=raw_client(name,"{\"reviewed\":true}",response,client_failure,true);
        try {
            require(channel->receive()=="{\"reviewed\":true}","request bytes changed");
            HANDLE token=nullptr;
            require(!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&token) &&
                GetLastError()==ERROR_NO_TOKEN,"caller impersonation retained");
            refuses([&] { channel->receive(); });
            channel->reply("completed");
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
