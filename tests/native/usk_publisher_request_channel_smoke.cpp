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
    std::string& response, std::exception_ptr& failure) {
    return std::thread([&,name,message] {
        try {
            const auto pipe_name=usk::platform::windows::publisher_request_pipe_name(name);
            HANDLE pipe=CreateFileW(pipe_name.c_str(), FILE_READ_DATA|FILE_WRITE_DATA|
                FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE,
                0,nullptr,OPEN_EXISTING,SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
            require(pipe!=INVALID_HANDLE_VALUE,"raw client connection denied");
            DWORD mode=PIPE_READMODE_MESSAGE, transferred=0;
            const bool configured=SetNamedPipeHandleState(pipe,&mode,nullptr,nullptr)!=FALSE;
            const bool written=configured && WriteFile(pipe,message.data(),static_cast<DWORD>(message.size()),&transferred,nullptr)!=FALSE;
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
        const auto name=L"USK_transport_test_"+std::to_wstring(GetCurrentProcessId());
        const auto sid=current_sid();
        const std::wstring service_sid=L"S-1-5-80-1-2-3-4-5";
        std::string response;
        std::exception_ptr client_failure;
        auto channel=std::make_unique<PublisherRequestChannel>(name,service_sid,sid,nullptr,2000);
        refuses([&] { PublisherRequestChannel duplicate(name,service_sid,sid,nullptr); });
        auto client=raw_client(name,"{\"reviewed\":true}",response,client_failure);
        try {
            require(channel->receive()=="{\"reviewed\":true}","request bytes changed");
            HANDLE token=nullptr;
            require(!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&token) &&
                GetLastError()==ERROR_NO_TOKEN,"caller impersonation retained");
            refuses([&] { channel->receive(); });
            channel->reply("completed");
            refuses([&] { channel->reply("duplicate"); });
        } catch (...) { channel.reset(); client.join(); throw; }
        client.join();
        if(client_failure) std::rethrow_exception(client_failure);
        require(response=="completed","response bytes changed");
        channel.reset();
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
