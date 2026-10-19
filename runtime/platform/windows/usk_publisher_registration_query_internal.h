// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_REGISTRATION_QUERY_INTERNAL_H
#define USK_PUBLISHER_REGISTRATION_QUERY_INTERNAL_H
#if defined(_WIN32)
#include "usk_publisher_request_channel.h"
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <vector>
namespace usk::platform::windows::detail::registration_query {
class ServiceHandle {
public:
    explicit ServiceHandle(SC_HANDLE value) : value_(value) {}
    ~ServiceHandle() { if (value_) CloseServiceHandle(value_); }
    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;
    SC_HANDLE get() const noexcept { return value_; }
    SC_HANDLE release() noexcept { const auto value = value_; value_ = nullptr; return value; }
private:
    SC_HANDLE value_;
};

struct ServiceConfiguration {
    std::wstring binary_path;
    std::wstring account;
    std::wstring display_name;
    DWORD type = 0;
    DWORD start = 0;
    DWORD sid_type = 0;
};


// Per-request observations only. These data and handles confer no registration,
// controller, raw-volume or effect authority and are not reusable admission.
struct RegisteredClientRequest {
    std::string schema;
    std::string inspection_id;
    bool service_observation = false;
    std::uint64_t windows_build = 0;
};
std::uint64_t observe_supported_discovery_windows_build();
bool generated_name(const std::wstring& name);
bool lower_sha256(const std::wstring& value);
void require_canonical_sid(const std::wstring& value);
void require_current_caller_sid(const std::wstring& expected);
std::filesystem::path publisher_binary_path(const std::wstring& name);
void require_volume(const std::wstring& value);
std::wstring command_prefix(const std::wstring& service, const std::wstring& binary, const std::wstring& volume);
std::wstring command_suffix(const std::wstring& caller, const std::wstring& mode);
std::vector<std::wstring> command_arguments(const std::wstring& command);
bool same_configuration(const ServiceConfiguration& first, const ServiceConfiguration& second);
ServiceConfiguration query_configuration(SC_HANDLE service);
void require_profile(const ServiceConfiguration& config);
void require_existing_command(const std::wstring& command, const std::wstring& service,
    const std::wstring& binary, const std::wstring& volume, const std::wstring& caller, const std::wstring& mode);
std::string utf8(const std::wstring& value);
RegisteredClientRequest parse_registered_client_request(const std::wstring& name,
    const std::string& request, const PublisherRequestOptions& options);
void admit_service_client(SC_HANDLE service, const std::wstring& name,
    const ServiceConfiguration& before, const std::vector<std::wstring>& args,
    const std::wstring& caller, bool private_discovery);
}
#endif
#endif
