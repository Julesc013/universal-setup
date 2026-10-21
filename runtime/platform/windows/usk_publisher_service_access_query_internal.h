// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_SERVICE_ACCESS_QUERY_INTERNAL_H
#define USK_PUBLISHER_SERVICE_ACCESS_QUERY_INTERNAL_H
#if defined(_WIN32)
#include "usk_publisher_service_access.h"
#include <vector>
namespace usk::platform::windows::detail::service_access_query {
using usk::json::Value;
constexpr std::uint64_t query_rights = READ_CONTROL | SERVICE_QUERY_CONFIG |
    SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_INTERROGATE |
    SERVICE_USER_DEFINED_CONTROL;
constexpr DWORD client_rights = READ_CONTROL | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START;
struct LocalAllocation {
    HLOCAL value = nullptr;
    ~LocalAllocation() { if (value) LocalFree(value); }
};

void require(bool okay, const char* message);
std::string sid_text(PSID sid);
bool canonical_sid(const std::string& text);
bool privileged(const std::string& sid);
std::vector<unsigned char> descriptor(SC_HANDLE service);
Value decode(std::vector<unsigned char>& bytes, const std::string& client);
}
#endif
#endif
