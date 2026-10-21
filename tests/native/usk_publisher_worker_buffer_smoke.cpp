// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_worker_security.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sddl.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using usk::json::Value;
namespace native = usk::platform::windows::detail;

void require(bool okay, const char* reason) { if (!okay) throw std::runtime_error(reason); }
struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value) CloseHandle(value); }
    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
std::string sid_text(PSID sid) {
    LPSTR text = nullptr;
    require(IsValidSid(sid) && ConvertSidToStringSidA(sid, &text), "fixture SID unavailable");
    const std::string result(text);
    LocalFree(text);
    return result;
}
std::vector<unsigned char> reference_token(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    DWORD bytes = 0;
    require(!GetTokenInformation(token, kind, nullptr, 0, &bytes) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER && bytes && bytes <= 1024u * 1024u,
        "reference token size unavailable");
    std::vector<unsigned char> result(bytes);
    require(GetTokenInformation(token, kind, result.data(), bytes, &bytes) && bytes <= result.size(),
        "reference token unavailable");
    result.resize(bytes);
    return result;
}
std::size_t remaining(const std::vector<unsigned char>& bytes, const void* pointer, std::size_t minimum) {
    const auto base = reinterpret_cast<std::uintptr_t>(bytes.data());
    const auto at = reinterpret_cast<std::uintptr_t>(pointer);
    require(pointer && at >= base && at - base <= bytes.size() && minimum <= bytes.size() - (at - base),
        "returned native pointer left its owned buffer");
    return bytes.size() - (at - base);
}
std::vector<unsigned char> make_acl(PSID user, DWORD count) {
    std::vector<unsigned char> bytes(8192u);
    auto* acl = reinterpret_cast<PACL>(bytes.data());
    require(InitializeAcl(acl, static_cast<DWORD>(bytes.size()), ACL_REVISION), "fixture ACL unavailable");
    for (DWORD index = 0; index != count; ++index)
        require(AddAccessAllowedAce(acl, ACL_REVISION, EVENT_ALL_ACCESS, user), "fixture ACE unavailable");
    ACL_SIZE_INFORMATION size{};
    require(GetAclInformation(acl, &size, sizeof(size), AclSizeInformation) &&
        size.AclBytesInUse <= bytes.size(), "fixture ACL size unavailable");
    acl->AclSize = static_cast<WORD>(size.AclBytesInUse);
    bytes.resize(size.AclBytesInUse);
    require(IsValidAcl(reinterpret_cast<PACL>(bytes.data())), "fixture ACL invalid");
    return bytes;
}
void verify_token_default(HANDLE token, const std::vector<unsigned char>& acl, bool large) {
    TOKEN_DEFAULT_DACL update{reinterpret_cast<PACL>(const_cast<unsigned char*>(acl.data()))};
    require(SetTokenInformation(token, TokenDefaultDacl, &update, sizeof(update)), "fixture token DACL not set");
    const auto actual = native::observe_publisher_worker_token_bytes_for_test(token, TokenDefaultDacl);
    const auto expected = reference_token(token, TokenDefaultDacl);
    require(actual.size() >= sizeof(TOKEN_DEFAULT_DACL) && expected.size() >= sizeof(TOKEN_DEFAULT_DACL),
        "returned token default DACL truncated");
    const auto a = reinterpret_cast<const TOKEN_DEFAULT_DACL*>(actual.data())->DefaultDacl;
    const auto b = reinterpret_cast<const TOKEN_DEFAULT_DACL*>(expected.data())->DefaultDacl;
    require(remaining(actual, a, sizeof(ACL)) >= a->AclSize &&
        remaining(expected, b, sizeof(ACL)) >= b->AclSize && IsValidAcl(a) && IsValidAcl(b),
        "token DACL exceeds returned storage");
    require(a->AclSize == b->AclSize && a->AclSize == acl.size() &&
        std::memcmp(a, b, a->AclSize) == 0 && std::memcmp(a, acl.data(), acl.size()) == 0,
        "fresh token DACL differs from the independent native query");
    require((actual.size() > 1024u) == large, "token fixture did not exercise the intended buffer size");
}
void verify_object(HANDLE event, const std::vector<unsigned char>& acl, bool large) {
    SECURITY_DESCRIPTOR update{};
    require(InitializeSecurityDescriptor(&update, SECURITY_DESCRIPTOR_REVISION) &&
        SetSecurityDescriptorDacl(&update, TRUE, reinterpret_cast<PACL>(const_cast<unsigned char*>(acl.data())), FALSE),
        "fixture object descriptor unavailable");
    if (!SetKernelObjectSecurity(event, DACL_SECURITY_INFORMATION, &update))
        throw std::runtime_error("fixture object DACL not set; Win32 " + std::to_string(GetLastError()));
    const auto actual = native::observe_publisher_worker_object_security_for_test(event);
    constexpr SECURITY_INFORMATION requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    DWORD needed = 0;
    require(!GetKernelObjectSecurity(event, requested, nullptr, 0, &needed) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed <= 1024u * 1024u,
        "reference object size unavailable");
    std::vector<unsigned char> bytes(needed);
    require(GetKernelObjectSecurity(event, requested, bytes.data(), needed, &needed) &&
        needed <= bytes.size() && IsValidSecurityDescriptor(bytes.data()), "reference object unavailable");
    PSID owner = nullptr; PACL dacl = nullptr;
    BOOL defaulted = FALSE, present = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
    require(GetSecurityDescriptorOwner(bytes.data(), &owner, &defaulted) &&
        GetSecurityDescriptorDacl(bytes.data(), &present, &dacl, &defaulted) && present && dacl &&
        GetSecurityDescriptorControl(bytes.data(), &control, &revision), "reference object fields unavailable");
    require(actual.as_object().size() == 4u && actual.at("owner_sid").as_string() == sid_text(owner) &&
        actual.at("dacl_present").as_boolean() &&
        actual.at("dacl_protected").as_boolean() == ((control & SE_DACL_PROTECTED) != 0),
        "fresh object security differs from native descriptor");
    const auto& aces = actual.at("dacl_aces").as_array();
    require(aces.size() == dacl->AceCount, "fresh object ACE count differs");
    for (DWORD index = 0; index != dacl->AceCount; ++index) {
        void* raw = nullptr; require(GetAce(dacl, index, &raw) && raw, "reference ACE unavailable");
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        require(aces[index].as_object().size() == 4u &&
            aces[index].at("type").as_unsigned() == ace->Header.AceType &&
            aces[index].at("flags").as_unsigned() == ace->Header.AceFlags &&
            aces[index].at("access_mask").as_unsigned() == ace->Mask &&
            aces[index].at("sid").as_string() == sid_text(const_cast<DWORD*>(&ace->SidStart)),
            "fresh object ordered ACE differs");
    }
    require((needed > 1024u) == large, "object fixture did not exercise the intended buffer size");
}
struct WaitingThread {
    Handle ready{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Handle release{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Handle thread;
    DWORD id = 0;
    static DWORD WINAPI run(void* value) {
        auto& self = *static_cast<WaitingThread*>(value);
        if (!SetEvent(self.ready.value)) return 1;
        return WaitForSingleObject(self.release.value, INFINITE) == WAIT_OBJECT_0 ? 0u : 1u;
    }
    WaitingThread() {
        require(ready.value && release.value, "thread fixture events unavailable");
        thread.value = CreateThread(nullptr, 0, run, this, 0, &id);
        require(thread.value && id, "thread fixture unavailable");
        if (WaitForSingleObject(ready.value, 5000) != WAIT_OBJECT_0) {
            SetEvent(release.value); WaitForSingleObject(thread.value, INFINITE);
            throw std::runtime_error("thread fixture did not start");
        }
    }
    ~WaitingThread() {
        if (thread.value) { SetEvent(release.value); WaitForSingleObject(thread.value, INFINITE); }
    }
    void finish() {
        require(SetEvent(release.value) && WaitForSingleObject(thread.value, 5000) == WAIT_OBJECT_0,
            "thread fixture did not finish");
    }
};
template<class Read> void refuses(Read read) {
    try { read(); } catch (const std::exception&) { return; }
    throw std::runtime_error("invalid native handle was accepted");
}
} // namespace

int main() {
    try {
        Handle original, token;
        require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &original.value),
            "fixture process token unavailable");
        require(DuplicateTokenEx(original.value, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, nullptr,
            SecurityImpersonation, TokenPrimary, &token.value), "fixture private token unavailable");
        const auto user = native::observe_publisher_worker_token_bytes_for_test(token.value, TokenUser);
        require(user.size() >= sizeof(TOKEN_USER), "fixture token user truncated");
        auto* sid = reinterpret_cast<const TOKEN_USER*>(user.data())->User.Sid;
        require(remaining(user, sid, 8u) >= GetLengthSid(sid) && IsValidSid(sid), "token user pointer invalid");
        const auto compact_acl = make_acl(sid, 1), expanded_acl = make_acl(sid, 64);
        const auto event_name = L"Local\\USK_Worker_Buffer_" + std::to_wstring(GetCurrentProcessId()) +
            L"_" + std::to_wstring(GetTickCount64());
        Handle event(CreateEventW(nullptr, FALSE, FALSE, event_name.c_str()));
        const auto create_error = GetLastError();
        require(event.value && create_error != ERROR_ALREADY_EXISTS, "new fixture object unavailable");
        verify_token_default(token.value, compact_acl, false);
        verify_token_default(token.value, expanded_acl, true);
        verify_token_default(token.value, compact_acl, false);
        verify_object(event.value, compact_acl, false);
        verify_object(event.value, expanded_acl, true);
        verify_object(event.value, compact_acl, false);
        const auto warm = native::observe_publisher_system_thread_census_for_test();
        require(std::find(warm.begin(), warm.end(), GetCurrentThreadId()) != warm.end(), "census omitted caller");
        WaitingThread fixture;
        const auto during = native::observe_publisher_system_thread_census_for_test();
        require(std::find(during.begin(), during.end(), fixture.id) != during.end(), "warm census omitted new thread");
        fixture.finish(); // Keep its handle to prevent TID reuse during the final fresh census.
        const auto after = native::observe_publisher_system_thread_census_for_test();
        require(std::find(after.begin(), after.end(), fixture.id) == after.end(), "warm census retained ended thread");
        refuses([] { (void)native::observe_publisher_worker_token_bytes_for_test(nullptr, TokenUser); });
        refuses([] { (void)native::observe_publisher_worker_object_security_for_test(nullptr); });
        std::cout << "worker native buffer controls pass\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
