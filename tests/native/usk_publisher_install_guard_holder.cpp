// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
// Private hosted fixture. It holds only a coordination mutex;
// the parent must bind the owned disposable target and actual child identity.
#include "usk_publisher_volume_operation_guard.h"
#include "usk_json.h"
#if defined(_WIN32)
#include <iostream>
#include <sddl.h>
#include <aclapi.h>
#include <vector>
namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE handle) : value(handle) {}
    ~Handle() { if (value) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    void close_checked() {
        require(!value || CloseHandle(value) != FALSE, "holder native handle close failed");
        value = nullptr;
    }
};
struct LocalAllocation {
    void* value = nullptr;
    ~LocalAllocation() { if (value) LocalFree(value); }
};
std::wstring registered_service_sid(const std::wstring& input) {
    require(input.rfind(L"S-1-5-80-", 0) == 0, "holder registered service SID differs");
    LocalAllocation parsed;
    require(ConvertStringSidToSidW(input.c_str(), &parsed.value) != FALSE && IsValidSid(parsed.value) != FALSE &&
        *GetSidSubAuthorityCount(parsed.value) == 6 && *GetSidSubAuthority(parsed.value, 0) == SECURITY_SERVICE_ID_BASE_RID,
        "holder service SID is not a native service identity");
    LocalAllocation canonical;
    require(ConvertSidToStringSidW(parsed.value, reinterpret_cast<LPWSTR*>(&canonical.value)) != FALSE &&
        input == static_cast<const wchar_t*>(canonical.value), "holder service SID is not canonical");
    return input;
}
bool environment(const wchar_t* name, const wchar_t* expected) {
    wchar_t value[64]{};
    const DWORD count = GetEnvironmentVariableW(name, value, 64);
    return count > 0 && count < 64 && std::wstring(value) == expected;
}
void require_hosted_system() {
    require(environment(L"GITHUB_ACTIONS", L"true") &&
        environment(L"RUNNER_ENVIRONMENT", L"github-hosted"), "holder requires hosted fixture context");
    HANDLE token = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != FALSE, "holder token unavailable");
    Handle held(token);
    DWORD size = 0;
    (void)GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    require(size > 0 && size <= 65536, "holder token user budget differs");
    std::vector<unsigned char> data(size);
    require(GetTokenInformation(token, TokenUser, data.data(), size, &size) != FALSE, "holder user unavailable");
    unsigned char expected[SECURITY_MAX_SID_SIZE]{};
    DWORD expected_size = SECURITY_MAX_SID_SIZE;
    require(CreateWellKnownSid(WinLocalSystemSid, nullptr, expected, &expected_size) != FALSE &&
        EqualSid(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid, expected) != FALSE,
        "holder identity is not SYSTEM");
}
void require_event_pair(const std::wstring& ready, const std::wstring& release) {
    const std::wstring prefix = L"Global\\USK_INSTALL_GUARD_";
    require(ready.size() == prefix.size() + 32 + 6 && ready.compare(0, prefix.size(), prefix) == 0 &&
        ready.substr(prefix.size() + 32) == L"_ready", "holder ready event differs");
    for (std::size_t n = prefix.size(); n < prefix.size() + 32; ++n)
        require((ready[n] >= L'0' && ready[n] <= L'9') || (ready[n] >= L'a' && ready[n] <= L'f'),
            "holder event nonce differs");
    require(release == ready.substr(0, prefix.size() + 32) + L"_release", "holder release event differs");
}
std::string ascii_install_id(const std::wstring& input) {
    require(!input.empty() && input.size() <= 128, "holder install identity budget differs");
    std::string result;
    for (wchar_t c : input) {
        require(c > 0 && c < 128, "holder install identity is not fixture ASCII");
        result.push_back(static_cast<char>(c));
    }
    return result;
}
std::uint64_t creation_time() {
    FILETIME created{}, exited{}, kernel{}, user{};
    require(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user) != FALSE,
        "holder birth unavailable");
    return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32u) | created.dwLowDateTime;
}
usk::json::Value coordination_security(HANDLE mutex, const std::wstring& service_sid) {
    using usk::json::Value;
    LocalAllocation descriptor;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    require(GetSecurityInfo(mutex, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.value)) == ERROR_SUCCESS &&
        owner && dacl && IsValidAcl(dacl) != FALSE && dacl->AceCount == 2,
        "holder coordination native security unavailable");
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    require(GetSecurityDescriptorControl(descriptor.value, &control, &revision) != FALSE &&
        (control & SE_DACL_PROTECTED) != 0, "holder coordination DACL is not protected");
    LocalAllocation owner_text;
    require(ConvertSidToStringSidW(owner, reinterpret_cast<LPWSTR*>(&owner_text.value)) != FALSE &&
        std::wstring(static_cast<const wchar_t*>(owner_text.value)) == L"S-1-5-18",
        "holder coordination owner differs");
    Value::Array aces;
    for (DWORD index = 0; index < 2; ++index) {
        void* raw = nullptr;
        require(GetAce(dacl, index, &raw) != FALSE, "holder coordination ACE unavailable");
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        require(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Header.AceFlags == 0 &&
            ace->Mask == MUTEX_ALL_ACCESS, "holder coordination ACE form or rights differ");
        const auto sid = const_cast<DWORD*>(&ace->SidStart);
        LocalAllocation text;
        require(IsValidSid(sid) != FALSE &&
            ConvertSidToStringSidW(sid, reinterpret_cast<LPWSTR*>(&text.value)) != FALSE,
            "holder coordination ACE SID unavailable");
        const std::wstring observed(static_cast<const wchar_t*>(text.value));
        require(observed == (index == 0 ? L"S-1-5-18" : service_sid), "holder coordination grantee differs");
        aces.emplace_back(Value::Object{{"sid", Value(ascii_install_id(observed))},
            {"mask", Value(static_cast<std::uint64_t>(ace->Mask))},
            {"type", Value(static_cast<std::uint64_t>(ace->Header.AceType))},
            {"flags", Value(static_cast<std::uint64_t>(ace->Header.AceFlags))}});
    }
    return Value(Value::Object{{"schema", Value("usk.publisher_install_guard_security.v1")},
        {"owner", Value("S-1-5-18")}, {"dacl_protected", Value(true)}, {"aces", Value(std::move(aces))}});
}
}
int wmain(int argc, wchar_t** argv) {
    using usk::json::Value;
    using namespace usk::platform::windows;
    try {
        require(argc == 6, "holder arguments differ");
        require_hosted_system();
        const std::wstring volume(argv[1]), ready_name(argv[3]), release_name(argv[4]);
        const auto install_id = ascii_install_id(argv[2]);
        const auto service_sid = registered_service_sid(argv[5]);
        require_event_pair(ready_name, release_name);
        Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, ready_name.c_str()));
        Handle release(OpenEventW(SYNCHRONIZE, FALSE, release_name.c_str()));
        require(ready.value && release.value, "owned holder events unavailable");
        // Create only the exact disposable installation coordination object.
        // Its restricted service must pass both token access checks. Refuse an
        // existing object rather than changing a pre-existing descriptor.
        LocalAllocation descriptor;
        const std::wstring sddl = L"O:SYG:SYD:P(A;;0x001f0001;;;SY)(A;;0x001f0001;;;" + service_sid + L")";
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
            &descriptor.value, nullptr) != FALSE, "holder coordination descriptor unavailable");
        SECURITY_ATTRIBUTES attributes{static_cast<DWORD>(sizeof(SECURITY_ATTRIBUTES)), descriptor.value, FALSE};
        const auto name = publisher_install_operation_guard_name(volume, install_id);
        SetLastError(ERROR_SUCCESS);
        Handle coordination(CreateMutexW(&attributes, FALSE, name.c_str()));
        require(coordination.value && GetLastError() != ERROR_ALREADY_EXISTS,
            "holder coordination object is missing or pre-existing");
        const auto security = coordination_security(coordination.value, service_sid);
        {
            PublisherInstallOperationGuard guard(volume, install_id);
            guard.require_owned(volume, install_id);
            require(!guard.previous_owner_abandoned(), "holder found an abandoned fixture guard");
            const Value observed(Value::Object{
                {"schema", Value("usk.publisher_install_guard_holder.v1")},
                {"scope", Value("owned_installation_mutex_only_no_product_effects")},
                {"process_id", Value(static_cast<std::uint64_t>(GetCurrentProcessId()))},
                {"creation_file_time", Value(std::to_string(creation_time()))},
                {"identity", Value("S-1-5-18")},
                {"install_id", Value(install_id)},
                {"service_sid", Value(ascii_install_id(service_sid))},
                {"coordination_acl_scope", Value("system_and_registered_service_sid_only")},
                {"coordination_security", security},
                {"operation_inspection_ref", Value(publisher_install_operation_inspection_reference(volume, install_id))},
                {"publication_authority_granted", Value(false)}});
            std::cout << usk::json::canonical(observed) << '\n' << std::flush;
            require(std::cout.good(), "holder readiness output failed");
            require(SetEvent(ready.value) != FALSE, "holder readiness signal failed");
            require(WaitForSingleObject(release.value, 180000) == WAIT_OBJECT_0, "holder release deadline expired");
            guard.require_owned(volume, install_id);
            require(usk::json::canonical(coordination_security(coordination.value, service_sid)) ==
                usk::json::canonical(security), "holder coordination security changed before release");
        }
        ready.close_checked();
        release.close_checked();
        coordination.close_checked();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
#endif
