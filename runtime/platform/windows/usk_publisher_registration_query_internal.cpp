// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_registration_query_internal.h"
#if defined(_WIN32)
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_service_access.h"
#include "usk_publisher_volume_operation_guard.h"
#include "usk_effect_dispatch.h"
#include <sddl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <cstring>
#include <memory>
namespace usk::platform::windows {
namespace {
class QueryTokenHandle final {
public:
    explicit QueryTokenHandle(HANDLE value) : value_(value) {}
    ~QueryTokenHandle() { if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    QueryTokenHandle(const QueryTokenHandle&) = delete;
    QueryTokenHandle& operator=(const QueryTokenHandle&) = delete;
    HANDLE get() const noexcept { return value_; }
private:
    HANDLE value_;
};

struct LocalFreeDeleter {
    void operator()(void* pointer) const { if (pointer) LocalFree(pointer); }
};
struct CoTaskMemDeleter {
    void operator()(void* pointer) const { if (pointer) CoTaskMemFree(pointer); }
};

}
static void require_account_sid(const std::string& sid, DWORD minimum_rid) {
    PSID raw = nullptr;
    if (sid.empty() || !ConvertStringSidToSidA(sid.c_str(), &raw)) {
        throw std::runtime_error("publisher consumer SID is malformed");
    }
    std::unique_ptr<void, LocalFreeDeleter> owned(raw);
    const SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (!IsValidSid(raw) || *GetSidSubAuthorityCount(raw) != 5 ||
        *GetSidSubAuthority(raw, 0) != SECURITY_NT_NON_UNIQUE ||
        *GetSidSubAuthority(raw, 4) < minimum_rid ||
        std::memcmp(GetSidIdentifierAuthority(raw), &nt, sizeof(nt)) != 0) {
        throw std::runtime_error("publisher account SID differs from its required account class");
    }
    LPSTR canonical = nullptr;
    if (!ConvertSidToStringSidA(raw, &canonical)) {
        throw std::runtime_error("publisher consumer SID cannot be rendered");
    }
    std::unique_ptr<void, LocalFreeDeleter> canonical_owned(canonical);
    if (sid != canonical) throw std::runtime_error("publisher consumer SID is not canonical");
}

void require_publisher_registered_account_sid(const std::string& sid) {
    require_account_sid(sid, 0);
}

void require_publisher_consumer_sid(const std::string& sid) {
    require_account_sid(sid, 1000);
}

std::wstring publisher_volume_operation_guard_name(const std::wstring& root)
{
    const std::wstring prefix = L"\\\\?\\Volume{";
    if (root.size() != prefix.size() + 38u || root.rfind(prefix, 0) != 0 ||
        root[root.size() - 2u] != L'}' || root.back() != L'\\') {
        throw std::invalid_argument("publisher volume guard requires an exact volume GUID root");
    }
    std::wstring guid = root.substr(prefix.size(), 36u);
    for (std::size_t index = 0; index < guid.size(); ++index) {
        const bool hyphen = index == 8u || index == 13u || index == 18u || index == 23u;
        const wchar_t ch = guid[index];
        if (hyphen ? ch != L'-' :
            !((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ||
                (ch >= L'A' && ch <= L'F'))) {
            throw std::invalid_argument("publisher volume guard GUID is malformed");
        }
        if (ch >= L'A' && ch <= L'F') guid[index] = ch - L'A' + L'a';
    }
    return L"Global\\USK.Publisher.Volume." + guid;
}

usk::json::Value parse_publisher_maintenance_recovery_request(const std::string& bytes) {
    usk::json::ParseLimits limits;
    limits.max_bytes = 2048;
    limits.max_string_bytes = 256;
    const auto request = usk::json::parse(bytes, limits);
    const auto& operation = request.at("operation").as_string();
    if (request.as_object().size() != 4 ||
        request.at("schema").as_string() != "usk.publisher_maintenance_recovery_request.v1" ||
        (operation != "repair" && operation != "move" && operation != "uninstall"))
        throw std::runtime_error("maintenance recovery requires a closed original operation selector");
    for (const auto field : {"install_id", "transaction_id"}) {
        const auto& id = request.at(field).as_string();
        if (id.empty() || id.size() > 128 || id.find_first_not_of(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != std::string::npos)
            throw std::runtime_error("maintenance recovery original identity differs");
    }
    return request;
}


namespace detail::registration_query {
std::uint64_t observe_supported_discovery_windows_build() {
#if !defined(_M_X64) && !defined(__x86_64__)
    throw std::runtime_error("publisher discovery requires the x64 implementation");
#else
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    if (sizeof(void*) != 8 || system.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64)
        throw std::runtime_error("publisher discovery requires native x64 Windows");
    // Query the already-loaded OS module; no module-search or manifest-based
    // version fallback. Documented OSVERSIONINFOW/RtlGetVersion observation:
    // https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlgetversion
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto address = module ? GetProcAddress(module, "RtlGetVersion") : nullptr;
    using Query = LONG (WINAPI*)(OSVERSIONINFOW*);
    Query query = nullptr;
    static_assert(sizeof(query) == sizeof(address));
    std::memcpy(&query, &address, sizeof(query));
    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    if (!query || query(&version) != 0 || version.dwPlatformId != VER_PLATFORM_WIN32_NT ||
        version.dwMajorVersion != 10 || version.dwMinorVersion != 0 || version.dwBuildNumber < 17763)
        throw std::runtime_error("publisher discovery Windows build is unavailable or unsupported");
    return version.dwBuildNumber;
#endif
}

bool generated_name(const std::wstring& name) {
    constexpr wchar_t prefix[] = L"USK_PUB_";
    if (name.size() != 40 || name.compare(0, 8, prefix) != 0) return false;
    for (std::size_t index = 8; index < name.size(); ++index) {
        const wchar_t ch = name[index];
        if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) return false;
    }
    return true;
}

bool lower_sha256(const std::wstring& value) {
    if (value.size() != 64) return false;
    for (const wchar_t ch : value) {
        if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) return false;
    }
    return true;
}

void require_canonical_sid(const std::wstring& value) {
    PSID parsed = nullptr;
    if (!ConvertStringSidToSidW(value.c_str(), &parsed))
        throw std::runtime_error("caller SID is invalid");
    LPWSTR canonical = nullptr;
    const bool okay = ConvertSidToStringSidW(parsed, &canonical) &&
        value == canonical;
    if (canonical) LocalFree(canonical);
    LocalFree(parsed);
    if (!okay) throw std::runtime_error("caller SID is not canonical");
}

void require_current_caller_sid(const std::wstring& expected) {
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
        throw std::runtime_error("current caller token unavailable");
    }
    QueryTokenHandle token(raw_token);
    DWORD needed = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &needed);
    if (!needed || needed > 64u * 1024u) {
        throw std::runtime_error("current caller identity size is invalid");
    }
    std::vector<BYTE> bytes(needed);
    if (!GetTokenInformation(token.get(), TokenUser, bytes.data(), needed, &needed)) {
        throw std::runtime_error("current caller identity unavailable");
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(bytes.data());
    LPWSTR rendered = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &rendered) || !rendered) {
        throw std::runtime_error("current caller SID unavailable");
    }
    const bool matching = expected == rendered;
    LocalFree(rendered);
    if (!matching) {
        throw std::runtime_error("reviewed apply caller differs from this process identity");
    }
}

std::filesystem::path publisher_binary_path(const std::wstring& name) {
    PWSTR raw = nullptr;
    const auto status = SHGetKnownFolderPath(FOLDERID_ProgramFilesX64, 0, nullptr, &raw);
    std::unique_ptr<void, CoTaskMemDeleter> owned(raw);
    if (FAILED(status) || !raw) {
        owned.reset();
        throw std::runtime_error("protected Program Files location unavailable");
    }
    const std::filesystem::path root(raw);
    owned.reset();
    return root / L"Universal Setup" / L"Publisher" / (name + L".exe");
}

void require_volume(const std::wstring& value) {
    (void)usk::platform::windows::publisher_volume_operation_guard_name(value);
}

std::wstring command_prefix(const std::wstring& service,
    const std::wstring& binary, const std::wstring& volume) {
    return L"\"" + binary + L"\" --service " + service +
        L" --no-receipt " + volume;
}

std::wstring command_suffix(const std::wstring& caller, const std::wstring& mode) {
    if (mode == L"--grant-client-read") {
        return L" --authorized-client-sid " + caller + L" --grant-client-read";
    }
    return (mode.empty() ? L"" : L" " + mode) +
        std::wstring(L" --authorized-client-sid ") + caller;
}

std::vector<std::wstring> command_arguments(const std::wstring& command) {
    int count = 0;
    LPWSTR* raw = CommandLineToArgvW(command.c_str(), &count);
    std::unique_ptr<void, LocalFreeDeleter> owned(raw);
    if (!raw || count < 0 || count > 16) {
        owned.reset();
        throw std::runtime_error("registered service command is malformed");
    }
    std::vector<std::wstring> result;
    for (int index = 0; index < count; ++index) result.emplace_back(raw[index]);
    owned.reset();
    return result;
}

bool same_configuration(const ServiceConfiguration& first, const ServiceConfiguration& second) {
    return first.binary_path == second.binary_path && first.account == second.account &&
        first.display_name == second.display_name && first.type == second.type &&
        first.start == second.start && first.sid_type == second.sid_type;
}

ServiceConfiguration query_configuration(SC_HANDLE service) {
    DWORD needed = 0;
    (void)QueryServiceConfigW(service, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > 16384)
        throw std::runtime_error("service configuration size is unavailable");
    std::vector<BYTE> bytes(needed);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(bytes.data());
    if (!QueryServiceConfigW(service, config, needed, &needed) ||
        !config->lpBinaryPathName || !config->lpServiceStartName || !config->lpDisplayName)
        throw std::runtime_error("service configuration is unavailable");
    SERVICE_SID_INFO sid{};
    if (!QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO,
            reinterpret_cast<BYTE*>(&sid), sizeof(sid), &needed))
        throw std::runtime_error("service SID configuration is unavailable");
    return {config->lpBinaryPathName, config->lpServiceStartName, config->lpDisplayName,
        config->dwServiceType, config->dwStartType, sid.dwServiceSidType};
}

void require_profile(const ServiceConfiguration& config) {
    if (config.type != SERVICE_WIN32_OWN_PROCESS ||
        config.start != SERVICE_DEMAND_START ||
        CompareStringOrdinal(config.account.c_str(), -1,
            L"LocalSystem", -1, TRUE) != CSTR_EQUAL ||
        config.sid_type != SERVICE_SID_TYPE_RESTRICTED) {
        throw std::runtime_error("service is not the restricted own-process profile");
    }
}

void require_existing_command(const std::wstring& command,
    const std::wstring& service, const std::wstring& binary,
    const std::wstring& volume, const std::wstring& caller,
    const std::wstring& mode) {
    const auto args = command_arguments(command);
    if (args.size() < 8 || args[0] != binary || args[1] != L"--service" ||
        args[2] != service || args[3] != L"--no-receipt" || args[4] != volume) {
        throw std::runtime_error("existing service identity or volume differs");
    }
    std::size_t index = 5;
    if (args[index] == L"--reviewed-plan-envelope") {
        if (args.size() < index + 5 || !lower_sha256(args[index + 2]))
            throw std::runtime_error("existing reviewed source binding is malformed");
        index += 3;
    } else if (args[index] == L"--recover-reviewed") {
        ++index;
    } else if (args[index] == L"--verify-installed") {
        ++index;
    } else {
        throw std::runtime_error("existing service mode differs");
    }
    if (mode == L"--admit-client-observer" || mode == L"--service-admitted-client") {
        if (index >= args.size() || args[index++] != mode)
            throw std::runtime_error("existing caller access mode differs");
    }
    const bool grant = mode == L"--grant-client-read";
    if (args.size() != index + 2 + static_cast<std::size_t>(grant) ||
        args[index] != L"--authorized-client-sid" || args[index + 1] != caller ||
        (grant && args[index + 2] != mode)) {
        throw std::runtime_error("existing authorized caller differs");
    }
}

std::string utf8(const std::wstring& value) {
    if (value.empty()) return {};
    if (value.size() > 16384) throw std::runtime_error("publisher registration text exceeds bound");
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (count <= 0) throw std::runtime_error("publisher registration text is invalid");
    std::string result(static_cast<std::size_t>(count), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), count, nullptr, nullptr) != count)
        throw std::runtime_error("publisher registration text conversion failed");
    return result;
}


RegisteredClientRequest parse_registered_client_request(const std::wstring& name,
    const std::string& request, const PublisherRequestOptions& options) {
    RegisteredClientRequest parsed;
    auto& schema = parsed.schema;
    auto& inspection_id = parsed.inspection_id;
    auto& service_observation = parsed.service_observation;
    auto& windows_build = parsed.windows_build;
    try {
        if (!generated_name(name) || request.empty() || request.size() > 1024u * 1024u)
            throw std::runtime_error("publisher request identity or size differs");
        usk::json::ParseLimits limits;
        limits.max_bytes = 1024u * 1024u;
        limits.max_string_bytes = 512u * 1024u;
        const auto submitted = usk::json::parse(request, limits);
        schema = submitted.at("schema").as_string();
        if (schema == "usk.publisher_capability_request.v1" ||
            schema == "usk.publisher_capability_request.v2" ||
            schema == "usk.publisher_capability_request.v5") {
            service_observation = schema != "usk.publisher_capability_request.v1";
            inspection_id = submitted.at("request_id").as_string();
            if (submitted.as_object().size() != 2 || inspection_id.empty() || inspection_id.size() > 128 ||
                inspection_id.find_first_not_of(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != std::string::npos)
                throw std::runtime_error("publisher inspection request differs");
            windows_build = observe_supported_discovery_windows_build();
        } else if (schema != "usk.install_local_apply_request.v1" &&
            schema != "usk.repair_apply_request.v1" && schema != "usk.move_apply_request.v1" &&
            schema != "usk.uninstall_apply_request.v1" &&
            schema != "usk.publisher_recovery_request.v1" &&
            schema != "usk.publisher_maintenance_recovery_request.v1" &&
            schema != "usk.publisher_installed_verify_request.v1" &&
            schema != "usk.installed_verify_request.v1")
            throw std::runtime_error("publisher request schema is unavailable");
        if (schema == "usk.publisher_maintenance_recovery_request.v1")
            (void)parse_publisher_maintenance_recovery_request(request);
        if (options.conflict_wait_milliseconds > publisher_request_max_conflict_wait_milliseconds)
            throw std::invalid_argument("publisher contention wait exceeds bound");
        if (options.cancel_event) {
            const DWORD cancelled = WaitForSingleObject(options.cancel_event, 0);
            if (cancelled == WAIT_OBJECT_0)
                throw usk::base::EffectRequestNotDispatched(
                    usk::base::EffectRequestNotDispatched::Reason::operation_cancelled,
                    publisher_request_inspection_reference(name));
            if (cancelled != WAIT_TIMEOUT) throw std::runtime_error("publisher cancellation event unavailable");
        }
    } catch (const usk::base::EffectRequestNotDispatched&) {
        throw;
    } catch (const std::exception&) {
        throw usk::base::EffectRequestNotDispatched();
    }
    return parsed;
}

void admit_service_client(SC_HANDLE service, const std::wstring& name,
    const ServiceConfiguration& before, const std::vector<std::wstring>& args,
    const std::wstring& caller, bool private_discovery) {
            require_publisher_consumer_sid(utf8(caller));
            const auto service_access = observe_publisher_service_access(service, utf8(caller));
            // The administrator-owned SCM command selects this service-side
            // admission path. The actual worker checks its private records and
            // disk identity under its controller guard before opening the pipe.
            // The client binds the live pipe/PID/image before sending any bytes.
            require_existing_command(before.binary_path, name, args[0], args[4], caller, L"--service-admitted-client");
            if (CompareStringOrdinal(args[0].c_str(), -1, publisher_binary_path(name).c_str(), -1, TRUE) != CSTR_EQUAL)
                throw std::runtime_error("registered publisher image is outside the protected installation");
            if (private_discovery) {
                // V1 discovery requires five genuine private/raw-disk bindings.
                // Recognize this mode and refuse after caller/SCM validation,
                // without a guard, service start or fabricated digest.
                throw std::runtime_error("standard publisher discovery evidence is unavailable");
            }
            SERVICE_STATUS_PROCESS status{};
            DWORD needed = 0;
            if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&status), sizeof(status), &needed))
                throw std::runtime_error("registered publisher process status unavailable");
            if (status.dwCurrentState == SERVICE_STOPPED) {
                if (!StartServiceW(service, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
                    throw std::runtime_error("registered publisher could not be started");
            } else if (status.dwCurrentState != SERVICE_RUNNING && status.dwCurrentState != SERVICE_START_PENDING)
                throw std::runtime_error("registered publisher is unavailable while stopping");
            const auto after = query_configuration(service);
            require_profile(after);
            if (after.binary_path != before.binary_path || after.display_name != before.display_name ||
                usk::json::canonical(observe_publisher_service_access(service, utf8(caller))) !=
                    usk::json::canonical(service_access))
                throw std::runtime_error("registered publisher configuration changed before dispatch");
}
}
}
#endif
