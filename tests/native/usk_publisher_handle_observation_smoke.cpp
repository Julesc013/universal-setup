// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_handle_observation.h"
#include "usk_publisher_security_descriptor.h"

#include <aclapi.h>
#include <windows.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using usk::platform::windows::observe_publisher_directory_handle;
using usk::platform::windows::observe_publisher_file_handle;

namespace {
class Handle {
public:
    explicit Handle(HANDLE value) : value_(value) {
        if (value_ == INVALID_HANDLE_VALUE) throw std::runtime_error("fixture handle open failed");
    }
    ~Handle() { CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

bool refused(HANDLE handle) {
    try { (void)observe_publisher_directory_handle(handle); }
    catch (const std::exception&) { return true; }
    return false;
}

void check_stored_protection(HANDLE handle, bool directory) {
    using usk::platform::windows::read_publisher_owner_dacl_from_handle;
    const auto observe = [&] { return directory ?
        observe_publisher_directory_handle(handle) : observe_publisher_file_handle(handle); };
    const auto before = observe();
    const auto original = read_publisher_owner_dacl_from_handle(handle);
    using NtSetSecurityObjectFn = LONG (NTAPI *)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto set_security = module ? reinterpret_cast<NtSetSecurityObjectFn>(
        GetProcAddress(module, "NtSetSecurityObject")) : nullptr;
    check(set_security != nullptr, "fixture native security setter unavailable");
    // This changes only the owned fixture's stored control bit. No parent or
    // descendant ACL propagation, profile owner or publication authority.
    for (const bool protect : {false, true, false}) {
        auto descriptor = original;
        check(SetSecurityDescriptorControl(descriptor.data(), SE_DACL_PROTECTED,
            protect ? SE_DACL_PROTECTED : 0) != FALSE, "fixture control change failed");
        check(set_security(handle, DACL_SECURITY_INFORMATION |
            (protect ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION),
            descriptor.data()) == 0, "fixture stored DACL change failed");
        const auto after = observe();
        check(after.dacl_protected == protect,
            "same-handle observation differs from the stored DACL control bit");
        check(after.file_id == before.file_id && after.native_name == before.native_name &&
            after.attributes == before.attributes && after.link_count == before.link_count &&
            after.case_sensitive == before.case_sensitive && after.owner_sid == before.owner_sid &&
            after.dacl_aces.size() == before.dacl_aces.size(),
            "stored protection observation changed other object facts");
        for (std::size_t index = 0; index < before.dacl_aces.size(); ++index) {
            const auto& expected = before.dacl_aces[index];
            const auto& actual = after.dacl_aces[index];
            check(expected.type == actual.type && expected.flags == actual.flags &&
                expected.access_mask == actual.access_mask && expected.sid == actual.sid,
                "stored protection operation changed ordered ACE facts");
        }
    }
}
} // namespace

int main() {
    try {
        const auto root = fs::temp_directory_path() /
            ("usk-publisher-observe-" + std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count()));
        check(fs::create_directory(root), "fixture root already exists");
        const auto directory = root / "observed";
        check(fs::create_directory(directory), "fixture directory creation failed");
        {
            Handle handle(CreateFileW(directory.c_str(),
                FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE |
                    FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            const auto observed = observe_publisher_directory_handle(handle.get());
            check(observed.file_id.size() == 49 && observed.file_id[16] == ':',
                "composite native file identity is malformed");
            check(observed.native_name.size() >= 8 &&
                observed.native_name.substr(observed.native_name.size() - 8) == L"observed",
                "same-handle native name does not identify the fixture");
            check((observed.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                observed.link_count == 1, "directory facts were not observed");
            check(!observed.owner_sid.empty() && !observed.dacl_aces.empty(),
                "same-handle owner and DACL were not observed");
            check(observed.owner_sid != "S-1-5-18",
                "ordinary disposable fixture unexpectedly has the protected profile owner");

            check_stored_protection(handle.get(), true);

            check(usk::platform::windows::observe_publisher_noninheritable_handle_flags(handle.get()) == 0,
                "owned fixture handle flags were not observed");
            check(SetHandleInformation(handle.get(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) != FALSE,
                "owned handle inheritance control setup failed");
            check(refused(handle.get()), "inheritable handle supplied publisher facts");
            check(SetHandleInformation(handle.get(), HANDLE_FLAG_INHERIT, 0) != FALSE,
                "owned handle inheritance control teardown failed");
            check(observe_publisher_directory_handle(handle.get()).file_id == observed.file_id,
                "inheritance control changed owned object identity");

            PACL original_dacl = nullptr;
            PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
            const DWORD read_status = GetSecurityInfo(handle.get(), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION, nullptr, nullptr, &original_dacl,
                nullptr, &raw_descriptor);
            check(read_status == ERROR_SUCCESS && raw_descriptor && original_dacl,
                "fixture DACL could not be read for the protected-DACL probe");
            const DWORD write_status = SetSecurityInfo(handle.get(), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr, nullptr, original_dacl, nullptr);
            LocalFree(raw_descriptor);
            check(write_status == ERROR_SUCCESS, "fixture DACL protection failed");
            const auto protected_observation = observe_publisher_directory_handle(handle.get());
            check(protected_observation.file_id == observed.file_id &&
                protected_observation.owner_sid == observed.owner_sid &&
                protected_observation.dacl_protected,
                "same-handle reobservation missed a DACL control change");
        }
        check(refused(INVALID_HANDLE_VALUE), "invalid handle was admitted");
        {
            Handle limited(CreateFileW(directory.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            check(refused(limited.get()), "a handle lacking READ_CONTROL supplied security facts");
        }
        const auto file = root / "file.bin";
        {
            Handle created(CreateFileW(file.c_str(), GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL, nullptr));
        }
        {
            Handle regular(CreateFileW(file.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            check(refused(regular.get()), "regular file was admitted as a directory");
            const auto observed_file = observe_publisher_file_handle(regular.get());
            check((observed_file.attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
                observed_file.link_count == 1 && !observed_file.owner_sid.empty() &&
                !observed_file.dacl_aces.empty() && !observed_file.case_sensitive,
                "same-handle regular-file security facts were not observed");
            check(observed_file.native_name.size() >= 8 &&
                observed_file.native_name.substr(
                    observed_file.native_name.size() - 8) == L"file.bin",
                "same-handle regular-file native name diverged");
            check_stored_protection(regular.get(), false);
        }
        {
            Handle limited(CreateFileW(file.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            bool denied = false;
            try { (void)observe_publisher_file_handle(limited.get()); }
            catch (const std::runtime_error&) { denied = true; }
            check(denied, "file handle lacking READ_CONTROL supplied security facts");
        }
        fs::remove(file);
        fs::remove(directory);
        fs::remove(root);
        std::cout << "Windows publisher same-handle identity/security observation PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
