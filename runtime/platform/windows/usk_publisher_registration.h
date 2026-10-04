// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_REGISTRATION_H
#define USK_PUBLISHER_REGISTRATION_H
#if defined(_WIN32)
#include <string>
#include <memory>
namespace usk::platform::windows {
// Internal controller entry point; the packaged CLI and machine client share
// the same SCM, protected-binary and dedicated-volume admission implementation.
int publisher_service_control_main(int argc, wchar_t** argv);
// Opt-in administrator-created registration: the actual restricted service
// holds the controller guard and protected executable through its one request,
// and validates private registration/target/storage facts before receiving it.
// Ordinary clients supply neither these records nor privileged disk handles.
class RegisteredPublisherAdmission final {
public:
    RegisteredPublisherAdmission(const std::wstring& service_name,
        const std::wstring& volume_root, const std::wstring& caller_sid);
    ~RegisteredPublisherAdmission();
    RegisteredPublisherAdmission(const RegisteredPublisherAdmission&) = delete;
    RegisteredPublisherAdmission& operator=(const RegisteredPublisherAdmission&) = delete;
private:
    struct State;
    std::unique_ptr<State> state_;
};
// Discover the administrator-owned registration, bind the current caller,
// start or reconnect, then use the authenticated one-request channel. No
// caller-supplied volume, executable, SID or activation flag grants authority.
// The closed capability request performs read-only discovery without creating
// controller locks, admitting a volume, starting SCM or dispatching effects.
std::string submit_registered_publisher_request(const std::wstring& service_name,
    const std::string& request);
}
#endif
#endif
