// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_REGISTRATION_H
#define USK_PUBLISHER_REGISTRATION_H
#if defined(_WIN32)
#include <string>
#include <memory>
#include "usk_json.h"
#include "usk_publisher_request_channel.h"
namespace usk::platform::windows {
// Internal controller entry point; the packaged CLI and machine client share
// the same SCM, protected-binary and dedicated-volume admission implementation.
int publisher_service_control_main(int argc, wchar_t** argv);
// Closed grammar only. This supplies no registration, approval or effect
// authority; enrollment and execution independently retain those native facts.
usk::json::Value parse_publisher_reviewed_operation_envelope(
    const std::string& bytes, const std::string& canonical_request);
usk::json::Value parse_publisher_maintenance_recovery_request(const std::string& bytes);
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
    // Retain the actual protected executable and controller admission binding
    // while the guard and executable remain held. This is observed provenance,
    // not source qualification, an export-history assertion or a new grant.
    usk::json::Value evidence() const;
    // Service-mediated observation may activate SCM and acquire the controller
    // guard. It reads admission facts without dispatching installation effects.
    usk::json::Value capability_observation(const std::string& request_id, bool scoped_profile = false) const;
    // Select only an administrator-enrolled exact request under this held
    // registration and the channel's actual authenticated caller. Both native
    // approval/envelope files remain held against mutation through dispatch.
    // Absence preserves the original immutable SCM-envelope route.
    bool select_reviewed_operation(const std::string& request,
        const PublisherRequestChannel& channel, std::wstring& envelope_path,
        std::string& envelope_sha256) const;
    bool has_selected_reviewed_operation() const noexcept;
    usk::json::Value selected_reviewed_envelope() const;
    usk::json::Value selected_reviewed_operation_observation() const;
private:
    struct State;
    std::unique_ptr<State> state_;
};
// Discover the administrator-owned registration, bind the current caller,
// start or reconnect, then use the authenticated one-request channel. No
// caller-supplied volume, executable, SID or activation flag grants authority.
// The v1 capability request performs read-only discovery without creating
// controller locks, admitting a volume, starting SCM or dispatching effects.
// V2 separately allows startup and the service-side controller guard while
// observing retained admission; it does not dispatch installation effects.
std::string submit_registered_publisher_request(const std::wstring& service_name,
    const std::string& request, const PublisherRequestOptions& options = {});
}
#endif
#endif
