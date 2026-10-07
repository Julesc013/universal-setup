// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_EFFECT_WORKER_CUSTODY_INTERNAL_H
#define USK_PUBLISHER_EFFECT_WORKER_CUSTODY_INTERNAL_H
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "usk_json.h"
#include "usk_stable_file.h"
#include "usk_publisher_token_observation.h"
#include <memory>
#include <string>
#include <exception>
#include <stdexcept>

namespace usk::platform::windows {
inline constexpr wchar_t publisher_effect_worker_transport_switch[] =
    L"--usk-private-effect-worker-transport-v1";
struct PublisherEffectWorkerClosure {
    bool job_closed = false;
    bool child_ended = false;
    bool io_retired = false;
    DWORD job_close_error = ERROR_SUCCESS;
    DWORD child_wait_result = WAIT_FAILED;
    DWORD io_retirement_error = ERROR_SUCCESS;
    DWORD child_process_id = 0;
    std::uint64_t child_process_birth = 0;
    bool confirmed() const noexcept { return job_closed && child_ended && io_retired; }
};
class PublisherEffectWorkerClosureUnknown final : public std::runtime_error {
public:
    PublisherEffectWorkerClosureUnknown(const PublisherEffectWorkerClosure& closure,
        std::exception_ptr primary);
    const PublisherEffectWorkerClosure& closure() const noexcept { return closure_; }
    const std::exception_ptr& primary_failure() const noexcept { return primary_; }
private:
    PublisherEffectWorkerClosure closure_;
    std::exception_ptr primary_;
};

// Private native process/transport custody ONLY. This does not admit an effect
// worker, copy SCM authority, select an operation, or create filesystem effects.
// The production admission must separately join the actual service, original
// authenticated request/caller, registration, target and worker token/image.
// No publisher file, token, lease, SCM or creator handle is inherited/exported.
// The child receives only one private connected pipe, a query/synchronize-only
// parent process handle and a synchronize-only cancellation event.
class PublisherEffectWorkerCustody final {
public:
    PublisherEffectWorkerCustody(const usk::base::StableFile& original_image,
        const std::wstring& custody_sid, const std::string& canonical_request,
        HANDLE cancel_event = nullptr);
    ~PublisherEffectWorkerCustody();
    PublisherEffectWorkerCustody(const PublisherEffectWorkerCustody&) = delete;
    PublisherEffectWorkerCustody& operator=(const PublisherEffectWorkerCustody&) = delete;
    // Packet deadline plus at most 10s to observe cancellation completion.
    // Unobserved completion retains its owned storage and fails permanently.
    void send(const usk::json::Value& body, DWORD timeout_ms = 120000);
    usk::json::Value receive(DWORD timeout_ms = 120000);
    // Fresh held native process/job/image observations, not admission evidence.
    usk::json::Value observation() const;
    // Actual remote primary-token facts, bracketed by the held native peer
    // identity. The impersonation field describes this observing thread.
    PublisherTokenObservation peer_primary_token() const;
    const std::string& canonical_request() const;
    bool wait_for_exit(DWORD timeout_ms, DWORD& exit_code) const;
    // One bounded shutdown attempt. Unknown results permanently retain the
    // child/job/image/pending-I/O state until process exit and refuse another
    // launch in this process. A destructor performs the same attempt if needed.
    PublisherEffectWorkerClosure close(DWORD timeout_ms = 10000);
private:
    struct State;
    std::unique_ptr<State> state_;
};

// The executable explicitly handles the closed private switch before SCM
// dispatch. Constructing this transport grants no operation/effect authority.
// Its independently held live parent and current image must be joined to a
// fresh admitted broker by the production worker before any effect dispatch.
class PublisherEffectWorkerPeer final {
public:
    PublisherEffectWorkerPeer(int argc, wchar_t** argv);
    ~PublisherEffectWorkerPeer();
    PublisherEffectWorkerPeer(const PublisherEffectWorkerPeer&) = delete;
    PublisherEffectWorkerPeer& operator=(const PublisherEffectWorkerPeer&) = delete;
    // Same finite packet/retirement bounds and retained-unknown rule.
    void send(const usk::json::Value& body, DWORD timeout_ms = 120000);
    usk::json::Value receive(DWORD timeout_ms = 120000);
    usk::json::Value observation() const;
    PublisherTokenObservation peer_primary_token() const;
    const std::string& canonical_request() const;
private:
    friend class PublisherEffectWorkerReadback;
    // Borrowed only inside the fixed native readback's startup wait; never
    // returned publicly or serialized, and never grants event modification.
    HANDLE cancellation_observer() const;
    struct State;
    std::unique_ptr<State> state_;
};
} // namespace usk::platform::windows
#endif
#endif
