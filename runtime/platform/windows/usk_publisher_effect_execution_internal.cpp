// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_effect_execution_internal.h"
#if defined(_WIN32)
#include "usk_publisher_process_boundary.h"
#include <atomic>
#include <limits>
#include <stdexcept>

namespace usk::platform::windows {
namespace {
using usk::json::Value;
// A child construction attempt must never restart its pinned native baseline
// or fall back to SCM, even if the original proof fails. It stays set until exit.
std::atomic<bool> child_route_used{false};
void require(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
}
bool same(const Value& first, const Value& second) {
    return usk::json::canonical(first) == usk::json::canonical(second);
}
}
struct PublisherEffectExecutionOwner::State {
    PublisherEffectWorkerPeer& peer;
    PublisherEffectWorkerReadback readback;
    PublisherEffectWorkerNativeSecurity security;
    const DWORD process_id = GetCurrentProcessId(), thread_id = GetCurrentThreadId();
    const std::wstring name;
    const std::string request;
    const Value original;
    std::uint64_t routing_id = 0;
    bool failed = false;
    State(PublisherEffectWorkerPeer& p, const std::wstring& service_name) :
        peer(p), readback(p), security(readback), name(service_name),
        request(p.canonical_request()), original(readback.service_admission()) {
        (void)observe();
    }
    Value observe() {
        try {
            require(!failed && process_id == GetCurrentProcessId() && thread_id == GetCurrentThreadId() &&
                peer.canonical_request() == request, "publisher child original observation owner/thread/request changed");
            const auto before = readback.service_admission();
            require(same(publisher_effect_broker_immutable_record(before),
                publisher_effect_broker_immutable_record(original)), "publisher child original broker binding changed");
            const auto broker = publisher_effect_broker_service_record(before);
            const auto worker = publisher_effect_worker_record_context(before);
            require(broker.service_name == name && broker.process_id != process_id && worker.process_id == process_id &&
                broker.service_sid == worker.service_sid, "publisher child requires its actual worker and distinct original SCM owner");
            const auto native = security.observe_current();
            require(native.at("worker").at("process_id").as_unsigned() == worker.process_id &&
                native.at("worker").at("service_sid").as_string() == worker.service_sid &&
                same(native.at("worker").at("primary_token"), before.at("effect_primary_token")),
                "publisher child security belongs to another original worker");
            require_publisher_worker_security(native.at("worker_security"), worker);
            require_publisher_process_boundary(native.at("process_boundary"), worker.process_id,
                worker.service_sid, worker.token.process_groups);
            const auto after = readback.service_admission();
            require(same(publisher_effect_broker_immutable_record(after),
                publisher_effect_broker_immutable_record(before)), "publisher child native owner changed across readback");
            return after;
        } catch (...) { failed = true; throw; }
    }
};
struct PublisherEffectExecutionOwner::Routing {
    bool active = false;
    std::uint64_t last_id = 0, active_id = 0;
    std::weak_ptr<State> state;
};
PublisherEffectExecutionOwner::Routing& PublisherEffectExecutionOwner::current_routing() {
    static thread_local Routing routing;
    return routing;
}
void PublisherEffectExecutionOwner::require_available() {
    require(!current_routing().active && !child_route_used.load(),
        "publisher original child observation route is already used or expired");
}
PublisherEffectExecutionOwner::PublisherEffectExecutionOwner(PublisherEffectWorkerPeer& peer,
    const std::wstring& service_name) {
    require_available();
    auto& routing = current_routing();
    require(routing.last_id != std::numeric_limits<std::uint64_t>::max(),
        "publisher original child observation identity exhausted");
    // Claim before allocation or native proof. Failure retains this single
    // attempt and its primary exception, but never installs an active route.
    bool unused = false;
    require(child_route_used.compare_exchange_strong(unused, true),
        "publisher original child observation route was concurrently used");
    auto state = std::make_shared<State>(peer, service_name);
    state->routing_id = ++routing.last_id;
    state_ = std::move(state);
    routing.state = state_;
    routing.active_id = state_->routing_id;
    routing.active = true;
}
void PublisherEffectExecutionOwner::require_current() const {
    require(state_ && state_->process_id == GetCurrentProcessId() && state_->thread_id == GetCurrentThreadId(),
        "publisher child observation changed execution owner");
    const auto& routing = current_routing();
    require(routing.active && routing.active_id == state_->routing_id && routing.state.lock() == state_ && !state_->failed,
        "publisher original child observation route is expired or failed");
}
void PublisherEffectExecutionOwner::require_engine_origin(const PublisherEffectExecutionOwner* owner,
    const std::wstring& service_name) {
    if (!owner) {
        require(!current_routing().active && !child_route_used.load(),
            "publisher engine ordinary origin cannot omit its claimed child execution owner");
        return;
    }
    owner->require_current();
    require(child_route_used.load() && owner->state_->name == service_name,
        "publisher engine child origin differs from its original native owner/service");
}
PublisherEffectExecutionOwner::~PublisherEffectExecutionOwner() {
    // Wrong-thread destruction leaves an expired active weak reference on the
    // original thread. The process marker also refuses all other SCM fallbacks.
    if (state_ && state_->process_id == GetCurrentProcessId() && state_->thread_id == GetCurrentThreadId()) {
        auto& routing = current_routing();
        if (routing.active && routing.active_id == state_->routing_id && routing.state.lock() == state_) {
            routing.active = false;
            routing.active_id = 0;
            routing.state.reset();
        }
    }
}
PublisherNativeExecutionObservation PublisherEffectExecutionOwner::observe_current() {
    const auto profile = service_admission();
    return {publisher_effect_broker_service_record(profile), publisher_effect_worker_record_context(profile)};
}
Value PublisherEffectExecutionOwner::service_admission() { require_current(); return state_->observe(); }
Value PublisherEffectExecutionOwner::selected_reviewed_operation() {
    require_current();
    try {
        (void)state_->observe();
        const auto selected = state_->readback.selected_reviewed_operation();
        (void)state_->observe();
        return selected;
    } catch (...) { state_->failed = true; throw; }
}
Value PublisherEffectExecutionOwner::authenticated_object_access(HANDLE handle) {
    require_current();
    try {
        (void)state_->observe();
        const auto access = state_->readback.authenticated_object_access(handle);
        (void)state_->observe();
        return access;
    } catch (...) { state_->failed = true; throw; }
}
const std::string& PublisherEffectExecutionOwner::canonical_request() const {
    require_current(); return state_->request;
}
PublisherEffectWorkerReadback& PublisherEffectExecutionOwner::readback() { require_current(); return state_->readback; }
PublisherEffectWorkerNativeSecurity& PublisherEffectExecutionOwner::security() { require_current(); return state_->security; }
HANDLE PublisherEffectExecutionOwner::cancellation_observer() const {
    require_current(); return state_->peer.cancellation_observer();
}
PublisherNativeExecutionObservation observe_current_publisher_native_execution_owner(const std::wstring& name) {
    const auto& routing = PublisherEffectExecutionOwner::current_routing();
    if (routing.active) {
        const auto original = routing.state.lock();
        require(original && original->routing_id == routing.active_id && original->process_id == GetCurrentProcessId() &&
            original->thread_id == GetCurrentThreadId() && original->name == name,
            "publisher original child observation route is expired or mismatched");
        const auto profile = original->observe();
        return {publisher_effect_broker_service_record(profile), publisher_effect_worker_record_context(profile)};
    }
    require(!child_route_used.load(), "publisher child observation requires its original active execution owner");
    // The legacy route still corroborates this actual current SCM process.
    const auto service = observe_current_restricted_publisher_service(name);
    return {service, PublisherWorkerTokenContext{service.process_id, service.service_sid, service.token}};
}
}
#endif
