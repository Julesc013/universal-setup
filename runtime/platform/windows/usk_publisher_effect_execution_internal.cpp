// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_effect_execution_internal.h"
#if defined(_WIN32)
#include "usk_publisher_process_boundary.h"
#include "usk_install_lease.h"
#include <atomic>
#include <limits>
#include <filesystem>
#include <set>
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
    return usk::json::equal_values(first, second);
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
    void require_owner() const {
        require(!failed && process_id == GetCurrentProcessId() && thread_id == GetCurrentThreadId() &&
            peer.canonical_request() == request, "publisher child original observation owner/thread/request changed");
    }
    void require_native_binding(const Value& profile, const Value& native) const {
        require(same(publisher_effect_broker_immutable_record(profile),
            publisher_effect_broker_immutable_record(original)), "publisher child original broker binding changed");
        const auto broker = publisher_effect_broker_service_record(profile);
        const auto worker = publisher_effect_worker_record_context(profile);
        require(broker.service_name == name && broker.process_id != process_id && worker.process_id == process_id &&
            broker.service_sid == worker.service_sid, "publisher child requires its actual worker and distinct original SCM owner");
        require(native.at("worker").at("process_id").as_unsigned() == worker.process_id &&
            native.at("worker").at("service_sid").as_string() == worker.service_sid &&
            same(native.at("worker").at("primary_token"), profile.at("effect_primary_token")),
            "publisher child security belongs to another original worker");
        require_publisher_worker_security(native.at("worker_security"), worker);
        require_publisher_process_boundary(native.at("process_boundary"), worker.process_id,
            worker.service_sid, worker.token.process_groups);
    }
    Value observe() {
        try {
            require_owner();
            // The original native security owner performs this whole bracket.
            // Its two profiles are actual validated replies around unchanged
            // local child checks, not supplied or previously cached records.
            auto observed = security.observe_brokered();
            const auto& before = observed.before;
            require_native_binding(before, observed.native);
            const auto& after = observed.after;
            require(same(publisher_effect_broker_immutable_record(after),
                publisher_effect_broker_immutable_record(before)), "publisher child native owner changed across readback");
            return std::move(observed.after);
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
        auto selected = state_->readback.selected_reviewed_operation();
        (void)state_->observe();
        return selected;
    } catch (...) { state_->failed = true; throw; }
}
Value PublisherEffectExecutionOwner::authenticated_object_access(HANDLE handle) {
    require_current();
    try {
        state_->require_owner();
        // Complete original child-local native proofs surround the actual
        // read-only query. The parent independently encloses that same query
        // with its full fresh native checks and returns BOTH actual profiles.
        // These brackets overlap; no former wire sampling instant is claimed.
        const auto native_before = state_->security.observe_local_current();
        auto observed = state_->readback.authenticated_object_access_bracket(handle);
        const auto native_after = state_->security.observe_local_current();
        state_->require_native_binding(observed.before, native_before);
        state_->require_native_binding(observed.after, native_after);
        require_publisher_worker_security_continuity(native_before.at("worker_security"), native_after.at("worker_security"));
        require(same(publisher_effect_broker_immutable_record(observed.before),
            publisher_effect_broker_immutable_record(observed.after)), "publisher child native owner changed across object access");
        state_->require_owner();
        state_->readback.retain_object_access_bracket(observed);
        return std::move(observed.access);
    } catch (...) { state_->failed = true; throw; }
}
Value PublisherEffectExecutionOwner::authenticated_object_access_batch(const std::vector<HANDLE>& handles) {
    require_current();
    try {
        state_->require_owner();
        const auto native_before = state_->security.observe_local_current();
        auto observed = state_->readback.authenticated_object_access_batch_bracket(handles);
        const auto native_after = state_->security.observe_local_current();
        state_->require_native_binding(observed.before, native_before);
        state_->require_native_binding(observed.after, native_after);
        require_publisher_worker_security_continuity(native_before.at("worker_security"), native_after.at("worker_security"));
        require(same(publisher_effect_broker_immutable_record(observed.before),
            publisher_effect_broker_immutable_record(observed.after)), "publisher child native owner changed across object access batch");
        state_->require_owner();
        state_->readback.retain_object_access_bracket(observed);
        return std::move(observed.access);
    } catch (...) { state_->failed = true; throw; }
}
Value PublisherEffectExecutionOwner::selected_original_maintenance_recovery() {
    require_current();
    try {
        (void)state_->observe();
        auto selected = state_->readback.selected_original_maintenance_recovery();
        (void)state_->observe();
        return selected;
    } catch (...) { state_->failed = true; throw; }
}
Value PublisherEffectExecutionOwner::selected_original_installation_recovery() {
    require_current();
    try {
        (void)state_->observe();
        auto selected = state_->readback.selected_original_installation_recovery();
        (void)state_->observe();
        return selected;
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
void require_publisher_effect_maintenance_original_record(const Value& original,
    const Value& request, const std::wstring& service_name) {
    const std::set<std::string> fields{"schema", "transaction_id", "operation", "plan_digest",
        "original_context_sha256", "original_lease_ownership", "worker_security", "process_boundary",
        "registration_sha256", "authenticated_client", "original_consumer_completion", "installed_root",
        "installed_root_journal_identity", "original_objects", "broker_readback"};
    require(original.as_object().size() == fields.size(), "child maintenance original custody is not closed");
    for (const auto& item : original.as_object())
        require(fields.count(item.first) != 0, "child maintenance original custody has an unknown field");
    require(original.at("schema").as_string() == "usk.publisher.maintenance_original_custody.v3" ||
        original.at("schema").as_string() == "usk.publisher.maintenance_original_custody.v4",
        "child maintenance original custody has another provenance family");
    const auto& broker = original.at("broker_readback");
    const auto worker = publisher_effect_worker_record_context(broker);
    const auto service = publisher_effect_broker_service_record(broker);
    require(original.at("worker_security").at("schema").as_string() ==
        (original.at("schema").as_string() == "usk.publisher.maintenance_original_custody.v4" ?
            "usk.publisher_worker_security.v2" : "usk.publisher_worker_security.v1"),
        "original custody reinterpreted worker-security provenance");
    require_publisher_worker_security(original.at("worker_security"), worker);
    require_publisher_process_boundary(original.at("process_boundary"), worker.process_id,
        worker.service_sid, worker.token.process_groups);
    const auto& lease = original.at("original_lease_ownership");
    usk::transaction::require_install_lease_record(lease);
    const auto& operation = original.at("operation").as_string();
    const auto& arguments = broker.at("service_configuration").at("arguments").as_array();
    const auto schema = operation == "repair" ? "usk.repair_apply_request.v1" :
        operation == "move" ? "usk.move_apply_request.v1" :
        operation == "uninstall" ? "usk.uninstall_apply_request.v1" : "";
    require(schema[0] != '\0' && request.at("schema").as_string() == schema &&
        arguments.size() == 11 && arguments.at(5).as_string() == "--reviewed-plan-envelope" &&
        service.service_name == service_name && service.process_id != worker.process_id &&
        broker.at("request_sha256").as_string() == usk::json::sha256_canonical(request) &&
        original.at("registration_sha256").as_string() == usk::json::sha256_canonical(broker.at("registered_admission")) &&
        original.at("plan_digest").as_string() == request.at("reviewed_plan_digest").as_string() &&
        same(original.at("authenticated_client"), broker.at("authenticated_client")) &&
        lease.at("status").as_string() == "active" && lease.at("operation").as_string() == operation &&
        lease.at("operation_id").as_string() == original.at("transaction_id").as_string() &&
        lease.at("operation_id").as_string() == request.at("transaction_id").as_string() &&
        lease.at("install_id").as_string() == request.at("plan_request").at("install_id").as_string() &&
        lease.at("operation_context_sha256").as_string() == original.at("original_context_sha256").as_string() &&
        lease.at("state_root_identity").at("volume_serial").as_string() ==
            broker.at("registered_admission").at("target_identity").at("volume_identity").at("volume_serial").as_string() &&
        lease.at("holder").at("process_id").as_unsigned() == worker.process_id &&
        lease.at("holder").at("process_creation_time").as_string() == broker.at("custody").at("peer_process_birth").as_string(),
        "child maintenance original custody lost its actual broker/worker/lease/request/caller provenance");
}
}
#endif
