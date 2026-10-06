// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_process_boundary.h"
#include "usk_publisher_execution_observation.h"
#include "usk_publisher_worker_security.h"
#include <functional>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

using usk::json::Value;
using namespace usk::platform::windows;

namespace {
const std::string service_sid = "S-1-5-80-1-2-3-4-5";
const std::string consumer_sid = "S-1-5-21-1-2-3-1000";
const std::vector<ObservedTokenGroup> groups{
    {service_sid, SE_GROUP_ENABLED}, {"S-1-5-5-0-900", SE_GROUP_LOGON_ID | SE_GROUP_ENABLED}};
constexpr std::uint32_t query_rights = SYNCHRONIZE | READ_CONTROL |
    PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

Value ace(const std::string& sid, std::uint32_t mask) {
    return Value(Value::Object{{"type", Value(std::uint64_t{0})},
        {"flags", Value(std::uint64_t{0})}, {"access_mask", Value(static_cast<std::uint64_t>(mask))},
        {"sid", Value(sid)}});
}

Value boundary() {
    return Value(Value::Object{{"schema", Value("usk.publisher_process_boundary.v1")},
        {"scope", Value("stored_current_process_owner_dacl")}, {"process_id", Value(std::uint64_t{500})},
        {"owner_sid", Value("S-1-5-18")}, {"dacl_present", Value(true)}, {"dacl_protected", Value(false)},
        {"dacl_aces", Value(Value::Array{ace("S-1-5-18", PROCESS_ALL_ACCESS),
            ace(service_sid, PROCESS_ALL_ACCESS), ace(consumer_sid, query_rights)})}});
}
Value::Object security_object(std::uint32_t query) {
    return {{"owner_sid", Value("S-1-5-18")}, {"dacl_present", Value(true)}, {"dacl_protected", Value(false)},
        {"dacl_aces", Value(Value::Array{ace("S-1-5-18", 0x1fffffu), ace(service_sid, 0x1fffffu), ace(consumer_sid, query)})}};
}
Value worker_security() {
    auto primary = security_object(TOKEN_QUERY | TOKEN_QUERY_SOURCE | READ_CONTROL);
    primary.emplace("token_id", Value("0000000000000500"));
    primary.emplace("authentication_id", Value("0000000000000900"));
    primary.emplace("modified_id", Value("0000000000000501"));
    primary.emplace("default_owner_sid", Value("S-1-5-18"));
    primary.emplace("default_dacl_aces", Value(Value::Array{ace("S-1-5-18", GENERIC_ALL),
        ace(service_sid, GENERIC_ALL), ace(consumer_sid, READ_CONTROL)}));
    auto thread = security_object(SYNCHRONIZE | READ_CONTROL | THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION);
    thread.emplace("thread_id", Value(std::uint64_t{700}));
    thread.emplace("creation_time", Value("0000000000000700"));
    thread.emplace("thread_impersonating", Value(false));
    return Value(Value::Object{{"schema", Value("usk.publisher_worker_security.v1")},
        {"scope", Value("stored_primary_token_defaults_and_process_thread_owner_dacls")},
        {"process_id", Value(std::uint64_t{500})}, {"current_thread_id", Value(std::uint64_t{700})},
        {"primary_token", Value(std::move(primary))}, {"threads", Value(Value::Array{Value(std::move(thread))})}});
}
void worker_security_controls() {
    const auto observed = observe_current_publisher_worker_security();
    check(observed.as_object().size() == 6 && observed.at("process_id").as_unsigned() == GetCurrentProcessId() &&
        observed.at("current_thread_id").as_unsigned() == GetCurrentThreadId() &&
        observed.at("primary_token").as_object().size() == 9 && !observed.at("threads").as_array().empty(),
        "actual primary-token/default-DACL/own-thread security unavailable");
    PublisherServiceObservation service{};
    service.process_id = 500; service.service_sid = service_sid; service.token.process_groups = groups;
    service.token.identity = {0x500, 0x900, 0x501, TokenPrimary};
    require_publisher_worker_security(worker_security(), service);
    const auto refuses = [&](const std::function<void(Value&)>& change) {
        auto value = worker_security(); change(value);
        bool refused = false;
        try { require_publisher_worker_security(value, service); }
        catch (const std::exception&) { refused = true; }
        check(refused, "worker security admitted an outside capability or contradictory record");
    };
    const std::uint32_t rights[] = {TOKEN_QUERY | TOKEN_QUERY_SOURCE | READ_CONTROL, READ_CONTROL,
        SYNCHRONIZE | READ_CONTROL | THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION};
    for (unsigned target = 0; target < 3; ++target) {
        for (unsigned bit = 0; bit < 32; ++bit) {
            const std::uint32_t right = std::uint32_t{1} << bit;
            if (rights[target] & right) continue;
            refuses([&](Value& value) {
                auto& aces = target == 2 ? value.as_object().at("threads").as_array().front().as_object().at("dacl_aces") :
                    value.as_object().at("primary_token").as_object().at(target == 1 ? "default_dacl_aces" : "dacl_aces");
                aces.as_array().back().as_object().at("access_mask") = Value(static_cast<std::uint64_t>(rights[target] | right));
            });
        }
    }
    refuses([](Value& value) { value.as_object().at("primary_token").as_object().at("owner_sid") = Value(consumer_sid); });
    refuses([](Value& value) { value.as_object().at("primary_token").as_object().at("default_owner_sid") = Value(consumer_sid); });
    refuses([](Value& value) { value.as_object().at("current_thread_id") = Value(std::uint64_t{701}); });
    refuses([](Value& value) { value.as_object().at("threads").as_array().clear(); });
    refuses([](Value& value) { value.as_object().at("threads").as_array().push_back(value.at("threads").as_array().front()); });
    refuses([](Value& value) { value.as_object().at("primary_token").as_object().at("token_id") = Value("0000000000000502"); });
    refuses([](Value& value) { value.as_object().at("threads").as_array().front().as_object().at("thread_impersonating") = Value(true); });
}
class TestThread {
public:
    explicit TestThread(LPTHREAD_START_ROUTINE routine = nullptr, void* parameter = nullptr) {
        stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        check(stop_ != nullptr, "test thread release event unavailable");
        thread_ = CreateThread(nullptr, 0, routine ? routine : wait_for_release,
            routine ? parameter : stop_, 0, &id_);
        if (!thread_) { CloseHandle(stop_); throw std::runtime_error("test helper thread unavailable"); }
    }
    ~TestThread() {
        if (!SetEvent(stop_) || WaitForSingleObject(thread_, 5000u) != WAIT_OBJECT_0) {
            std::cerr << "test helper still active; fail-stop before releasing its dependencies\n";
            std::_Exit(1);
        }
        CloseHandle(thread_); CloseHandle(stop_);
    }
    TestThread(const TestThread&) = delete;
    TestThread& operator=(const TestThread&) = delete;
    HANDLE handle() const { return thread_; }
    DWORD id() const { return id_; }
    void retire() {
        check(SetEvent(stop_) && WaitForSingleObject(thread_, 5000u) == WAIT_OBJECT_0,
            "actual test thread did not end");
    }
private:
    static DWORD WINAPI wait_for_release(void* parameter) {
        return WaitForSingleObject(static_cast<HANDLE>(parameter), INFINITE) == WAIT_OBJECT_0 ? 0u : 1u;
    }
    HANDLE stop_ = nullptr, thread_ = nullptr;
    DWORD id_ = 0;
};
class TestThreadDacl {
public:
    explicit TestThreadDacl(HANDLE thread) : thread_(thread) {
        DWORD size = 0;
        constexpr auto information = DACL_SECURITY_INFORMATION;
        check(!GetKernelObjectSecurity(thread_, information, nullptr, 0, &size) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER && size && size <= 1024u * 1024u,
            "test thread original descriptor size unavailable");
        original_.resize(size);
        check(GetKernelObjectSecurity(thread_, information, original_.data(), size, &size) != FALSE,
            "test thread original descriptor unavailable");
        SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
        check(GetSecurityDescriptorControl(original_.data(), &control, &revision) != FALSE,
            "test thread original descriptor control unavailable");
        original_protected_ = (control & SE_DACL_PROTECTED) != 0;
        BOOL present = FALSE, defaulted = FALSE; PACL dacl = nullptr;
        check(GetSecurityDescriptorDacl(original_.data(), &present, &dacl, &defaulted) && present && dacl,
            "test thread original DACL unavailable");
        unsigned char sid[SECURITY_MAX_SID_SIZE]{}; DWORD sid_size = sizeof(sid);
        check(CreateWellKnownSid(WinWorldSid, nullptr, sid, &sid_size) != FALSE,
            "test thread control SID unavailable");
        const auto size_with_deny = static_cast<DWORD>(dacl->AclSize + sizeof(ACCESS_DENIED_ACE) - sizeof(DWORD) + sid_size);
        std::vector<unsigned char> changed(size_with_deny);
        auto* changed_acl = reinterpret_cast<PACL>(changed.data());
        check(InitializeAcl(changed_acl, size_with_deny, ACL_REVISION) &&
            AddAccessDeniedAce(changed_acl, ACL_REVISION, THREAD_SET_INFORMATION, sid),
            "test thread control deny ACE unavailable");
        for (DWORD index = 0; index != dacl->AceCount; ++index) {
            void* ace_value = nullptr;
            check(GetAce(dacl, index, &ace_value) && AddAce(changed_acl, ACL_REVISION, MAXDWORD, ace_value,
                static_cast<ACE_HEADER*>(ace_value)->AceSize), "test thread original ACE copy failed");
        }
        SECURITY_DESCRIPTOR descriptor{};
        check(InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) &&
            SetSecurityDescriptorDacl(&descriptor, TRUE, changed_acl, FALSE) &&
            SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, original_protected_ ? SE_DACL_PROTECTED : 0) &&
            SetKernelObjectSecurity(thread_, information, &descriptor), "test thread stored DACL change failed");
    }
    ~TestThreadDacl() { restore(); }
    TestThreadDacl(const TestThreadDacl&) = delete;
    TestThreadDacl& operator=(const TestThreadDacl&) = delete;
    void restore_checked() { check(restore(), "test thread descriptor restoration failed"); }
private:
    bool restore() {
        if (restored_) return true;
        restored_ = SetKernelObjectSecurity(thread_, DACL_SECURITY_INFORMATION | (original_protected_ ?
            PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION), original_.data()) != FALSE;
        return restored_;
    }
    HANDLE thread_;
    std::vector<unsigned char> original_;
    bool original_protected_ = false, restored_ = false;
};
struct ExecutionThreadControl {
    const PublisherWorkerSecurityContinuity& continuity;
    std::string diagnostic;
    static DWORD WINAPI run(void* parameter) {
        auto& control = *static_cast<ExecutionThreadControl*>(parameter);
        try { (void)control.continuity.observe_current(); }
        catch (const std::exception& error) { control.diagnostic = error.what(); }
        return 0;
    }
};
void worker_lifetime_controls() {
    // Ordinary owned test threads only; no service, token mutation or native
    // effect scope. The continuity observer itself has query-only handles.
    TestThread original;
    const auto baseline = observe_current_publisher_worker_security();
    const auto frozen = usk::json::canonical(baseline);
    PublisherWorkerSecurityContinuity continuity(baseline);
    check(usk::json::canonical(continuity.observe_current()) == frozen,
        "unchanged actual worker continuity failed");
    const auto refuses_baseline = [&](const std::function<void(Value&)>& change) {
        auto forged = baseline; change(forged);
        std::string diagnostic;
        try { PublisherWorkerSecurityContinuity invalid(forged); }
        catch (const std::exception& error) { diagnostic = error.what(); }
        check(diagnostic.find("differs from actual worker before thread pinning") != std::string::npos,
            "forged baseline was admitted or refused for an unrelated reason");
    };
    refuses_baseline([](Value& value) { value.as_object().at("primary_token").as_object().at("token_id") = Value("0000000000000000"); });
    refuses_baseline([](Value& value) { value.as_object().at("current_thread_id") = Value(std::uint64_t{0}); });
    refuses_baseline([](Value& value) { value.as_object().at("threads").as_array().clear(); });
    refuses_baseline([](Value& value) { value.as_object().at("threads").as_array().front().as_object().at("creation_time") = Value("0000000000000001"); });
    {
        TestThread added;
        std::string diagnostic;
        try { (void)continuity.observe_current(); }
        catch (const std::exception& error) { diagnostic = error.what(); }
        check(diagnostic.find("added a thread after its frozen baseline") != std::string::npos,
            "actual added thread was admitted or refused for an unrelated reason");
        added.retire();
    }
    {
        ExecutionThreadControl control{continuity, {}};
        TestThread different(ExecutionThreadControl::run, &control);
        different.retire();
        check(control.diagnostic.find("original execution thread changed") != std::string::npos,
            "different actual execution thread was admitted or refused for an unrelated reason");
    }
    {
        TestThreadDacl changed(original.handle());
        check(usk::json::canonical(observe_current_publisher_worker_security()) != frozen,
            "test thread stored security control did not change native facts");
        std::string diagnostic;
        try { (void)continuity.observe_current(); }
        catch (const std::exception& error) { diagnostic = error.what(); }
        changed.restore_checked();
        if (diagnostic.find("surviving original thread facts changed") == std::string::npos)
            std::cerr << "actual security-control refusal: " << diagnostic << '\n';
        check(diagnostic.find("surviving original thread facts changed") != std::string::npos,
            "changed actual surviving thread security was admitted or refused for an unrelated reason");
    }
    (void)continuity.observe_current();
    original.retire();
    for (unsigned repeat = 0; repeat != 2; ++repeat) {
        const auto current = continuity.observe_current();
        for (const auto& thread : current.at("threads").as_array())
            check(thread.at("thread_id").as_unsigned() != original.id(), "ended original test thread still reported live");
        check(usk::json::canonical(baseline) == frozen, "original worker baseline was refreshed");
    }
    std::cout << "actual retained-thread retirement and addition/security/execution/forgery controls passed\n";
}
} // namespace

int main() {
    try {
        // Ordinary-process readback and owned test-thread controls only. No
        // SCM or opens against another process; no publisher effect authority.
        const auto actual = observe_current_publisher_process_boundary();
        check(actual.as_object().size() == 7 && actual.at("process_id").as_unsigned() == GetCurrentProcessId() &&
            actual.at("dacl_present").as_boolean() && !actual.at("owner_sid").as_string().empty(),
            "current process owner/DACL facts were not observed");
        worker_security_controls();
        worker_lifetime_controls();

        // Synthetic policy controls are separate from the native observation.
        require_publisher_process_boundary(boundary(), 500, service_sid, groups);
        for (const auto& owner : {std::string("S-1-5-18"), std::string("S-1-5-32-544"),
                                 service_sid, std::string("S-1-5-5-0-900")}) {
            auto value = boundary();
            value.as_object().at("owner_sid") = Value(owner);
            require_publisher_process_boundary(value, 500, service_sid, groups);
        }
        auto deny = boundary();
        auto denied = ace(consumer_sid, PROCESS_ALL_ACCESS);
        denied.as_object().at("type") = Value(std::uint64_t{1});
        deny.as_object().at("dacl_aces").as_array().push_back(denied);
        require_publisher_process_boundary(deny, 500, service_sid, groups);

        const auto refuses = [&](const std::function<void(Value&)>& change) {
            auto value = boundary();
            change(value);
            bool refused = false;
            try { require_publisher_process_boundary(value, 500, service_sid, groups); }
            catch (const std::exception&) { refused = true; }
            check(refused, "process boundary admitted an outside capability or contradictory record");
        };
        for (unsigned bit = 0; bit < 32; ++bit) {
            const std::uint32_t right = std::uint32_t{1} << bit;
            if (query_rights & right) continue;
            refuses([&](Value& value) {
                value.as_object().at("dacl_aces").as_array().back().as_object().at("access_mask") =
                    Value(static_cast<std::uint64_t>(query_rights | right));
            });
        }
        refuses([](Value& value) { value.as_object().at("process_id") = Value(true); });
        refuses([](Value& value) { value.as_object().at("owner_sid") = Value(consumer_sid); });
        refuses([](Value& value) { value.as_object().at("dacl_present") = Value(false); });
        refuses([](Value& value) {
            value.as_object().at("dacl_aces").as_array().back().as_object().at("flags") =
                Value(std::uint64_t{INHERITED_ACE});
        });
        bool refused = false;
        try {
            require_publisher_process_boundary(boundary(), 500, service_sid,
                {{"S-1-5-5-900", SE_GROUP_LOGON_ID | SE_GROUP_ENABLED}});
        } catch (const std::exception&) { refused = true; }
        check(refused, "process boundary admitted an invalid publisher logon SID");

        // Pure cross-record continuity controls; phase admission is separate.
        const Value earlier(Value::Object{{"schema", Value("usk.publisher_execution_observation.v2")},
            {"scope", Value("supplied_held_service_handles_and_process_owner_dacl")},
            {"platform", Value(Value::Object{})}, {"handles", Value(Value::Array{})},
            {"service", Value(Value::Object{{"process_id", Value(std::uint64_t{500})},
                {"token_id", Value("0000000000000500")}})}, {"process_boundary", boundary()}});
        require_publisher_execution_record_continuity(earlier, earlier);
        auto later = earlier;
        later.as_object().at("process_boundary").as_object().at("dacl_protected") = Value(true);
        refused = false;
        try { require_publisher_execution_record_continuity(earlier, later); }
        catch (const std::exception&) { refused = true; }
        check(refused, "same-worker prepared/visible process boundary changed");
        later = earlier;
        later.as_object().at("schema") = Value("usk.publisher_execution_observation.v1");
        later.as_object().at("scope") = Value("supplied_held_service_handles");
        later.as_object().erase("process_boundary");
        refused = false;
        try { require_publisher_execution_record_continuity(earlier, later); }
        catch (const std::exception&) { refused = true; }
        check(refused, "same-worker visible record downgraded its process boundary");
        later = earlier;
        later.as_object().at("service").as_object().at("process_id") = Value(std::uint64_t{600});
        later.as_object().at("service").as_object().at("token_id") = Value("0000000000000600");
        later.as_object().at("process_boundary").as_object().at("process_id") = Value(std::uint64_t{600});
        require_publisher_execution_record_continuity(earlier, later);
        std::cout << "actual read-only current process boundary and synthetic policy controls passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
