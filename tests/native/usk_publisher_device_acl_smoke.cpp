// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_device_acl.h"

#if defined(_WIN32)
#include <sddl.h>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

namespace {

constexpr wchar_t service_sid[] = L"S-1-5-80-100-200-300-400-500";

bool inspect(const std::wstring& sddl, bool restrict_default = false, bool make_postimage = false, bool read_only_original = false) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PSID service = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),
            SDDL_REVISION_1, &descriptor, nullptr) ||
        !ConvertStringSidToSidW(service_sid, &service)) {
        if (descriptor) LocalFree(descriptor);
        throw std::runtime_error("device ACL test fixture cannot be parsed");
    }
    PSID owner = nullptr;
    BOOL owner_defaulted = FALSE;
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &owner_defaulted)) {
        LocalFree(service);
        LocalFree(descriptor);
        throw std::runtime_error("device ACL test fixture has no owner");
    }
    PACL dacl = nullptr;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) ||
        !present) {
        LocalFree(service);
        LocalFree(descriptor);
        throw std::runtime_error("device ACL test fixture has no DACL");
    }
    try {
        std::vector<BYTE> restricted;
        if (make_postimage) {
            const auto length = GetSecurityDescriptorLength(descriptor);
            const auto* first = static_cast<const BYTE*>(descriptor);
            const std::vector<BYTE> original(first, first + length);
            restricted = read_only_original ?
                usk::platform::windows::publisher_read_only_device_admission_postimage(owner, dacl, service) :
                usk::platform::windows::publisher_device_admission_postimage(owner, dacl, service);
            if (std::memcmp(original.data(), descriptor, original.size()) != 0)
                throw std::runtime_error("device admission postimage changed original descriptor bytes");
            PSID intended_owner = nullptr;
            SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
            if (!GetSecurityDescriptorOwner(restricted.data(), &intended_owner, &owner_defaulted) ||
                !EqualSid(owner, intended_owner) ||
                !GetSecurityDescriptorDacl(restricted.data(), &present, &dacl, &defaulted) || !present ||
                !GetSecurityDescriptorControl(restricted.data(), &control, &revision) ||
                (control & SE_DACL_PROTECTED) == 0)
                throw std::runtime_error("device admission postimage lost its owner, DACL or protection");
            owner = intended_owner;
        }
        if (restrict_default) {
            const auto* first = reinterpret_cast<const BYTE*>(dacl);
            const std::vector<BYTE> original(first, first + dacl->AclSize);
            restricted = usk::platform::windows::restrict_publisher_default_device_acl(owner, dacl, service);
            if (std::memcmp(original.data(), dacl, original.size()) != 0)
                throw std::runtime_error("device ACL transformation changed original bytes");
            dacl = reinterpret_cast<PACL>(restricted.data());
        }
        const bool result = usk::platform::windows::require_publisher_device_acl_shape(
            owner, dacl, service);
        LocalFree(service);
        LocalFree(descriptor);
        return result;
    } catch (...) {
        LocalFree(service);
        LocalFree(descriptor);
        throw;
    }
}

bool selects_read_only(const std::wstring& sddl) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PSID service = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),
        SDDL_REVISION_1, &descriptor, nullptr))
        throw std::runtime_error("optional device fixture cannot be parsed");
    std::unique_ptr<void, decltype(&LocalFree)> owned_descriptor(descriptor, &LocalFree);
    if (!ConvertStringSidToSidW(service_sid, &service))
        throw std::runtime_error("optional device fixture service cannot be parsed");
    std::unique_ptr<void, decltype(&LocalFree)> owned_service(service, &LocalFree);
    PSID owner = nullptr; PACL dacl = nullptr; BOOL defaulted = FALSE, present = FALSE;
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present)
        throw std::runtime_error("optional device fixture cannot be inspected");
    return usk::platform::windows::publisher_try_read_only_device_admission_postimage(
        owner, dacl, service).has_value();
}

bool refuses(const std::wstring& sddl, bool restrict_default = false, bool make_postimage = false, bool read_only_original = false) {
    try { (void)inspect(sddl, restrict_default, make_postimage, read_only_original); }
    catch (const std::runtime_error&) { return true; }
    return false;
}

} // namespace

int main() {
    const std::wstring baseline =
        L"O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)";
    const std::wstring service = L"(A;;FA;;;" + std::wstring(service_sid) + L")";
    if (inspect(baseline) || !inspect(baseline + service)) return 1;
    const std::wstring default_modify = L"(A;;0x1301bf;;;AU)";
    if (!refuses(baseline + default_modify + service) ||
        !inspect(baseline + default_modify + service, true) ||
        !inspect(baseline + L"(A;OICI;0x1301bf;;;AU)" + service, true) ||
        inspect(baseline + default_modify, true) ||
        !refuses(baseline + default_modify + default_modify + service, true) ||
        !refuses(baseline + L"(A;ID;0x1301bf;;;AU)" + service, true) ||
        !refuses(baseline + L"(A;;FA;;;AU)" + service, true) ||
        !refuses(baseline + default_modify + L"(A;;0x2;;;BU)" + service, true) ||
        !refuses(L"O:BUD:(A;;FA;;;SY)(A;;FA;;;BA)" + default_modify + service, true)) return 3;
    if (!refuses(baseline + L"(A;;0x2;;;BU)" + service) ||
        !refuses(baseline + L"(A;;FA;;;WD)" + service) ||
        !refuses(baseline + L"(D;;0x2;;;BU)" + service) ||
        !refuses(baseline + service + service) ||
        !refuses(baseline + L"(A;;FR;;;" + std::wstring(service_sid) + L")") ||
        !refuses(L"O:BUD:(A;;FA;;;SY)(A;;FA;;;BA)" + service)) {
        return 2;
    }
    if (!inspect(baseline, false, true) || !inspect(baseline + service, false, true) ||
        !inspect(baseline + default_modify, false, true) ||
        !inspect(baseline + default_modify + service, false, true) ||
        !inspect(baseline + L"(A;OICI;0x1301bf;;;AU)", false, true) ||
        !refuses(baseline + default_modify + default_modify, false, true) ||
        !refuses(baseline + L"(A;;FA;;;AU)", false, true) ||
        !refuses(baseline + L"(A;;0x2;;;BU)", false, true) ||
        !refuses(baseline + service + service, false, true) ||
        !refuses(L"O:BUD:(A;;FA;;;SY)(A;;FA;;;BA)" + default_modify, false, true)) return 4;
    // Mounted completion accepts only originals that are already safe; the
    // locked/default path above retains its separate AU transformation.
    if (!inspect(baseline, false, true, true) ||
        !inspect(baseline + service, false, true, true) ||
        !refuses(baseline + default_modify, false, true, true) ||
        !refuses(baseline + L"(A;;0x2;;;BU)", false, true, true) ||
        !refuses(baseline + service + service, false, true, true) ||
        !refuses(L"O:BUD:(A;;FA;;;SY)(A;;FA;;;BA)", false, true, true)) return 7;
    // Exact old startup observation: BA owner, no service ACE, only trusted
    // admin/system mutation and built-in users read/execute. This is eligible
    // for the existing pure safe-original postimage; AU/BU mutation is not.
    const std::wstring retained_default =
        L"O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)";
    if (!inspect(retained_default, false, true, true) ||
        !refuses(retained_default + default_modify, false, true, true) ||
        !refuses(retained_default + L"(A;;0x2;;;BU)", false, true, true) ||
        !refuses(retained_default + L"(A;;FA;;;WD)", false, true, true)) return 8;
    if (!selects_read_only(retained_default) || !selects_read_only(baseline + service) ||
        selects_read_only(baseline + default_modify) ||
        selects_read_only(baseline + L"(A;;0x2;;;BU)") ||
        selects_read_only(baseline + L"(A;;FA;;;WD)") ||
        selects_read_only(baseline + service + service)) return 9;
    // Added completion has its own finite admission budget. Old strict shape
    // still accepts these additional read-only ACEs; decline does not lower the
    // independent legacy route's existing profile or widen the composer limit.
    std::wstring at_capacity = baseline;
    for (unsigned index = 0; index < 61u; ++index) at_capacity += L"(A;;FR;;;BU)";
    const auto beyond_capacity = at_capacity + L"(A;;FR;;;BU)";
    if (!selects_read_only(at_capacity) || selects_read_only(beyond_capacity) ||
        selects_read_only(beyond_capacity + L"(A;;FR;;;BU)") ||
        !inspect(beyond_capacity + service)) return 11;
    // Unavailable native inputs are hard failures, never policy-decline results.
    bool unavailable_refused = false;
    try { (void)usk::platform::windows::publisher_try_read_only_device_admission_postimage(
        nullptr, nullptr, nullptr); }
    catch (const std::runtime_error&) { unavailable_refused = true; }
    if (!unavailable_refused) return 10;
    using usk::json::Value;
    const Value policy(Value::Object{{"owner", Value("S-1-5-18")}, {"dacl_protected", Value(true)},
        {"aces", Value(Value::Array{Value(Value::Object{{"type", Value(std::uint64_t{0})},
            {"flags", Value(std::uint64_t{0})}, {"mask", Value(std::uint64_t{2032127})}, {"sid", Value("S-1-5-18")}})})}});
    const Value captured_default(Value::Object{
        {"original_owner_dacl", Value("O:BAD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)")},
        {"intended_policy", policy}});
    auto captured_intended = captured_default;
    captured_intended.as_object()["original_owner_dacl"] =
        Value("O:BAD:P(A;;FA;;;S-1-5-80-100-200-300-400-500)(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)");
    const auto default_before = usk::json::canonical(captured_default);
    const auto intended_before = usk::json::canonical(captured_intended);
    const auto default_diagnostic = usk::platform::windows::publisher_device_transition_diagnostic(
        captured_default, false);
    const auto intended_diagnostic = usk::platform::windows::publisher_device_transition_diagnostic(
        captured_intended, true);
    if (default_diagnostic.at("provenance").as_string() != "legacy_locked_capture" ||
        intended_diagnostic.at("provenance").as_string() != "unpublished_retained" ||
        default_diagnostic.at("original_owner_dacl_prefix").as_string() !=
            captured_default.at("original_owner_dacl").as_string() ||
        intended_diagnostic.at("original_owner_dacl_prefix").as_string() !=
            captured_intended.at("original_owner_dacl").as_string() ||
        default_diagnostic.at("original_owner_dacl_canonical_sha256").as_string() !=
            usk::json::sha256_canonical(captured_default.at("original_owner_dacl")) ||
        intended_diagnostic.at("original_owner_dacl_canonical_sha256").as_string() !=
            usk::json::sha256_canonical(captured_intended.at("original_owner_dacl")) ||
        default_diagnostic.at("original_owner_dacl_canonical_sha256").as_string() ==
            intended_diagnostic.at("original_owner_dacl_canonical_sha256").as_string() ||
        default_diagnostic.at("intended_policy_sha256").as_string() !=
            intended_diagnostic.at("intended_policy_sha256").as_string() ||
        default_diagnostic.at("original_owner_dacl_prefix_truncated").as_boolean() ||
        usk::json::canonical(captured_default) != default_before ||
        usk::json::canonical(captured_intended) != intended_before) return 12;
    auto bounded_transition = captured_default;
    bounded_transition.as_object()["original_owner_dacl"] = Value(std::string(8192u, 'x'));
    const auto bounded = usk::platform::windows::publisher_device_transition_diagnostic(
        bounded_transition, false);
    if (bounded.at("original_owner_dacl_prefix").as_string().size() != 2048u ||
        !bounded.at("original_owner_dacl_prefix_truncated").as_boolean() ||
        bounded.at("original_owner_dacl_bytes").as_unsigned() != 8192u ||
        bounded.at("original_owner_dacl_canonical_sha256").as_string() !=
            usk::json::sha256_canonical(bounded_transition.at("original_owner_dacl"))) return 13;
    for (const auto length : {0u, 8193u}) {
        bounded_transition.as_object()["original_owner_dacl"] = Value(std::string(length, 'x'));
        bool refused = false;
        try { (void)usk::platform::windows::publisher_device_transition_diagnostic(
            bounded_transition, false); }
        catch (const std::runtime_error&) { refused = true; }
        if (!refused) return 14;
    }
    const Value intent(Value::Object{{"schema", Value("usk.publisher_target_intent.v3")},
        {"identity", Value(Value::Object{})}, {"original_metadata", Value(Value::Array{})},
        {"original_owner_dacl", Value("O:SYD:P(A;;FA;;;SY)")},
        {"mounted_device_transition", Value(Value::Object{{"original_owner_dacl", Value("O:SYD:(A;;FA;;;SY)")},
            {"intended_policy", policy}})}});
    // Shapes only, never admission/native effects. Native derivation and
    // identity/custody remain separate and mandatory in the controller.
    if (!usk::platform::windows::publisher_target_intent_has_device_transition(intent)) return 5;
    auto legacy = intent;
    legacy.as_object().at("schema") = Value("usk.publisher_target_intent.v2");
    legacy.as_object().erase("mounted_device_transition");
    if (usk::platform::windows::publisher_target_intent_has_device_transition(legacy)) return 5;
    for (unsigned variant = 0; variant < 8u; ++variant) {
        auto malformed = intent;
        if (variant == 0) malformed.as_object().at("mounted_device_transition") = Value();
        if (variant == 1) malformed.as_object().erase("mounted_device_transition");
        if (variant == 2) malformed.as_object().emplace("extra", Value());
        if (variant == 3) malformed.as_object().at("mounted_device_transition").as_object().at("intended_policy") = Value();
        if (variant == 4) malformed.as_object().at("mounted_device_transition").as_object().at("intended_policy").as_object().erase("aces");
        if (variant == 5) malformed.as_object().at("schema") = Value("usk.publisher_target_intent.v9");
        if (variant == 6) malformed.as_object().at("mounted_device_transition").as_object().at("original_owner_dacl") = Value("");
        if (variant == 7) { malformed = legacy; malformed.as_object().emplace("mounted_device_transition", Value()); }
        bool refused = false;
        try { (void)usk::platform::windows::publisher_target_intent_has_device_transition(malformed); }
        catch (const std::runtime_error&) { refused = true; }
        if (!refused) return 6;
    }
    return 0;
}
#endif
