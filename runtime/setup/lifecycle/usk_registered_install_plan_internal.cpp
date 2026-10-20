// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#if defined(_WIN32)
#include "usk_registered_install_plan_internal.h"
#include "usk_public_lifecycle.h"
#include "usk_publisher_registration.h"
#include "usk_publisher_response_internal.h"
#include "usk_publisher_directory_entries.h"
#include <algorithm>
#include <filesystem>
#include <memory>
#include <stdexcept>

namespace usk::lifecycle {
usk::json::Value registered_install_plan(
    usk::platform::windows::RegisteredPublisherAdmission& admission,
    const usk::platform::windows::PublisherRequestChannel& channel)
{
    using usk::json::Value;
    try {
        const auto envelope = admission.admit_install_plan(channel);
        const auto& request = envelope.at("plan_request");
        const auto acceptance = std::filesystem::u8path(envelope.at("acceptance_root").as_string());
        const auto state = std::filesystem::u8path(envelope.at("state_root").as_string());
        const auto target = std::filesystem::u8path(request.at("target").at("root").as_string());
        const auto root = acceptance.wstring();
        const auto component = target.filename().wstring();
        const auto configuration = admission.execution_configuration_observation();
        const auto volume = configuration.at("arguments").as_array().at(4).as_string();
        const std::wstring native_volume(volume.begin(), volume.end());
        const auto require_roots = [&] {
            wchar_t mapped[128]{};
            if (root.size() != 3 || root[1] != L':' || root[2] != L'\\' ||
                !((root[0] >= L'A' && root[0] <= L'Z') || (root[0] >= L'a' && root[0] <= L'z')) ||
                !GetVolumeNameForVolumeMountPointW(root.c_str(), mapped, static_cast<DWORD>(std::size(mapped))) ||
                CompareStringOrdinal(mapped, -1, native_volume.c_str(), -1, TRUE) != CSTR_EQUAL ||
                state != acceptance / "setup-state" || target != target.lexically_normal() ||
                target.parent_path() != acceptance / "publication" / "destination" ||
                !usk::platform::windows::is_publisher_canonical_component(component) ||
                !std::all_of(component.begin(), component.end(), [](wchar_t ch) { return ch >= 0x20 && ch <= 0x7e; }) ||
                request.at("required_commit_authority").as_string() != "staged_child_bound_v1")
                throw std::runtime_error("registered planning roots differ from the admitted volume/profile");
        };
        require_roots();
        const auto payload = usk::json::canonical(request);
        int status = -1;
        std::unique_ptr<char, decltype(&usk_public_lifecycle_command_free)> response(
            usk_public_lifecycle_command_json("install_local.plan", payload.data(), payload.size(),
                envelope.at("state_root").as_string().c_str(), envelope.at("acceptance_root").as_string().c_str(),
                "operator_acceptance_candidate", &status), &usk_public_lifecycle_command_free);
        if (!response || status != 0) throw std::runtime_error("registered read-only native planning refused");
        usk::json::ParseLimits limits;
        limits.max_bytes = usk::command::detail::publisher_response_max_bytes;
        limits.max_string_bytes = limits.max_bytes / 2;
        const auto native = usk::json::parse(response.get(), limits);
        const auto endpoint = admission.evidence();
        Value result(Value::Object{
            {"schema", Value("usk.publisher_lab_service_observation.v1")}, {"status", Value("pass")},
            {"service_name", endpoint.at("service_name")}, {"service_sid", endpoint.at("service_sid")},
            {"process_id", endpoint.at("process_id")}, {"registered_admission", endpoint},
            {"request_sha256", Value(usk::json::sha256_canonical(request))}, {"plan_response", native}});
        usk::command::detail::require_public_install_plan_response(request, result);
        require_roots();
        // No provisional result escapes before this explicit successful proof.
        // Destruction only cleans resources; it cannot finalize validation.
        admission.finish_install_plan(channel);
        return result;
    } catch (...) {
        admission.fail_install_plan();
        throw;
    }
}
}
#endif
