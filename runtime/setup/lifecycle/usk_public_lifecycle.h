// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLIC_LIFECYCLE_H
#define USK_PUBLIC_LIFECYCLE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char* usk_public_lifecycle_command_json(
    const char* command_name,
    const char* request_json,
    size_t request_size,
    const char* state_root,
    const char* authorized_acceptance_root,
    const char* target_policy_activation,
    int* out_command_status);

void usk_public_lifecycle_command_free(char* value);

#ifdef __cplusplus
}

#include "usk_lifecycle.h"
#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#endif
namespace usk::lifecycle {
// Private dispatcher seam for deterministic crash qualification; never a public C ABI hook.
char* public_command_json(const char* command_name, const char* request_json, size_t request_size,
    const char* state_root, const char* authorized_acceptance_root, const char* target_policy_activation,
    int* out_command_status, const LifecycleFaultInjector& fault_injector);

// Internal publisher seam: capture the complete, source-validated plan while
// the original source and target evidence are still available.
InstallPlan reviewed_install_plan_for_publisher(const std::string& request_json,
    const std::string& state_root, const std::string& authorized_acceptance_root,
    const std::string& target_policy_activation);
#if defined(_WIN32)
void initialize_setup_root_for_publisher(const std::string& state_root,
    const std::string& authorized_acceptance_root,
    const std::string& target_policy_activation, HANDLE held_volume,
    const std::wstring& volume_guid_root, const std::wstring& service_name = {});
#endif
}
#endif

#endif
