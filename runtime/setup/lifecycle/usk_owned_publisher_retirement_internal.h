// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_OWNED_PUBLISHER_RETIREMENT_INTERNAL_H
#define USK_OWNED_PUBLISHER_RETIREMENT_INTERNAL_H
#if defined(_WIN32)
#include "usk_lifecycle.h"
#include "usk_publisher_owned_retirement_custody_internal.h"
#include <map>
namespace usk::lifecycle::detail {
// Historical inputs only; tests may supply these without obtaining any
// native custody or permission to call the private retirement effects.
struct OwnedPublisherRetirementHistory {
    usk::json::Value registration;
    std::wstring volume_root;
    std::vector<usk::platform::windows::PublisherRetirementRecord> records;
    std::map<std::wstring, usk::platform::windows::PublisherRetirementDirectoryMetadata> directories;
};
struct OwnedPublisherRetirementSelection {
    std::vector<std::string> installation_ids;
    std::vector<usk::json::Value> historical_holders;
    std::vector<std::filesystem::path> reviewed_volume_paths;
};
InstallPlan decode_owned_retirement_install_history(
    const std::string& snapshot, const std::string& prepared,
    const std::string& visible, const std::string& completion,
    const std::wstring& service_name, const std::string& service_sid,
    const std::string& consumer_sid);
OwnedPublisherRetirementSelection validate_owned_publisher_retirement_history(
    const OwnedPublisherRetirementHistory&, const std::wstring& service_name);
// This fixed native owner is the sole friend of private native final effects.
void retire_owned_publisher(const std::wstring& service_name);
}
#endif
#endif
