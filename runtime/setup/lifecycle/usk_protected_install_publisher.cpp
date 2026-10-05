// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_anchor_create.h"
#include "usk_publisher_staged_stream.h"
#include "usk_publisher_volume_operation_guard.h"
#include "usk_publisher_installation_lease.h"
#include "usk_publisher_metadata.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_archive_payload.h"
#include "usk_json.h"
#include "usk_sha256.h"
#include "usk_stable_file.h"
#include "usk_record_io.h"
#include "usk_public_lifecycle.h"
#include "usk_protected_install_publisher_internal.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_consumer_access.h"
#include "usk_publisher_token_observation.h"
#include "usk_publisher_execution_observation.h"
#include "usk_publisher_request_channel.h"
#include "usk_publisher_registration.h"
#include "usk_publisher_creation_observation.h"
#include "usk_publisher_tree_observation.h"
#include "usk_publisher_volume_stream_observation.h"

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <stdexcept>
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <filesystem>
#include <exception>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace {
bool is_authenticated_record_schema(const std::string& schema) {
    return schema == "usk.publisher.lab_phase_evidence.v8" || schema == "usk.publisher.lab_phase_evidence.v9";
}

struct OwnedHandle {
    HANDLE value;
    explicit OwnedHandle(HANDLE handle) : value(handle) {}
    ~OwnedHandle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
    HANDLE get() const { return value; }
    void close_checked() {
        if (value && value != INVALID_HANDLE_VALUE) {
            const HANDLE closing = value;
            value = INVALID_HANDLE_VALUE;
            if (!CloseHandle(closing)) {
                throw std::runtime_error("publisher handle close failed; Win32 " +
                    std::to_string(GetLastError()));
            }
        }
    }
};

thread_local std::wstring service_name;
thread_local std::wstring receipt_path;
thread_local std::wstring volume_root;
thread_local std::wstring visible_component = L"visible";
thread_local bool prepublish_gate = false;
thread_local bool poststage_gate = false;
thread_local bool postrename_gate = false;
thread_local bool postjournal_gate = false;
thread_local bool recover_prepared = false;
thread_local bool recover_snapshot_only = false;
thread_local bool recover_reviewed = false;
thread_local bool recover_sealed_journal = false;
thread_local bool recover_visible_bound = false;
thread_local bool reviewed_install_reentry = false;
thread_local bool verify_installed_request = false;

using usk::platform::windows::StaleReviewedInstallRequest;
thread_local bool selected_archive_mode = false;
thread_local std::wstring selected_archive_path;
thread_local std::string selected_archive_sha256;
thread_local std::wstring reviewed_plan_envelope_path;
thread_local std::string reviewed_plan_envelope_sha256;
thread_local std::optional<std::string> submitted_apply_request;
thread_local std::optional<std::string> submitted_recovery_request;
thread_local std::optional<std::string> submitted_verify_request;
thread_local std::string consumer_read_sid;
thread_local const usk::platform::windows::PublisherRequestChannel* authenticated_request = nullptr;
thread_local const usk::platform::windows::RegisteredPublisherAdmission* registered_admission = nullptr;
thread_local std::optional<usk::json::Value> registered_operation_admission;
thread_local bool interrupt_consumer_grant = false;
struct ReviewedPlanBinding {
    std::string plan_digest;
    std::string envelope_sha256;
    std::string selected_file_set_digest;
    std::string durable_snapshot;
    std::string setup_root;
    std::string acceptance_root;
    std::string transaction_id;
    std::string applied_at;
    usk::lifecycle::InstallPlan install_plan;
    usk::archive::StreamingStoredArchivePayload selected_payload;
    std::string apply_request;
};
std::wstring selected_utf8_path(const std::string& path);
thread_local HANDLE stop_event = nullptr;
constexpr std::size_t lab_record_limit = 4u * 1024u * 1024u;

std::string current_utc_timestamp() {
    SYSTEMTIME now{};
    GetSystemTime(&now);
    char result[21]{};
    const int written = std::snprintf(result, sizeof(result),
        "%04u-%02u-%02uT%02u:%02u:%02uZ", now.wYear, now.wMonth,
        now.wDay, now.wHour, now.wMinute, now.wSecond);
    if (written != 20) throw std::runtime_error("publisher UTC timestamp is unavailable");
    return result;
}

bool lower_sha256_ascii(const std::string& value) {
    if (value.size() != 64) return false;
    for (const char ch : value) {
        if (!((ch >= '0' && ch <= '9') ||
                (ch >= 'a' && ch <= 'f'))) return false;
    }
    return true;
}

std::wstring gate_sibling(const wchar_t* name) {
    const auto slash = receipt_path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        throw std::runtime_error("publisher lab receipt has no parent");
    }
    const auto parent = receipt_path.substr(0, slash + 1);
    if (!selected_archive_mode) return parent + name;
    const auto filename = receipt_path.substr(slash + 1);
    if (filename.size() <= 5 ||
        filename.compare(filename.size() - 5, 5, L".json") != 0) {
        throw std::runtime_error("selected lab receipt extension is invalid");
    }
    return parent + filename.substr(0, filename.size() - 5) + L"-" + name;
}

void wait_for_prepublish_gate() {
    const std::wstring ready = gate_sibling(L"prepublish-ready.txt");
    const std::wstring ready_temp = gate_sibling(L"prepublish-ready.tmp");
    const std::wstring release = gate_sibling(L"prepublish-release.txt");
    static constexpr char ready_bytes[] = "usk.publisher.lab_prepared.v1\n";
    static constexpr char release_bytes[] = "usk.publisher.lab_continue.v1\n";
    if (GetFileAttributesW(release.c_str()) != INVALID_FILE_ATTRIBUTES) {
        throw std::runtime_error("prepublish release marker existed before readiness");
    }
    {
        OwnedHandle marker(CreateFileW(ready_temp.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (marker.get() == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("cannot create prepublish readiness marker");
        }
        DWORD written = 0;
        if (!WriteFile(marker.get(), ready_bytes, sizeof(ready_bytes) - 1, &written, nullptr) ||
            written != sizeof(ready_bytes) - 1 || !FlushFileBuffers(marker.get())) {
            throw std::runtime_error("cannot flush prepublish readiness marker");
        }
    }
    if (!MoveFileExW(ready_temp.c_str(), ready.c_str(), MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("cannot expose flushed prepublish readiness marker");
    }
    for (unsigned attempt = 0; attempt != 1200; ++attempt) {
        OwnedHandle signal(CreateFileW(release.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (signal.get() != INVALID_HANDLE_VALUE) {
            char bytes[sizeof(release_bytes)]{};
            DWORD read = 0;
            if (!ReadFile(signal.get(), bytes, sizeof(bytes), &read, nullptr) ||
                read != sizeof(release_bytes) - 1 ||
                std::string(bytes, read) != std::string(release_bytes, sizeof(release_bytes) - 1)) {
                throw std::runtime_error("prepublish release marker is invalid");
            }
            return;
        }
        if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            throw std::runtime_error("cannot inspect prepublish release marker");
        }
        if (WaitForSingleObject(stop_event, 100) != WAIT_TIMEOUT) {
            throw std::runtime_error("prepublish gate interrupted");
        }
    }
    throw std::runtime_error("prepublish gate timed out");
}

void wait_for_poststage_gate() {
    const std::wstring ready = gate_sibling(L"poststage-ready.txt");
    static constexpr char ready_bytes[] =
        "usk.publisher.lab_snapshot_and_stage_sealed.v1\n";
    {
        OwnedHandle marker(CreateFileW(ready.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (marker.get() == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("cannot create poststage readiness marker");
        }
        DWORD written = 0;
        if (!WriteFile(marker.get(), ready_bytes, sizeof(ready_bytes) - 1,
                &written, nullptr) || written != sizeof(ready_bytes) - 1 ||
            !FlushFileBuffers(marker.get())) {
            throw std::runtime_error("cannot flush poststage readiness marker");
        }
    }
    if (WaitForSingleObject(stop_event, 120000) != WAIT_TIMEOUT) {
        throw std::runtime_error("poststage gate stopped before forced VM poweroff");
    }
    throw std::runtime_error("poststage gate timed out without VM poweroff");
}

void wait_for_postrename_gate() {
    const std::wstring ready = gate_sibling(L"postrename-ready.txt");
    const std::wstring ready_temp = gate_sibling(L"postrename-ready.tmp");
    const std::wstring release = gate_sibling(L"postrename-release.txt");
    static constexpr char ready_bytes[] = "usk.publisher.lab_renamed_unconfirmed.v1\n";
    static constexpr char release_bytes[] = "usk.publisher.lab_continue_after_rename.v1\n";
    if (GetFileAttributesW(ready.c_str()) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(release.c_str()) != INVALID_FILE_ATTRIBUTES) {
        throw std::runtime_error("postrename gate markers existed before rename");
    }
    {
        OwnedHandle marker(CreateFileW(ready_temp.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (marker.get() == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("cannot create postrename readiness marker");
        }
        DWORD written = 0;
        if (!WriteFile(marker.get(), ready_bytes, sizeof(ready_bytes) - 1,
                &written, nullptr) || written != sizeof(ready_bytes) - 1 ||
            !FlushFileBuffers(marker.get())) {
            throw std::runtime_error("cannot flush postrename readiness marker");
        }
    }
    if (!MoveFileExW(ready_temp.c_str(), ready.c_str(), MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("cannot expose flushed postrename readiness marker");
    }
    for (unsigned attempt = 0; attempt != 1200; ++attempt) {
        OwnedHandle signal(CreateFileW(release.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (signal.get() != INVALID_HANDLE_VALUE) {
            char bytes[sizeof(release_bytes)]{};
            DWORD read = 0;
            if (!ReadFile(signal.get(), bytes, sizeof(bytes), &read, nullptr) ||
                read != sizeof(release_bytes) - 1 ||
                std::string(bytes, read) !=
                    std::string(release_bytes, sizeof(release_bytes) - 1)) {
                throw std::runtime_error("postrename release marker is invalid");
            }
            return;
        }
        if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            throw std::runtime_error("cannot inspect postrename release marker");
        }
        if (WaitForSingleObject(stop_event, 100) != WAIT_TIMEOUT) {
            throw std::runtime_error("postrename gate interrupted");
        }
    }
    throw std::runtime_error("postrename gate timed out");
}

void wait_for_postjournal_gate() {
    const std::wstring ready = gate_sibling(L"postjournal-ready.txt");
    const std::wstring ready_temp = gate_sibling(L"postjournal-ready.tmp");
    const std::wstring release = gate_sibling(L"postjournal-release.txt");
    static constexpr char ready_bytes[] =
        "usk.publisher.lab_visible_recorded.v1\n";
    static constexpr char release_bytes[] =
        "usk.publisher.lab_continue_after_visible_record.v1\n";
    if (GetFileAttributesW(ready.c_str()) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(release.c_str()) != INVALID_FILE_ATTRIBUTES) {
        throw std::runtime_error("postjournal gate markers existed before closure");
    }
    {
        OwnedHandle marker(CreateFileW(ready_temp.c_str(), GENERIC_WRITE, 0,
            nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (marker.get() == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("cannot create postjournal readiness marker");
        }
        DWORD written = 0;
        if (!WriteFile(marker.get(), ready_bytes, sizeof(ready_bytes) - 1,
                &written, nullptr) || written != sizeof(ready_bytes) - 1 ||
            !FlushFileBuffers(marker.get())) {
            throw std::runtime_error("cannot flush postjournal readiness marker");
        }
    }
    if (!MoveFileExW(ready_temp.c_str(), ready.c_str(),
            MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("cannot expose flushed postjournal readiness marker");
    }
    for (unsigned attempt = 0; attempt != 1200; ++attempt) {
        OwnedHandle signal(CreateFileW(release.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (signal.get() != INVALID_HANDLE_VALUE) {
            char bytes[sizeof(release_bytes)]{};
            DWORD read = 0;
            if (!ReadFile(signal.get(), bytes, sizeof(bytes), &read, nullptr) ||
                read != sizeof(release_bytes) - 1 ||
                std::string(bytes, read) !=
                    std::string(release_bytes, sizeof(release_bytes) - 1)) {
                throw std::runtime_error("postjournal release marker is invalid");
            }
            return;
        }
        if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            throw std::runtime_error("cannot inspect postjournal release marker");
        }
        if (WaitForSingleObject(stop_event, 100) != WAIT_TIMEOUT) {
            throw std::runtime_error("postjournal gate interrupted");
        }
    }
    throw std::runtime_error("postjournal gate timed out");
}

std::string ascii(const std::wstring& value) {
    std::string result;
    for (const wchar_t ch : value) {
        if (ch < 32 || ch > 126) throw std::runtime_error("non-ASCII lab service name");
        result.push_back(static_cast<char>(ch));
    }
    return result;
}

std::wstring selected_visible_component(const std::string& target) {
    // Public plans persist generic '/' paths; service configuration may use '\\'.
    // Normalize only separator spelling before checking for dot or duplicate
    // components, so both representations have the same strict path grammar.
    std::filesystem::path path(target);
    path.make_preferred();
    const std::filesystem::path root = path.root_path();
    const std::wstring root_name = root.wstring();
    if (!path.is_absolute() || path.lexically_normal() != path ||
        root_name.size() != 3 || root_name[1] != L':' || root_name[2] != L'\\' ||
        path.parent_path() != root / L"publication" / L"destination") {
        throw std::runtime_error("reviewed target is outside the protected destination parent");
    }
    const std::wstring component = path.filename().wstring();
    if (!usk::platform::windows::is_publisher_canonical_component(component)) {
        throw std::runtime_error("reviewed visible target component is not canonical");
    }
    (void)ascii(component); // The current durable evidence format records ASCII names.
    return component;
}

std::string json_quote(const std::string& value) {
    std::string result = "\"";
    constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char ch : value) {
        if (ch == '\\' || ch == '"') { result.push_back('\\'); result.push_back(static_cast<char>(ch)); }
        else if (ch < 32) {
            result += "\\u00";
            result.push_back(hex[ch >> 4]);
            result.push_back(hex[ch & 15]);
        } else result.push_back(static_cast<char>(ch));
    }
    result.push_back('"');
    return result;
}

std::string json_groups(
    const std::vector<usk::platform::windows::ObservedTokenGroup>& groups) {
    std::string result = "[";
    for (std::size_t index = 0; index < groups.size(); ++index) {
        if (index != 0) result.push_back(',');
        result += "{\"sid\":" + json_quote(groups[index].sid) +
            ",\"attributes\":" + std::to_string(groups[index].attributes) + "}";
    }
    return result + "]";
}

std::string check_directory_dacl(HANDLE directory, DWORD desired_access) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD security_error = GetSecurityInfo(directory, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION,
        nullptr, nullptr, nullptr, nullptr, &descriptor);
    if (security_error != ERROR_SUCCESS) {
        return "security-info=" + std::to_string(security_error);
    }
    HANDLE process_token = nullptr;
    HANDLE check_token = nullptr;
    std::string result;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE,
            &process_token) ||
        !DuplicateToken(process_token, SecurityImpersonation, &check_token)) {
        result = "token=" + std::to_string(GetLastError());
    } else {
        GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
        DWORD requested = desired_access;
        MapGenericMask(&requested, &mapping);
        std::vector<unsigned char> privileges(4096);
        DWORD privilege_bytes = static_cast<DWORD>(privileges.size());
        DWORD granted = 0;
        BOOL allowed = FALSE;
        if (!AccessCheck(descriptor, check_token, requested, &mapping,
                reinterpret_cast<PPRIVILEGE_SET>(privileges.data()),
                &privilege_bytes, &granted, &allowed)) {
            result = "api=" + std::to_string(GetLastError());
        } else {
            result = std::string(allowed ? "allowed" : "denied") +
                ",granted=" + std::to_string(granted);
        }
    }
    if (check_token) CloseHandle(check_token);
    if (process_token) CloseHandle(process_token);
    LocalFree(descriptor);
    return result;
}

std::string observed_dacl_sddl(HANDLE object) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD error = GetSecurityInfo(object, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr,
        &descriptor);
    if (error != ERROR_SUCCESS) return "security-info=" + std::to_string(error);
    LPWSTR sddl = nullptr;
    std::string result;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor,
            SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, nullptr)) {
        result = "sddl=" + std::to_string(GetLastError());
    } else {
        result = ascii(sddl);
    }
    if (sddl) LocalFree(sddl);
    LocalFree(descriptor);
    return result;
}

std::string observed_token_integrity_sid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return "token=" + std::to_string(GetLastError());
    }
    DWORD size = 0;
    (void)GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
    std::string result;
    if (size < sizeof(TOKEN_MANDATORY_LABEL) || size > 4096) {
        result = "size=" + std::to_string(size);
    } else {
        std::vector<unsigned char> buffer(size);
        if (!GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), size, &size)) {
            result = "integrity=" + std::to_string(GetLastError());
        } else {
            LPWSTR sid = nullptr;
            const auto* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.data());
            if (!ConvertSidToStringSidW(label->Label.Sid, &sid)) {
                result = "sid=" + std::to_string(GetLastError());
            } else {
                result = ascii(sid);
                LocalFree(sid);
            }
        }
    }
    CloseHandle(token);
    return result;
}

std::string json_protected_object(
    const usk::platform::windows::PublisherHandleObservation& object) {
    std::string aces = "[";
    for (std::size_t index = 0; index < object.dacl_aces.size(); ++index) {
        if (index) aces.push_back(',');
        const auto& ace = object.dacl_aces[index];
        aces += "{\"type\":" + std::to_string(ace.type) +
            ",\"flags\":" + std::to_string(ace.flags) +
            ",\"access_mask\":" + std::to_string(ace.access_mask) +
            ",\"sid\":" + json_quote(ace.sid) + "}";
    }
    return "{\"file_id\":" + json_quote(object.file_id) +
        ",\"native_name\":" + json_quote(ascii(object.native_name)) +
        ",\"owner_sid\":" + json_quote(object.owner_sid) +
        ",\"dacl_protected\":" +
            std::string(object.dacl_protected ? "true" : "false") +
        ",\"attributes\":" + std::to_string(object.attributes) +
        ",\"reparse_tag\":" + std::to_string(object.reparse_tag) +
        ",\"link_count\":" + std::to_string(object.link_count) +
        ",\"case_sensitive\":" +
            std::string(object.case_sensitive ? "true" : "false") +
        ",\"dacl_aces\":" + aces + "]}";
}

std::string json_volume(
    const usk::platform::windows::PublisherVolumeObservation& volume) {
    return "{\"volume_label\":" + json_quote(ascii(volume.volume_label)) +
        ",\"volume_information_serial\":" +
            std::to_string(volume.volume_information_serial) +
        ",\"file_id_volume_serial\":" +
            std::to_string(volume.file_id_volume_serial) +
        ",\"filesystem_name\":" + json_quote(ascii(volume.filesystem_name)) +
        ",\"maximum_component_length\":" +
            std::to_string(volume.maximum_component_length) +
        ",\"filesystem_flags\":" + std::to_string(volume.filesystem_flags) +
        ",\"remote_protocol_error\":" +
            std::to_string(volume.remote_protocol_error) + "}";
}

std::string json_streams(
    const std::vector<usk::platform::windows::PublisherStreamObservation>& streams) {
    std::string result = "[";
    for (std::size_t index = 0; index < streams.size(); ++index) {
        if (index) result.push_back(',');
        const auto& stream = streams[index];
        result += "{\"name\":" + json_quote(ascii(stream.name)) +
            ",\"size\":" + std::to_string(stream.size) +
            ",\"allocation_size\":" +
            std::to_string(stream.allocation_size) + "}";
        if (result.size() > lab_record_limit) {
            throw std::runtime_error("publisher lab stream evidence exceeds byte budget");
        }
    }
    return result + "]";
}

std::string json_tree(
    const usk::platform::windows::PublisherTreeObservation& tree) {
    std::string entries = "[";
    for (std::size_t index = 0; index < tree.descendants.size(); ++index) {
        const auto& entry = tree.descendants[index];
        if (index) entries.push_back(',');
        entries += "{\"relative_path\":" +
            json_quote(ascii(entry.relative_path)) +
            ",\"object\":" + json_protected_object(entry.object) +
            ",\"size\":" + std::to_string(entry.size) +
            ",\"sha256\":" + json_quote(entry.sha256) +
            ",\"streams\":" + json_streams(entry.streams) + "}";
        if (entries.size() > lab_record_limit) {
            throw std::runtime_error("publisher lab tree evidence exceeds byte budget");
        }
    }
    return "{\"volume\":" + json_volume(tree.volume) +
        ",\"root\":" + json_protected_object(tree.root) +
        ",\"root_streams\":" + json_streams(tree.root_streams) +
        ",\"descendants\":" + entries + "]}";
}

std::string json_anchor_set(
    const usk::platform::windows::PublisherAnchorSetObservation& set) {
    std::string chain = "[";
    for (std::size_t index = 0; index < set.chain.children.size(); ++index) {
        const auto& link = set.chain.children[index];
        if (index) chain.push_back(',');
        chain += "{\"component\":" + json_quote(ascii(link.component)) +
            ",\"object\":" + json_protected_object(link.object) + "}";
        if (chain.size() > lab_record_limit) {
            throw std::runtime_error("publisher lab anchor evidence exceeds byte budget");
        }
    }
    return "{\"volume\":" + json_volume(set.chain.volume) +
        ",\"boundary\":" + json_protected_object(set.chain.boundary) +
        ",\"chain\":" + chain + "]" +
        ",\"staging\":" + json_protected_object(set.staging.object) +
        ",\"destination_parent\":" +
            json_protected_object(set.destination_parent.object) +
        ",\"state\":" + json_protected_object(set.state.object) +
        ",\"journal\":" + json_protected_object(set.journal.object) + "}";
}

std::string canonical_record(const std::string& record) {
    if (record.size() > lab_record_limit) {
        throw std::runtime_error("publisher lab phase evidence exceeds byte budget");
    }
    const std::string canonical =
        usk::json::canonical(usk::json::parse(record)) + "\n";
    if (canonical.size() > lab_record_limit) {
        throw std::runtime_error("canonical publisher lab phase exceeds byte budget");
    }
    return canonical;
}

std::string record_sha256(const std::string& record) {
    usk::base::Sha256 hash;
    hash.update(reinterpret_cast<const unsigned char*>(record.data()), record.size());
    return hash.finish();
}

std::vector<std::pair<std::string, std::string>> phase_object_bindings(
    const usk::json::Value& anchors, const usk::json::Value& tree) {
    const auto& chain = anchors.at("chain").as_array();
    if (chain.size() != 1 || chain.front().at("component").as_string() != "publication") {
        throw std::runtime_error("execution observation requires the bound direct publication chain");
    }
    return {{"volume_root", anchors.at("boundary").at("file_id").as_string()},
        {"publication_root", chain.front().at("object").at("file_id").as_string()},
        {"staging_anchor", anchors.at("staging").at("file_id").as_string()},
        {"destination_parent", anchors.at("destination_parent").at("file_id").as_string()},
        {"state_anchor", anchors.at("state").at("file_id").as_string()},
        {"journal_anchor", anchors.at("journal").at("file_id").as_string()},
        {"payload_root", tree.at("root").at("file_id").as_string()}};
}

void require_same_handle_phase_objects(const usk::json::Value& execution,
    const usk::json::Value& anchors, const usk::json::Value& tree) {
    if (execution.at("schema").as_string() != "usk.publisher_execution_observation.v5" &&
        execution.at("schema").as_string() != "usk.publisher_execution_observation.v6") return;
    const std::vector<const usk::json::Value*> expected{
        &anchors.at("boundary"), &anchors.at("chain").as_array().at(0).at("object"),
        &anchors.at("staging"), &anchors.at("destination_parent"),
        &anchors.at("state"), &anchors.at("journal"), &tree.at("root")};
    const auto& handles = execution.at("handles").as_array();
    if (handles.size() != expected.size()) throw std::runtime_error("same-handle phase object closure differs");
    for (std::size_t index = 0; index < expected.size(); ++index) {
        if (usk::json::canonical(handles[index].at("object_observation")) != usk::json::canonical(*expected[index]))
            throw std::runtime_error("fresh same-handle phase facts differ from the bound anchor or payload root");
    }
}

usk::json::Value capture_native_execution_phase(const std::string& phase,
    const std::vector<HANDLE>& handles,
    const usk::platform::windows::PublisherAnchorSetObservation& anchors,
    const usk::platform::windows::PublisherTreeObservation& tree, bool authenticated_bound = false,
    bool descendants_bound = false) {
    using namespace usk::platform::windows;
    const auto anchor_value = usk::json::parse(json_anchor_set(anchors));
    const auto tree_value = usk::json::parse(json_tree(tree));
    const auto bindings = phase_object_bindings(anchor_value, tree_value);
    if (handles.size() != bindings.size()) {
        throw std::runtime_error("execution observation has incomplete retained handles");
    }
    std::vector<PublisherPhaseHandle> phase_handles;
    for (std::size_t index = 0; index < handles.size(); ++index) {
        phase_handles.push_back({bindings[index].first, handles[index], bindings[index].second});
    }
    if (authenticated_bound && !authenticated_request)
        throw std::runtime_error("authenticated phase requires the live private request channel");
    const auto execution = observe_publisher_execution_phase(service_name, phase, phase_handles,
        authenticated_bound ? authenticated_request : nullptr);
    require_same_handle_phase_objects(execution, anchor_value, tree_value);
    usk::json::Value result(usk::json::Value::Object{
        {"execution", execution},
        {"protected_anchors_sha256", usk::json::Value(usk::json::sha256_canonical(anchor_value))},
        {"tree_sha256", usk::json::Value(usk::json::sha256_canonical(tree_value))}});
    if (descendants_bound) {
        if (!authenticated_bound) throw std::runtime_error("descendant access requires authenticated phase evidence");
        auto access = observe_publisher_authenticated_descendant_access(handles.back(), tree,
            *authenticated_request, execution.at("authenticated_client"));
        require_publisher_authenticated_descendant_access(access, execution.at("authenticated_client"), tree_value);
        const auto after = observe_publisher_execution_phase(service_name, phase, phase_handles, authenticated_request);
        if (usk::json::canonical(execution) != usk::json::canonical(after))
            throw std::runtime_error("authenticated phase bindings changed during descendant access observation");
        result.as_object().emplace("authenticated_descendants", std::move(access));
    }
    return result;
}

void require_native_execution_phase(const usk::json::Value& value,
    const std::string& phase, const std::string& service_sid,
    const usk::json::Value& anchors, const usk::json::Value& tree,
    const std::wstring& expected_service_name, bool descendants_bound = false) {
    if (value.as_object().size() != (descendants_bound ? 4u : 3u) ||
        value.at("protected_anchors_sha256").as_string() != usk::json::sha256_canonical(anchors) ||
        value.at("tree_sha256").as_string() != usk::json::sha256_canonical(tree)) {
        throw std::runtime_error("native execution phase differs from its anchor/tree binding");
    }
    usk::platform::windows::require_publisher_execution_phase(value.at("execution"),
        expected_service_name, service_sid, phase, phase_object_bindings(anchors, tree));
    require_same_handle_phase_objects(value.at("execution"), anchors, tree);
    if (descendants_bound)
        usk::platform::windows::require_publisher_authenticated_descendant_access(
            value.at("authenticated_descendants"), value.at("execution").at("authenticated_client"), tree);
}

std::string json_native_rename_call(
    const usk::platform::windows::PublisherBoundRenameObservation& observed) {
    return canonical_record("{\"schema\":\"usk.publisher_bound_rename_call.v2\","
        "\"api\":\"NtSetInformationFile\",\"source_file_id\":" + json_quote(observed.root_file_id) +
        ",\"destination_parent_file_id\":" + json_quote(observed.destination_parent_file_id) +
        ",\"destination_component\":" + json_quote(ascii(observed.destination_component)) +
        ",\"former_name\":" + json_quote(ascii(observed.former_name)) +
        ",\"visible_name\":" + json_quote(ascii(observed.visible_name)) +
        ",\"destination_absence_status\":" + std::to_string(observed.destination_absence_status) +
        ",\"information_class\":" + std::to_string(observed.information_class) +
        ",\"information_bytes\":" + std::to_string(observed.information_bytes) +
        ",\"file_name_bytes\":" + std::to_string(observed.file_name_bytes) +
        ",\"replace_if_exists\":" + (observed.replace_if_exists ? "true" : "false") +
        ",\"native_status\":" + std::to_string(observed.native_status) +
        ",\"io_status\":" + std::to_string(observed.io_status) +
        ",\"source_granted_access\":" + std::to_string(observed.source_granted_access) +
        ",\"destination_parent_granted_access\":" + std::to_string(observed.destination_parent_granted_access) +
        ",\"handle_access_api\":\"NtQueryObject:ObjectBasicInformation\"" +
        ",\"clock\":\"qpc\",\"start_tick\":" + std::to_string(observed.native_call_start_tick) +
        ",\"end_tick\":" + std::to_string(observed.native_call_end_tick) +
        ",\"frequency\":" + std::to_string(observed.clock_frequency) + "}");
}

void require_native_descendant_continuity(const usk::json::Value& earlier, const usk::json::Value& later) {
    if (earlier.at("execution").at("phase").as_string() == "protected_empty") return;
    const auto& first = earlier.at("authenticated_descendants").at("objects").as_array();
    const auto& second = later.at("authenticated_descendants").at("objects").as_array();
    if (first.size() != second.size()) throw std::runtime_error("authenticated descendant phase closure changed");
    const auto& old_service = earlier.at("execution").at("service");
    const auto& new_service = later.at("execution").at("service");
    const bool same_worker = old_service.at("process_id").as_unsigned() == new_service.at("process_id").as_unsigned() &&
        usk::json::canonical(old_service.at("token_id")) == usk::json::canonical(new_service.at("token_id"));
    for (std::size_t index = 0; index < first.size(); ++index) {
        if (first[index].at("relative_path").as_string() != second[index].at("relative_path").as_string())
            throw std::runtime_error("authenticated descendant phase path changed");
        const auto& before = first[index].at("authenticated_access");
        auto after = second[index].at("authenticated_access");
        for (const auto* key : {"descriptor_api", "descriptor_hex", "observed_group_sid"})
            if (usk::json::canonical(before.at(key)) != usk::json::canonical(after.at(key)))
                throw std::runtime_error("authenticated descendant descriptor changed across phases");
        if (same_worker) {
            // Each object hash was already bound to its exact phase tree; only
            // the expected publication-prefix transition changes that hash.
            after.as_object().at("native_object_sha256") = before.at("native_object_sha256");
            if (usk::json::canonical(before) != usk::json::canonical(after))
                throw std::runtime_error("authenticated descendant access changed within one worker");
        }
    }
}

void require_native_rename_call(const usk::json::Value& call,
    const usk::json::Value& prepared, const usk::json::Value& bound) {
    const auto& component = prepared.at("destination_name").as_string();
    const bool rights_bound = call.at("schema").as_string() == "usk.publisher_bound_rename_call.v2";
    if (call.as_object().size() != (rights_bound ? 21u : 18u) ||
        (!rights_bound && call.at("schema").as_string() != "usk.publisher_bound_rename_call.v1") ||
        ((prepared.at("schema").as_string() == "usk.publisher.lab_phase_evidence.v6" ||
          (prepared.at("schema").as_string() == "usk.publisher.lab_phase_evidence.v7" || is_authenticated_record_schema(prepared.at("schema").as_string()))) && !rights_bound) ||
        call.at("api").as_string() != "NtSetInformationFile" ||
        call.at("source_file_id").as_string() != prepared.at("source_file_id").as_string() ||
        call.at("destination_parent_file_id").as_string() != prepared.at("destination_parent_file_id").as_string() ||
        call.at("destination_component").as_string() != component ||
        call.at("former_name").as_string() != prepared.at("sealed_tree").at("root").at("native_name").as_string() ||
        call.at("visible_name").as_string() != bound.at("visible_tree").at("root").at("native_name").as_string() ||
        call.at("destination_absence_status").as_unsigned() != 0xc0000034u ||
        call.at("information_class").as_unsigned() != 10 ||
        call.at("file_name_bytes").as_unsigned() != component.size() * sizeof(WCHAR) ||
        call.at("information_bytes").as_unsigned() != sizeof(FILE_RENAME_INFO) + component.size() * sizeof(WCHAR) ||
        call.at("replace_if_exists").as_boolean() || call.at("native_status").as_unsigned() != 0 ||
        call.at("io_status").as_unsigned() != 0 || call.at("clock").as_string() != "qpc" ||
        (rights_bound && (call.at("source_granted_access").as_unsigned() > 0xffffffffu ||
        (call.at("source_granted_access").as_unsigned() & DELETE) == 0 ||
        call.at("destination_parent_granted_access").as_unsigned() > 0xffffffffu ||
        (call.at("destination_parent_granted_access").as_unsigned() & FILE_ADD_SUBDIRECTORY) == 0 ||
        call.at("handle_access_api").as_string() != "NtQueryObject:ObjectBasicInformation" ||
        call.at("source_granted_access").as_unsigned() != bound.at("execution_phases").as_array().at(0)
            .at("execution").at("handles").as_array().at(6).at("granted_access").as_unsigned() ||
        call.at("destination_parent_granted_access").as_unsigned() != bound.at("execution_phases").as_array().at(0)
            .at("execution").at("handles").as_array().at(3).at("granted_access").as_unsigned())) ||
        call.at("start_tick").as_unsigned() == 0 ||
        call.at("start_tick").as_unsigned() > 0x7fffffffffffffffULL ||
        call.at("end_tick").as_unsigned() > 0x7fffffffffffffffULL ||
        call.at("frequency").as_unsigned() > 0x7fffffffffffffffULL ||
        call.at("end_tick").as_unsigned() < call.at("start_tick").as_unsigned() ||
        call.at("frequency").as_unsigned() == 0) {
        throw std::runtime_error("retained native rename call differs from its bound objects or arguments");
    }
}

bool is_execution_record_schema(const std::string& schema) {
    return schema == "usk.publisher.lab_phase_evidence.v3" ||
        schema == "usk.publisher.lab_phase_evidence.v4" || schema == "usk.publisher.lab_phase_evidence.v5" ||
        schema == "usk.publisher.lab_phase_evidence.v6" || (schema == "usk.publisher.lab_phase_evidence.v7" || is_authenticated_record_schema(schema));
}

std::size_t visible_record_field_count(const std::string& schema) {
    if (schema == "usk.publisher.lab_phase_evidence.v5" ||
        schema == "usk.publisher.lab_phase_evidence.v6" || (schema == "usk.publisher.lab_phase_evidence.v7" || is_authenticated_record_schema(schema))) return 12;
    return is_execution_record_schema(schema) ? 11 : 9;
}

void require_registered_operation_record(const usk::json::Value& prepared) {
    const auto& admission = prepared.at("operation_admission");
    // Private legacy transports can retain authenticated phase observations;
    // null explicitly retains that narrower scope and cannot qualify a route.
    if (usk::json::canonical(admission) == "null") return;
    const auto& execution = prepared.at("execution_phases").as_array().at(0).at("execution");
    const auto& client = execution.at("authenticated_client");
    const auto& source = prepared.at("source_binding");
    if (admission.as_object().size() != 18 ||
        admission.at("schema").as_string() != "usk.publisher_operation_admission.v1" ||
        admission.at("scope").as_string() != "live_registered_request_and_held_volume_before_effects" ||
        admission.at("route").as_string() != "registered_service_admitted_production" ||
        admission.at("service_name").as_string() != execution.at("service").at("service_name").as_string() ||
        admission.at("service_sid").as_string() != prepared.at("service_sid").as_string() ||
        admission.at("service_process_id").as_unsigned() != execution.at("service").at("process_id").as_unsigned() ||
        admission.at("configured_caller_sid").as_string() != client.at("user_sid").as_string() ||
        admission.at("captured_client_process_id").as_unsigned() != client.at("captured_process_id").as_unsigned() ||
        admission.at("authenticated_client_sha256").as_string() != usk::json::sha256_canonical(client) ||
        admission.at("root_file_id").as_string() != prepared.at("protected_anchors").at("boundary").at("file_id").as_string() ||
        admission.at("volume_serial").as_unsigned() != prepared.at("volume_serial").as_unsigned() ||
        admission.at("reviewed_plan_digest").as_string() != source.at("reviewed_plan_digest").as_string() ||
        admission.at("reviewed_plan_snapshot_sha256").as_string() != source.at("reviewed_plan_snapshot_sha256").as_string() ||
        !usk::record_io::valid_identifier(admission.at("transaction_id").as_string()))
        throw std::runtime_error("registered operation admission differs from its native phase, target or reviewed source");
    for (const auto* key : {"registration_sha256", "target_admitted_sha256", "publisher_image_sha256"})
        if (!lower_sha256_ascii(admission.at(key).as_string()))
            throw std::runtime_error("registered operation admission has malformed provenance digests");
    const auto& guid = admission.at("volume_guid_root").as_string();
    if (guid.size() != 49 || guid.compare(0, 11, "\\\\?\\Volume{") != 0 || guid.compare(47, 2, "}\\") != 0)
        throw std::runtime_error("registered operation admission volume GUID differs");
    for (std::size_t index = 11; index < 47; ++index) {
        const char ch = guid[index];
        const bool separator = index == 19 || index == 24 || index == 29 || index == 34;
        if (separator ? ch != '-' : !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')))
            throw std::runtime_error("registered operation admission has a malformed volume GUID");
    }
}

void require_prepared_execution_phases(const usk::json::Value& prepared,
    const std::string& service_sid, const std::wstring& expected_service_name = service_name) {
    const auto& schema = prepared.at("schema").as_string();
    const bool creation_bound = schema == "usk.publisher.lab_phase_evidence.v4" ||
        schema == "usk.publisher.lab_phase_evidence.v5" || schema == "usk.publisher.lab_phase_evidence.v6" ||
        (schema == "usk.publisher.lab_phase_evidence.v7" || is_authenticated_record_schema(schema));
    const bool authenticated_bound = is_authenticated_record_schema(schema);
    if (!is_execution_record_schema(schema)) {
        if (prepared.contains("execution_phases") || prepared.contains("execution_origin") ||
            prepared.contains("creation_evidence") || prepared.contains("operation_admission")) {
            throw std::runtime_error("legacy prepared record cannot claim native execution phases");
        }
        return;
    }
    if (prepared.as_object().size() != (authenticated_bound ? 15u : creation_bound ? 14u : 13u) ||
        (!creation_bound && prepared.contains("creation_evidence"))) {
        throw std::runtime_error("native prepared record is not its closed execution schema");
    }
    const auto& phases = prepared.at("execution_phases").as_array();
    if (schema == "usk.publisher.lab_phase_evidence.v6" || (schema == "usk.publisher.lab_phase_evidence.v7" || is_authenticated_record_schema(schema))) {
        for (const auto& phase : phases) {
            const auto& execution_schema = phase.at("execution").at("schema").as_string();
            if ((execution_schema != "usk.publisher_execution_observation.v4" &&
                 execution_schema != "usk.publisher_execution_observation.v5" &&
                 execution_schema != "usk.publisher_execution_observation.v6") ||
                (schema == "usk.publisher.lab_phase_evidence.v7" && execution_schema != "usk.publisher_execution_observation.v5") ||
                (authenticated_bound && execution_schema != "usk.publisher_execution_observation.v6") ||
                (!authenticated_bound && execution_schema == "usk.publisher_execution_observation.v6"))
                throw std::runtime_error("current native prepared evidence requires held-handle rights");
        }
    }
    const auto& origin = prepared.at("execution_origin").as_string();
    const bool fresh = origin == "created_empty_in_current_worker";
    if ((!fresh && origin != "reopened_staged_tree") || phases.size() != (fresh ? 3u : 2u)) {
        throw std::runtime_error("native prepared phase origin or sequence is incomplete");
    }
    auto empty_tree = prepared.at("sealed_tree");
    empty_tree.as_object().at("descendants") = usk::json::Value(usk::json::Value::Array{});
    if (fresh) require_native_execution_phase(phases[0], "protected_empty", service_sid,
        prepared.at("protected_anchors"), empty_tree, expected_service_name, schema == "usk.publisher.lab_phase_evidence.v9");
    const std::size_t sealed_index = fresh ? 1u : 0u;
    require_native_execution_phase(phases[sealed_index], "sealed", service_sid,
        prepared.at("protected_anchors"), prepared.at("sealed_tree"), expected_service_name, schema == "usk.publisher.lab_phase_evidence.v9");
    require_native_execution_phase(phases[sealed_index + 1], "publish_prepared", service_sid,
        prepared.at("protected_anchors"), prepared.at("sealed_tree"), expected_service_name, schema == "usk.publisher.lab_phase_evidence.v9");
    for (std::size_t index = 1; index < phases.size(); ++index) {
        usk::platform::windows::require_publisher_execution_worker_match(
            phases[index - 1].at("execution"), phases[index].at("execution"));
        if (schema == "usk.publisher.lab_phase_evidence.v9")
            require_native_descendant_continuity(phases[index - 1], phases[index]);
    }
    if (creation_bound) {
        if (!fresh) throw std::runtime_error("reopened staging cannot claim current-worker creation evidence");
        usk::platform::windows::require_publisher_creation_certificate(prepared.at("creation_evidence"),
            prepared.at("protected_anchors"), prepared.at("sealed_tree"), phases.front().at("execution"));
    }
    if (authenticated_bound) require_registered_operation_record(prepared);
}

void require_visible_execution_phase(const usk::json::Value& bound,
    const std::string& service_sid, const usk::json::Value& prepared,
    const std::wstring& expected_service_name = service_name) {
    if (is_execution_record_schema(bound.at("schema").as_string())) {
        const bool authenticated_bound = is_authenticated_record_schema(bound.at("schema").as_string());
        const bool metadata_bound = (bound.at("schema").as_string() == "usk.publisher.lab_phase_evidence.v7" || is_authenticated_record_schema(bound.at("schema").as_string()));
        const bool rights_bound = metadata_bound || bound.at("schema").as_string() == "usk.publisher.lab_phase_evidence.v6";
        const bool rename_bound = rights_bound || bound.at("schema").as_string() == "usk.publisher.lab_phase_evidence.v5";
        if (bound.as_object().size() != visible_record_field_count(bound.at("schema").as_string()) ||
            bound.at("schema").as_string() != prepared.at("schema").as_string()) {
            throw std::runtime_error("native visible record differs from its closed prepared execution schema");
        }
        const auto& phases = bound.at("execution_phases").as_array();
        if (rights_bound) {
            for (const auto& phase : phases) {
                const auto& execution_schema = phase.at("execution").at("schema").as_string();
                if ((execution_schema != "usk.publisher_execution_observation.v4" &&
                     execution_schema != "usk.publisher_execution_observation.v5" &&
                     execution_schema != "usk.publisher_execution_observation.v6") ||
                    (metadata_bound && !authenticated_bound && execution_schema != "usk.publisher_execution_observation.v5") ||
                    (authenticated_bound && execution_schema != "usk.publisher_execution_observation.v6") ||
                    (!authenticated_bound && execution_schema == "usk.publisher_execution_observation.v6"))
                    throw std::runtime_error("current native visible evidence requires held-handle rights");
            }
        }
        const auto& transition = bound.at("execution_transition").as_string();
        const bool renamed = transition == "renamed_by_current_worker";
        if ((!renamed && transition != "observed_visible_on_restart") ||
            phases.size() != (renamed ? 2u : 1u)) {
            throw std::runtime_error("native visible phase transition or sequence is incomplete");
        }
        if (rename_bound) {
            if (renamed) require_native_rename_call(bound.at("rename_call"), prepared, bound);
            else if (usk::json::canonical(bound.at("rename_call")) != "null")
                throw std::runtime_error("restart observation cannot claim an unobserved native rename call");
        }
        if (renamed) {
            // The retained pre-rename tree keeps its original native names.
            // It is checked against the prepared seal by the surrounding reader.
            require_native_execution_phase(phases[0], "before_rename", service_sid,
                bound.at("protected_anchors"), prepared.at("sealed_tree"), expected_service_name, bound.at("schema").as_string() == "usk.publisher.lab_phase_evidence.v9");
            usk::platform::windows::require_publisher_execution_worker_match(
                phases[0].at("execution"), phases[1].at("execution"));
            if (bound.at("schema").as_string() == "usk.publisher.lab_phase_evidence.v9")
                require_native_descendant_continuity(phases[0], phases[1]);
        }
        require_native_execution_phase(phases.back(), "visible_bound", service_sid,
            bound.at("protected_anchors"), bound.at("visible_tree"), expected_service_name, bound.at("schema").as_string() == "usk.publisher.lab_phase_evidence.v9");
        const auto& prepared_phases = prepared.at("execution_phases").as_array();
        if (prepared_phases.empty()) throw std::runtime_error("prepared native execution record is empty");
        usk::platform::windows::require_publisher_execution_record_continuity(
            prepared_phases.back().at("execution"), phases.front().at("execution"));
        if (bound.at("schema").as_string() == "usk.publisher.lab_phase_evidence.v9")
            require_native_descendant_continuity(prepared_phases.back(), phases.front());
    } else if (bound.contains("execution_phases") || bound.contains("execution_transition") || bound.contains("rename_call")) {
        throw std::runtime_error("legacy visible record cannot claim a native execution phase");
    }
}

std::string selected_file_set_digest(
    std::vector<usk::platform::windows::PublisherExpectedFile> files) {
    if (files.empty() || files.size() > 4096) {
        throw std::runtime_error("selected file set count is invalid");
    }
    std::sort(files.begin(), files.end(), [](const auto& left, const auto& right) {
        const int order = CompareStringOrdinal(left.relative_path.data(),
            static_cast<int>(left.relative_path.size()), right.relative_path.data(),
            static_cast<int>(right.relative_path.size()), TRUE);
        if (order == 0 || order == CSTR_EQUAL) {
            throw std::runtime_error("selected file set has an alias");
        }
        return order == CSTR_LESS_THAN;
    });
    std::string document =
        "{\"schema\":\"usk.publisher.lab_selected_file_set.v1\",\"files\":[";
    for (std::size_t index = 0; index < files.size(); ++index) {
        const auto& file = files[index];
        if (index) document.push_back(',');
        document += "{\"relative_path\":" + json_quote(ascii(file.relative_path)) +
            ",\"size\":" + std::to_string(file.size) +
            ",\"sha256\":" + json_quote(file.sha256) + "}";
        if (document.size() > lab_record_limit) {
            throw std::runtime_error("selected file set exceeds lab record budget");
        }
    }
    return record_sha256(canonical_record(document + "]}"));
}

std::string selected_file_set_digest(
    const usk::platform::windows::PublisherTreeObservation& tree) {
    std::vector<usk::platform::windows::PublisherExpectedFile> files;
    for (const auto& entry : tree.descendants) {
        if ((entry.object.attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            files.push_back({entry.relative_path, entry.size, entry.sha256});
        }
    }
    return selected_file_set_digest(std::move(files));
}

void write_journal_phase(HANDLE journal, const std::wstring& name,
    const std::vector<unsigned char>& descriptor, const std::string& record) {
    if (record != canonical_record(record)) {
        throw std::runtime_error("publisher lab phase record is not canonical");
    }
    {
        OwnedHandle file(usk::platform::windows::create_file_relative_with_descriptor(
            journal, name, descriptor));
        DWORD written = 0;
        usk::platform::windows::require_current_publisher_effect_fence();
        if (record.size() > MAXDWORD ||
            !WriteFile(file.get(), record.data(), static_cast<DWORD>(record.size()),
                &written, nullptr) || written != record.size() ||
            !FlushFileBuffers(file.get())) {
            throw std::runtime_error("publisher lab journal phase write or flush failed");
        }
    }
    HANDLE reopened = INVALID_HANDLE_VALUE;
    for (const auto& listed :
            usk::platform::windows::observe_publisher_directory_entries(journal)) {
        if (listed.name == name) {
            if (reopened != INVALID_HANDLE_VALUE) {
                CloseHandle(reopened);
                throw std::runtime_error("duplicate publisher lab phase record");
            }
            reopened = usk::platform::windows::open_publisher_listed_child(
                journal, listed);
        }
    }
    if (reopened == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("publisher lab phase record not listed after flush");
    }
    OwnedHandle readback(reopened);
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(readback.get(), &size) || size.QuadPart < 0 ||
        static_cast<unsigned long long>(size.QuadPart) != record.size()) {
        throw std::runtime_error("publisher lab phase record size changed");
    }
    std::string stored(record.size(), '\0');
    DWORD read = 0;
    if (!ReadFile(readback.get(), stored.data(),
            static_cast<DWORD>(stored.size()), &read, nullptr) ||
        read != stored.size() || stored != record ||
        stored != canonical_record(stored)) {
        throw std::runtime_error("publisher lab phase record readback differs");
    }
}

HANDLE open_exact_lab_child(HANDLE parent, const std::wstring& name,
    bool require_add_subdirectory = false, bool require_delete = false,
    bool require_add_file = false, bool require_write_dac = false) {
    HANDLE result = INVALID_HANDLE_VALUE;
    for (const auto& listed :
            usk::platform::windows::observe_publisher_directory_entries(parent)) {
        if (listed.name != name) continue;
        if (result != INVALID_HANDLE_VALUE) {
            CloseHandle(result);
            throw std::runtime_error("duplicate recovery child listing");
        }
        result = usk::platform::windows::open_publisher_listed_child(
            parent, listed, require_add_subdirectory, require_delete,
            require_add_file, require_write_dac);
    }
    if (result == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("required recovery child is absent");
    }
    return result;
}

bool recovery_journal_has_visible_record(HANDLE parent) {
    const auto listed =
        usk::platform::windows::observe_publisher_directory_entries(parent);
    bool prepared = false;
    bool reviewed = false;
    bool visible = false;
    for (const auto& entry : listed) {
        if (entry.name == L"lab-prepared-evidence.json") prepared = true;
        else if (entry.name == L"lab-reviewed-plan.json") reviewed = true;
        else if (entry.name == L"lab-visible-evidence.json") visible = true;
        else throw std::runtime_error("recovery journal has unexpected children");
    }
    if (prepared && listed.size() == 1u + (reviewed ? 1u : 0u) +
            (visible ? 1u : 0u)) return visible;
    throw std::runtime_error("recovery journal has unexpected children");
}

bool recovery_journal_has_snapshot_only(HANDLE volume,
    const std::string& service_sid) {
    using namespace usk::platform::windows;
    const PublisherAnchorNames names{
        L"staging", L"destination", L"state", L"journal"};
    const auto anchors = observe_publisher_anchor_set(
        volume, {L"publication"}, names);
    require_publisher_anchor_set_security_shape(anchors, service_sid);
    OwnedHandle publication(open_exact_lab_child(volume, L"publication"));
    if (observe_publisher_directory_entries(publication.get()).size() != 4) {
        throw std::runtime_error("recovery publication has unexpected anchors");
    }
    OwnedHandle journal(open_exact_lab_child(publication.get(), L"journal"));
    const auto listed = observe_publisher_directory_entries(journal.get());
    return listed.size() == 1 && listed.front().name == L"lab-reviewed-plan.json";
}

bool recovery_state_has_completion_record(HANDLE parent) {
    const auto listed =
        usk::platform::windows::observe_publisher_directory_entries(parent);
    if (listed.empty()) return false;
    if (listed.size() == 1 && listed.front().name == L"lab-installed-state.json") {
        return true;
    }
    throw std::runtime_error("recovery state has unexpected children");
}

std::string read_phase_record(HANDLE journal, const std::wstring& name) {
    if (name != L"lab-prepared-evidence.json" &&
        name != L"lab-reviewed-plan.json" &&
        name != L"lab-visible-evidence.json" &&
        name != L"lab-installed-state.json") {
        throw std::runtime_error("invalid recovery phase record name");
    }
    OwnedHandle file(open_exact_lab_child(journal, name));
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.get(), &size) || size.QuadPart <= 0 ||
        static_cast<unsigned long long>(size.QuadPart) > lab_record_limit) {
        throw std::runtime_error("recovery phase record exceeds byte budget");
    }
    std::string stored(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    if (!ReadFile(file.get(), stored.data(), static_cast<DWORD>(stored.size()),
            &read, nullptr) || read != stored.size() ||
        stored != canonical_record(stored)) {
        throw std::runtime_error("recovery phase record is not canonical");
    }
    return stored;
}

void require_reviewed_plan_snapshot(const std::string& record,
    const usk::json::Value& prepared, const std::string& selected_digest) {
    const auto snapshot = usk::json::parse(record);
    const std::wstring selected_name =
        selected_visible_component(snapshot.at("target_root").as_string());
    const auto& binding = prepared.at("source_binding");
    const std::string schema = snapshot.at("schema").as_string();
    const bool consumer_bound = schema == "usk.publisher.lab_reviewed_plan_snapshot.v4";
    const bool caller_bound = consumer_bound || schema == "usk.publisher.lab_reviewed_plan_snapshot.v3";
    const bool finalization_context = caller_bound ||
        schema == "usk.publisher.lab_reviewed_plan_snapshot.v2";
    if ((!finalization_context && schema !=
            "usk.publisher.lab_reviewed_plan_snapshot.v1") ||
        snapshot.as_object().size() != (consumer_bound ? 17u : caller_bound ? 16u : finalization_context ? 15u : 10u) ||
        record_sha256(record) !=
            binding.at("reviewed_plan_snapshot_sha256").as_string() ||
        snapshot.at("plan_digest").as_string() !=
            binding.at("reviewed_plan_digest").as_string() ||
        snapshot.at("plan_envelope_sha256").as_string() !=
            binding.at("plan_envelope_sha256").as_string() ||
        snapshot.at("archive_sha256").as_string() !=
            binding.at("archive_sha256").as_string() ||
        snapshot.at("archive_identity_digest").as_string() !=
            binding.at("archive_identity_digest").as_string() ||
        snapshot.at("entry_set_digest").as_string() !=
            binding.at("entry_set_digest").as_string() ||
        snapshot.at("selected_file_set_digest").as_string() != selected_digest ||
        prepared.at("destination_name").as_string() != ascii(selected_name) ||
        std::filesystem::path(snapshot.at("target_root").as_string())
            .lexically_normal().generic_u8string() !=
        std::filesystem::path(snapshot.at("plan_request").at("target")
            .at("root").as_string()).lexically_normal().generic_u8string() ||
        snapshot.at("archive_sha256").as_string() !=
            snapshot.at("plan_request").at("archive")
                .at("expected_sha256").as_string() ||
        snapshot.at("plan_request").at("required_commit_authority")
            .as_string() != "staged_child_bound_v1") {
        throw std::runtime_error("recovery reviewed plan snapshot identity differs");
    }
    if (finalization_context) {
        const auto context = usk::json::parse(
            snapshot.at("restart_policy_context").as_string());
        if (snapshot.at("setup_root").as_string().empty() ||
            (!caller_bound && snapshot.at("transaction_id").as_string() !=
                "labpub." + snapshot.at("plan_digest").as_string().substr(0, 32)) ||
            snapshot.at("applied_at").as_string().empty() ||
            snapshot.at("policy_digest").as_string() !=
                usk::json::sha256_canonical(context.at("policy"))) {
            throw std::runtime_error("recovery finalization policy context differs");
        }
        usk::lifecycle::require_candidate_snapshot_apply_binding(snapshot);
    }
    std::vector<usk::platform::windows::PublisherExpectedFile> files;
    for (const auto& entry : snapshot.at("planned_entries").as_array()) {
        const std::string kind = entry.at("entry_type").as_string();
        if (kind == "file") {
            files.push_back({selected_utf8_path(entry.at("relative_path").as_string()),
                entry.at("size_bytes").as_unsigned(),
                entry.at("sha256").as_string()});
        } else if (kind != "directory") {
            throw std::runtime_error("recovery reviewed plan has an unsupported entry");
        }
    }
    if (selected_file_set_digest(std::move(files)) != selected_digest) {
        throw std::runtime_error("recovery reviewed plan file closure differs");
    }
    visible_component = selected_name;
}

usk::lifecycle::InstallPlan restore_reviewed_install_plan(
    const std::string& record) {
    const auto snapshot = usk::json::parse(record);
    if (snapshot.at("schema").as_string() != "usk.publisher.lab_reviewed_plan_snapshot.v2" &&
        snapshot.at("schema").as_string() != "usk.publisher.lab_reviewed_plan_snapshot.v3" &&
        snapshot.at("schema").as_string() != "usk.publisher.lab_reviewed_plan_snapshot.v4") {
        throw std::runtime_error("protected public finalization requires a v2 plan snapshot");
    }
    usk::lifecycle::require_candidate_snapshot_apply_binding(snapshot);
    const auto& request = snapshot.at("plan_request");
    const auto& recipe = request.at("recipe");
    const std::filesystem::path setup_root(snapshot.at("setup_root").as_string());
    usk::lifecycle::RecipeBinding binding;
    binding.product_id = recipe.at("product_id").as_string();
    binding.product_version = recipe.at("product_version").as_string();
    binding.recipe_digest = recipe.at("recipe_digest").as_string();
    binding.source_archive_digest = snapshot.at("archive_sha256").as_string();
    binding.source_identity_digest = snapshot.at("archive_identity_digest").as_string();
    binding.entry_set_digest = snapshot.at("entry_set_digest").as_string();
    binding.policy_digest = snapshot.at("policy_digest").as_string();
    binding.restart_policy_context =
        snapshot.at("restart_policy_context").as_string();
    binding.provider_revision = recipe.at("provider_revision").as_string();
    for (const auto& component : recipe.at("components").as_array()) {
        binding.components.push_back(component.as_string());
    }
    for (const auto& entry : recipe.at("entrypoints").as_array()) {
        binding.entrypoints.push_back({entry.at("entrypoint_id").as_string(),
            entry.at("relative_path").as_string(), entry.at("kind").as_string()});
    }
    std::vector<usk::lifecycle::PayloadFile> files;
    for (const auto& entry : snapshot.at("planned_entries").as_array()) {
        if (entry.at("entry_type").as_string() != "file") continue;
        usk::lifecycle::PayloadFile file;
        file.relative_path = entry.at("relative_path").as_string();
        file.size_bytes = entry.at("size_bytes").as_unsigned();
        file.sha256 = entry.at("sha256").as_string();
        file.reader = [](std::uint64_t, unsigned char*, std::size_t) -> std::size_t {
            throw std::runtime_error("protected finalization may not reopen payload source");
        };
        files.push_back(std::move(file));
    }
    auto plan = usk::lifecycle::plan_install(request.at("request_id").as_string(),
        request.at("install_id").as_string(), request.at("created_at").as_string(),
        snapshot.at("target_root").as_string(),
        {setup_root / "staging", setup_root / "state", setup_root / "audit"},
        std::move(binding), std::move(files), [] {
            throw std::runtime_error("protected finalization has no source replay authority");
        }, usk::transaction::CommitAuthorityRequirement::staged_child_bound_v1);
    if (plan.plan_digest != snapshot.at("plan_digest").as_string()) {
        throw std::runtime_error("restored protected install plan digest differs");
    }
    return plan;
}

ReviewedPlanBinding reviewed_plan_from_retained_snapshot(const std::string& record, bool require_request_binding);

ReviewedPlanBinding reviewed_plan_from_protected_snapshot(HANDLE volume,
    const std::string& service_sid, bool require_request_binding, bool snapshot_only) {
    using namespace usk::platform::windows;
    const PublisherAnchorNames names{
        L"staging", L"destination", L"state", L"journal"};
    const auto anchors = observe_publisher_anchor_set(
        volume, {L"publication"}, names);
    require_publisher_anchor_set_security_shape(anchors, service_sid);
    OwnedHandle publication(open_exact_lab_child(volume, L"publication"));
    OwnedHandle journal(open_exact_lab_child(publication.get(), L"journal"));
    if (snapshot_only && !recovery_journal_has_snapshot_only(volume, service_sid)) {
        throw std::runtime_error("recovery snapshot-only journal changed");
    }
    const auto journal_tree = observe_publisher_tree(journal.get());
    require_publisher_tree_security_shape(journal_tree, service_sid);
    const auto snapshot_entry = std::find_if(journal_tree.descendants.begin(), journal_tree.descendants.end(),
        [](const auto& entry) { return entry.relative_path == L"lab-reviewed-plan.json"; });
    if (journal_tree.root.file_id != anchors.journal.object.file_id ||
        journal_tree.descendants.empty() || journal_tree.descendants.size() > 3 ||
        (snapshot_only && journal_tree.descendants.size() != 1) || snapshot_entry == journal_tree.descendants.end()) {
        throw std::runtime_error("recovery snapshot file identity or security differs");
    }
    const std::string record = read_phase_record(
        journal.get(), L"lab-reviewed-plan.json");
    for (const auto& entry : journal_tree.descendants) {
        if ((entry.object.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
            (entry.relative_path != L"lab-reviewed-plan.json" && entry.relative_path != L"lab-prepared-evidence.json" &&
                entry.relative_path != L"lab-visible-evidence.json"))
            throw std::runtime_error("recovery journal closure differs");
    }
    if (snapshot_entry->size != record.size() || snapshot_entry->sha256 != record_sha256(record)) {
        throw std::runtime_error("recovery snapshot bytes changed during observation");
    }
    const auto journal_reobserved = observe_publisher_tree(journal.get());
    require_publisher_tree_security_shape(journal_reobserved, service_sid);
    require_publisher_tree_phase_match(journal_tree, journal_reobserved);
    return reviewed_plan_from_retained_snapshot(record, require_request_binding);
}

ReviewedPlanBinding reviewed_plan_from_retained_snapshot(const std::string& record, bool require_request_binding) {
    using namespace usk::platform::windows;
    const auto snapshot = usk::json::parse(record);
    const bool consumer_bound=snapshot.at("schema").as_string() == "usk.publisher.lab_reviewed_plan_snapshot.v4";
    const bool caller_bound=consumer_bound || snapshot.at("schema").as_string() == "usk.publisher.lab_reviewed_plan_snapshot.v3";
    if ((!caller_bound && snapshot.at("schema").as_string() !=
            "usk.publisher.lab_reviewed_plan_snapshot.v2") ||
        snapshot.as_object().size() != (consumer_bound ? 17u : caller_bound ? 16u : 15u) ||
        !lower_sha256_ascii(snapshot.at("plan_envelope_sha256").as_string()) ||
        !lower_sha256_ascii(snapshot.at("archive_sha256").as_string()) ||
        snapshot.at("plan_request").at("archive")
            .at("expected_sha256").as_string() !=
                snapshot.at("archive_sha256").as_string() ||
        snapshot.at("plan_request").at("required_commit_authority")
            .as_string() != "staged_child_bound_v1" ||
        std::filesystem::path(snapshot.at("plan_request").at("target")
            .at("root").as_string()).lexically_normal() !=
        std::filesystem::path(snapshot.at("target_root").as_string())
            .lexically_normal()) {
        throw std::runtime_error("recovery protected snapshot identity differs");
    }
    if (require_request_binding &&
        (snapshot.at("plan_envelope_sha256").as_string() !=
            reviewed_plan_envelope_sha256 ||
         snapshot.at("archive_sha256").as_string() !=
            selected_archive_sha256)) {
        throw StaleReviewedInstallRequest();
    }
    auto plan = restore_reviewed_install_plan(record);
    usk::archive::StreamingStoredArchivePayload payload;
    payload.source_sha256 = snapshot.at("archive_sha256").as_string();
    payload.source_identity_digest =
        snapshot.at("archive_identity_digest").as_string();
    payload.entry_set_digest = snapshot.at("entry_set_digest").as_string();
    std::vector<PublisherExpectedFile> expected;
    for (const auto& entry : snapshot.at("planned_entries").as_array()) {
        const std::string kind = entry.at("entry_type").as_string();
        if (kind == "directory") continue;
        if (kind != "file") {
            throw std::runtime_error("snapshot-only plan has unsupported entry");
        }
        const std::string path = entry.at("relative_path").as_string();
        const std::uint64_t size = entry.at("size_bytes").as_unsigned();
        const std::string sha = entry.at("sha256").as_string();
        expected.push_back({selected_utf8_path(path), size, sha});
        payload.files.push_back({path, sha, 0, size,
            [](std::uint64_t, unsigned char*, std::size_t) -> std::size_t {
                throw std::runtime_error("snapshot-only replay may not reopen source");
            }, "stored"});
    }
    if (selected_file_set_digest(std::move(expected)) !=
            snapshot.at("selected_file_set_digest").as_string()) {
        throw std::runtime_error("snapshot-only selected file set differs");
    }
    payload.validate_source = [] {};
    const std::string setup_root = snapshot.at("setup_root").as_string();
    const std::string acceptance_root =
        std::filesystem::path(setup_root).root_path().u8string();
    if (acceptance_root.empty() ||
        std::filesystem::path(setup_root).lexically_normal() !=
            std::filesystem::path(acceptance_root) / "setup-state") {
        throw std::runtime_error("snapshot-only setup root is outside lab profile");
    }
    const std::wstring selected_name =
        selected_visible_component(snapshot.at("target_root").as_string());
    const std::string expected_target =
        (std::filesystem::path(acceptance_root) / L"publication" /
            L"destination" / selected_name).lexically_normal().generic_u8string();
    if (std::filesystem::path(snapshot.at("target_root").as_string())
            .lexically_normal().generic_u8string() != expected_target) {
        throw std::runtime_error("snapshot-only target differs from the reviewed acceptance root");
    }
    visible_component = selected_name;
    return {snapshot.at("plan_digest").as_string(),
        snapshot.at("plan_envelope_sha256").as_string(),
        snapshot.at("selected_file_set_digest").as_string(), record,
        setup_root, acceptance_root,
        snapshot.at("transaction_id").as_string(),
        snapshot.at("applied_at").as_string(), std::move(plan),
        std::move(payload)};
}

ReviewedPlanBinding reviewed_plan_from_snapshot_only(HANDLE volume,
    const std::string& service_sid, bool require_request_binding = true) {
    return reviewed_plan_from_protected_snapshot(volume, service_sid, require_request_binding, true);
}

void require_public_mount_mapping(HANDLE volume, const std::string& setup_root,
    const std::string& target_root) {
    FILE_ID_INFO held{};
    if (!GetFileInformationByHandleEx(volume, FileIdInfo, &held, sizeof(held))) {
        throw std::runtime_error("held publisher volume identity is unavailable");
    }
    for (const std::string& path : {setup_root, target_root}) {
        const std::wstring drive =
            std::filesystem::path(path).root_name().wstring() + L"\\";
        wchar_t mapped[128]{};
        if (drive.size() != 3 || drive[1] != L':' ||
            !GetVolumeNameForVolumeMountPointW(drive.c_str(), mapped,
                static_cast<DWORD>(std::size(mapped))) ||
            CompareStringOrdinal(mapped, -1, volume_root.c_str(), -1,
                TRUE) != CSTR_EQUAL) {
            throw std::runtime_error("public install path is not mapped to held publisher volume");
        }
    }
}

usk::json::Value admit_current_registered_operation(HANDLE volume, const std::string& service_sid,
    const std::string& setup_root, const std::string& target_root, const std::string& plan_digest,
    const std::string& durable_snapshot, const std::string& transaction_id) {
    using namespace usk::platform::windows;
    using usk::json::Value;
    if (!registered_admission || !authenticated_request)
        throw std::runtime_error("registered operation requires the held host admission and authenticated channel");
    if (!publisher_registered_execution_platform_qualified(observe_publisher_execution_platform()))
        throw usk::transaction::CommitAuthorityUnavailable();
    const auto registration = registered_admission->evidence();
    const auto observed = observe_current_restricted_publisher_service(service_name);
    const auto volume_facts = observe_local_ntfs_volume_handle(volume);
    const auto root = observe_publisher_directory_handle(volume);
    require_publisher_object_security_shape(root, service_sid);
    const auto& target = registration.at("target_identity").at("volume_identity");
    if (registration.at("service_name").as_string() != ascii(service_name) ||
        registration.at("service_sid").as_string() != service_sid || observed.service_sid != service_sid ||
        registration.at("process_id").as_unsigned() != observed.process_id ||
        target.at("volume_root").as_string() != ascii(volume_root) ||
        target.at("root_file_id").as_string() != root.file_id ||
        target.at("volume_serial").as_string() != std::to_string(volume_facts.file_id_volume_serial))
        throw std::runtime_error("registered operation lost its live service or held target identity");
    auto access = authenticated_request->observe_authenticated_object_access(volume);
    const auto client = access.at("client");
    if (client.at("user_sid").as_string() != registration.at("configured_caller_sid").as_string() ||
        usk::json::canonical(access.at("native_object")) != usk::json::canonical(publisher_handle_observation_json(root)))
        throw std::runtime_error("registered operation caller or held volume security changed");
    access.as_object().erase("client");
    access.as_object().erase("native_object");
    access.as_object().emplace("client_sha256", Value(usk::json::sha256_canonical(client)));
    access.as_object().emplace("native_object_sha256", Value(usk::json::sha256_canonical(publisher_handle_observation_json(root))));
    require_publisher_authenticated_object_access(access, client, publisher_handle_observation_json(root));
    constexpr DWORD mutation_mask = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD |
        FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER;
    for (const auto& [name, check] : access.at("checks").as_object())
        if (name == "maximum_allowed" ? (check.at("granted").as_unsigned() & mutation_mask) != 0 :
            check.at("allowed").as_boolean() || check.at("granted").as_unsigned() != 0)
            throw std::runtime_error("registered operation caller retains mutation access to the volume boundary");
    require_public_mount_mapping(volume, setup_root, target_root);
    return Value(Value::Object{
        {"schema", Value("usk.publisher_operation_admission.v1")},
        {"scope", Value("live_registered_request_and_held_volume_before_effects")},
        {"route", Value("registered_service_admitted_production")},
        {"service_name", registration.at("service_name")}, {"service_sid", registration.at("service_sid")},
        {"service_process_id", registration.at("process_id")},
        {"configured_caller_sid", registration.at("configured_caller_sid")},
        {"authenticated_client_sha256", Value(usk::json::sha256_canonical(client))},
        {"captured_client_process_id", client.at("captured_process_id")},
        {"registration_sha256", registration.at("registration_sha256")},
        {"target_admitted_sha256", registration.at("target_admitted_sha256")},
        {"publisher_image_sha256", registration.at("publisher_image").at("sha256")},
        {"volume_guid_root", target.at("volume_root")}, {"root_file_id", target.at("root_file_id")},
        {"volume_serial", Value(volume_facts.file_id_volume_serial)}, {"reviewed_plan_digest", Value(plan_digest)},
        {"reviewed_plan_snapshot_sha256", Value(record_sha256(durable_snapshot))},
        {"transaction_id", Value(transaction_id)}});
}

usk::json::Value admit_current_registered_operation(HANDLE volume, const std::string& service_sid,
    const ReviewedPlanBinding& reviewed) {
    return admit_current_registered_operation(volume, service_sid, reviewed.setup_root,
        reviewed.install_plan.target_root.u8string(), reviewed.plan_digest,
        reviewed.durable_snapshot, reviewed.transaction_id);
}

void require_registered_recovery_binding(const usk::json::Value& prepared,
    const usk::json::Value& current) {
    if (!is_authenticated_record_schema(prepared.at("schema").as_string())) return;
    require_registered_operation_record(prepared);
    const auto& prior = prepared.at("operation_admission");
    if (usk::json::canonical(prior) == "null")
        throw std::runtime_error("registered recovery cannot promote a private legacy admission");
    for (const auto& [key, value] : current.as_object()) {
        if (key == "service_process_id" || key == "captured_client_process_id" || key == "authenticated_client_sha256") continue;
        if (usk::json::canonical(prior.at(key)) != usk::json::canonical(value))
            throw std::runtime_error("registered recovery differs from retained target, source or caller admission");
    }
}

void require_current_registered_publication_admission(const usk::json::Value& prepared,
    const usk::json::Value& before, const ReviewedPlanBinding& reviewed, HANDLE volume,
    const std::string& service_sid) {
    if (!registered_admission) return;
    if (!is_authenticated_record_schema(prepared.at("schema").as_string()) ||
        !registered_operation_admission ||
        usk::json::canonical(prepared.at("operation_admission")) != usk::json::canonical(*registered_operation_admission) ||
        usk::json::canonical(admit_current_registered_operation(volume, service_sid, reviewed)) !=
            usk::json::canonical(*registered_operation_admission))
        throw std::runtime_error("registered publication lacks its current operation-bound native admission");
    require_prepared_execution_phases(prepared, service_sid);
    require_native_execution_phase(before, "before_rename", service_sid,
        prepared.at("protected_anchors"), prepared.at("sealed_tree"), service_name,
        prepared.at("schema").as_string() == "usk.publisher.lab_phase_evidence.v9");
    usk::platform::windows::require_publisher_execution_worker_match(prepared.at("execution_phases").as_array().back().at("execution"),
        before.at("execution"));
}

void with_public_roots_bound(HANDLE volume, const usk::lifecycle::InstallPlan& plan,
    const std::string& expected_target_file_id, const std::function<void()>& action) {
    using namespace usk::platform::windows;
    const std::string setup_root = plan.roots.state_root.parent_path().u8string();
    const std::string target_root = plan.target_root.u8string();
    require_public_mount_mapping(volume, setup_root, target_root);
    const auto open_directory = [](const std::filesystem::path& path) {
        return OwnedHandle(CreateFileW(path.wstring().c_str(),
            FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | READ_CONTROL | SYNCHRONIZE,
            // The public metadata path is still pathname based. Keep both
            // roots open without delete sharing until those writes finish.
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
                FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    };
    OwnedHandle setup(open_directory(plan.roots.state_root.parent_path()));
    const DWORD setup_error = setup.get() == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    OwnedHandle target(open_directory(plan.target_root));
    const DWORD target_error = target.get() == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    if (setup.get() == INVALID_HANDLE_VALUE || target.get() == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("public install root handle is unavailable; setup Win32 " +
            std::to_string(setup_error) + ", target Win32 " + std::to_string(target_error));
    }
    FILE_ID_INFO held{}, setup_id{}, target_id{};
    if (!GetFileInformationByHandleEx(volume, FileIdInfo, &held, sizeof(held)) ||
        !GetFileInformationByHandleEx(setup.get(), FileIdInfo, &setup_id, sizeof(setup_id)) ||
        !GetFileInformationByHandleEx(target.get(), FileIdInfo, &target_id, sizeof(target_id)) ||
        setup_id.VolumeSerialNumber != held.VolumeSerialNumber ||
        target_id.VolumeSerialNumber != held.VolumeSerialNumber) {
        throw std::runtime_error("public install root is not on held publisher volume");
    }
    const auto before_setup = observe_publisher_directory_handle(setup.get());
    const auto before_target = observe_publisher_directory_handle(target.get());
    if (before_setup.reparse_tag != 0 || before_target.reparse_tag != 0 ||
        (before_setup.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (before_target.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        before_setup.link_count != 1 || before_target.link_count != 1 ||
        before_setup.case_sensitive || before_target.case_sensitive ||
        before_target.file_id != expected_target_file_id) {
        throw std::runtime_error("public install root identity or shape differs");
    }
    action();
    require_public_mount_mapping(volume, setup_root, target_root);
    const auto after_setup = observe_publisher_directory_handle(setup.get());
    const auto after_target = observe_publisher_directory_handle(target.get());
    OwnedHandle reopened_setup(open_directory(plan.roots.state_root.parent_path()));
    const DWORD reopened_setup_error = reopened_setup.get() == INVALID_HANDLE_VALUE ?
        GetLastError() : 0;
    OwnedHandle reopened_target(open_directory(plan.target_root));
    const DWORD reopened_target_error = reopened_target.get() == INVALID_HANDLE_VALUE ?
        GetLastError() : 0;
    if (reopened_setup.get() == INVALID_HANDLE_VALUE ||
        reopened_target.get() == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("public install path disappeared during finalization; setup Win32 " +
            std::to_string(reopened_setup_error) + ", target Win32 " +
            std::to_string(reopened_target_error));
    }
    const auto path_setup = observe_publisher_directory_handle(reopened_setup.get());
    const auto path_target = observe_publisher_directory_handle(reopened_target.get());
    if (after_setup.file_id != before_setup.file_id ||
        after_target.file_id != before_target.file_id ||
        after_setup.native_name != before_setup.native_name ||
        after_target.native_name != before_target.native_name ||
        path_setup.file_id != before_setup.file_id ||
        path_target.file_id != before_target.file_id ||
        path_setup.native_name != before_setup.native_name ||
        path_target.native_name != before_target.native_name) {
        throw std::runtime_error("public install root identity changed during finalization");
    }
}

std::optional<usk::lifecycle::InstallResult> finalize_reviewed_public_state(const std::string& snapshot_record,
    const std::string& protected_completion_sha256, HANDLE volume,
    HANDLE journal, HANDLE state, HANDLE visible_root,
    const std::string& visible_root_file_id,
    std::string* installed_response = nullptr) {
    const auto snapshot = usk::json::parse(snapshot_record);
    if (snapshot.at("schema").as_string() != "usk.publisher.lab_reviewed_plan_snapshot.v2" &&
        snapshot.at("schema").as_string() != "usk.publisher.lab_reviewed_plan_snapshot.v3" &&
        snapshot.at("schema").as_string() != "usk.publisher.lab_reviewed_plan_snapshot.v4") return std::nullopt;
    const auto plan = restore_reviewed_install_plan(snapshot_record);
    usk::lifecycle::ProtectedPublisherEvidence evidence{
        volume, journal, state, visible_root, volume_root, service_name,
        read_phase_record(journal, L"lab-prepared-evidence.json"),
        read_phase_record(journal, L"lab-visible-evidence.json"),
        snapshot_record,
        read_phase_record(state, L"lab-installed-state.json")};
    if (record_sha256(evidence.completion_record) != protected_completion_sha256) {
        throw std::runtime_error("public finalization completion identity differs");
    }
    usk::lifecycle::InstallResult completed;
    std::string installed_reply;
    with_public_roots_bound(volume, plan, visible_root_file_id, [&] {
    const auto result = usk::lifecycle::finalize_protected_visible_install(plan,
        snapshot.at("transaction_id").as_string(),
        snapshot.at("applied_at").as_string(), evidence);
    completed = result;
    if (result.verification.status != "pass") {
        throw std::runtime_error("protected public installed state did not verify");
    }
    const std::string setup_root = snapshot.at("setup_root").as_string();
    const std::string acceptance_root =
        std::filesystem::path(setup_root).root_path().u8string();
    const auto public_command = [&](const char* command,
        const usk::json::Value& request) -> usk::json::Value {
        const std::string input = usk::json::canonical(request);
        int status = -1;
        char* raw = usk_public_lifecycle_command_json(command, input.data(), input.size(),
            setup_root.c_str(), acceptance_root.c_str(),
            "operator_acceptance_candidate", &status);
        if (!raw) throw std::runtime_error("publisher public lifecycle response is absent");
        const std::string output(raw);
        usk_public_lifecycle_command_free(raw);
        const auto response = usk::json::parse(output);
        if (status != 0 || response.at("status").as_string() != "ok") {
            throw std::runtime_error("publisher public lifecycle readback refused");
        }
        if (std::string(command) == "installed.inspect") installed_reply = output;
        return response.at("payload");
    };
    const auto installed = public_command("installed.inspect", usk::json::Value(
        usk::json::Value::Object{
            {"schema", usk::json::Value("usk.installed_inspect_request.v1")},
            {"request_id", usk::json::Value("inspect." + result.installed_state.transaction_id)},
            {"install_id", usk::json::Value(plan.install_id)}}));
    if (installed.at("schema").as_string() != "usk.installed_state.v1" ||
        installed.at("transaction_id").as_string() != result.installed_state.transaction_id ||
        installed.at("ownership_manifest_digest").as_string() !=
            result.ownership.manifest_digest ||
        installed.at("last_verification").at("report_digest").as_string() !=
            result.verification.report_digest) {
        throw std::runtime_error("publisher public installed inspection differs");
    }
    const auto verification = public_command("installed.verify", usk::json::Value(
        usk::json::Value::Object{
            {"schema", usk::json::Value("usk.installed_verify_request.v1")},
            {"request_id", usk::json::Value("verify." + result.installed_state.transaction_id)},
            {"install_id", usk::json::Value(plan.install_id)},
            {"report_id", usk::json::Value("verify." + result.installed_state.transaction_id + ".public")},
            {"verified_at", usk::json::Value(current_utc_timestamp())}}));
    if (verification.at("schema").as_string() != "usk.verification_report.v1" ||
        verification.at("status").as_string() != "pass" ||
        verification.at("ownership_manifest_digest").as_string() !=
            result.ownership.manifest_digest ||
        verification.at("files").as_array().size() != plan.files.size()) {
        throw std::runtime_error("publisher public installed verification differs");
    }
    });
    if (installed_response) *installed_response = std::move(installed_reply);
    return completed;
}

std::string prepared_tree_at_visible_name(const usk::json::Value& sealed,
    const std::string& staged_name, const std::string& visible_name) {
    usk::json::Value expected = sealed;
    auto& root_name = expected.as_object().at("root").as_object().at("native_name");
    if (root_name.as_string() != staged_name) {
        throw std::runtime_error("recovery sealed root name is not under staging");
    }
    root_name = usk::json::Value(visible_name);
    for (auto& entry : expected.as_object().at("descendants").as_array()) {
        auto& native_name = entry.as_object().at("object").as_object().at("native_name");
        const std::string original = native_name.as_string();
        if (original.size() <= staged_name.size() ||
            original.compare(0, staged_name.size(), staged_name) != 0 ||
            original[staged_name.size()] != '\\') {
            throw std::runtime_error("recovery sealed descendant name escaped staging");
        }
        native_name = usk::json::Value(
            visible_name + original.substr(staged_name.size()));
    }
    return usk::json::canonical(expected);
}

std::string lab_visible_record(
    const std::string& source_file_id,
    const std::string& destination_parent_file_id,
    const std::string& prepared_digest,
    const usk::platform::windows::PublisherAnchorSetObservation& anchors,
    const usk::platform::windows::PublisherTreeObservation& visible,
    const std::string& selected_digest = {},
    const usk::json::Value::Array& execution_phases = {},
    const std::string& execution_transition = {}, bool creation_bound = false,
    bool rename_bound = false,
    const usk::platform::windows::PublisherBoundRenameObservation* rename_call = nullptr,
    bool rights_bound = false, bool metadata_bound = false, bool authenticated_bound = false, bool descendants_bound = false) {
    if (descendants_bound && !authenticated_bound) throw std::runtime_error("descendant-bound visible record requires authenticated evidence");
    if (authenticated_bound && !metadata_bound) throw std::runtime_error("authenticated visible record requires stored metadata");
    if (metadata_bound && !rights_bound) throw std::runtime_error("metadata-bound visible record requires held rights");
    if (rights_bound && !rename_bound) throw std::runtime_error("rights-bound visible record requires rename evidence");
    if (creation_bound && execution_phases.empty()) {
        throw std::runtime_error("creation-bound visible record requires native execution phases");
    }
    if (rename_bound && (!creation_bound || execution_phases.empty() ||
        ((execution_transition == "renamed_by_current_worker") != (rename_call != nullptr)))) {
        throw std::runtime_error("rename-bound visible record requires the measured current-worker call");
    }
    if (selected_digest.empty() && (visible.descendants.size() != 1 ||
        visible.descendants.front().relative_path != L"payload.bin")) {
        throw std::runtime_error("visible lab payload closure differs");
    }
    if (!selected_digest.empty() &&
        selected_file_set_digest(visible) != selected_digest) {
        throw std::runtime_error("visible selected file set differs");
    }
    return canonical_record(
        std::string("{\"schema\":\"usk.publisher.lab_phase_evidence.") +
        (!execution_phases.empty() ? (descendants_bound ? "v9" : authenticated_bound ? "v8" : metadata_bound ? "v7" : rights_bound ? "v6" : rename_bound ? "v5" : creation_bound ? "v4" : "v3") : selected_digest.empty() ? "v1" : "v2") +
        "\",\"phase\":\"lab_visible_evidence\",\"source_file_id\":" +
        json_quote(source_file_id) +
        ",\"destination_parent_file_id\":" +
        json_quote(destination_parent_file_id) +
        ",\"destination_name\":" + json_quote(ascii(visible_component)) + "," +
        (selected_digest.empty() ?
            "\"payload_sha256\":" +
                json_quote(visible.descendants.front().sha256) :
            "\"selected_file_set_digest\":" + json_quote(selected_digest)) +
        ",\"prepared_record_sha256\":" + json_quote(prepared_digest) +
        ",\"protected_anchors\":" + json_anchor_set(anchors) +
        ",\"visible_tree\":" + json_tree(visible) +
        (!execution_phases.empty() ?
            ",\"execution_phases\":" + usk::json::canonical(usk::json::Value(execution_phases)) +
            ",\"execution_transition\":" + json_quote(execution_transition) : std::string{}) +
        (rename_bound ? ",\"rename_call\":" + (rename_call ? json_native_rename_call(*rename_call) : "null") : std::string{}) + "}");
}

std::string lab_selected_installed_record(
    const usk::json::Value& prepared, const std::string& prepared_digest,
    const std::string& visible_digest,
    const usk::platform::windows::PublisherAnchorSetObservation& anchors,
    const usk::platform::windows::PublisherTreeObservation& visible,
    const std::string& service_sid,
    const std::string& selected_digest = {}) {
    if (!prepared.contains("source_binding") ||
        (selected_digest.empty() && (visible.descendants.size() != 1 ||
            visible.descendants.front().relative_path != L"payload.bin")) ||
        (!selected_digest.empty() &&
            selected_file_set_digest(visible) != selected_digest)) {
        throw std::runtime_error("selected lab state has no exact source or visible payload");
    }
    return canonical_record(
        std::string("{\"schema\":\"usk.publisher.lab_installed_state.") +
        (selected_digest.empty() ? "v1" : "v2") +
        "\",\"phase\":\"lab_installed_state\",\"service_sid\":" +
        json_quote(service_sid) +
        ",\"volume_serial\":" +
        std::to_string(visible.volume.file_id_volume_serial) +
        ",\"source_binding\":" +
        usk::json::canonical(prepared.at("source_binding")) +
        ",\"prepared_record_sha256\":" + json_quote(prepared_digest) +
        ",\"visible_record_sha256\":" + json_quote(visible_digest) +
        ",\"visible_root_file_id\":" + json_quote(visible.root.file_id) +
        ",\"destination_parent_file_id\":" +
        json_quote(anchors.destination_parent.object.file_id) +
        ",\"destination_name\":" + json_quote(ascii(visible_component)) + "," +
        (selected_digest.empty() ?
            "\"payload_sha256\":" +
                json_quote(visible.descendants.front().sha256) :
            "\"selected_file_set_digest\":" + json_quote(selected_digest)) + "}");
}

std::string complete_selected_lab_state(HANDLE state,
    const usk::json::Value& prepared, const std::string& prepared_digest,
    const std::string& visible_record,
    const usk::platform::windows::PublisherAnchorSetObservation& anchors,
    const usk::platform::windows::PublisherTreeObservation& visible,
    const std::string& service_sid, bool may_write,
    const std::string& selected_digest = {}) {
    using namespace usk::platform::windows;
    const std::string expected = lab_selected_installed_record(prepared,
        prepared_digest, record_sha256(visible_record), anchors, visible,
        service_sid, selected_digest);
    if (!recovery_state_has_completion_record(state)) {
        if (!may_write) return {};
        const auto descriptor = make_publisher_directory_security_descriptor(
            std::wstring(service_sid.begin(), service_sid.end()));
        write_journal_phase(state, L"lab-installed-state.json", descriptor, expected);
    }
    if (read_phase_record(state, L"lab-installed-state.json") != expected) {
        throw std::runtime_error("selected lab installed state differs from visible closure");
    }
    const auto state_tree = observe_publisher_tree(state);
    require_publisher_tree_security_shape(state_tree, service_sid);
    if (state_tree.root.file_id != anchors.state.object.file_id ||
        state_tree.descendants.size() != 1 ||
        state_tree.descendants.front().relative_path != L"lab-installed-state.json" ||
        state_tree.descendants.front().size != expected.size() ||
        state_tree.descendants.front().sha256 != record_sha256(expected)) {
        throw std::runtime_error("selected lab installed state identity differs");
    }
    require_publisher_tree_phase_match(state_tree, observe_publisher_tree(state));
    return record_sha256(expected);
}

std::string observe_prepared_recovery(HANDLE volume,
    const std::string& service_sid, bool bind_visible_forward,
    const std::string& expected_envelope_sha256 = {},
    const std::string& expected_archive_sha256 = {},
    bool require_reviewed_snapshot = false,
    std::string* installed_response = nullptr) {
    using namespace usk::platform::windows;
    const PublisherAnchorNames names{
        L"staging", L"destination", L"state", L"journal"};
    const auto anchors = observe_publisher_anchor_set(
        volume, {L"publication"}, names);
    require_publisher_anchor_set_security_shape(anchors, service_sid);
    OwnedHandle publication(open_exact_lab_child(volume, L"publication"));
    if (observe_publisher_directory_entries(publication.get()).size() != 4) {
        throw std::runtime_error("recovery publication has unexpected anchors");
    }
    OwnedHandle staging(open_exact_lab_child(publication.get(), L"staging"));
    OwnedHandle destination(open_exact_lab_child(
        publication.get(), L"destination", bind_visible_forward));
    OwnedHandle state(open_exact_lab_child(publication.get(), L"state",
        false, false, bind_visible_forward));
    OwnedHandle journal(open_exact_lab_child(publication.get(), L"journal",
        false, false, bind_visible_forward));
    const bool has_completion_record =
        recovery_state_has_completion_record(state.get());
    const bool has_visible_record =
        recovery_journal_has_visible_record(journal.get());
    const auto listed_journal = observe_publisher_directory_entries(journal.get());
    const bool has_reviewed_snapshot = std::any_of(listed_journal.begin(),
        listed_journal.end(), [](const auto& entry) {
            return entry.name == L"lab-reviewed-plan.json";
        });
    if (require_reviewed_snapshot && !has_reviewed_snapshot) {
        throw std::runtime_error(
            "independent recovery requires a durable reviewed-plan snapshot");
    }
    const std::string stored = read_phase_record(
        journal.get(), L"lab-prepared-evidence.json");
    const std::string stored_snapshot = has_reviewed_snapshot ?
        read_phase_record(journal.get(), L"lab-reviewed-plan.json") :
        std::string{};
    const std::string stored_visible = has_visible_record ?
        read_phase_record(journal.get(), L"lab-visible-evidence.json") :
        std::string{};
    usk::base::Sha256 digest;
    digest.update(reinterpret_cast<const unsigned char*>(stored.data()), stored.size());
    const std::string prepared_digest = digest.finish();
    const auto journal_tree = observe_publisher_tree(journal.get());
    require_publisher_tree_security_shape(journal_tree, service_sid);
    if (journal_tree.root.file_id != anchors.journal.object.file_id ||
        journal_tree.descendants.size() != 1u +
            (has_reviewed_snapshot ? 1u : 0u) +
            (has_visible_record ? 1u : 0u) ||
        journal_tree.descendants.front().relative_path != L"lab-prepared-evidence.json" ||
        journal_tree.descendants.front().size != stored.size() ||
        journal_tree.descendants.front().sha256 != prepared_digest ||
        (has_reviewed_snapshot &&
            (journal_tree.descendants[1].relative_path != L"lab-reviewed-plan.json" ||
            journal_tree.descendants[1].size != stored_snapshot.size() ||
            journal_tree.descendants[1].sha256 != record_sha256(stored_snapshot))) ||
        (has_visible_record &&
            (journal_tree.descendants.back().relative_path !=
                L"lab-visible-evidence.json" ||
            journal_tree.descendants.back().size != stored_visible.size()))) {
        throw std::runtime_error("recovery prepared journal identity or security differs");
    }
    std::string visible_digest;
    if (has_visible_record) {
        usk::base::Sha256 visible_hasher;
        visible_hasher.update(
            reinterpret_cast<const unsigned char*>(stored_visible.data()),
            stored_visible.size());
        visible_digest = visible_hasher.finish();
        if (journal_tree.descendants.back().sha256 != visible_digest) {
            throw std::runtime_error("recovery visible record identity differs");
        }
    }
    const auto prepared = usk::json::parse(stored);
    const std::string prepared_schema = prepared.at("schema").as_string();
    const bool execution_bound = is_execution_record_schema(prepared_schema);
    const bool selected_v2 = execution_bound || prepared_schema == "usk.publisher.lab_phase_evidence.v2";
    if (has_reviewed_snapshot) {
        if (!prepared.contains("source_binding") ||
            !prepared.at("source_binding").contains("reviewed_plan_snapshot_sha256") ||
            record_sha256(stored_snapshot) != prepared.at("source_binding")
                .at("reviewed_plan_snapshot_sha256").as_string()) {
            throw std::runtime_error("recovery target has no durable reviewed snapshot binding");
        }
        visible_component = selected_visible_component(
            usk::json::parse(stored_snapshot).at("target_root").as_string());
    }
    if ((!selected_v2 && prepared_schema !=
            "usk.publisher.lab_phase_evidence.v1") ||
        prepared.at("phase").as_string() != "lab_prepared_evidence" ||
        prepared.at("service_sid").as_string() != service_sid ||
        prepared.at("destination_name").as_string() != ascii(visible_component) ||
        prepared.at("destination_parent_file_id").as_string() !=
            anchors.destination_parent.object.file_id ||
        prepared.at("volume_serial").as_unsigned() !=
            anchors.chain.volume.file_id_volume_serial ||
        usk::json::canonical(prepared.at("protected_anchors")) !=
            usk::json::canonical(usk::json::parse(json_anchor_set(anchors)))) {
        throw std::runtime_error("recovery prepared anchors differ from held observations");
    }
    require_prepared_execution_phases(prepared, service_sid);
    if (prepared.contains("source_binding")) {
        const auto& binding = prepared.at("source_binding");
        const bool reviewed = binding.contains("reviewed_plan_digest");
        const bool snapshotted = binding.contains("reviewed_plan_snapshot_sha256");
        if (binding.as_object().size() != (snapshotted ? 6u : reviewed ? 5u : 3u) ||
            !lower_sha256_ascii(binding.at("archive_sha256").as_string()) ||
            !lower_sha256_ascii(binding.at("archive_identity_digest").as_string()) ||
            !lower_sha256_ascii(binding.at("entry_set_digest").as_string()) ||
            (reviewed && (!lower_sha256_ascii(
                binding.at("reviewed_plan_digest").as_string()) ||
                !lower_sha256_ascii(
                    binding.at("plan_envelope_sha256").as_string()))) ||
            (snapshotted && (!reviewed || !lower_sha256_ascii(
                binding.at("reviewed_plan_snapshot_sha256").as_string())))) {
            throw std::runtime_error("recovery selected source binding is malformed");
        }
        if (has_reviewed_snapshot != snapshotted) {
            throw std::runtime_error("recovery reviewed snapshot presence differs from prepared");
        }
    }
    const bool selected_source = prepared.contains("source_binding");
    const std::string selected_digest = selected_v2 ?
        prepared.at("selected_file_set_digest").as_string() : std::string{};
    if (selected_v2 && (!selected_source ||
        !lower_sha256_ascii(selected_digest))) {
        throw std::runtime_error("recovery selected file set binding is invalid");
    }
    if (has_reviewed_snapshot) {
        if (!selected_v2) {
            throw std::runtime_error("recovery reviewed snapshot requires selected v2 closure");
        }
        require_reviewed_plan_snapshot(stored_snapshot, prepared, selected_digest);
        if (require_reviewed_snapshot) {
            // A source-free forward replay must prove that the durable v2
            // snapshot can restore the exact public plan before any effect.
            // Earlier read-only recovery modes retain their v1 compatibility.
            (void)restore_reviewed_install_plan(stored_snapshot);
        }
    }
    if (registered_admission) {
        if (!has_reviewed_snapshot)
            throw std::runtime_error("registered recovery requires the durable reviewed snapshot");
        const auto snapshot = usk::json::parse(stored_snapshot);
        const auto plan = restore_reviewed_install_plan(stored_snapshot);
        registered_operation_admission = admit_current_registered_operation(volume, service_sid,
            plan.roots.state_root.parent_path().u8string(), plan.target_root.u8string(),
            snapshot.at("plan_digest").as_string(), stored_snapshot, snapshot.at("transaction_id").as_string());
        require_registered_recovery_binding(prepared, *registered_operation_admission);
    }
    if (!expected_envelope_sha256.empty() || !expected_archive_sha256.empty()) {
        if (!has_reviewed_snapshot || !selected_v2 ||
            !lower_sha256_ascii(expected_envelope_sha256) ||
            !lower_sha256_ascii(expected_archive_sha256)) {
            throw std::runtime_error("reviewed install reentry has no durable plan binding");
        }
        const auto& snapshot = usk::json::parse(stored_snapshot);
        if (snapshot.at("plan_envelope_sha256").as_string() !=
                expected_envelope_sha256 ||
            snapshot.at("archive_sha256").as_string() !=
                expected_archive_sha256) {
            if (has_completion_record) {
                throw StaleReviewedInstallRequest();
            }
            throw std::runtime_error("reviewed install reentry differs from durable plan and source");
        }
    }
    if (has_completion_record && (!selected_source || !has_visible_record)) {
        throw std::runtime_error("recovery state has no selected visible source");
    }
    const auto staged_entries = observe_publisher_directory_entries(staging.get());
    const auto destination_entries =
        observe_publisher_directory_entries(destination.get());
    const bool staged = staged_entries.size() == 1 &&
        staged_entries.front().name == L"candidate" && destination_entries.empty();
    const bool visible = staged_entries.empty() &&
        destination_entries.size() == 1 &&
        destination_entries.front().name == visible_component;
    if (!staged && !visible) {
        throw std::runtime_error("recovery namespace is neither prepared nor visible");
    }
    if (has_visible_record && !visible) {
        throw std::runtime_error("recovery visible record has no visible namespace");
    }
    OwnedHandle root(open_exact_lab_child(
        staged ? staging.get() : destination.get(),
        staged ? L"candidate" : visible_component, false,
        bind_visible_forward && staged));
    const auto actual_tree = observe_publisher_tree(root.get());
    const bool consumer_bound = has_reviewed_snapshot && visible &&
        usk::json::parse(stored_snapshot).at("schema").as_string() == "usk.publisher.lab_reviewed_plan_snapshot.v4";
    auto observed_tree = actual_tree;
    if (consumer_bound) {
        const bool has_grant = actual_tree.root.dacl_aces.size() != 2 ||
            std::any_of(actual_tree.descendants.begin(), actual_tree.descendants.end(),
                [](const auto& entry) { return entry.object.dacl_aces.size() != 2; });
        if (has_grant) {
            if (!has_completion_record) throw std::runtime_error("consumer ACE precedes protected completion");
            const auto snapshot = usk::json::parse(stored_snapshot);
            usk::lifecycle::require_completed_consumer_install(
                restore_reviewed_install_plan(stored_snapshot),
                snapshot.at("transaction_id").as_string(), snapshot.at("applied_at").as_string(),
                record_sha256(read_phase_record(state.get(),L"lab-installed-state.json")),volume_root,volume,service_name);
        }
        observed_tree = publisher_consumer_read_projection(actual_tree,service_sid,consumer_read_sid);
    }
    require_publisher_tree_security_shape(observed_tree, service_sid);
    if (selected_v2) {
        if (selected_file_set_digest(observed_tree) != selected_digest) {
            throw std::runtime_error("recovery selected file set differs from prepared");
        }
    } else {
        require_publisher_tree_exact_file_closure(observed_tree,
            {{L"payload.bin", prepared.at("sealed_tree").at("descendants")
                .as_array().at(0).at("size").as_unsigned(),
                prepared.at("payload_sha256").as_string()}});
    }
    const std::string staged_name =
        ascii(anchors.staging.object.native_name) + "\\candidate";
    const std::string visible_name =
        ascii(anchors.destination_parent.object.native_name) + "\\" + ascii(visible_component);
    const std::string expected_tree = staged ?
        usk::json::canonical(prepared.at("sealed_tree")) :
        prepared_tree_at_visible_name(
            prepared.at("sealed_tree"), staged_name, visible_name);
    if (prepared.at("source_file_id").as_string() != observed_tree.root.file_id ||
        (!selected_v2 && prepared.at("payload_sha256").as_string() !=
            observed_tree.descendants.front().sha256) ||
        expected_tree !=
            usk::json::canonical(usk::json::parse(json_tree(observed_tree)))) {
        throw std::runtime_error("recovery closure differs from prepared record");
    }
    if (has_visible_record) {
        const auto bound = usk::json::parse(stored_visible);
        if (bound.as_object().size() != visible_record_field_count(prepared_schema) ||
            bound.at("schema").as_string() != prepared_schema ||
            bound.at("phase").as_string() != "lab_visible_evidence" ||
            bound.at("source_file_id").as_string() !=
                observed_tree.root.file_id ||
            bound.at("destination_parent_file_id").as_string() !=
                anchors.destination_parent.object.file_id ||
            bound.at("destination_name").as_string() != ascii(visible_component) ||
            (selected_v2 ?
                bound.at("selected_file_set_digest").as_string() !=
                    selected_digest :
                bound.at("payload_sha256").as_string() !=
                    observed_tree.descendants.front().sha256) ||
            bound.at("prepared_record_sha256").as_string() !=
                prepared_digest ||
            usk::json::canonical(bound.at("protected_anchors")) !=
                usk::json::canonical(usk::json::parse(json_anchor_set(anchors))) ||
            usk::json::canonical(bound.at("visible_tree")) !=
                usk::json::canonical(usk::json::parse(json_tree(observed_tree)))) {
            throw std::runtime_error("recovery visible record differs from held observations");
        }
        require_visible_execution_phase(bound, service_sid, prepared);
    }
    std::string completion_digest;
    if (selected_source && has_visible_record) {
        completion_digest = complete_selected_lab_state(state.get(), prepared,
            prepared_digest, stored_visible, anchors, observed_tree,
            service_sid, false, selected_digest);
    }
    const auto second = observe_publisher_anchor_set(
        volume, {L"publication"}, names);
    require_publisher_anchor_set_phase_match(anchors, second);
    require_publisher_tree_phase_match(actual_tree,
        observe_publisher_tree(root.get()));
    require_publisher_tree_phase_match(journal_tree,
        observe_publisher_tree(journal.get()));
    if (recovery_journal_has_visible_record(journal.get()) != has_visible_record ||
        read_phase_record(journal.get(), L"lab-prepared-evidence.json") != stored ||
        (has_reviewed_snapshot && read_phase_record(
            journal.get(), L"lab-reviewed-plan.json") != stored_snapshot) ||
        (has_visible_record && read_phase_record(
            journal.get(), L"lab-visible-evidence.json") != stored_visible) ||
        recovery_state_has_completion_record(state.get()) != has_completion_record) {
        throw std::runtime_error("recovery journal or state changed during observation");
    }
    const auto staged_after = observe_publisher_directory_entries(staging.get());
    const auto destination_after =
        observe_publisher_directory_entries(destination.get());
    if (staged ?
            (staged_after.size() != 1 || staged_after.front().name != L"candidate" ||
                !destination_after.empty()) :
            (!staged_after.empty() || destination_after.size() != 1 ||
                destination_after.front().name != visible_component)) {
        throw std::runtime_error("recovery namespace changed during observation");
    }
    if (observe_publisher_directory_entries(publication.get()).size() != 4) {
        throw std::runtime_error("recovery publication anchor set changed");
    }
    if (bind_visible_forward && !has_visible_record) {
        PublisherTreeObservation forward_visible = observed_tree;
        std::optional<PublisherBoundRenameObservation> forward_rename_call;
        usk::json::Value::Array forward_execution_phases;
        const std::vector<HANDLE> forward_handles{volume, publication.get(), staging.get(),
            destination.get(), state.get(), journal.get(), root.get()};
        if (staged) {
            // A recovered worker uses the same protected handles, exact
            // prepared closure and no-replace rename as the initial worker.
            // There is no retry after a rename with an uncertain outcome.
            require_publisher_anchor_set_phase_match(anchors,
                observe_publisher_anchor_set(volume, {L"publication"}, names));
            require_publisher_tree_phase_match(actual_tree,
                observe_publisher_tree(root.get()));
            if (execution_bound) forward_execution_phases.push_back(capture_native_execution_phase(
                "before_rename", forward_handles, anchors, actual_tree,
                is_authenticated_record_schema(prepared_schema), prepared_schema == "usk.publisher.lab_phase_evidence.v9"));
            if (execution_bound && prepared_schema == "usk.publisher.lab_phase_evidence.v9")
                require_native_descendant_continuity(prepared.at("execution_phases").as_array().back(),
                    forward_execution_phases.back());
            if (registered_admission && is_authenticated_record_schema(prepared_schema)) {
                require_registered_recovery_binding(prepared, *registered_operation_admission);
                const auto& current = forward_execution_phases.back().at("execution");
                if (usk::json::sha256_canonical(current.at("authenticated_client")) !=
                        registered_operation_admission->at("authenticated_client_sha256").as_string() ||
                    current.at("service").at("process_id").as_unsigned() !=
                        registered_operation_admission->at("service_process_id").as_unsigned())
                    throw std::runtime_error("registered recovery phase lost its current authenticated worker binding");
                require_native_execution_phase(forward_execution_phases.back(), "before_rename", service_sid,
                    prepared.at("protected_anchors"), prepared.at("sealed_tree"), service_name,
                    prepared.at("schema").as_string() == "usk.publisher.lab_phase_evidence.v9");
            }
            forward_rename_call = probe_publisher_bound_rename_no_replace(root.get(),
                destination.get(), visible_component, observed_tree.root,
                anchors.destination_parent.object);
            forward_visible = observe_visible_publisher_tree_against_seal(
                destination.get(), visible_component, observed_tree);
        }
        require_publisher_tree_security_shape(forward_visible, service_sid);
        require_publisher_anchor_set_phase_match(anchors,
            observe_publisher_anchor_set(volume, {L"publication"}, names));
        if (prepared_tree_at_visible_name(prepared.at("sealed_tree"),
                staged_name, visible_name) !=
            usk::json::canonical(usk::json::parse(json_tree(forward_visible)))) {
            throw std::runtime_error("forward recovery visible closure differs from prepared");
        }
        const auto descriptor = make_publisher_directory_security_descriptor(
            std::wstring(service_sid.begin(), service_sid.end()));
        if (execution_bound) forward_execution_phases.push_back(capture_native_execution_phase(
            "visible_bound", forward_handles, anchors, forward_visible,
            is_authenticated_record_schema(prepared_schema), prepared_schema == "usk.publisher.lab_phase_evidence.v9"));
        const std::string forward_record = lab_visible_record(
            forward_visible.root.file_id,
            anchors.destination_parent.object.file_id, prepared_digest,
            anchors, forward_visible, selected_digest, forward_execution_phases,
            staged ? "renamed_by_current_worker" : "observed_visible_on_restart",
            prepared_schema == "usk.publisher.lab_phase_evidence.v4" ||
                prepared_schema == "usk.publisher.lab_phase_evidence.v5" || prepared_schema == "usk.publisher.lab_phase_evidence.v6" ||
                (prepared_schema == "usk.publisher.lab_phase_evidence.v7" || is_authenticated_record_schema(prepared_schema)),
            prepared_schema == "usk.publisher.lab_phase_evidence.v5" || prepared_schema == "usk.publisher.lab_phase_evidence.v6" ||
                (prepared_schema == "usk.publisher.lab_phase_evidence.v7" || is_authenticated_record_schema(prepared_schema)),
            forward_rename_call ? &*forward_rename_call : nullptr,
            prepared_schema == "usk.publisher.lab_phase_evidence.v6" || prepared_schema == "usk.publisher.lab_phase_evidence.v7" || is_authenticated_record_schema(prepared_schema),
            prepared_schema == "usk.publisher.lab_phase_evidence.v7" || is_authenticated_record_schema(prepared_schema),
            is_authenticated_record_schema(prepared_schema), prepared_schema == "usk.publisher.lab_phase_evidence.v9");
        require_visible_execution_phase(usk::json::parse(forward_record), service_sid, prepared);
        write_journal_phase(journal.get(), L"lab-visible-evidence.json",
            descriptor, forward_record);
        if (read_phase_record(journal.get(), L"lab-visible-evidence.json") !=
                forward_record ||
            recovery_journal_has_visible_record(journal.get()) != true) {
            throw std::runtime_error("forward recovery visible record did not persist");
        }
        if (selected_source) {
            completion_digest = complete_selected_lab_state(state.get(), prepared,
                prepared_digest, forward_record, anchors, forward_visible,
                service_sid, true, selected_digest);
        }
        usk::base::Sha256 visible_hasher;
        visible_hasher.update(
            reinterpret_cast<const unsigned char*>(forward_record.data()),
            forward_record.size());
        const auto forward_journal = observe_publisher_tree(journal.get());
        require_publisher_tree_security_shape(forward_journal, service_sid);
        if (forward_journal.root.file_id != anchors.journal.object.file_id ||
            forward_journal.descendants.size() !=
                (has_reviewed_snapshot ? 3u : 2u) ||
            forward_journal.descendants[0].relative_path !=
                L"lab-prepared-evidence.json" ||
            forward_journal.descendants[0].sha256 != prepared_digest ||
            (has_reviewed_snapshot &&
                (forward_journal.descendants[1].relative_path !=
                    L"lab-reviewed-plan.json" ||
                forward_journal.descendants[1].sha256 !=
                    record_sha256(stored_snapshot))) ||
            forward_journal.descendants.back().relative_path !=
                L"lab-visible-evidence.json" ||
            forward_journal.descendants.back().sha256 != visible_hasher.finish()) {
            throw std::runtime_error("forward recovery journal closure differs");
        }
        require_publisher_tree_phase_match(forward_visible,
            observe_publisher_tree(root.get()));
        require_publisher_tree_phase_match(forward_journal,
            observe_publisher_tree(journal.get()));
        require_publisher_anchor_set_phase_match(anchors,
            observe_publisher_anchor_set(volume, {L"publication"}, names));
        const auto final_staging = observe_publisher_directory_entries(staging.get());
        const auto final_destination =
            observe_publisher_directory_entries(destination.get());
        if (!final_staging.empty() || final_destination.size() != 1 ||
            final_destination.front().name != visible_component) {
            throw std::runtime_error("forward recovery namespace changed after journal write");
        }
        if (selected_source &&
            complete_selected_lab_state(state.get(), prepared, prepared_digest,
                forward_record, anchors, forward_visible, service_sid, false,
                selected_digest) !=
                completion_digest) {
            throw std::runtime_error("forward recovery completion changed after closure check");
        }
        if (has_reviewed_snapshot && !completion_digest.empty()) {
            OwnedHandle final_visible(open_exact_lab_child(
                destination.get(), visible_component));
            require_publisher_tree_phase_match(forward_visible,
                observe_publisher_tree(final_visible.get()));
            if (staged) root.close_checked();
            finalize_reviewed_public_state(stored_snapshot, completion_digest,
                volume, journal.get(), state.get(), final_visible.get(),
                forward_visible.root.file_id, installed_response);
        }
        return "{\"decision\":\"visible_bound_forward\",\"prepared_sha256\":" +
            json_quote(prepared_digest) +
            ",\"source_file_id\":" + json_quote(forward_visible.root.file_id) +
            ",\"payload_sha256\":" +
            (selected_v2 ? "null" :
                json_quote(forward_visible.descendants.front().sha256)) +
            (selected_v2 ? ",\"selected_file_set_digest\":" +
                json_quote(selected_digest) : std::string{}) +
            ",\"completion_record_sha256\":" +
            (completion_digest.empty() ? "null" : json_quote(completion_digest)) +
            ",\"observed_location\":\"visible_with_visible_record\","
            "\"destination_empty\":false,\"state_empty\":" +
            (completion_digest.empty() ? "true" : "false") + "}";
    }
    if (bind_visible_forward && has_visible_record) {
        const bool completion_was_present = !completion_digest.empty();
        if (selected_source) {
            completion_digest = complete_selected_lab_state(state.get(), prepared,
                prepared_digest, stored_visible, anchors, observed_tree,
                service_sid, !completion_was_present, selected_digest);
            if (completion_digest.empty()) {
                throw std::runtime_error("recovery completion disappeared during repeat");
            }
        }
        require_publisher_tree_phase_match(actual_tree,
            observe_publisher_tree(root.get()));
        require_publisher_tree_phase_match(journal_tree,
            observe_publisher_tree(journal.get()));
        require_publisher_anchor_set_phase_match(anchors,
            observe_publisher_anchor_set(volume, {L"publication"}, names));
        if (!recovery_journal_has_visible_record(journal.get()) ||
            read_phase_record(journal.get(), L"lab-prepared-evidence.json") != stored ||
            (has_reviewed_snapshot && read_phase_record(
                journal.get(), L"lab-reviewed-plan.json") != stored_snapshot) ||
            read_phase_record(journal.get(), L"lab-visible-evidence.json") !=
                stored_visible) {
            throw std::runtime_error("recovery journal changed after completion");
        }
        const auto final_staging = observe_publisher_directory_entries(staging.get());
        const auto final_destination =
            observe_publisher_directory_entries(destination.get());
        if (!final_staging.empty() || final_destination.size() != 1 ||
            final_destination.front().name != visible_component ||
            observe_publisher_directory_entries(publication.get()).size() != 4) {
            throw std::runtime_error("recovery namespace changed after completion");
        }
        if (selected_source &&
            complete_selected_lab_state(state.get(), prepared, prepared_digest,
                stored_visible, anchors, observed_tree, service_sid, false,
                selected_digest) !=
                completion_digest) {
            throw std::runtime_error("recovery completion changed after closure check");
        }
        if (has_reviewed_snapshot && !completion_digest.empty()) {
            finalize_reviewed_public_state(stored_snapshot, completion_digest,
                volume, journal.get(), state.get(), root.get(),
                observed_tree.root.file_id, installed_response);
        }
        return "{\"decision\":" + json_quote(
            selected_source && !completion_was_present ?
                "installed_state_completed_forward" : "already_visible_bound") +
            ",\"prepared_sha256\":" +
            json_quote(prepared_digest) +
            ",\"source_file_id\":" + json_quote(observed_tree.root.file_id) +
            ",\"payload_sha256\":" +
            (selected_v2 ? "null" :
                json_quote(observed_tree.descendants.front().sha256)) +
            (selected_v2 ? ",\"selected_file_set_digest\":" +
                json_quote(selected_digest) : std::string{}) +
            ",\"completion_record_sha256\":" +
            (completion_digest.empty() ? "null" : json_quote(completion_digest)) +
            ",\"observed_location\":\"visible_with_visible_record\","
            "\"destination_empty\":false,\"state_empty\":" +
            (completion_digest.empty() ? "true" : "false") + "}";
    }
    return "{\"decision\":\"recovery_required\",\"prepared_sha256\":" +
        json_quote(prepared_digest) +
        ",\"prepared_bytes\":" + std::to_string(stored.size()) +
        ",\"source_file_id\":" + json_quote(observed_tree.root.file_id) +
        ",\"payload_sha256\":" +
        (selected_v2 ? "null" :
            json_quote(observed_tree.descendants.front().sha256)) +
        (selected_v2 ? ",\"selected_file_set_digest\":" +
            json_quote(selected_digest) : std::string{}) +
        ",\"completion_record_sha256\":" +
        (completion_digest.empty() ? "null" : json_quote(completion_digest)) +
        ",\"observed_location\":" +
        json_quote(staged ? "staging_prepared" :
            (has_visible_record ? "visible_with_visible_record" :
                "visible_without_visible_record")) +
        (has_visible_record ? ",\"visible_record_sha256\":" +
            json_quote(visible_digest) : std::string{}) +
        ",\"destination_empty\":" + (staged ? "true" : "false") +
        ",\"state_empty\":" +
        (completion_digest.empty() ? "true" : "false") + "}";
}

struct CaseInsensitiveNativePath {
    bool operator()(const std::wstring& left, const std::wstring& right) const {
        const int order = CompareStringOrdinal(left.data(),
            static_cast<int>(left.size()), right.data(),
            static_cast<int>(right.size()), TRUE);
        if (order == 0) {
            throw std::runtime_error("selected source path comparison failed");
        }
        return order == CSTR_LESS_THAN;
    }
};

std::wstring selected_utf8_path(const std::string& path) {
    if (path.empty() || path.size() > 32767 ||
        path.find('\0') != std::string::npos) {
        throw std::runtime_error("selected source path is invalid");
    }
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        path.data(), static_cast<int>(path.size()), nullptr, 0);
    if (count <= 0) {
        throw std::runtime_error("selected source path is not UTF-8");
    }
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            path.data(), static_cast<int>(path.size()), result.data(), count) !=
            count) {
        throw std::runtime_error("selected source path conversion changed");
    }
    // This laboratory record format still serializes native names as ASCII.
    (void)ascii(result);
    return result;
}

std::vector<usk::platform::windows::PublisherExpectedFile>
stage_selected_archive_files(HANDLE candidate,
    const std::vector<unsigned char>& descriptor,
    const usk::archive::StreamingStoredArchivePayload& payload) {
    using namespace usk::platform::windows;
    if (payload.files.empty() || payload.files.size() > 4096) {
        throw std::runtime_error("selected source file count is outside lab budget");
    }
    struct SourceEntry {
        const usk::archive::StreamingPayloadFile* file;
        std::vector<std::wstring> components;
    };
    std::vector<SourceEntry> sources;
    std::vector<PublisherExpectedFile> expected;
    std::set<std::wstring, CaseInsensitiveNativePath> file_paths;
    std::set<std::wstring, CaseInsensitiveNativePath> directory_paths;
    sources.reserve(payload.files.size());
    expected.reserve(payload.files.size());
    for (const auto& file : payload.files) {
        const std::wstring path = selected_utf8_path(file.relative_path);
        std::vector<std::wstring> components;
        std::size_t start = 0;
        while (true) {
            const auto slash = path.find(L'/', start);
            const auto component = path.substr(start,
                slash == std::wstring::npos ? std::wstring::npos : slash - start);
            if (components.size() >= 128 ||
                !is_publisher_canonical_component(component)) {
                throw std::runtime_error("selected source component is not canonical");
            }
            components.push_back(component);
            if (slash == std::wstring::npos) break;
            const std::wstring directory = path.substr(0, slash);
            const auto inserted = directory_paths.insert(directory);
            if (!inserted.second && *inserted.first != directory) {
                throw std::runtime_error("selected source directory has a case alias");
            }
            start = slash + 1;
        }
        if (!file_paths.insert(path).second ||
            !lower_sha256_ascii(file.sha256)) {
            throw std::runtime_error("selected source file collides or has no digest");
        }
        sources.push_back({&file, std::move(components)});
        expected.push_back({path, file.size_bytes, file.sha256});
    }
    for (const auto& directory : directory_paths) {
        if (file_paths.find(directory) != file_paths.end()) {
            throw std::runtime_error("selected source file is an ancestor of another file");
        }
    }
    (void)selected_file_set_digest(expected);
    for (const auto& source : sources) {
        HANDLE parent = candidate;
        std::vector<std::unique_ptr<OwnedHandle>> held_parents;
        for (std::size_t index = 0; index + 1 < source.components.size(); ++index) {
            const auto& component = source.components[index];
            const auto listed = observe_publisher_directory_entries(parent);
            const auto found = std::find_if(listed.begin(), listed.end(),
                [&](const PublisherDirectoryEntry& entry) {
                    const int order = CompareStringOrdinal(entry.name.c_str(), -1,
                        component.c_str(), -1, TRUE);
                    if (order == 0) {
                        throw std::runtime_error("selected source parent comparison failed");
                    }
                    return order == CSTR_EQUAL;
                });
            HANDLE child = INVALID_HANDLE_VALUE;
            if (found == listed.end()) {
                child = create_staged_directory_relative_with_descriptor(
                    parent, component, descriptor);
            } else {
                if (found->name != component ||
                    (found->attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
                    throw std::runtime_error("selected source parent alias or type differs");
                }
                child = open_publisher_listed_child(parent, *found,
                    true, false, true);
            }
            held_parents.push_back(std::make_unique<OwnedHandle>(child));
            parent = child;
        }
        const auto& file = *source.file;
        const auto streamed = stream_verified_reader_to_staged_file(
            parent, source.components.back(), descriptor, file.size_bytes,
            file.sha256, file.reader, payload.validate_source);
        OwnedHandle staged(streamed.file);
        if (streamed.bytes_written != file.size_bytes ||
            streamed.sha256 != file.sha256) {
            throw std::runtime_error("selected source staged bytes differ");
        }
    }
    return expected;
}

usk::archive::StreamingStoredArchivePayload inspect_selected_lab_archive() {
    const auto source_path = std::filesystem::path(selected_archive_path).u8string();
    const std::string request =
        "{\"schema\":\"usk.archive_inspect_request.v1\","
        "\"archive_path\":" + json_quote(source_path) +
        ",\"archive_format\":\"zip\",\"budgets\":{"
        "\"max_entries\":4096,\"max_entry_bytes\":16777216,"
        "\"max_uncompressed_bytes\":268435456,\"max_depth\":128,"
        "\"max_ratio\":100,\"max_elapsed_ms\":300000}}";
    auto payload = usk::archive::inspect_streaming_payload(request, "");
    if (payload.source_sha256 != selected_archive_sha256 ||
        !lower_sha256_ascii(payload.source_identity_digest) ||
        !lower_sha256_ascii(payload.entry_set_digest) ||
        payload.files.empty() || payload.files.size() > 4096) {
        throw std::runtime_error("selected lab archive identity or closure differs");
    }
    return payload;
}

ReviewedPlanBinding require_reviewed_selected_plan() {
    using namespace usk::platform::windows;
    if (reviewed_plan_envelope_path.empty() ||
        !lower_sha256_ascii(reviewed_plan_envelope_sha256)) {
        throw std::runtime_error("selected publisher has no reviewed plan envelope");
    }
    usk::base::StableFile file{std::filesystem::path(reviewed_plan_envelope_path)};
    if (file.identity().size_bytes == 0 ||
        file.identity().size_bytes > 1024u * 1024u ||
        file.sha256_hex() != reviewed_plan_envelope_sha256) {
        throw std::runtime_error("reviewed plan envelope identity differs");
    }
    const auto bytes = file.read(0,
        static_cast<std::size_t>(file.identity().size_bytes));
    file.verify_unchanged();
    const auto envelope = usk::json::parse(
        std::string(bytes.begin(), bytes.end()));
    const bool apply_envelope = envelope.at("schema").as_string() ==
        "usk.publisher.lab_reviewed_plan_envelope.v2";
    if (envelope.as_object().size() != (apply_envelope ? 7u : 6u) ||
        (!apply_envelope && envelope.at("schema").as_string() !=
            "usk.publisher.lab_reviewed_plan_envelope.v1") ||
        envelope.at("activation").as_string() !=
            "operator_acceptance_candidate") {
        throw std::runtime_error("reviewed plan envelope schema or activation differs");
    }
    const auto normalized = [](const std::string& path) {
        return std::filesystem::path(path).lexically_normal().generic_u8string();
    };
    const std::string acceptance = envelope.at("acceptance_root").as_string();
    const std::string state_root = envelope.at("state_root").as_string();
    const std::wstring acceptance_native =
        std::filesystem::path(acceptance).wstring();
    wchar_t mapped_volume[128]{};
    if (acceptance_native.size() != 3 ||
        !((acceptance_native[0] >= L'A' && acceptance_native[0] <= L'Z') ||
            (acceptance_native[0] >= L'a' && acceptance_native[0] <= L'z')) ||
        acceptance_native[1] != L':' || acceptance_native[2] != L'\\' ||
        !GetVolumeNameForVolumeMountPointW(acceptance_native.c_str(),
            mapped_volume, static_cast<DWORD>(std::size(mapped_volume))) ||
        CompareStringOrdinal(mapped_volume, -1, volume_root.c_str(), -1,
            TRUE) != CSTR_EQUAL) {
        throw std::runtime_error("reviewed plan drive root is not the held volume");
    }
    const std::string expected_root =
        std::filesystem::path(acceptance).lexically_normal().generic_u8string();
    visible_component = selected_visible_component(
        envelope.at("plan_request").at("target").at("root").as_string());
    const std::string expected_target =
        (std::filesystem::path(acceptance) / L"publication" /
            L"destination" / visible_component).lexically_normal().generic_u8string();
    const std::string plan_digest =
        envelope.at("reviewed_plan_digest").as_string();
    const auto& request = envelope.at("plan_request");
    if (submitted_apply_request && (!apply_envelope ||
        usk::json::canonical(envelope.at("apply_request")) !=
            *submitted_apply_request)) {
        throw StaleReviewedInstallRequest();
    }
    if (selected_archive_path.empty()) {
        // The restricted service may take its local source only from the
        // digest-checked envelope and the independently authenticated apply
        // request. A second SCM pathname is not publication authority.
        if (!submitted_apply_request) {
            throw std::runtime_error("reviewed source requires authenticated apply");
        }
        const std::filesystem::path source(
            request.at("archive").at("path").as_string());
        const std::wstring source_root = source.root_path().wstring();
        const std::string source_sha =
            request.at("archive").at("expected_sha256").as_string();
        if (!source.is_absolute() || source.lexically_normal() != source ||
            source_root.size() != 3 || source_root[1] != L':' ||
            source_root[2] != L'\\' || !lower_sha256_ascii(source_sha)) {
            throw std::runtime_error("reviewed source path or digest is invalid");
        }
        selected_archive_path = source.wstring();
        selected_archive_sha256 = source_sha;
    }
    if (normalized(acceptance) != expected_root ||
        !lower_sha256_ascii(plan_digest) ||
        request.at("schema").as_string() !=
            "usk.install_local_plan_request.v1" ||
        request.at("required_commit_authority").as_string() !=
            "staged_child_bound_v1" ||
        normalized(request.at("archive").at("path").as_string()) !=
            normalized(std::filesystem::path(selected_archive_path).u8string()) ||
        request.at("archive").at("expected_sha256").as_string() !=
            selected_archive_sha256 ||
        normalized(request.at("target").at("root").as_string()) !=
            expected_target) {
        throw std::runtime_error("reviewed plan does not bind selected source and target");
    }
    const std::string canonical_request = usk::json::canonical(request);
    auto internal_plan = usk::lifecycle::reviewed_install_plan_for_publisher(
        canonical_request, state_root, acceptance,
        "operator_acceptance_candidate");
    int status = -1;
    char* raw = usk_public_lifecycle_command_json("install_local.plan",
        canonical_request.data(), canonical_request.size(), state_root.c_str(),
        acceptance.c_str(), "operator_acceptance_candidate", &status);
    if (!raw) throw std::runtime_error("native reviewed plan response is unavailable");
    std::string response(raw);
    usk_public_lifecycle_command_free(raw);
    const auto& result = usk::json::parse(response);
    if (status != 0 || result.at("status").as_string() != "ok") {
        throw std::runtime_error("native reviewed plan revalidation refused");
    }
    const auto& plan = result.at("payload");
    if (plan.at("plan_digest").as_string() != plan_digest) {
        throw std::runtime_error("native reviewed plan digest differs after revalidation");
    }
    if (plan.at("schema").as_string() != "usk.install_plan.v1" ||
        plan.at("plan_id").as_string() !=
            request.at("request_id").as_string() ||
        plan.at("required_commit_authority").as_string() !=
            "staged_child_bound_v1" ||
        plan.at("commit_authority_available").as_boolean() ||
        normalized(plan.at("target").at("root").as_string()) !=
            expected_target ||
        normalized(plan.at("source").at("path").as_string()) !=
            normalized(std::filesystem::path(selected_archive_path).u8string()) ||
        plan.at("source").at("sha256").as_string() !=
            selected_archive_sha256) {
        throw std::runtime_error("native reviewed plan identity differs");
    }
    // Staging must consume the exact verified readers selected by the native
    // plan. Reopening with laboratory budgets and an empty strip prefix can
    // change the closure and reject a valid reviewed source.
    usk::archive::StreamingStoredArchivePayload selected_payload;
    selected_payload.source_sha256 = internal_plan.recipe.source_archive_digest;
    selected_payload.source_identity_digest = internal_plan.recipe.source_identity_digest;
    selected_payload.entry_set_digest = internal_plan.recipe.entry_set_digest;
    selected_payload.archive_size_bytes = plan.at("source").at("size_bytes").as_unsigned();
    selected_payload.uncompressed_bytes = plan.at("totals").at("uncompressed_bytes").as_unsigned();
    selected_payload.payload_buffer_bytes = usk::lifecycle::streaming_payload_buffer_bytes;
    selected_payload.validate_source = internal_plan.validate_source;
    for (const auto& planned_file : internal_plan.files) {
        if (!planned_file.bytes.empty() || !planned_file.reader) {
            throw std::runtime_error("reviewed publisher requires source-bound streaming readers");
        }
        usk::archive::StreamingPayloadFile selected_file;
        selected_file.relative_path = planned_file.relative_path;
        selected_file.sha256 = planned_file.sha256;
        selected_file.size_bytes = planned_file.size_bytes;
        selected_file.reader = planned_file.reader;
        selected_payload.files.push_back(std::move(selected_file));
    }
    if (plan.at("source").at("filesystem_identity_digest").as_string() !=
            selected_payload.source_identity_digest ||
        plan.at("source").at("size_bytes").as_unsigned() !=
            selected_payload.archive_size_bytes ||
        internal_plan.plan_digest != plan_digest ||
        internal_plan.recipe.source_identity_digest !=
            selected_payload.source_identity_digest ||
        internal_plan.recipe.entry_set_digest != selected_payload.entry_set_digest) {
        throw std::runtime_error("selected archive filesystem identity differs from reviewed plan");
    }
    std::vector<PublisherExpectedFile> expected_files;
    for (const auto& entry : plan.at("planned_entries").as_array()) {
        if (entry.at("entry_type").as_string() == "file") {
            expected_files.push_back({
                selected_utf8_path(entry.at("relative_path").as_string()),
                entry.at("size_bytes").as_unsigned(),
                entry.at("sha256").as_string()});
        } else if (entry.at("entry_type").as_string() != "directory") {
            throw std::runtime_error("native reviewed plan has an unsupported entry");
        }
    }
    std::vector<PublisherExpectedFile> selected_files;
    for (const auto& selected_entry : selected_payload.files) {
        selected_files.push_back({selected_utf8_path(selected_entry.relative_path),
            selected_entry.size_bytes, selected_entry.sha256});
    }
    const std::string planned_set = selected_file_set_digest(std::move(expected_files));
    if (selected_file_set_digest(std::move(selected_files)) != planned_set) {
        throw std::runtime_error("selected source differs from reviewed native plan");
    }
    selected_payload.validate_source();
    const std::string apply_request = apply_envelope ?
        usk::json::canonical(envelope.at("apply_request")) : std::string{};
    if (submitted_apply_request && *submitted_apply_request != apply_request)
        throw StaleReviewedInstallRequest();
    if (apply_envelope && (envelope.at("apply_request").at("schema").as_string() !=
            "usk.install_local_apply_request.v1" ||
        usk::json::canonical(envelope.at("apply_request").at("plan_request")) != canonical_request ||
        envelope.at("apply_request").at("reviewed_plan_id").as_string() != internal_plan.plan_id ||
        envelope.at("apply_request").at("reviewed_plan_digest").as_string() != plan_digest)) {
        throw std::runtime_error("apply envelope differs from the reviewed native plan");
    }
    const std::string transaction_id = apply_envelope ?
        envelope.at("apply_request").at("transaction_id").as_string() : "labpub." + plan_digest.substr(0, 32);
    const std::string applied_at = apply_envelope ?
        envelope.at("apply_request").at("applied_at").as_string() : current_utc_timestamp();
    usk::json::Value snapshot_value(usk::json::Value::Object{
            {"schema", usk::json::Value(!consumer_read_sid.empty() ? "usk.publisher.lab_reviewed_plan_snapshot.v4" : apply_envelope ? "usk.publisher.lab_reviewed_plan_snapshot.v3" : "usk.publisher.lab_reviewed_plan_snapshot.v2")},
            {"plan_digest", usk::json::Value(plan_digest)},
            {"plan_envelope_sha256", usk::json::Value(reviewed_plan_envelope_sha256)},
            {"archive_sha256", usk::json::Value(selected_payload.source_sha256)},
            {"archive_identity_digest", usk::json::Value(selected_payload.source_identity_digest)},
            {"entry_set_digest", usk::json::Value(selected_payload.entry_set_digest)},
            {"selected_file_set_digest", usk::json::Value(planned_set)},
            {"target_root", plan.at("target").at("root")},
            {"setup_root", usk::json::Value(state_root)},
            {"transaction_id", usk::json::Value(transaction_id)},
            {"applied_at", usk::json::Value(applied_at)},
            {"policy_digest", usk::json::Value(internal_plan.recipe.policy_digest)},
            {"restart_policy_context", usk::json::Value(
                internal_plan.recipe.restart_policy_context)},
            {"plan_request", request},
            {"planned_entries", plan.at("planned_entries")}});
    if (!consumer_read_sid.empty()) {
        if (!apply_envelope) throw std::runtime_error("consumer read grant requires reviewed ordinary apply");
        snapshot_value.as_object().emplace("consumer_read_sid",usk::json::Value(consumer_read_sid));
    }
    if (apply_envelope) snapshot_value.as_object().emplace("apply_request",envelope.at("apply_request"));
    const std::string snapshot=canonical_record(usk::json::canonical(snapshot_value));
    usk::lifecycle::require_candidate_snapshot_apply_binding(snapshot_value);
    return {plan_digest, reviewed_plan_envelope_sha256,
        planned_set, snapshot, state_root, acceptance,
        transaction_id, applied_at, std::move(internal_plan),
        std::move(selected_payload), apply_request};
}

std::string observe_protected_anchors(HANDLE volume, const std::string& service_sid,
    const std::optional<ReviewedPlanBinding>& reviewed_plan,
    bool staged_only_reentry = false,
    usk::lifecycle::InstallResult* completed_result = nullptr,
    std::string* installed_response = nullptr) {
    using namespace usk::platform::windows;
    const std::wstring sid(service_sid.begin(), service_sid.end());
    const auto descriptor = make_publisher_directory_security_descriptor(sid);
    PSID owner = nullptr;
    BOOL owner_defaulted = FALSE;
    PACL dacl = nullptr;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    if (!GetSecurityDescriptorOwner(
            const_cast<unsigned char*>(descriptor.data()), &owner, &owner_defaulted) ||
        !GetSecurityDescriptorDacl(
            const_cast<unsigned char*>(descriptor.data()), &dacl_present, &dacl, &dacl_defaulted) ||
        !owner || !dacl_present || !dacl || owner_defaulted || dacl_defaulted) {
        throw std::runtime_error("protected lab descriptor is malformed");
    }
    if (staged_only_reentry && (!reviewed_plan || !selected_archive_mode)) {
        throw std::runtime_error("staged-only reentry requires a reviewed selected source");
    }
    const bool execution_bound = reviewed_plan.has_value() &&
        (submitted_apply_request.has_value() || submitted_recovery_request.has_value());
    const bool authenticated_bound = execution_bound && authenticated_request && !staged_only_reentry;
    std::unique_ptr<PublisherCreationCapture> creation_capture;
    if (execution_bound && !staged_only_reentry) {
        creation_capture = std::make_unique<PublisherCreationCapture>(volume, service_name);
    }
    OwnedHandle publication(staged_only_reentry ?
        open_exact_lab_child(volume, L"publication") :
        create_directory_relative_with_descriptor(volume, L"publication", descriptor));
    OwnedHandle staging(staged_only_reentry ?
        open_exact_lab_child(publication.get(), L"staging") :
        create_directory_relative_with_descriptor(
            publication.get(), L"staging", descriptor));
    std::string created_destination_id;
    {
        OwnedHandle created(staged_only_reentry ?
            open_exact_lab_child(publication.get(), L"destination", true) :
            create_directory_relative_with_descriptor(
                publication.get(), L"destination", descriptor));
        created_destination_id = observe_publisher_directory_handle(
            created.get()).file_id;
    }
    OwnedHandle state(staged_only_reentry ?
        open_exact_lab_child(publication.get(), L"state", false, false, true) :
        create_directory_relative_with_descriptor(
            publication.get(), L"state", descriptor));
    OwnedHandle journal(staged_only_reentry ?
        open_exact_lab_child(publication.get(), L"journal", false, false, true) :
        create_directory_relative_with_descriptor(
            publication.get(), L"journal", descriptor));
    const PublisherAnchorNames names{
        L"staging", L"destination", L"state", L"journal"};
    const auto first = observe_publisher_anchor_set(
        volume, {L"publication"}, names);
    require_publisher_anchor_set_security_shape(first, service_sid);
    if (first.destination_parent.object.file_id != created_destination_id) {
        throw std::runtime_error("created destination anchor identity changed");
    }
    HANDLE reopened_destination = INVALID_HANDLE_VALUE;
    for (const auto& listed : observe_publisher_directory_entries(publication.get())) {
        if (listed.name == L"destination") {
            if (reopened_destination != INVALID_HANDLE_VALUE) {
                CloseHandle(reopened_destination);
                throw std::runtime_error("duplicate destination anchor listing");
            }
            reopened_destination = open_publisher_listed_child(
                publication.get(), listed, true);
        }
    }
    if (reopened_destination == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("created destination anchor not listed");
    }
    OwnedHandle destination(reopened_destination);
    if (staged_only_reentry &&
        (observe_publisher_directory_entries(publication.get()).size() != 4 ||
         !observe_publisher_directory_entries(destination.get()).empty() ||
         !observe_publisher_directory_entries(state.get()).empty() ||
         observe_publisher_directory_entries(journal.get()).size() != 1 ||
         observe_publisher_directory_entries(journal.get()).front().name !=
             L"lab-reviewed-plan.json")) {
        throw std::runtime_error("staged-only reentry has unexpected protected children");
    }
    if (observe_publisher_directory_handle(destination.get()).file_id !=
            created_destination_id) {
        throw std::runtime_error("reopened destination anchor identity changed");
    }
    const auto second = observe_publisher_anchor_set(
        volume, {L"publication"}, names);
    require_publisher_anchor_set_phase_match(first, second);
    if (reviewed_plan && !staged_only_reentry) {
        require_public_mount_mapping(volume, reviewed_plan->setup_root,
            reviewed_plan->install_plan.target_root.u8string());
        write_journal_phase(journal.get(), L"lab-reviewed-plan.json",
            descriptor, reviewed_plan->durable_snapshot);
    }
    std::optional<usk::archive::StreamingStoredArchivePayload> selected_payload;
    bool selected_v2 = false;
    if (selected_archive_mode) {
        selected_payload = reviewed_plan ?
            reviewed_plan->selected_payload : inspect_selected_lab_archive();
        if (!staged_only_reentry) selected_payload->validate_source();
        selected_v2 = reviewed_plan.has_value() ||
            selected_payload->files.size() != 1 ||
            selected_payload->files.front().relative_path != "payload.bin";
    }
    if (staged_only_reentry) {
        const auto staged_children = observe_publisher_directory_entries(staging.get());
        if (staged_children.size() != 1 ||
            staged_children.front().name != L"candidate") {
            throw std::runtime_error("staged-only reentry has unexpected staging children");
        }
    }
    OwnedHandle candidate(staged_only_reentry ?
        open_exact_lab_child(staging.get(), L"candidate", false, true) :
        create_directory_relative_with_descriptor(
            staging.get(), L"candidate", descriptor));
    const std::vector<HANDLE> phase_handles{volume, publication.get(), staging.get(),
        destination.get(), state.get(), journal.get(), candidate.get()};
    usk::json::Value::Array prepared_execution_phases;
    if (execution_bound && !staged_only_reentry) {
        const auto empty = observe_publisher_tree(candidate.get());
        require_publisher_tree_security_shape(empty, service_sid);
        if (!empty.descendants.empty()) throw std::runtime_error("new protected candidate is not empty");
        prepared_execution_phases.push_back(capture_native_execution_phase(
            "protected_empty", phase_handles, first, empty, authenticated_bound, authenticated_bound));
    }
    static constexpr char bytes[] = "protected staged payload\n";
    std::uint64_t expected_payload_size = sizeof(bytes) - 1;
    std::string expected_source_digest;
    std::vector<PublisherExpectedFile> expected_files;
    if (selected_payload) {
        const auto& file = selected_payload->files.front();
        expected_payload_size = file.size_bytes;
        expected_source_digest = file.sha256;
        if (staged_only_reentry) {
            for (const auto& selected_file : selected_payload->files) {
                expected_files.push_back({
                    selected_utf8_path(selected_file.relative_path),
                    selected_file.size_bytes, selected_file.sha256});
            }
            if (selected_file_set_digest(expected_files) !=
                    reviewed_plan->selected_file_set_digest) {
                throw std::runtime_error("staged-only source differs from reviewed file set");
            }
        } else {
            expected_files = stage_selected_archive_files(
                candidate.get(), descriptor, *selected_payload);
        }
    } else {
        usk::base::Sha256 source_digest;
        source_digest.update(reinterpret_cast<const unsigned char*>(bytes),
            sizeof(bytes) - 1);
        expected_source_digest = source_digest.finish();
        // This source is a disposable service-owned fixture. The primitive
        // also needs separate source provenance before production use.
        OwnedHandle source(create_file_relative_with_descriptor(
            state.get(), L"lab-source.bin", descriptor));
        DWORD written = 0;
        if (!WriteFile(source.get(), bytes, sizeof(bytes) - 1, &written, nullptr) ||
            written != sizeof(bytes) - 1 || !FlushFileBuffers(source.get())) {
            throw std::runtime_error("protected lab source write or flush failed");
        }
        const auto streamed = stream_verified_source_to_staged_file(
            candidate.get(), L"payload.bin", descriptor, source.get(),
            sizeof(bytes) - 1, expected_source_digest);
        OwnedHandle payload(streamed.file);
        if (streamed.bytes_written != sizeof(bytes) - 1 ||
            streamed.sha256 != expected_source_digest) {
            throw std::runtime_error("protected lab source stream differs");
        }
        expected_files.push_back(
            {L"payload.bin", expected_payload_size, expected_source_digest});
        FILE_DISPOSITION_INFO disposition{};
        disposition.DeleteFile = TRUE;
        if (!SetFileInformationByHandle(source.get(), FileDispositionInfo,
                &disposition, sizeof(disposition))) {
            throw std::runtime_error("protected lab source cleanup failed");
        }
    }
    if (!observe_publisher_directory_entries(state.get()).empty()) {
        throw std::runtime_error("protected lab source remains in state");
    }
    const auto sealed = observe_publisher_tree(candidate.get());
    require_publisher_tree_security_shape(sealed, service_sid);
    require_publisher_tree_exact_file_closure(sealed, expected_files);
    if (execution_bound) prepared_execution_phases.push_back(capture_native_execution_phase(
        "sealed", phase_handles, observe_publisher_anchor_set(volume, {L"publication"}, names), sealed, authenticated_bound, authenticated_bound));
    const std::string selected_digest = selected_v2 ?
        selected_file_set_digest(expected_files) : std::string{};
    if (selected_v2 && selected_file_set_digest(sealed) != selected_digest) {
        throw std::runtime_error("selected lab staged file set differs from source");
    }
    const auto resealed = observe_publisher_tree(candidate.get());
    require_publisher_tree_phase_match(sealed, resealed);
    const auto third = observe_publisher_anchor_set(
        volume, {L"publication"}, names);
    require_publisher_anchor_set_phase_match(first, third);
    std::optional<usk::json::Value> creation_evidence;
    if (creation_capture) {
        creation_evidence = creation_capture->certificate(usk::json::parse(json_anchor_set(third)),
            usk::json::parse(json_tree(sealed)), prepared_execution_phases.front().at("execution"));
        // End capture before initializing the separate public metadata root.
        // This certificate covers these anchors and the sealed payload, not
        // later-created metadata files or objects reopened by another worker.
        creation_capture.reset();
    }
    if (poststage_gate && !staged_only_reentry) wait_for_poststage_gate();
    const std::string reviewed_snapshot_digest = reviewed_plan ?
        record_sha256(reviewed_plan->durable_snapshot) : std::string{};
    if (reviewed_plan) {
        require_public_mount_mapping(volume, reviewed_plan->setup_root,
            reviewed_plan->install_plan.target_root.u8string());
        usk::lifecycle::initialize_setup_root_for_publisher(
            reviewed_plan->setup_root, reviewed_plan->acceptance_root,
            "operator_acceptance_candidate", volume, volume_root, service_name);
        if (read_phase_record(journal.get(), L"lab-reviewed-plan.json") !=
                reviewed_plan->durable_snapshot) {
            throw std::runtime_error("reviewed plan snapshot changed before prepared phase");
        }
    }
    if (execution_bound) prepared_execution_phases.push_back(capture_native_execution_phase(
        "publish_prepared", phase_handles, third, observe_publisher_tree(candidate.get()), authenticated_bound, authenticated_bound));
    const std::string prepared = canonical_record(
        std::string("{\"schema\":\"usk.publisher.lab_phase_evidence.") +
        (execution_bound ? (creation_evidence ? (authenticated_bound ? "v9" : "v7") : "v3") : selected_v2 ? "v2" : "v1") + "\","
        "\"phase\":\"lab_prepared_evidence\",\"service_sid\":" +
        json_quote(service_sid) +
        ",\"volume_serial\":" +
        std::to_string(sealed.volume.file_id_volume_serial) +
        ",\"source_file_id\":" + json_quote(sealed.root.file_id) +
        ",\"destination_parent_file_id\":" +
        json_quote(first.destination_parent.object.file_id) +
        ",\"destination_name\":" + json_quote(ascii(visible_component)) + "," +
        (selected_v2 ?
            "\"selected_file_set_digest\":" + json_quote(selected_digest) :
            "\"payload_sha256\":" +
                json_quote(sealed.descendants.front().sha256)) +
        (selected_payload ?
            ",\"source_binding\":{\"archive_sha256\":" +
                json_quote(selected_payload->source_sha256) +
                ",\"archive_identity_digest\":" +
                json_quote(selected_payload->source_identity_digest) +
                ",\"entry_set_digest\":" +
                json_quote(selected_payload->entry_set_digest) +
                (reviewed_plan ?
                    ",\"reviewed_plan_digest\":" +
                        json_quote(reviewed_plan->plan_digest) +
                    ",\"plan_envelope_sha256\":" +
                        json_quote(reviewed_plan->envelope_sha256) +
                    ",\"reviewed_plan_snapshot_sha256\":" +
                        json_quote(reviewed_snapshot_digest) :
                    std::string{}) + "}" :
            std::string{}) +
        ",\"protected_anchors\":" + json_anchor_set(third) +
        ",\"sealed_tree\":" + json_tree(sealed) +
        (execution_bound ?
            ",\"execution_phases\":" + usk::json::canonical(usk::json::Value(prepared_execution_phases)) +
            ",\"execution_origin\":" + json_quote(staged_only_reentry ?
                "reopened_staged_tree" : "created_empty_in_current_worker") : std::string{}) +
        (authenticated_bound ? ",\"operation_admission\":" + (registered_operation_admission ?
            usk::json::canonical(*registered_operation_admission) : "null") : std::string{}) +
        (creation_evidence ? ",\"creation_evidence\":" + usk::json::canonical(*creation_evidence) : std::string{}) + "}");
    require_prepared_execution_phases(usk::json::parse(prepared), service_sid);
    if (reviewed_plan) {
        require_reviewed_plan_snapshot(reviewed_plan->durable_snapshot,
            usk::json::parse(prepared), selected_digest);
    }
    write_journal_phase(journal.get(), L"lab-prepared-evidence.json",
        descriptor, prepared);
    usk::base::Sha256 prepared_hasher;
    prepared_hasher.update(
        reinterpret_cast<const unsigned char*>(prepared.data()), prepared.size());
    const std::string prepared_digest = prepared_hasher.finish();
    if (prepublish_gate) wait_for_prepublish_gate();
    require_publisher_tree_phase_match(sealed, observe_publisher_tree(candidate.get()));
    require_publisher_anchor_set_phase_match(first,
        observe_publisher_anchor_set(volume, {L"publication"}, names));
    usk::json::Value::Array visible_execution_phases;
    if (execution_bound) {
        visible_execution_phases.push_back(capture_native_execution_phase("before_rename",
            phase_handles, observe_publisher_anchor_set(volume, {L"publication"}, names),
            observe_publisher_tree(candidate.get()), authenticated_bound, authenticated_bound));
        require_publisher_execution_worker_match(prepared_execution_phases.back().at("execution"),
            visible_execution_phases.front().at("execution"));
        if (authenticated_bound)
            require_native_descendant_continuity(prepared_execution_phases.back(),
                visible_execution_phases.front());
    }
    PublisherBoundRenameObservation renamed;
    if (registered_admission) {
        if (!reviewed_plan || visible_execution_phases.empty())
            throw std::runtime_error("registered publication requires the reviewed native phase closure");
        require_current_registered_publication_admission(usk::json::parse(prepared),
            visible_execution_phases.front(), *reviewed_plan, volume, service_sid);
    }
    renamed = probe_publisher_bound_rename_no_replace(candidate.get(),
        destination.get(), visible_component, sealed.root,
        first.destination_parent.object);
    if (postrename_gate) wait_for_postrename_gate();
    const auto visible = observe_visible_publisher_tree_against_seal(
        destination.get(), visible_component, sealed);
    require_publisher_tree_security_shape(visible, service_sid);
    const auto after = observe_publisher_anchor_set(
        volume, {L"publication"}, names);
    require_publisher_anchor_set_phase_match(first, after);
    if (execution_bound) visible_execution_phases.push_back(capture_native_execution_phase(
        "visible_bound", phase_handles, after, visible, authenticated_bound, authenticated_bound));
    const std::string bound = lab_visible_record(
        renamed.root_file_id, first.destination_parent.object.file_id,
        prepared_digest, after, visible, selected_digest, visible_execution_phases,
        "renamed_by_current_worker", creation_evidence.has_value(), creation_evidence.has_value(), &renamed,
        creation_evidence.has_value(), creation_evidence.has_value(), authenticated_bound, authenticated_bound);
    require_visible_execution_phase(usk::json::parse(bound), service_sid, usk::json::parse(prepared));
    write_journal_phase(journal.get(), L"lab-visible-evidence.json", descriptor, bound);
    const auto journal_tree = observe_publisher_tree(journal.get());
    require_publisher_tree_security_shape(journal_tree, service_sid);
    if (journal_tree.root.file_id != first.journal.object.file_id ||
        journal_tree.descendants.size() != (reviewed_plan ? 3u : 2u) ||
        journal_tree.descendants[0].relative_path != L"lab-prepared-evidence.json" ||
        journal_tree.descendants[0].size != prepared.size() ||
        (reviewed_plan &&
            (journal_tree.descendants[1].relative_path != L"lab-reviewed-plan.json" ||
            journal_tree.descendants[1].size != reviewed_plan->durable_snapshot.size() ||
            journal_tree.descendants[1].sha256 != reviewed_snapshot_digest)) ||
        journal_tree.descendants.back().relative_path != L"lab-visible-evidence.json" ||
        journal_tree.descendants.back().size != bound.size()) {
        throw std::runtime_error("publisher lab journal phase closure is not exact");
    }
    if (postjournal_gate) wait_for_postjournal_gate();
    std::string completion_digest;
    if (selected_payload) {
        completion_digest = complete_selected_lab_state(state.get(),
            usk::json::parse(prepared), prepared_digest, bound, after, visible,
            service_sid, true, selected_digest);
        OwnedHandle visible_root(open_exact_lab_child(
            destination.get(), visible_component));
        require_publisher_tree_phase_match(visible,
            observe_publisher_tree(visible_root.get()));
        require_publisher_tree_phase_match(journal_tree,
            observe_publisher_tree(journal.get()));
        require_publisher_anchor_set_phase_match(first,
            observe_publisher_anchor_set(volume, {L"publication"}, names));
        const auto final_destination =
            observe_publisher_directory_entries(destination.get());
        if (read_phase_record(journal.get(), L"lab-prepared-evidence.json") !=
                prepared ||
            (reviewed_plan && read_phase_record(journal.get(),
                L"lab-reviewed-plan.json") != reviewed_plan->durable_snapshot) ||
            read_phase_record(journal.get(), L"lab-visible-evidence.json") != bound ||
            !observe_publisher_directory_entries(staging.get()).empty() ||
            final_destination.size() != 1 ||
            final_destination.front().name != visible_component ||
            observe_publisher_directory_entries(publication.get()).size() != 4 ||
            complete_selected_lab_state(state.get(), usk::json::parse(prepared),
                prepared_digest, bound, after, visible, service_sid, false,
                selected_digest) !=
                completion_digest) {
            throw std::runtime_error("selected lab closure changed after completion");
        }
        if (reviewed_plan) {
            // The creation handle needed DELETE for the bound rename. The
            // re-opened visible root above now retains the same verified
            // identity without DELETE while public path writes are pinned.
            candidate.close_checked();
            const auto finalized = finalize_reviewed_public_state(
                reviewed_plan->durable_snapshot, completion_digest, volume,
                journal.get(), state.get(), visible_root.get(), visible.root.file_id, installed_response);
            if (completed_result) {
                if (!finalized) throw std::runtime_error("protected apply has no installed result");
                *completed_result = *finalized;
            }
        }
    }
    return "{\"boundary_file_id\":" + json_quote(first.chain.boundary.file_id) +
        ",\"publication_file_id\":" +
        json_quote(first.chain.children.front().object.file_id) +
        ",\"staging_file_id\":" + json_quote(first.staging.object.file_id) +
        ",\"destination_file_id\":" +
        json_quote(first.destination_parent.object.file_id) +
        ",\"state_file_id\":" + json_quote(first.state.object.file_id) +
        ",\"journal_file_id\":" + json_quote(first.journal.object.file_id) +
        ",\"objects\":{\"boundary\":" +
            json_protected_object(first.chain.boundary) +
        ",\"publication\":" +
            json_protected_object(first.chain.children.front().object) +
        ",\"staging\":" + json_protected_object(first.staging.object) +
        ",\"destination\":" +
            json_protected_object(first.destination_parent.object) +
        ",\"state\":" + json_protected_object(first.state.object) +
        ",\"journal\":" + json_protected_object(first.journal.object) +
        "},\"staged_tree\":" + (selected_v2 ? json_tree(sealed) :
            "{\"root\":" + json_protected_object(sealed.root) +
            ",\"file\":" +
                json_protected_object(sealed.descendants.front().object) +
            ",\"relative_path\":\"payload.bin\",\"size\":" +
                std::to_string(sealed.descendants.front().size) +
            ",\"sha256\":" +
                json_quote(sealed.descendants.front().sha256) + "}") +
        ",\"publication_probe\":{\"source_file_id\":" +
        json_quote(renamed.root_file_id) +
        ",\"former_name\":" + json_quote(ascii(renamed.former_name)) +
        ",\"visible_name\":" + json_quote(ascii(renamed.visible_name)) +
        ",\"native_rename_call\":" + json_native_rename_call(renamed) +
        ",\"visible_root\":" + json_protected_object(visible.root) +
        ",\"visible_file\":" + (selected_v2 ? "null" :
            json_protected_object(visible.descendants.front().object)) +
        ",\"visible_payload_sha256\":" + (selected_v2 ? "null" :
            json_quote(visible.descendants.front().sha256)) +
        (selected_v2 ? ",\"visible_tree\":" + json_tree(visible) +
            ",\"selected_file_set_digest\":" + json_quote(selected_digest) :
            std::string{}) +
        ",\"journal_root\":" + json_protected_object(journal_tree.root) +
        ",\"prepared_file\":" +
        json_protected_object(journal_tree.descendants[0].object) +
        ",\"bound_file\":" +
        json_protected_object(journal_tree.descendants.back().object) +
        ",\"prepared_record\":" + json_quote(prepared) +
        ",\"prepared_sha256\":" +
        json_quote(journal_tree.descendants[0].sha256) +
        ",\"bound_record\":" + json_quote(bound) +
        ",\"bound_sha256\":" +
        json_quote(journal_tree.descendants.back().sha256) +
        ",\"reviewed_plan_snapshot_sha256\":" +
        (reviewed_plan ? json_quote(reviewed_snapshot_digest) : "null") +
        ",\"completion_record_sha256\":" +
        (completion_digest.empty() ? "null" : json_quote(completion_digest)) +
        "}}";
}


struct CandidateApplyContext {
    HANDLE volume;
    std::string service_sid;
    const ReviewedPlanBinding& reviewed;
    bool& effects_may_exist;
    std::string anchors;
    bool entered=false;
    std::function<void()> start_installation_lease;
    std::exception_ptr operation_failure;
};
thread_local usk::platform::windows::PublisherInstallOperationContext* original_operation_context=nullptr;
class ScopedOriginalOperationContext final {
public:
    explicit ScopedOriginalOperationContext(usk::platform::windows::PublisherInstallOperationContext& context) {
        if (original_operation_context) throw std::runtime_error("nested original operation context");
        context.require_fence();
        original_operation_context=&context;
    }
    ~ScopedOriginalOperationContext() { original_operation_context=nullptr; }
    ScopedOriginalOperationContext(const ScopedOriginalOperationContext&)=delete;
    ScopedOriginalOperationContext& operator=(const ScopedOriginalOperationContext&)=delete;
};
thread_local CandidateApplyContext* candidate_apply=nullptr;
class ScopedCandidateApply final {
public:
    explicit ScopedCandidateApply(CandidateApplyContext& context) {
        if (candidate_apply) throw std::runtime_error("nested candidate publisher context");
        candidate_apply=&context;
    }
    ~ScopedCandidateApply() { candidate_apply=nullptr; }
    ScopedCandidateApply(const ScopedCandidateApply&)=delete;
    ScopedCandidateApply& operator=(const ScopedCandidateApply&)=delete;
};
thread_local bool execution_active=false;
struct ScopedExecution {
    explicit ScopedExecution(const usk::platform::windows::CandidatePublisherConfiguration& config) {
        if (execution_active) throw std::runtime_error("nested publisher execution");
        if (config.authenticated_request && !config.submitted_apply_request &&
            !config.submitted_recovery_request && !config.submitted_verify_request)
            throw std::runtime_error("authenticated channel lacks an operation request");
        if (config.registered_admission && (!config.authenticated_request || config.prepare_disposable_boundary))
            throw std::runtime_error("registered operation requires its channel and an already protected target");
        service_name=config.service_name;
        receipt_path=config.receipt_path;
        volume_root=config.volume_root;
        visible_component=L"visible";
        prepublish_gate=config.prepublish_gate;
        poststage_gate=config.poststage_gate;
        postrename_gate=config.postrename_gate;
        postjournal_gate=config.postjournal_gate;
        recover_prepared=config.recover_prepared;
        recover_snapshot_only=config.recover_snapshot_only;
        recover_reviewed=config.recover_reviewed;
        recover_sealed_journal=config.recover_sealed_journal;
        recover_visible_bound=config.recover_visible_bound;
        verify_installed_request=config.verify_installed;
        selected_archive_mode=config.selected_archive_mode;
        selected_archive_path=config.selected_archive_path;
        selected_archive_sha256=config.selected_archive_sha256;
        reviewed_plan_envelope_path=config.reviewed_plan_envelope_path;
        reviewed_plan_envelope_sha256=config.reviewed_plan_envelope_sha256;
        submitted_apply_request=config.submitted_apply_request ?
            std::optional<std::string>{usk::json::canonical(usk::json::parse(*config.submitted_apply_request))} :
            std::nullopt;
        submitted_recovery_request=config.submitted_recovery_request ?
            std::optional<std::string>{usk::json::canonical(usk::json::parse(*config.submitted_recovery_request))} :
            std::nullopt;
        submitted_verify_request=config.submitted_verify_request ?
            std::optional<std::string>{usk::json::canonical(usk::json::parse(*config.submitted_verify_request))} :
            std::nullopt;
        if (verify_installed_request != submitted_verify_request.has_value() ||
            (submitted_recovery_request && (!recover_reviewed ||
                submitted_apply_request || submitted_verify_request ||
                !reviewed_plan_envelope_path.empty() || !selected_archive_path.empty())) ||
            (verify_installed_request && (submitted_apply_request || submitted_recovery_request ||
                recover_prepared || recover_reviewed || recover_snapshot_only ||
                !reviewed_plan_envelope_path.empty() || !selected_archive_path.empty() ||
                config.prepare_disposable_boundary || config.interrupt_consumer_grant))) {
            throw std::runtime_error("read-only verify mode has incompatible publisher authority");
        }
        consumer_read_sid=config.consumer_read_sid;
        interrupt_consumer_grant=config.interrupt_consumer_grant;
        if (!consumer_read_sid.empty()) {
            usk::platform::windows::require_publisher_consumer_sid(consumer_read_sid);
            if (!submitted_apply_request && !submitted_recovery_request &&
                !(verify_installed_request && submitted_verify_request)) {
                throw std::runtime_error("consumer policy requires an authenticated operation");
            }
        } else if (interrupt_consumer_grant) throw std::runtime_error("consumer fault requires admitted consumer policy");
        stop_event=config.stop_event;
        authenticated_request=config.authenticated_request;
        registered_admission=config.registered_admission;
        registered_operation_admission.reset();
        reviewed_install_reentry=false;
        execution_active=true;
    }
    ~ScopedExecution() { submitted_apply_request.reset(); submitted_recovery_request.reset();
        submitted_verify_request.reset();
        authenticated_request=nullptr;
        registered_admission=nullptr;
        registered_operation_admission.reset();
        consumer_read_sid.clear(); visible_component=L"visible"; execution_active=false; }
};
} // namespace

std::optional<usk::json::Value> usk::lifecycle::candidate_publisher_plan_replay(
    const usk::json::Value& plan_request) {
    if (!original_operation_context) return std::nullopt;
    if (!execution_active || !registered_admission || !authenticated_request || !submitted_apply_request)
        throw std::runtime_error("original operation replay lacks the live authenticated engine");
    const auto& snapshot=original_operation_context->record().at("reviewed_snapshot");
    require_candidate_snapshot_apply_binding(snapshot);
    if (usk::json::canonical(snapshot.at("plan_request")) != usk::json::canonical(plan_request))
        throw StaleReviewedInstallRequest();
    return usk::json::Value(usk::json::Value::Object{
        {"archive_sha256",snapshot.at("archive_sha256")},
        {"archive_identity_digest",snapshot.at("archive_identity_digest")},
        {"entry_set_digest",snapshot.at("entry_set_digest")},
        {"policy_digest",snapshot.at("policy_digest")},
        {"policy_context",snapshot.at("restart_policy_context")}});
}

void usk::lifecycle::require_candidate_snapshot_apply_binding(const usk::json::Value& snapshot) {
    const bool consumer_bound = snapshot.at("schema").as_string() == "usk.publisher.lab_reviewed_plan_snapshot.v4";
    const bool caller_bound = consumer_bound || snapshot.at("schema").as_string() == "usk.publisher.lab_reviewed_plan_snapshot.v3";
    if ((!consumer_read_sid.empty() && !consumer_bound) ||
        (consumer_bound && snapshot.at("consumer_read_sid").as_string() != consumer_read_sid) ||
        (submitted_apply_request && (!caller_bound ||
         usk::json::canonical(snapshot.at("apply_request")) != *submitted_apply_request))) {
        throw StaleReviewedInstallRequest();
    }
    if (consumer_bound) usk::platform::windows::require_publisher_consumer_sid(snapshot.at("consumer_read_sid").as_string());
    if (!caller_bound) return;
    const auto& apply=snapshot.at("apply_request");
    if (snapshot.as_object().size() != (consumer_bound ? 17u : 16u) || apply.as_object().size() != 7 ||
        apply.at("schema").as_string() != "usk.install_local_apply_request.v1" ||
        apply.at("confirmation").as_string() != "APPLY" ||
        usk::json::canonical(apply.at("plan_request")) != usk::json::canonical(snapshot.at("plan_request")) ||
        apply.at("reviewed_plan_id").as_string() != snapshot.at("plan_request").at("request_id").as_string() ||
        apply.at("reviewed_plan_digest").as_string() != snapshot.at("plan_digest").as_string() ||
        apply.at("transaction_id").as_string() != snapshot.at("transaction_id").as_string() ||
        !usk::record_io::valid_identifier(apply.at("transaction_id").as_string()) ||
        apply.at("applied_at").as_string() != snapshot.at("applied_at").as_string()) {
        throw std::runtime_error("durable caller apply binding differs");
    }
}

std::optional<usk::lifecycle::InstallResult> usk::lifecycle::apply_in_candidate_publisher_context(
    const InstallPlan& plan, const std::string& transaction_id, const std::string& applied_at) {
    if (!candidate_apply) return std::nullopt;
    auto& context=*candidate_apply;
    const auto& bound=context.reviewed;
    if (context.entered || plan.required_commit_authority !=
            usk::transaction::CommitAuthorityRequirement::staged_child_bound_v1 ||
        plan.plan_id != bound.install_plan.plan_id || plan.plan_digest != bound.plan_digest ||
        plan.target_root != bound.install_plan.target_root ||
        plan.roots.state_root != bound.install_plan.roots.state_root ||
        plan.roots.audit_root != bound.install_plan.roots.audit_root ||
        plan.roots.staging_parent != bound.install_plan.roots.staging_parent ||
        transaction_id != bound.transaction_id || applied_at != bound.applied_at) {
        throw std::runtime_error("protected apply differs from its operation-bound context");
    }
    const auto service=usk::platform::windows::observe_current_restricted_publisher_service(service_name);
    if (service.service_sid != context.service_sid) throw std::runtime_error("publisher service identity changed");
    require_install_execution_identity(plan,bound.plan_digest,transaction_id,applied_at);
    require_install_path_capacity(plan,transaction_id);
    require_public_mount_mapping(context.volume,bound.setup_root,plan.target_root.u8string());
    usk::platform::windows::require_publisher_object_security_shape(
        usk::platform::windows::observe_publisher_directory_handle(context.volume),context.service_sid);
    if (registered_admission && (!registered_operation_admission ||
        usk::json::canonical(admit_current_registered_operation(context.volume, context.service_sid, bound)) !=
            usk::json::canonical(*registered_operation_admission)))
        throw std::runtime_error("public protected apply lacks the current native registered operation admission");
    plan.validate_source();
    context.entered=true;
    context.effects_may_exist=true;
    usk::lifecycle::InstallResult completed;
    auto selected=bound;
    selected.install_plan=plan;
    selected.selected_payload.validate_source=plan.validate_source;
    selected.selected_payload.files.clear();
    for (const auto& file : plan.files) {
        if (!file.reader || !file.bytes.empty()) throw std::runtime_error("protected apply requires native streaming readers");
        usk::archive::StreamingPayloadFile entry;
        entry.relative_path=file.relative_path;
        entry.sha256=file.sha256;
        entry.size_bytes=file.size_bytes;
        entry.reader=file.reader;
        selected.selected_payload.files.push_back(std::move(entry));
    }
    try {
        // The public dispatcher has already rebuilt and matched the reviewed
        // plan before entering this context. Bootstrap can legitimately change
        // its owned setup-root identity only after that stale-plan check.
        if (registered_admission && !context.start_installation_lease)
            throw std::runtime_error("registered apply lacks its native ownership initializer");
        if (context.start_installation_lease) context.start_installation_lease();
        context.anchors=observe_protected_anchors(context.volume,context.service_sid,selected,false,&completed);
    } catch (const std::exception& error) {
        // Keep the actual typed cause across the private C-ABI call. Its JSON
        // reply remains conservatively recovery-required; caller-controlled
        // response strings cannot manufacture an exception or authority.
        using namespace usk::platform::windows;
        using namespace usk::transaction;
        if (dynamic_cast<const InstallLeaseConflict*>(&error) || dynamic_cast<const InstallStateRevisionStale*>(&error) ||
            dynamic_cast<const InstallLeaseStale*>(&error) || dynamic_cast<const PublisherInstallBusy*>(&error) ||
            dynamic_cast<const PublisherVolumeBusy*>(&error) || dynamic_cast<const PublisherOperationCancelled*>(&error))
            context.operation_failure = std::current_exception();
        throw ProtectedApplyEffectsRetained(error.what());
    }
    return completed;
}

namespace {
struct CompletedVerificationBoundary {
    std::string snapshot_record;
    std::string completion_digest;
    std::string visible_root_file_id;
    std::string observation;
};

CompletedVerificationBoundary observe_completed_verification_boundary(
    HANDLE volume, const std::string& service_sid) {
    using namespace usk::platform::windows;
    const PublisherAnchorNames names{L"staging", L"destination", L"state", L"journal"};
    const auto anchors = observe_publisher_anchor_set(volume, {L"publication"}, names);
    require_publisher_anchor_set_security_shape(anchors, service_sid);
    OwnedHandle publication(open_exact_lab_child(volume, L"publication"));
    OwnedHandle staging(open_exact_lab_child(publication.get(), L"staging"));
    OwnedHandle destination(open_exact_lab_child(publication.get(), L"destination"));
    OwnedHandle state(open_exact_lab_child(publication.get(), L"state"));
    OwnedHandle journal(open_exact_lab_child(publication.get(), L"journal"));
    const std::string prepared_record = read_phase_record(journal.get(), L"lab-prepared-evidence.json");
    const std::string snapshot_record = read_phase_record(journal.get(), L"lab-reviewed-plan.json");
    const auto prepared = usk::json::parse(prepared_record);
    const bool execution_bound = is_execution_record_schema(prepared.at("schema").as_string());
    const auto snapshot = usk::json::parse(snapshot_record);
    if (!prepared.contains("source_binding") ||
        !prepared.at("source_binding").contains("reviewed_plan_snapshot_sha256") ||
        record_sha256(snapshot_record) != prepared.at("source_binding")
            .at("reviewed_plan_snapshot_sha256").as_string()) {
        throw std::runtime_error("verification target has no durable reviewed snapshot binding");
    }
    visible_component = selected_visible_component(snapshot.at("target_root").as_string());
    const auto destination_entries = observe_publisher_directory_entries(destination.get());
    if (observe_publisher_directory_entries(publication.get()).size() != 4 ||
        !observe_publisher_directory_entries(staging.get()).empty() ||
        destination_entries.size() != 1 || destination_entries.front().name != visible_component) {
        throw std::runtime_error("verification requires a completed protected namespace");
    }
    OwnedHandle visible(open_exact_lab_child(destination.get(), visible_component));
    const std::string visible_record = read_phase_record(journal.get(), L"lab-visible-evidence.json");
    const std::string completion_record = read_phase_record(state.get(), L"lab-installed-state.json");
    const auto bound = usk::json::parse(visible_record);
    const auto completion = usk::json::parse(completion_record);
    const auto journal_tree = observe_publisher_tree(journal.get());
    const auto state_tree = observe_publisher_tree(state.get());
    const auto visible_tree = observe_publisher_tree(visible.get());
    require_publisher_tree_security_shape(journal_tree, service_sid);
    require_publisher_tree_security_shape(state_tree, service_sid);
    const auto snapshot_schema = snapshot.at("schema").as_string();
    const bool consumer_bound = snapshot_schema ==
        "usk.publisher.lab_reviewed_plan_snapshot.v4";
    if ((consumer_bound != !consumer_read_sid.empty()) ||
        (consumer_bound && snapshot.at("consumer_read_sid").as_string() != consumer_read_sid)) {
        throw std::runtime_error("verification caller differs from durable consumer policy");
    }
    // A completed v4 install has granted every visible object to its exact
    // consumer. Project that one read-only ACE away before checking the
    // protected seal; a missing or broader grant is never accepted.
    const auto protected_visible = consumer_bound ?
        publisher_consumer_read_projection(visible_tree, service_sid,
            consumer_read_sid, true) : visible_tree;
    require_publisher_tree_security_shape(protected_visible, service_sid);
    const std::string prepared_digest = record_sha256(prepared_record);
    const std::string snapshot_digest = record_sha256(snapshot_record);
    const std::string visible_digest = record_sha256(visible_record);
    const std::string completion_digest = record_sha256(completion_record);
    if (journal_tree.root.file_id != anchors.journal.object.file_id ||
        journal_tree.descendants.size() != 3 ||
        journal_tree.descendants[0].relative_path != L"lab-prepared-evidence.json" ||
        journal_tree.descendants[0].sha256 != prepared_digest ||
        journal_tree.descendants[1].relative_path != L"lab-reviewed-plan.json" ||
        journal_tree.descendants[1].sha256 != snapshot_digest ||
        journal_tree.descendants[2].relative_path != L"lab-visible-evidence.json" ||
        journal_tree.descendants[2].sha256 != visible_digest ||
        state_tree.root.file_id != anchors.state.object.file_id ||
        state_tree.descendants.size() != 1 ||
        state_tree.descendants[0].relative_path != L"lab-installed-state.json" ||
        state_tree.descendants[0].sha256 != completion_digest ||
        (snapshot_schema != "usk.publisher.lab_reviewed_plan_snapshot.v3" &&
            !consumer_bound) ||
        (!execution_bound && prepared.at("schema").as_string() != "usk.publisher.lab_phase_evidence.v2") ||
        prepared.at("phase").as_string() != "lab_prepared_evidence" ||
        prepared.at("service_sid").as_string() != service_sid ||
        prepared.at("destination_name").as_string() != ascii(visible_component) ||
        prepared.at("source_file_id").as_string() != visible_tree.root.file_id ||
        prepared.at("destination_parent_file_id").as_string() !=
            anchors.destination_parent.object.file_id ||
        prepared.at("volume_serial").as_unsigned() !=
            anchors.chain.volume.file_id_volume_serial ||
        usk::json::canonical(prepared.at("protected_anchors")) !=
            usk::json::canonical(usk::json::parse(json_anchor_set(anchors)))) {
        throw std::runtime_error("verification protected evidence differs");
    }
    require_prepared_execution_phases(prepared, service_sid);
    const std::string selected_digest = prepared.at("selected_file_set_digest").as_string();
    require_reviewed_plan_snapshot(snapshot_record, prepared, selected_digest);
    const std::string staged_name =
        ascii(anchors.staging.object.native_name) + "\\candidate";
    const std::string visible_name =
        ascii(anchors.destination_parent.object.native_name) + "\\" + ascii(visible_component);
    const std::string sealed_visible = prepared_tree_at_visible_name(
        prepared.at("sealed_tree"), staged_name, visible_name);
    if (bound.as_object().size() != visible_record_field_count(prepared.at("schema").as_string()) ||
        bound.at("schema").as_string() != prepared.at("schema").as_string() ||
        bound.at("phase").as_string() != "lab_visible_evidence" ||
        bound.at("source_file_id").as_string() != visible_tree.root.file_id ||
        bound.at("destination_parent_file_id").as_string() !=
            anchors.destination_parent.object.file_id ||
        bound.at("destination_name").as_string() != ascii(visible_component) ||
        bound.at("selected_file_set_digest").as_string() != selected_digest ||
        bound.at("prepared_record_sha256").as_string() != prepared_digest ||
        usk::json::canonical(bound.at("protected_anchors")) !=
            usk::json::canonical(usk::json::parse(json_anchor_set(anchors))) ||
        usk::json::canonical(bound.at("visible_tree")) != sealed_visible ||
        completion.as_object().size() != 11 ||
        completion.at("schema").as_string() != "usk.publisher.lab_installed_state.v2" ||
        completion.at("phase").as_string() != "lab_installed_state" ||
        completion.at("service_sid").as_string() != service_sid ||
        completion.at("volume_serial").as_unsigned() !=
            anchors.chain.volume.file_id_volume_serial ||
        completion.at("prepared_record_sha256").as_string() != prepared_digest ||
        completion.at("visible_record_sha256").as_string() != visible_digest ||
        completion.at("visible_root_file_id").as_string() != visible_tree.root.file_id ||
        completion.at("destination_parent_file_id").as_string() !=
            anchors.destination_parent.object.file_id ||
        completion.at("destination_name").as_string() != ascii(visible_component) ||
        completion.at("selected_file_set_digest").as_string() != selected_digest ||
        usk::json::canonical(completion.at("source_binding")) !=
            usk::json::canonical(prepared.at("source_binding"))) {
        throw std::runtime_error("verification completed intent differs from prepared publication");
    }
    require_visible_execution_phase(bound, service_sid, prepared);
    require_publisher_anchor_set_phase_match(anchors,
        observe_publisher_anchor_set(volume, {L"publication"}, names));
    require_publisher_tree_phase_match(journal_tree, observe_publisher_tree(journal.get()));
    require_publisher_tree_phase_match(state_tree, observe_publisher_tree(state.get()));
    require_publisher_tree_phase_match(visible_tree, observe_publisher_tree(visible.get()));
    // Current payload bytes may differ from the sealed install. The shared
    // verifier reports that drift; protected intent and root identity may not.
    return {snapshot_record, completion_digest, visible_tree.root.file_id,
        json_anchor_set(anchors) + "\n" + json_tree(journal_tree) + "\n" +
            json_tree(state_tree) + "\n" + json_tree(visible_tree)};
}

std::string verify_completed_install_in_service(HANDLE volume,
    const std::string& service_sid) {
    if (!submitted_verify_request) throw std::runtime_error("authenticated verify request is absent");
    const auto request = usk::json::parse(*submitted_verify_request);
    if (request.as_object().size() != 6 ||
        request.at("schema").as_string() != "usk.publisher_installed_verify_request.v1") {
        throw std::runtime_error("authenticated verify request shape differs");
    }
    const auto boundary = observe_completed_verification_boundary(volume, service_sid);
    const std::string snapshot_record = boundary.snapshot_record;
    const auto snapshot = usk::json::parse(snapshot_record);
    if (snapshot.at("schema").as_string() != "usk.publisher.lab_reviewed_plan_snapshot.v3" &&
        snapshot.at("schema").as_string() != "usk.publisher.lab_reviewed_plan_snapshot.v4") {
        throw std::runtime_error("read-only verify requires caller-bound installed snapshot");
    }
    const auto plan = restore_reviewed_install_plan(snapshot_record);
    if (request.at("install_id").as_string() != plan.install_id ||
        request.at("transaction_id").as_string() != snapshot.at("transaction_id").as_string()) {
        throw std::runtime_error("authenticated verify request differs from completed install");
    }
    usk::lifecycle::require_completed_consumer_install(plan,
        snapshot.at("transaction_id").as_string(), snapshot.at("applied_at").as_string(),
        boundary.completion_digest, volume_root, volume, service_name);
    const auto public_request = usk::json::Value(usk::json::Value::Object{
        {"schema", usk::json::Value("usk.installed_verify_request.v1")},
        {"request_id", request.at("request_id")},
        {"install_id", request.at("install_id")},
        {"report_id", request.at("report_id")},
        {"verified_at", request.at("verified_at")}});
    std::string response;
    with_public_roots_bound(volume, plan,
        boundary.visible_root_file_id, [&] {
        const std::string input = usk::json::canonical(public_request);
        int status = -1;
        char* raw = usk_public_lifecycle_command_json("installed.verify",
            input.data(), input.size(), plan.roots.state_root.parent_path().u8string().c_str(),
            std::filesystem::path(plan.target_root).root_path().u8string().c_str(),
            "operator_acceptance_candidate", &status);
        if (!raw) throw std::runtime_error("installed verification response is absent");
        response = raw;
        usk_public_lifecycle_command_free(raw);
        if (status != 0 || usk::json::parse(response).at("status").as_string() != "ok") {
            throw std::runtime_error("installed verification refused");
        }
    });
    const auto result = usk::json::parse(response);
    const auto& report = result.at("payload");
    if (report.at("schema").as_string() != "usk.verification_report.v1" ||
        report.at("install_id").as_string() != plan.install_id) {
        throw std::runtime_error("installed verification response identity differs");
    }
    const std::string status = report.at("status").as_string();
    if (status != "pass" && status != "fail" && status != "warn" &&
        status != "unknown") {
        throw std::runtime_error("installed verification result is unsupported");
    }
    const auto bound_report = usk::lifecycle::verify_completed_install_on_bound_volume(
        plan, request.at("report_id").as_string(),
        request.at("verified_at").as_string(), volume_root, volume, service_name);
    if (report.at("report_digest").as_string() != bound_report.report_digest ||
        status != bound_report.status) {
        throw std::runtime_error("public verification differs from held-volume payload");
    }
    const auto after = observe_completed_verification_boundary(volume, service_sid);
    if (after.snapshot_record != snapshot_record ||
        after.completion_digest != boundary.completion_digest ||
        after.visible_root_file_id != boundary.visible_root_file_id ||
        after.observation != boundary.observation) {
        throw std::runtime_error("protected publication changed during read-only verify");
    }
    return "{\"schema\":\"usk.publisher_lab_service_observation.v1\",\"status\":" +
        json_quote(status == "pass" ? "pass" : "failed") +
        ",\"transaction_id\":" + json_quote(snapshot.at("transaction_id").as_string()) +
        ",\"bound_report_digest\":" + json_quote(bound_report.report_digest) +
        ",\"verify_response\":" + response + "}\n";
}
} // namespace

void usk::platform::windows::require_candidate_publisher_execution_records(
    const usk::json::Value& prepared, const usk::json::Value& visible,
    const std::wstring& expected_service_name, const std::string& expected_service_sid) {
    require_prepared_execution_phases(prepared, expected_service_sid, expected_service_name);
    require_visible_execution_phase(visible, expected_service_sid, prepared, expected_service_name);
}

std::string usk::platform::windows::execute_candidate_restricted_publisher(
    const CandidatePublisherConfiguration& config, bool& publication_effects_may_exist) {
    ScopedExecution execution(config);
        // Includes staged-only/snapshot replay, which can write metadata before
        // a rename gate. Read-only verification keeps its historical ceiling.
        if (registered_admission && !verify_installed_request &&
            !publisher_registered_execution_platform_qualified(observe_publisher_execution_platform()))
            throw usk::transaction::CommitAuthorityUnavailable();
        if (submitted_apply_request || submitted_recovery_request || submitted_verify_request) {
            usk::platform::windows::require_publisher_execution_platform(
                usk::platform::windows::observe_publisher_execution_platform());
        }
        const auto observed =
            usk::platform::windows::observe_current_restricted_publisher_service(service_name);
        const usk::platform::windows::PublisherVolumeOperationGuard operation_guard(volume_root, stop_event);
        std::optional<usk::platform::windows::PublisherInstallOperationGuard> install_guard;
        if (submitted_apply_request) {
            const auto request = usk::json::parse(*submitted_apply_request);
            install_guard.emplace(volume_root,
                request.at("plan_request").at("install_id").as_string(), stop_event);
        } else if (submitted_verify_request) {
            const auto request = usk::json::parse(*submitted_verify_request);
            install_guard.emplace(volume_root, request.at("install_id").as_string(), stop_event);
        }
        // Both guards are held before source/installed-state revalidation and
        // before effects. Source-free legacy replay retains the volume guard.
        const DWORD root_access = (recover_prepared && !registered_admission) || verify_installed_request ?
            (FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | READ_CONTROL | SYNCHRONIZE) :
            (FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_ADD_SUBDIRECTORY |
                READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE);
        HANDLE volume = CreateFileW(volume_root.c_str(), root_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (volume == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("cannot open admitted publisher volume root; Win32 "+std::to_string(GetLastError()));
        }
        OwnedHandle held_volume(volume);
        // Ancestors, OS ownership, the lease, and its borrowed callback all
        // survive every product effect, including public state and consumer
        // finalization. Read-only verification never creates a lease.
        std::unique_ptr<usk::platform::windows::PublisherInstallOperationContext> operation_context;
        std::unique_ptr<ScopedOriginalOperationContext> original_replay;
        bool operation_context_was_present=false;
        std::unique_ptr<OwnedHandle> lease_setup_root, lease_state_root;
        std::unique_ptr<usk::platform::windows::PublisherInstallationLease> installation_lease;
        std::function<void()> lease_fence;
        std::unique_ptr<usk::platform::windows::ScopedPublisherEffectFence> effect_fence;
        const auto start_installation_lease = [&](const ReviewedPlanBinding& reviewed, bool recovery) {
            if (!registered_admission) return;
            if (!install_guard || !authenticated_request)
                throw std::runtime_error("registered effect lacks exclusive installation ownership");
            if (installation_lease) {
                if (recovery || !operation_context ||
                    usk::json::canonical(operation_context->record().at("reviewed_snapshot")) + "\n" != reviewed.durable_snapshot)
                    throw StaleReviewedInstallRequest();
                operation_context->require_fence();
                installation_lease->require_start();
                return;
            }
            registered_operation_admission = admit_current_registered_operation(volume, observed.service_sid, reviewed);
            if (!operation_context) operation_context =
                std::make_unique<usk::platform::windows::PublisherInstallOperationContext>(volume,
                    volume_root, service_name, *install_guard, reviewed.install_plan.install_id, reviewed.transaction_id);
            operation_context_was_present = operation_context->exists();
            // Durable original intent precedes even empty setup bootstrap. A
            // restart can recover the exact reviewed policy before active
            // ownership or a public publication snapshot exists.
            publication_effects_may_exist = true;
            operation_context->prepare(usk::json::parse(reviewed.durable_snapshot),
                usk::json::sha256_canonical(usk::json::Value(usk::json::Value::Array{})));

            // Empty repository bootstrap creates protected layout only. It is
            // conservatively reported as an effect and supplies the real state
            // root identity needed before the ownership record can be created.
            const auto setup_component = std::filesystem::u8path(reviewed.setup_root).filename().wstring();
            bool existing_layout = false;
            for (const auto& entry : observe_publisher_directory_entries(volume)) {
                if (CompareStringOrdinal(entry.name.c_str(), -1, setup_component.c_str(), -1, TRUE) == CSTR_EQUAL) {
                    if (entry.name != setup_component || existing_layout)
                        throw std::runtime_error("installation setup-root name is ambiguous");
                    existing_layout = true;
                }
            }
            if (!existing_layout) publication_effects_may_exist = true;
            usk::lifecycle::initialize_setup_root_for_publisher(reviewed.setup_root,
                reviewed.acceptance_root, "operator_acceptance_candidate", volume, volume_root, service_name,
                existing_layout);
            lease_setup_root = std::make_unique<OwnedHandle>(open_exact_lab_child(volume, setup_component, true));
            lease_state_root = std::make_unique<OwnedHandle>(open_exact_lab_child(lease_setup_root->get(),
                L"state", true, false, true));
            operation_context->bind_state_roots(lease_setup_root->get(), lease_state_root->get());
            const std::function<std::string()> revision = [&, install_id = reviewed.install_plan.install_id] {
                return usk::platform::windows::observe_publisher_install_state_revision(
                    lease_state_root->get(), install_id, observed.service_sid);
            };
            const auto holder = usk::platform::windows::observe_publisher_lease_holder();
            static std::atomic<std::uint64_t> attempt_sequence{0};
            usk::transaction::InstallLeaseRequest request{reviewed.install_plan.install_id, "install_local",
                reviewed.transaction_id, "attempt." + std::to_string(GetCurrentProcessId()) + "." +
                    holder.at("process_creation_time").as_string() + "." + std::to_string(++attempt_sequence),
                recovery ? revision() : operation_context->record().at("initial_state_revision").as_string(),
                recovery || operation_context_was_present,
                operation_context->lease_binding_sha256()};
            publication_effects_may_exist = true;
            installation_lease = std::make_unique<usk::platform::windows::PublisherInstallationLease>(
                lease_state_root->get(), volume_root, service_name, *install_guard, request, revision);
            installation_lease->require_start();
            const auto setup_id = observe_publisher_directory_handle(lease_setup_root->get()).file_id;
            const auto state_id = observe_publisher_directory_handle(lease_state_root->get()).file_id;
            lease_fence = [&, setup_component, setup_id, state_id] {
                OwnedHandle current_setup(open_exact_lab_child(volume, setup_component));
                OwnedHandle current_state(open_exact_lab_child(current_setup.get(), L"state"));
                const auto setup_facts = observe_publisher_directory_handle(current_setup.get());
                const auto state_facts = observe_publisher_directory_handle(current_state.get());
                require_publisher_object_security_shape(setup_facts, observed.service_sid);
                require_publisher_object_security_shape(state_facts, observed.service_sid);
                if (setup_facts.file_id != setup_id || state_facts.file_id != state_id)
                    throw usk::transaction::InstallLeaseStale();
                operation_context->require_fence();
                installation_lease->require_fence();
            };
            effect_fence = std::make_unique<usk::platform::windows::ScopedPublisherEffectFence>(lease_fence);
            if (!recovery) operation_context->prepare_publication(*installation_lease);
        };
        std::string apply_response;
        std::string recovery_installed_response;
        usk::platform::windows::PublisherVolumeObservation volume_observation;
        std::string anchors;
        bool snapshot_only_replay = false;
        try {
            volume_observation = usk::platform::windows::observe_local_ntfs_volume_handle(volume);
            if (registered_admission && !verify_installed_request) {
                // Existing durable coordination or publication remains an
                // effect even if a subsequent read-only admission check fails.
                for (const auto& entry : observe_publisher_directory_entries(volume)) {
                    if (CompareStringOrdinal(entry.name.c_str(),-1,L"installation-operations",-1,TRUE)==CSTR_EQUAL ||
                        CompareStringOrdinal(entry.name.c_str(),-1,L"publication",-1,TRUE)==CSTR_EQUAL)
                        publication_effects_may_exist=true;
                }
            }
            if (registered_admission && submitted_apply_request) {
                const auto apply=usk::json::parse(*submitted_apply_request);
                operation_context=std::make_unique<usk::platform::windows::PublisherInstallOperationContext>(volume,
                    volume_root, service_name, *install_guard, apply.at("plan_request").at("install_id").as_string(),
                    apply.at("transaction_id").as_string());
                if (operation_context->exists()) {
                    publication_effects_may_exist=true;
                    const auto& snapshot=operation_context->record().at("reviewed_snapshot");
                    (void)restore_reviewed_install_plan(usk::json::canonical(snapshot));
                    if (snapshot.at("plan_envelope_sha256").as_string() != reviewed_plan_envelope_sha256)
                        throw StaleReviewedInstallRequest();
                    const auto setup_component=std::filesystem::u8path(snapshot.at("setup_root").as_string()).filename().wstring();
                    bool setup_exists=false;
                    for (const auto& entry : observe_publisher_directory_entries(volume)) {
                        if (CompareStringOrdinal(entry.name.c_str(),-1,setup_component.c_str(),-1,TRUE)==CSTR_EQUAL) {
                            if (entry.name != setup_component || setup_exists) throw StaleReviewedInstallRequest();
                            setup_exists=true;
                        }
                    }
                    if (setup_exists) {
                        usk::lifecycle::initialize_setup_root_for_publisher(snapshot.at("setup_root").as_string(),
                            std::filesystem::u8path(snapshot.at("setup_root").as_string()).root_path().u8string(),
                            "operator_acceptance_candidate", volume, volume_root, service_name, true);
                        original_replay=std::make_unique<ScopedOriginalOperationContext>(*operation_context);
                    }
                    if (operation_context->bootstrap_resume_required()) {
                        // Preserve the exact reserved partial ancestry before
                        // ordinary planning. Its removal restores the original
                        // target probe; no recorded policy digest substitutes
                        // for a changed live target or source.
                        usk::base::StableFile envelope{std::filesystem::path(reviewed_plan_envelope_path)};
                        if (envelope.identity().size_bytes == 0 || envelope.identity().size_bytes > 1024u * 1024u ||
                            envelope.sha256_hex() != snapshot.at("plan_envelope_sha256").as_string())
                            throw StaleReviewedInstallRequest();
                        const auto bytes = envelope.read(0, static_cast<std::size_t>(envelope.identity().size_bytes));
                        envelope.verify_unchanged();
                        const auto original_envelope = usk::json::parse(std::string(bytes.begin(), bytes.end()));
                        if (original_envelope.at("schema").as_string() != "usk.publisher.lab_reviewed_plan_envelope.v2" ||
                            usk::json::canonical(original_envelope.at("apply_request")) != *submitted_apply_request ||
                            usk::json::canonical(original_envelope.at("plan_request")) != usk::json::canonical(snapshot.at("plan_request")))
                            throw StaleReviewedInstallRequest();
                        usk::lifecycle::require_candidate_bootstrap_source(snapshot);
                        const auto original = reviewed_plan_from_retained_snapshot(usk::json::canonical(snapshot) + "\n", false);
                        start_installation_lease(original, false);
                    }
                }
            }

            if ((recover_snapshot_only || recover_reviewed) && !install_guard) {
                // Source-free recovery has no submitted apply request from which
                // to name the install guard. Bind it to the protected snapshot
                // while the volume guard is held, before recovery can mutate.
                bool has_publication=false;
                for (const auto& entry : observe_publisher_directory_entries(volume))
                    if (entry.name==L"publication") has_publication=true;
                if (registered_admission && submitted_recovery_request) {
                    const auto request=usk::json::parse(*submitted_recovery_request);
                    if (request.as_object().size()!=4 ||
                        request.at("schema").as_string()!="usk.publisher_recovery_request.v1" ||
                        !usk::record_io::valid_identifier(request.at("request_id").as_string()))
                        throw StaleReviewedInstallRequest();
                    install_guard.emplace(volume_root,request.at("install_id").as_string(),stop_event);
                    operation_context=std::make_unique<usk::platform::windows::PublisherInstallOperationContext>(volume,
                        volume_root,service_name,*install_guard,request.at("install_id").as_string(),
                        request.at("transaction_id").as_string());
                    if (operation_context->exists()) {
                        publication_effects_may_exist=true;
                        (void)restore_reviewed_install_plan(usk::json::canonical(operation_context->record().at("reviewed_snapshot")));
                        if (!has_publication || operation_context->bootstrap_resume_required())
                            throw std::runtime_error("prepublication operation retained; retry exact original install_local.apply with its source");
                    } else if (!has_publication) {
                        throw std::runtime_error("protected original operation unavailable");
                    }
                    // A complete historical publication retains its existing
                    // protected snapshot path. Missing intent cannot authorize
                    // bootstrap preservation or qualify a new reservation.
                }
                OwnedHandle publication(open_exact_lab_child(volume, L"publication"));
                OwnedHandle journal(open_exact_lab_child(publication.get(), L"journal"));
                const std::string record = read_phase_record(
                    journal.get(), L"lab-reviewed-plan.json");
                const auto plan = restore_reviewed_install_plan(record);
                if (submitted_recovery_request) {
                    const auto request = usk::json::parse(*submitted_recovery_request);
                    const auto snapshot = usk::json::parse(record);
                    if (request.as_object().size() != 4u ||
                        request.at("schema").as_string() != "usk.publisher_recovery_request.v1" ||
                        !usk::record_io::valid_identifier(request.at("request_id").as_string()) ||
                        (snapshot.at("schema").as_string() !=
                            "usk.publisher.lab_reviewed_plan_snapshot.v3" &&
                         snapshot.at("schema").as_string() !=
                            "usk.publisher.lab_reviewed_plan_snapshot.v4") ||
                        request.at("install_id").as_string() != plan.install_id ||
                        request.at("transaction_id").as_string() !=
                            snapshot.at("transaction_id").as_string()) {
                        throw StaleReviewedInstallRequest();
                    }
                }
                if (!install_guard) install_guard.emplace(volume_root, plan.install_id, stop_event);
                start_installation_lease(reviewed_plan_from_protected_snapshot(volume, observed.service_sid, false, false), true);
            }
            if (verify_installed_request) {
                return verify_completed_install_in_service(volume, observed.service_sid);
            }
            if (recover_prepared) {
                anchors = observe_prepared_recovery(volume, observed.service_sid,
                    recover_visible_bound, {}, {}, recover_sealed_journal,
                    &recovery_installed_response);
            } else {
                bool publication_present = false;
                for (const auto& entry :
                        usk::platform::windows::observe_publisher_directory_entries(volume)) {
                    if (CompareStringOrdinal(entry.name.c_str(), -1,
                            L"publication", -1, TRUE) == CSTR_EQUAL) {
                        if (entry.name != L"publication" || publication_present) {
                            throw std::runtime_error("publisher publication root name is ambiguous");
                        }
                        publication_present = true;
                    }
                }
                const bool reviewed_source_reentry = publication_present &&
                    selected_archive_mode && selected_archive_path.empty() &&
                    !reviewed_plan_envelope_path.empty() && submitted_apply_request;
                if (reviewed_source_reentry) reviewed_install_reentry = true;
                if (registered_admission && publication_present && !installation_lease &&
                    (recover_snapshot_only || recover_reviewed || !reviewed_plan_envelope_path.empty())) {
                    start_installation_lease(reviewed_plan_from_protected_snapshot(volume,
                        observed.service_sid, !reviewed_source_reentry && !submitted_recovery_request ? true : false,
                        false), true);
                }
                if (recover_snapshot_only || recover_reviewed || reviewed_source_reentry) {
                    publication_effects_may_exist = publication_present;
                    if (!publication_present) {
                        throw std::runtime_error(
                            "independent recovery requires a protected publication");
                    }
                    snapshot_only_replay = recovery_journal_has_snapshot_only(
                        volume, observed.service_sid);
                    if (snapshot_only_replay) {
                        selected_archive_mode = true;
                        const ReviewedPlanBinding reviewed_plan =
                            reviewed_plan_from_snapshot_only(
                                volume, observed.service_sid, false);
                        selected_archive_sha256 =
                            reviewed_plan.selected_payload.source_sha256;
                        reviewed_plan_envelope_sha256 = reviewed_plan.envelope_sha256;
                        anchors = observe_protected_anchors(volume,
                            observed.service_sid, reviewed_plan, true, nullptr, &recovery_installed_response);
                    } else if (recover_reviewed || reviewed_source_reentry) {
                        // A completed durable snapshot needs no source handle.
                        // Do not emit an empty archive digest as source evidence.
                        selected_archive_mode = false;
                        anchors = observe_prepared_recovery(volume,
                            observed.service_sid, true, {}, {}, true,
                            &recovery_installed_response);
                    } else {
                        throw std::runtime_error(
                            "independent recovery requires an exact snapshot-only state");
                    }
                } else if (publication_present && !reviewed_plan_envelope_path.empty()) {
                    publication_effects_may_exist = true;
                    if (recovery_journal_has_snapshot_only(volume,
                            observed.service_sid)) {
                        const ReviewedPlanBinding reviewed_plan =
                            reviewed_plan_from_snapshot_only(
                                volume, observed.service_sid);
                        anchors = observe_protected_anchors(volume,
                            observed.service_sid, reviewed_plan, true, nullptr, &recovery_installed_response);
                    } else {
                        reviewed_install_reentry = true;
                        anchors = observe_prepared_recovery(volume,
                            observed.service_sid, true,
                            reviewed_plan_envelope_sha256,
                            selected_archive_sha256, false,
                            &recovery_installed_response);
                    }
                } else {
                    const std::optional<ReviewedPlanBinding> reviewed_plan =
                        reviewed_plan_envelope_path.empty() ?
                            std::optional<ReviewedPlanBinding>{} :
                            std::optional<ReviewedPlanBinding>{require_reviewed_selected_plan()};
                    if (config.prepare_disposable_boundary) {
                        publication_effects_may_exist=true;
                        config.prepare_disposable_boundary(volume,observed.service_sid);
                    }
                    require_publisher_object_security_shape(observe_publisher_directory_handle(volume),observed.service_sid);
                    if (reviewed_plan && !reviewed_plan->apply_request.empty()) {
                        if (registered_admission) registered_operation_admission =
                            admit_current_registered_operation(volume, observed.service_sid, *reviewed_plan);
                        CandidateApplyContext context{volume,observed.service_sid,*reviewed_plan,publication_effects_may_exist,{}};
                        context.start_installation_lease = [&] { start_installation_lease(*reviewed_plan, false); };
                        ScopedCandidateApply candidate(context);
                        int status=-1;
                        char* raw=usk_public_lifecycle_command_json("install_local.apply",
                            reviewed_plan->apply_request.data(),reviewed_plan->apply_request.size(),
                            reviewed_plan->setup_root.c_str(),reviewed_plan->acceptance_root.c_str(),
                            "operator_acceptance_candidate",&status);
                        if (!raw) throw std::runtime_error("protected apply response absent");
                        apply_response=raw;
                        usk_public_lifecycle_command_free(raw);
                        if (status != 0 || usk::json::parse(apply_response).at("status").as_string() != "ok" ||
                                !context.entered || context.anchors.empty()) {
                            if (context.operation_failure) std::rethrow_exception(context.operation_failure);
                            throw std::runtime_error("protected ordinary apply refused: "+apply_response);
                        }
                        anchors=std::move(context.anchors);
                    } else {
                        publication_effects_may_exist=true;
                        anchors=observe_protected_anchors(volume,observed.service_sid,reviewed_plan);
                    }
                }
            }
        } catch (...) {
            throw;
        }
        std::string consumer_access = "null";
        if (!consumer_read_sid.empty()) {
            using namespace usk::platform::windows;
            if (apply_response.empty() && recovery_installed_response.empty()) {
                throw std::runtime_error("consumer access requires verified public installation completion");
            }
            OwnedHandle publication(open_exact_lab_child(volume,L"publication"));
            OwnedHandle destination(open_exact_lab_child(publication.get(),L"destination"));
            OwnedHandle journal(open_exact_lab_child(publication.get(),L"journal"));
            OwnedHandle state(open_exact_lab_child(publication.get(),L"state"));
            OwnedHandle visible(open_exact_lab_child(destination.get(),visible_component,false,false,false,true));
            const auto snapshot_record = read_phase_record(journal.get(),L"lab-reviewed-plan.json");
            const auto snapshot = usk::json::parse(snapshot_record);
            usk::lifecycle::require_candidate_snapshot_apply_binding(snapshot);
            const auto plan = restore_reviewed_install_plan(snapshot_record);
            usk::lifecycle::require_completed_consumer_install(plan,
                snapshot.at("transaction_id").as_string(),snapshot.at("applied_at").as_string(),
                record_sha256(read_phase_record(state.get(),L"lab-installed-state.json")),volume_root,volume,service_name);
            const PublisherAnchorNames grant_names{L"staging",L"destination",L"state",L"journal"};
            const auto grant_anchors=observe_publisher_anchor_set(volume,{L"publication"},grant_names);
            require_publisher_anchor_set_security_shape(grant_anchors,observed.service_sid);
            const auto prepared_record=read_phase_record(journal.get(),L"lab-prepared-evidence.json");
            const auto prepared=usk::json::parse(prepared_record);
            if (usk::json::canonical(prepared.at("protected_anchors")) !=
                    usk::json::canonical(usk::json::parse(json_anchor_set(grant_anchors)))) {
                throw std::runtime_error("consumer reopened anchors differ from durable publication");
            }
            std::string confirmed_installed;
            if (!finalize_reviewed_public_state(snapshot_record,
                    record_sha256(read_phase_record(state.get(),L"lab-installed-state.json")),
                    volume,journal.get(),state.get(),visible.get(),
                    observe_publisher_directory_handle(visible.get()).file_id,&confirmed_installed)) {
                throw std::runtime_error("consumer held publication proof is unavailable");
            }
            const auto grant_journal=observe_publisher_tree(journal.get());
            const auto grant_state=observe_publisher_tree(state.get());
            const auto before = observe_publisher_tree(visible.get());
            const auto projected = publisher_consumer_read_projection(before,observed.service_sid,consumer_read_sid);
            const auto expected = prepared_tree_at_visible_name(prepared.at("sealed_tree"),
                prepared.at("sealed_tree").at("root").at("native_name").as_string(),
                ascii(before.root.native_name));
            if (expected != usk::json::canonical(usk::json::parse(json_tree(projected)))) {
                throw std::runtime_error("consumer visible closure differs from prepared seal");
            }
            publication_effects_may_exist = true;
            const auto objects = grant_publisher_consumer_read(visible.get(),before,
                observed.service_sid,consumer_read_sid,stop_event,[&](std::size_t changed) {
                    if (interrupt_consumer_grant && changed == 1) {
                        throw std::runtime_error("injected interruption after first consumer grant; recovery required");
                    }
                });
            require_publisher_anchor_set_phase_match(grant_anchors,
                observe_publisher_anchor_set(volume,{L"publication"},grant_names));
            require_publisher_tree_phase_match(grant_journal,observe_publisher_tree(journal.get()));
            require_publisher_tree_phase_match(grant_state,observe_publisher_tree(state.get()));
            usk::lifecycle::require_completed_consumer_install(plan,
                snapshot.at("transaction_id").as_string(),snapshot.at("applied_at").as_string(),
                record_sha256(read_phase_record(state.get(),L"lab-installed-state.json")),volume_root,volume,service_name);
            consumer_access = "{\"status\":\"read_execute_granted\",\"consumer_sid\":" +
                json_quote(consumer_read_sid) + ",\"objects\":" + std::to_string(objects) + "}";
        }
        if (installation_lease) installation_lease->finish(false);
        const std::string data =
            "{\"schema\":\"usk.publisher_lab_service_observation.v1\",\"status\":" +
            json_quote(recover_prepared && !recover_visible_bound ?
                "recovery_required" : "pass") + ","
            "\"service_name\":" + json_quote(ascii(service_name)) +
            ",\"consumer_access\":" + consumer_access +
            ",\"apply_response\":" + (apply_response.empty() ? "null" : apply_response) +
            ",\"recovery_installed_response\":" +
                (recovery_installed_response.empty() ? "null" : recovery_installed_response) +
            ",\"service_sid\":" + json_quote(observed.service_sid) +
            ",\"service_sid_type\":" + std::to_string(observed.service_sid_type) +
            ",\"service_type\":" + std::to_string(observed.service_type) +
            ",\"service_state\":" + std::to_string(observed.service_state) +
            ",\"process_id\":" + std::to_string(observed.process_id) +
            ",\"process_user_sid\":" + json_quote(observed.token.process_user_sid) +
            ",\"thread_impersonating\":" +
            std::string(observed.token.current_thread_impersonating ? "true" : "false") +
            ",\"process_groups\":" + json_groups(observed.token.process_groups) +
            ",\"process_restricted_sids\":" +
            json_groups(observed.token.process_restricted_sids) +
            ",\"volume_root\":" + json_quote(ascii(volume_root)) +
            ",\"volume_operation_guard_abandoned\":" +
            std::string(operation_guard.previous_owner_abandoned() ? "true" : "false") +
            ",\"install_operation_guard_held\":" +
            std::string(install_guard.has_value() ? "true" : "false") +
            ",\"install_operation_guard_abandoned\":" +
            (install_guard ? std::string(install_guard->previous_owner_abandoned() ?
                "true" : "false") : std::string("null")) +
            ",\"volume_filesystem\":" +
            json_quote(ascii(volume_observation.filesystem_name)) +
            ",\"volume_serial\":" +
            std::to_string(volume_observation.volume_information_serial) +
            ",\"volume_file_id_serial\":" +
            std::to_string(volume_observation.file_id_volume_serial) +
            (selected_archive_mode ?
                ",\"selected_archive_sha256\":" + json_quote(selected_archive_sha256) :
                std::string{}) +
            ",\"prepublish_gate\":" +
            json_quote(recover_prepared || recover_reviewed || reviewed_install_reentry ? "not_applicable" :
                (prepublish_gate ? "released" : "disabled")) +
            (snapshot_only_replay ?
                ",\"recovery_observation\":{\"decision\":\"snapshot_only_completed_forward\","
                    "\"protected_anchors\":" :
                recover_prepared || recover_reviewed || reviewed_install_reentry ?
                    ",\"recovery_observation\":" : ",\"protected_anchors\":") +
            anchors + (snapshot_only_replay ? "}}\n" : "}\n");
        return data;
}
#endif
