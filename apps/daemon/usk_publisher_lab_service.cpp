// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_anchor_create.h"
#include "usk_publisher_staged_stream.h"
#include "usk_publisher_volume_operation_guard.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_archive_payload.h"
#include "usk_json.h"
#include "usk_sha256.h"
#include "usk_stable_file.h"
#include "usk_public_lifecycle.h"
#include "usk_protected_install_publisher_internal.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_token_observation.h"
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
#include <cstdio>
#include <filesystem>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace {
std::wstring service_name;
std::wstring receipt_path;
std::wstring volume_root;
bool prepublish_gate = false;
bool poststage_gate = false;
bool postrename_gate = false;
bool postjournal_gate = false;
bool recover_prepared = false;
bool recover_snapshot_only = false;
bool recover_sealed_journal = false;
bool recover_visible_bound = false;
bool reviewed_install_reentry = false;

bool selected_archive_mode = false;
std::wstring selected_archive_path;
std::string selected_archive_sha256;
std::wstring reviewed_plan_envelope_path;
std::string reviewed_plan_envelope_sha256;
SERVICE_STATUS_HANDLE status_handle = nullptr;
HANDLE stop_event = nullptr;
DWORD service_exit_code = ERROR_SUCCESS;
using usk::platform::windows::StaleReviewedInstallRequest;
bool campaign_vm_id_matches(const std::wstring& expected) {
    if (expected.size() != 36) return false;
    for (std::size_t index = 0; index < expected.size(); ++index) {
        const wchar_t ch = expected[index];
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (ch != L'-') return false;
        } else if (!((ch >= L'0' && ch <= L'9') ||
                (ch >= L'a' && ch <= L'f') ||
                (ch >= L'A' && ch <= L'F'))) {
            return false;
        }
    }
    wchar_t observed[64]{};
    DWORD bytes = sizeof(observed);
    const LONG result = RegGetValueW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        L"VirtualMachineId", RRF_RT_REG_SZ, nullptr, observed, &bytes);
    return result == ERROR_SUCCESS &&
        CompareStringOrdinal(expected.c_str(), -1, observed, -1,
            TRUE) == CSTR_EQUAL;
}

bool generated_service_name(const std::wstring& name,
    const std::wstring& prefix) {
    if (name.size() != prefix.size() + 32 ||
        name.compare(0, prefix.size(), prefix) != 0) return false;
    for (std::size_t index = prefix.size(); index < name.size(); ++index) {
        const wchar_t ch = name[index];
        if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) {
            return false;
        }
    }
    return true;
}

bool campaign_recovery_receipt_path(const std::wstring& path) {
    const std::wstring prefix = L"C:\\USK-Lab\\vm-recovery-";
    const std::wstring suffix = L".json";
    if (path.size() <= prefix.size() + suffix.size() ||
        path.compare(0, prefix.size(), prefix) != 0 ||
        path.compare(path.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return false;
    }
    for (std::size_t index = prefix.size();
            index < path.size() - suffix.size(); ++index) {
        const wchar_t ch = path[index];
        if (!((ch >= L'a' && ch <= L'z') ||
                (ch >= L'0' && ch <= L'9') || ch == L'-')) return false;
    }
    return true;
}

bool campaign_selected_receipt_path(const std::wstring& path) {
    const std::wstring prefix = L"C:\\USK-Lab\\vm-selected-";
    const std::wstring suffix = L".json";
    if (path.size() <= prefix.size() + suffix.size() ||
        path.compare(0, prefix.size(), prefix) != 0 ||
        path.compare(path.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return false;
    }
    for (std::size_t index = prefix.size();
            index < path.size() - suffix.size(); ++index) {
        const wchar_t ch = path[index];
        if (!((ch >= L'a' && ch <= L'z') ||
                (ch >= L'0' && ch <= L'9') || ch == L'-')) return false;
    }
    return true;
}

bool campaign_selected_archive_path(const std::wstring& path) {
    const std::wstring prefix = L"C:\\USK-Lab\\selected-";
    const std::wstring suffix = L".zip";
    if (path.size() <= prefix.size() + suffix.size() ||
        path.compare(0, prefix.size(), prefix) != 0 ||
        path.compare(path.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return false;
    }
    for (std::size_t index = prefix.size();
            index < path.size() - suffix.size(); ++index) {
        const wchar_t ch = path[index];
        if (!((ch >= L'a' && ch <= L'z') ||
                (ch >= L'0' && ch <= L'9') || ch == L'-')) return false;
    }
    return true;
}

bool campaign_reviewed_plan_envelope_path(const std::wstring& path) {
    const std::wstring prefix = L"C:\\USK-Lab\\plan-";
    const std::wstring suffix = L".json";
    if (path.size() <= prefix.size() + suffix.size() ||
        path.compare(0, prefix.size(), prefix) != 0 ||
        path.compare(path.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return false;
    }
    for (std::size_t index = prefix.size();
            index < path.size() - suffix.size(); ++index) {
        const wchar_t ch = path[index];
        if (!((ch >= L'a' && ch <= L'z') ||
                (ch >= L'0' && ch <= L'9') || ch == L'-')) return false;
    }
    return true;
}

bool lower_sha256(const std::wstring& value) {
    if (value.size() != 64) return false;
    for (const wchar_t ch : value) {
        if (!((ch >= L'0' && ch <= L'9') ||
                (ch >= L'a' && ch <= L'f'))) return false;
    }
    return true;
}

void report_status(DWORD state, DWORD accepted = 0, DWORD error = ERROR_SUCCESS) {
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = accepted;
    status.dwWin32ExitCode = error;
    status.dwWaitHint = state == SERVICE_START_PENDING ? 10000 : 0;
    if (!SetServiceStatus(status_handle, &status)) {
        throw std::runtime_error("cannot report publisher lab service status");
    }
}

std::string ascii(const std::wstring& value) {
    std::string result;
    for (const wchar_t ch : value) {
        if (ch < 0x20 || ch > 0x7e) throw std::runtime_error("lab CLI value is not ASCII");
        result.push_back(static_cast<char>(ch));
    }
    return result;
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

void write_receipt(const std::string& data) {
    HANDLE handle = CreateFileW(receipt_path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("cannot create publisher lab service receipt");
    }
    DWORD written = 0;
    const bool okay = data.size() <= MAXDWORD &&
        WriteFile(handle, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) &&
        written == data.size() && FlushFileBuffers(handle);
    CloseHandle(handle);
    if (!okay) throw std::runtime_error("cannot flush publisher lab service receipt");
}

DWORD WINAPI control_handler(DWORD control, DWORD, LPVOID, LPVOID) {
    if (control == SERVICE_CONTROL_STOP && stop_event) {
        SetEvent(stop_event);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

VOID WINAPI service_main(DWORD, LPWSTR*) {
    status_handle = RegisterServiceCtrlHandlerExW(service_name.c_str(), control_handler, nullptr);
    if (!status_handle) return;
    bool publication_effects_may_exist = false;
    try {
        report_status(SERVICE_START_PENDING);
        stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stop_event) throw std::runtime_error("cannot create publisher lab stop event");
        report_status(SERVICE_RUNNING, SERVICE_ACCEPT_STOP);
        usk::platform::windows::CandidatePublisherConfiguration config;
        config.service_name=service_name;
        config.receipt_path=receipt_path;
        config.volume_root=volume_root;
        config.prepublish_gate=prepublish_gate;
        config.poststage_gate=poststage_gate;
        config.postrename_gate=postrename_gate;
        config.postjournal_gate=postjournal_gate;
        config.recover_prepared=recover_prepared;
        config.recover_snapshot_only=recover_snapshot_only;
        config.recover_sealed_journal=recover_sealed_journal;
        config.recover_visible_bound=recover_visible_bound;
        config.selected_archive_mode=selected_archive_mode;
        config.selected_archive_path=selected_archive_path;
        config.selected_archive_sha256=selected_archive_sha256;
        config.reviewed_plan_envelope_path=reviewed_plan_envelope_path;
        config.reviewed_plan_envelope_sha256=reviewed_plan_envelope_sha256;
        config.stop_event=stop_event;
        config.prepare_disposable_boundary=[](HANDLE volume,const std::string& sid) {
            const auto descriptor=usk::platform::windows::make_publisher_directory_security_descriptor(
                std::wstring(sid.begin(),sid.end()));
            PSID owner=nullptr; BOOL owner_defaulted=FALSE, present=FALSE, dacl_defaulted=FALSE; PACL dacl=nullptr;
            if (!GetSecurityDescriptorOwner(const_cast<unsigned char*>(descriptor.data()),&owner,&owner_defaulted) ||
                !GetSecurityDescriptorDacl(const_cast<unsigned char*>(descriptor.data()),&present,&dacl,&dacl_defaulted) ||
                !owner || !present || !dacl || owner_defaulted || dacl_defaulted) {
                throw std::runtime_error("disposable volume descriptor is malformed");
            }
            const DWORD applied=SetSecurityInfo(volume,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION |
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,owner,nullptr,dacl,nullptr);
            if (applied != ERROR_SUCCESS) throw std::runtime_error(
                "cannot protect disposable volume root; Win32 "+std::to_string(applied));
        };
        const auto data=usk::platform::windows::execute_candidate_restricted_publisher(config,publication_effects_may_exist);
        write_receipt(data);
        WaitForSingleObject(stop_event, 120000);
    } catch (const std::exception& error) {
        service_exit_code = ERROR_SERVICE_SPECIFIC_ERROR;
        try {
            write_receipt("{\"schema\":\"usk.publisher_lab_service_observation.v1\","
                "\"status\":" +
                json_quote(dynamic_cast<const StaleReviewedInstallRequest*>(&error) ?
                    "failed" : recover_visible_bound || reviewed_install_reentry ||
                    publication_effects_may_exist ?
                    "recovery_required" : "failed") +
                ",\"error\":" + json_quote(error.what()) + "}\n");
        } catch (...) {}
    }
    if (stop_event) CloseHandle(stop_event);
    report_status(SERVICE_STOPPED, 0, service_exit_code);
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 5 || std::wstring(argv[1]) != L"--service") return 2;
    const std::wstring name(argv[2]);
    const bool hosted = (argc == 5 || argc == 6) &&
        generated_service_name(name, L"USK_WU006_") &&
        (argc != 6 || std::wstring(argv[5]) == L"--prepublish-gate");
    const bool campaign_vm = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        std::wstring(argv[5]) == L"--prepublish-gate" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_recovery = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_recovery_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--recover-prepared" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_replay = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_recovery_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--recover-visible-bound" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_snapshot_recovery = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_recovery_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--recover-snapshot-only" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_sealed_journal = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_recovery_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--recover-sealed-journal" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_postrename = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        std::wstring(argv[5]) == L"--postrename-gate" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_postjournal = argc == 8 &&
        generated_service_name(name, L"USK_VM_") &&
        std::wstring(argv[5]) == L"--postjournal-gate" &&
        std::wstring(argv[6]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[7]);
    const bool campaign_vm_selected = (argc == 10 || argc == 11) &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_selected_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--selected-zip" &&
        campaign_selected_archive_path(argv[6]) &&
        lower_sha256(argv[7]) &&
        std::wstring(argv[8]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[9]) &&
        (argc == 10 || std::wstring(argv[10]) == L"--prepublish-gate" ||
            std::wstring(argv[10]) == L"--postrename-gate" ||
            std::wstring(argv[10]) == L"--postjournal-gate");
    const bool campaign_vm_selected_plan = (argc == 13 || argc == 14) &&
        generated_service_name(name, L"USK_VM_") &&
        campaign_selected_receipt_path(argv[3]) &&
        std::wstring(argv[5]) == L"--selected-zip" &&
        campaign_selected_archive_path(argv[6]) &&
        lower_sha256(argv[7]) &&
        std::wstring(argv[8]) == L"--campaign-vm-id" &&
        campaign_vm_id_matches(argv[9]) &&
        std::wstring(argv[10]) == L"--reviewed-plan-envelope" &&
        campaign_reviewed_plan_envelope_path(argv[11]) &&
        lower_sha256(argv[12]) &&
        (argc == 13 || std::wstring(argv[13]) == L"--prepublish-gate" ||
            std::wstring(argv[13]) == L"--postrename-gate" ||
            std::wstring(argv[13]) == L"--postjournal-gate" ||
            std::wstring(argv[13]) == L"--poststage-gate");
    if (!hosted && !campaign_vm && !campaign_vm_recovery &&
        !campaign_vm_replay &&
        !campaign_vm_snapshot_recovery &&
        !campaign_vm_sealed_journal &&
        !campaign_vm_postrename && !campaign_vm_postjournal &&
        !campaign_vm_selected && !campaign_vm_selected_plan) return 2;
    service_name = argv[2];
    receipt_path = argv[3];
    volume_root = argv[4];
    const std::wstring selected_gate =
        campaign_vm_selected && argc == 11 ? argv[10] :
        campaign_vm_selected_plan && argc == 14 ? argv[13] : L"";
    prepublish_gate = argc == 6 || campaign_vm ||
        selected_gate == L"--prepublish-gate";
    poststage_gate = selected_gate == L"--poststage-gate";
    postrename_gate = campaign_vm_postrename ||
        selected_gate == L"--postrename-gate";
    postjournal_gate = campaign_vm_postjournal ||
        selected_gate == L"--postjournal-gate";
    recover_prepared = campaign_vm_recovery || campaign_vm_replay ||
        campaign_vm_sealed_journal;
    recover_snapshot_only = campaign_vm_snapshot_recovery;
    recover_sealed_journal = campaign_vm_sealed_journal;
    recover_visible_bound = campaign_vm_replay || campaign_vm_sealed_journal;
    selected_archive_mode = campaign_vm_selected || campaign_vm_selected_plan ||
        campaign_vm_snapshot_recovery;
    if (campaign_vm_selected || campaign_vm_selected_plan) {
        selected_archive_path = argv[6];
        selected_archive_sha256 = ascii(argv[7]);
    }
    if (campaign_vm_selected_plan) {
        reviewed_plan_envelope_path = argv[11];
        reviewed_plan_envelope_sha256 = ascii(argv[12]);
    }
    SERVICE_TABLE_ENTRYW table[] = {{service_name.data(), service_main}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) return 3;
    return service_exit_code == ERROR_SUCCESS ? 0 : 4;
}
#endif
