// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_anchor_create.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_json.h"
#include "usk_sha256.h"
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
#include <string>
#include <vector>

namespace {
struct OwnedHandle {
    HANDLE value;
    explicit OwnedHandle(HANDLE handle) : value(handle) {}
    ~OwnedHandle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
    HANDLE get() const { return value; }
};

std::wstring service_name;
std::wstring receipt_path;
std::wstring volume_root;
bool prepublish_gate = false;
SERVICE_STATUS_HANDLE status_handle = nullptr;
HANDLE stop_event = nullptr;
DWORD service_exit_code = ERROR_SUCCESS;
constexpr std::size_t lab_record_limit = 4u * 1024u * 1024u;

std::wstring gate_sibling(const wchar_t* name) {
    const auto slash = receipt_path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        throw std::runtime_error("publisher lab receipt has no parent");
    }
    return receipt_path.substr(0, slash + 1) + name;
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
        if (ch < 32 || ch > 126) throw std::runtime_error("non-ASCII lab service name");
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

void write_journal_phase(HANDLE journal, const std::wstring& name,
    const std::vector<unsigned char>& descriptor, const std::string& record) {
    if (record != canonical_record(record)) {
        throw std::runtime_error("publisher lab phase record is not canonical");
    }
    {
        OwnedHandle file(usk::platform::windows::create_file_relative_with_descriptor(
            journal, name, descriptor));
        DWORD written = 0;
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

std::string diagnose_bound_rename_on_disposable_volume(
    HANDLE staging, HANDLE destination,
    const std::vector<unsigned char>& descriptor) {
    using namespace usk::platform::windows;
    const auto parent = observe_publisher_directory_handle(destination);
    const auto attempt = [&](const std::wstring& source_name,
        const std::wstring& target_name, bool reopen_source) {
        try {
            HANDLE source = INVALID_HANDLE_VALUE;
            {
                OwnedHandle created(create_directory_relative_with_descriptor(
                    staging, source_name, descriptor));
                if (!reopen_source) {
                    source = created.get();
                    const auto observed = observe_publisher_directory_handle(source);
                    (void)probe_publisher_bound_rename_no_replace(source,
                        destination, target_name, observed, parent);
                    return std::string("success");
                }
            }
            const std::wstring path = volume_root + L"publication\\staging\\" + source_name;
            OwnedHandle reopened(CreateFileW(path.c_str(),
                DELETE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY |
                    READ_CONTROL | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr));
            if (reopened.get() == INVALID_HANDLE_VALUE) {
                return std::string("reopen-win32-") + std::to_string(GetLastError());
            }
            const auto observed = observe_publisher_directory_handle(reopened.get());
            (void)probe_publisher_bound_rename_no_replace(reopened.get(),
                destination, target_name, observed, parent);
            return std::string("success");
        } catch (const std::exception& failure) {
            return std::string(failure.what());
        }
    };
    const auto held = attempt(L"diagnostic-held", L"diagnostic-held-visible", false);
    const auto reopened = attempt(
        L"diagnostic-reopened", L"diagnostic-reopened-visible", true);
    std::string win32;
    try {
        {
            OwnedHandle created(create_directory_relative_with_descriptor(
                staging, L"diagnostic-win32", descriptor));
        }
        const std::wstring source = volume_root +
            L"publication\\staging\\diagnostic-win32";
        const std::wstring target = volume_root +
            L"publication\\destination\\diagnostic-win32-visible";
        if (MoveFileExW(source.c_str(), target.c_str(), 0)) {
            win32 = "success";
        } else {
            win32 = "win32-" + std::to_string(GetLastError());
        }
    } catch (const std::exception& failure) {
        win32 = failure.what();
    }
    return "empty-held=" + held + "; empty-reopened=" + reopened +
        "; empty-win32-absolute-diagnostic=" + win32;
}

std::string observe_protected_anchors(HANDLE volume, const std::string& service_sid) {
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
    const DWORD applied = SetSecurityInfo(volume, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
            PROTECTED_DACL_SECURITY_INFORMATION,
        owner, nullptr, dacl, nullptr);
    if (applied != ERROR_SUCCESS) {
        throw std::runtime_error("cannot protect disposable volume root; Win32 " +
            std::to_string(applied));
    }
    OwnedHandle publication(create_directory_relative_with_descriptor(
        volume, L"publication", descriptor));
    OwnedHandle staging(create_directory_relative_with_descriptor(
        publication.get(), L"staging", descriptor));
    std::string created_destination_id;
    {
        OwnedHandle created(create_directory_relative_with_descriptor(
            publication.get(), L"destination", descriptor));
        created_destination_id = observe_publisher_directory_handle(
            created.get()).file_id;
    }
    OwnedHandle state(create_directory_relative_with_descriptor(
        publication.get(), L"state", descriptor));
    OwnedHandle journal(create_directory_relative_with_descriptor(
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
    if (observe_publisher_directory_handle(destination.get()).file_id !=
            created_destination_id) {
        throw std::runtime_error("reopened destination anchor identity changed");
    }
    const auto second = observe_publisher_anchor_set(
        volume, {L"publication"}, names);
    require_publisher_anchor_set_phase_match(first, second);
    OwnedHandle candidate(create_directory_relative_with_descriptor(
        staging.get(), L"candidate", descriptor));
    static constexpr char bytes[] = "protected staged payload\n";
    {
        OwnedHandle payload(create_file_relative_with_descriptor(
            candidate.get(), L"payload.bin", descriptor));
        DWORD written = 0;
        if (!WriteFile(payload.get(), bytes, sizeof(bytes) - 1, &written, nullptr) ||
            written != sizeof(bytes) - 1 || !FlushFileBuffers(payload.get())) {
            throw std::runtime_error("protected lab payload write or flush failed");
        }
    }
    const auto sealed = observe_publisher_tree(candidate.get());
    require_publisher_tree_security_shape(sealed, service_sid);
    if (sealed.descendants.size() != 1 ||
        sealed.descendants.front().relative_path != L"payload.bin" ||
        sealed.descendants.front().size != sizeof(bytes) - 1) {
        throw std::runtime_error("protected lab staged closure is not exact");
    }
    const auto resealed = observe_publisher_tree(candidate.get());
    require_publisher_tree_phase_match(sealed, resealed);
    const auto third = observe_publisher_anchor_set(
        volume, {L"publication"}, names);
    require_publisher_anchor_set_phase_match(first, third);
    const std::string prepared = canonical_record(
        "{\"schema\":\"usk.publisher.lab_phase_evidence.v1\","
        "\"phase\":\"lab_prepared_evidence\",\"service_sid\":" +
        json_quote(service_sid) +
        ",\"volume_serial\":" +
        std::to_string(sealed.volume.file_id_volume_serial) +
        ",\"source_file_id\":" + json_quote(sealed.root.file_id) +
        ",\"destination_parent_file_id\":" +
        json_quote(first.destination_parent.object.file_id) +
        ",\"destination_name\":\"visible\",\"payload_sha256\":" +
        json_quote(sealed.descendants.front().sha256) +
        ",\"protected_anchors\":" + json_anchor_set(third) +
        ",\"sealed_tree\":" + json_tree(sealed) + "}");
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
    PublisherBoundRenameObservation renamed;
    try {
        renamed = probe_publisher_bound_rename_no_replace(candidate.get(),
            destination.get(), L"visible", sealed.root,
            first.destination_parent.object);
    } catch (const PublisherRenameUnconfirmed& failure) {
        // Every comparison uses a fresh sibling on the newly created VHD.
        // A failed or ambiguous rename is never retried on the same object.
        throw std::runtime_error(std::string(failure.what()) + "; diagnostics: " +
            diagnose_bound_rename_on_disposable_volume(
                staging.get(), destination.get(), descriptor));
    }
    const auto visible = observe_visible_publisher_tree_against_seal(
        destination.get(), L"visible", sealed);
    require_publisher_tree_security_shape(visible, service_sid);
    const auto after = observe_publisher_anchor_set(
        volume, {L"publication"}, names);
    require_publisher_anchor_set_phase_match(first, after);
    const std::string bound = canonical_record(
        "{\"schema\":\"usk.publisher.lab_phase_evidence.v1\","
        "\"phase\":\"lab_visible_evidence\",\"source_file_id\":" +
        json_quote(renamed.root_file_id) +
        ",\"destination_parent_file_id\":" +
        json_quote(first.destination_parent.object.file_id) +
        ",\"destination_name\":\"visible\",\"payload_sha256\":" +
        json_quote(visible.descendants.front().sha256) +
        ",\"prepared_record_sha256\":" + json_quote(prepared_digest) +
        ",\"protected_anchors\":" + json_anchor_set(after) +
        ",\"visible_tree\":" + json_tree(visible) + "}");
    write_journal_phase(journal.get(), L"lab-visible-evidence.json", descriptor, bound);
    const auto journal_tree = observe_publisher_tree(journal.get());
    require_publisher_tree_security_shape(journal_tree, service_sid);
    if (journal_tree.root.file_id != first.journal.object.file_id ||
        journal_tree.descendants.size() != 2 ||
        journal_tree.descendants[0].relative_path != L"lab-prepared-evidence.json" ||
        journal_tree.descendants[0].size != prepared.size() ||
        journal_tree.descendants[1].relative_path != L"lab-visible-evidence.json" ||
        journal_tree.descendants[1].size != bound.size()) {
        throw std::runtime_error("publisher lab journal phase closure is not exact");
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
        "},\"staged_tree\":{\"root\":" + json_protected_object(sealed.root) +
        ",\"file\":" + json_protected_object(sealed.descendants.front().object) +
        ",\"relative_path\":\"payload.bin\",\"size\":" +
            std::to_string(sealed.descendants.front().size) +
        ",\"sha256\":" + json_quote(sealed.descendants.front().sha256) +
        "},\"publication_probe\":{\"source_file_id\":" +
        json_quote(renamed.root_file_id) +
        ",\"former_name\":" + json_quote(ascii(renamed.former_name)) +
        ",\"visible_name\":" + json_quote(ascii(renamed.visible_name)) +
        ",\"visible_root\":" + json_protected_object(visible.root) +
        ",\"visible_file\":" +
        json_protected_object(visible.descendants.front().object) +
        ",\"visible_payload_sha256\":" +
        json_quote(visible.descendants.front().sha256) +
        ",\"journal_root\":" + json_protected_object(journal_tree.root) +
        ",\"prepared_file\":" +
        json_protected_object(journal_tree.descendants[0].object) +
        ",\"bound_file\":" +
        json_protected_object(journal_tree.descendants[1].object) +
        ",\"prepared_record\":" + json_quote(prepared) +
        ",\"prepared_sha256\":" +
        json_quote(journal_tree.descendants[0].sha256) +
        ",\"bound_record\":" + json_quote(bound) +
        ",\"bound_sha256\":" +
        json_quote(journal_tree.descendants[1].sha256) + "}}";
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
    try {
        report_status(SERVICE_START_PENDING);
        stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stop_event) throw std::runtime_error("cannot create publisher lab stop event");
        report_status(SERVICE_RUNNING, SERVICE_ACCEPT_STOP);
        const auto observed =
            usk::platform::windows::observe_current_restricted_publisher_service(service_name);
        const DWORD root_access =
            FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_ADD_SUBDIRECTORY |
                READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE;
        HANDLE volume = CreateFileW(volume_root.c_str(), root_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (volume == INVALID_HANDLE_VALUE) {
            const DWORD error = GetLastError();
            const auto probe = [&](DWORD access, DWORD flags) {
                HANDLE trial = CreateFileW(volume_root.c_str(), access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                    OPEN_EXISTING, flags, nullptr);
                const DWORD outcome = trial == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
                if (trial != INVALID_HANDLE_VALUE) CloseHandle(trial);
                return outcome;
            };
            const DWORD read_reparse = probe(FILE_READ_ATTRIBUTES,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
            const DWORD full_backup = probe(root_access, FILE_FLAG_BACKUP_SEMANTICS);
            const DWORD read_backup = probe(FILE_READ_ATTRIBUTES,
                FILE_FLAG_BACKUP_SEMANTICS);
            const DWORD read_sync_backup = probe(
                FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_FLAG_BACKUP_SEMANTICS);
            const DWORD list_backup = probe(
                FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | SYNCHRONIZE,
                FILE_FLAG_BACKUP_SEMANTICS);
            const DWORD control_backup = probe(
                FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                FILE_FLAG_BACKUP_SEMANTICS);
            const DWORD add_backup = probe(
                FILE_READ_ATTRIBUTES | FILE_ADD_SUBDIRECTORY | SYNCHRONIZE,
                FILE_FLAG_BACKUP_SEMANTICS);
            const DWORD dac_backup = probe(
                FILE_READ_ATTRIBUTES | WRITE_DAC | SYNCHRONIZE,
                FILE_FLAG_BACKUP_SEMANTICS);
            const DWORD owner_backup = probe(
                FILE_READ_ATTRIBUTES | WRITE_OWNER | SYNCHRONIZE,
                FILE_FLAG_BACKUP_SEMANTICS);
            std::string relative_create = "not_run";
            try {
                OwnedHandle boundary(CreateFileW(volume_root.c_str(),
                    FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | READ_CONTROL | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr));
                if (boundary.get() == INVALID_HANDLE_VALUE) {
                    throw std::runtime_error("read-only boundary handle unavailable");
                }
                (void)usk::platform::windows::observe_local_ntfs_volume_handle(boundary.get());
                const auto root = usk::platform::windows::observe_publisher_directory_handle(
                    boundary.get());
                if ((root.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                    root.reparse_tag != 0 || root.case_sensitive || root.link_count != 1) {
                    throw std::runtime_error("read-only boundary shape is inadmissible");
                }
                const std::wstring sid(observed.service_sid.begin(), observed.service_sid.end());
                const auto descriptor =
                    usk::platform::windows::make_publisher_directory_security_descriptor(sid);
                OwnedHandle created(
                    usk::platform::windows::create_directory_relative_with_descriptor(
                        boundary.get(), L"relative_probe", descriptor));
                relative_create = "created";
            } catch (const std::exception& failure) {
                relative_create = failure.what();
            }
            const std::wstring child_path = volume_root + L"diagnostic-child";
            const auto child_probe = [&](DWORD access) {
                HANDLE trial = CreateFileW(child_path.c_str(), access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
                        FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                const DWORD outcome = trial == INVALID_HANDLE_VALUE ?
                    GetLastError() : ERROR_SUCCESS;
                if (trial != INVALID_HANDLE_VALUE) CloseHandle(trial);
                return outcome;
            };
            const DWORD child_read = child_probe(FILE_READ_ATTRIBUTES);
            const DWORD child_add = child_probe(
                FILE_READ_ATTRIBUTES | FILE_ADD_SUBDIRECTORY | SYNCHRONIZE);
            const DWORD child_dac = child_probe(
                FILE_READ_ATTRIBUTES | WRITE_DAC | SYNCHRONIZE);
            const DWORD child_owner = child_probe(
                FILE_READ_ATTRIBUTES | WRITE_OWNER | SYNCHRONIZE);
            std::string child_dacl_add = "not_run";
            std::string child_dacl_dac = "not_run";
            OwnedHandle child_read_handle(CreateFileW(child_path.c_str(),
                FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
                    FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (child_read_handle.get() != INVALID_HANDLE_VALUE) {
                child_dacl_add = check_directory_dacl(child_read_handle.get(),
                    FILE_READ_ATTRIBUTES | FILE_ADD_SUBDIRECTORY | SYNCHRONIZE);
                child_dacl_dac = check_directory_dacl(child_read_handle.get(),
                    FILE_READ_ATTRIBUTES | WRITE_DAC | SYNCHRONIZE);
            }
            std::string volume_device_dacl = "not_run";
            const std::wstring volume_device_name =
                volume_root.substr(0, volume_root.size() - 1);
            OwnedHandle volume_device(CreateFileW(volume_device_name.c_str(),
                READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, 0, nullptr));
            if (volume_device.get() == INVALID_HANDLE_VALUE) {
                volume_device_dacl = "open=" + std::to_string(GetLastError());
            } else {
                volume_device_dacl = observed_dacl_sddl(volume_device.get());
            }
            const std::string token_integrity = observed_token_integrity_sid();
            throw std::runtime_error("restricted service cannot open disposable volume root; Win32 " +
                std::to_string(error) + "; read-reparse=" +
                std::to_string(read_reparse) + "; full-backup=" +
                std::to_string(full_backup) + "; read-backup=" +
                std::to_string(read_backup) + "; read-sync-backup=" +
                std::to_string(read_sync_backup) + "; list-backup=" +
                std::to_string(list_backup) + "; control-backup=" +
                std::to_string(control_backup) + "; add-backup=" +
                std::to_string(add_backup) + "; dac-backup=" +
                std::to_string(dac_backup) + "; owner-backup=" +
                std::to_string(owner_backup) + "; relative-create=" +
                relative_create + "; child-read=" +
                std::to_string(child_read) + "; child-add=" +
                std::to_string(child_add) + "; child-dac=" +
                std::to_string(child_dac) + "; child-owner=" +
                std::to_string(child_owner) + "; child-dacl-add=" +
                child_dacl_add + "; child-dacl-dac=" + child_dacl_dac +
                "; volume-device-dacl=" + volume_device_dacl +
                "; token-integrity=" + token_integrity);
        }
        usk::platform::windows::PublisherVolumeObservation volume_observation;
        std::string anchors;
        try {
            volume_observation = usk::platform::windows::observe_local_ntfs_volume_handle(volume);
            anchors = observe_protected_anchors(volume, observed.service_sid);
        } catch (...) {
            CloseHandle(volume);
            throw;
        }
        CloseHandle(volume);
        const std::string data =
            "{\"schema\":\"usk.publisher_lab_service_observation.v1\",\"status\":\"pass\","
            "\"service_name\":" + json_quote(ascii(service_name)) +
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
            ",\"volume_filesystem\":" +
            json_quote(ascii(volume_observation.filesystem_name)) +
            ",\"volume_serial\":" +
            std::to_string(volume_observation.volume_information_serial) +
            ",\"volume_file_id_serial\":" +
            std::to_string(volume_observation.file_id_volume_serial) +
            ",\"prepublish_gate\":" +
            json_quote(prepublish_gate ? "released" : "disabled") +
            ",\"protected_anchors\":" + anchors + "}\n";
        write_receipt(data);
        WaitForSingleObject(stop_event, 120000);
    } catch (const std::exception& error) {
        service_exit_code = ERROR_SERVICE_SPECIFIC_ERROR;
        try {
            write_receipt("{\"schema\":\"usk.publisher_lab_service_observation.v1\","
                "\"status\":\"failed\",\"error\":" + json_quote(error.what()) + "}\n");
        } catch (...) {}
    }
    if (stop_event) CloseHandle(stop_event);
    report_status(SERVICE_STOPPED, 0, service_exit_code);
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if ((argc != 5 && argc != 6) || std::wstring(argv[1]) != L"--service" ||
        (argc == 6 && std::wstring(argv[5]) != L"--prepublish-gate") ||
        std::wstring(argv[2]).rfind(L"USK_WU006_", 0) != 0) return 2;
    service_name = argv[2];
    receipt_path = argv[3];
    volume_root = argv[4];
    prepublish_gate = argc == 6;
    SERVICE_TABLE_ENTRYW table[] = {{service_name.data(), service_main}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) return 3;
    return service_exit_code == ERROR_SUCCESS ? 0 : 4;
}
#endif
