// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_tree_observation.h"

#if defined(_WIN32)
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_volume_stream_observation.h"
#include "usk_sha256.h"

#include <sddl.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace usk::platform::windows {
namespace {
class OwnedHandle {
public:
    explicit OwnedHandle(HANDLE handle) : handle_(handle) {}
    ~OwnedHandle() { if (handle_ && handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_); }
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
    HANDLE get() const { return handle_; }
private:
    HANDLE handle_;
};

FILE_ID_INFO handle_id(HANDLE handle) {
    FILE_ID_INFO id{};
    if (!GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id))) {
        throw std::runtime_error("publisher tree cannot read a held file ID");
    }
    return id;
}

FILE_STANDARD_INFO standard_info(HANDLE handle) {
    FILE_STANDARD_INFO info{};
    if (!GetFileInformationByHandleEx(handle, FileStandardInfo,
            &info, sizeof(info))) {
        throw std::runtime_error("publisher tree cannot read held size and link count");
    }
    return info;
}

void require_directory_case_disabled(HANDLE handle) {
    FILE_CASE_SENSITIVE_INFO info{};
    if (!GetFileInformationByHandleEx(handle, FileCaseSensitiveInfo,
            &info, sizeof(info)) ||
        (info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR) != 0) {
        throw std::runtime_error("publisher tree directory case policy is unavailable");
    }
}

std::string hash_file(HANDLE file, std::uint64_t expected_size) {
    usk::base::Sha256 digest;
    std::array<unsigned char, 64 * 1024> buffer{};
    std::uint64_t total = 0;
    while (true) {
        DWORD read = 0;
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()),
                &read, nullptr)) {
            throw std::runtime_error("publisher tree file read failed");
        }
        if (read == 0) break;
        if (total > expected_size || read > expected_size - total) {
            throw std::runtime_error("publisher tree file grew during observation");
        }
        digest.update(buffer.data(), read);
        total += read;
    }
    if (total != expected_size ||
        standard_info(file).EndOfFile.QuadPart !=
            static_cast<LONGLONG>(expected_size)) {
        throw std::runtime_error("publisher tree file size changed during observation");
    }
    return digest.finish();
}

void walk(HANDLE directory, const std::wstring& prefix, unsigned depth,
    const PublisherVolumeObservation& volume,
    PublisherTreeObservation& result,
    std::set<std::array<std::uint8_t, 16>>& seen,
    std::uint64_t& content_bytes, std::size_t& evidence_bytes,
    std::size_t& live_listing_bytes) {
    constexpr std::size_t maximum_entries = 200000;
    constexpr std::size_t maximum_evidence_bytes = 64 * 1024 * 1024;
    constexpr std::size_t maximum_live_listing_bytes = 64 * 1024 * 1024;
    constexpr std::uint64_t maximum_content_bytes = 16ULL * 1024 * 1024 * 1024 * 1024;
    if (depth > 128) {
        throw std::runtime_error("publisher tree exceeds its depth budget");
    }
    require_directory_case_disabled(directory);
    require_publisher_stream_shape(directory);
    const auto listed = observe_publisher_directory_entries(directory,
        maximum_live_listing_bytes - live_listing_bytes);
    std::size_t listing_bytes = 0;
    for (const auto& child : listed) {
        listing_bytes += 2 * sizeof(PublisherDirectoryEntry) +
            2 * child.name.size() * sizeof(WCHAR) + 128;
    }
    live_listing_bytes += listing_bytes;
    struct ListingBudgetRelease {
        std::size_t& live;
        std::size_t amount;
        ~ListingBudgetRelease() { live -= amount; }
    } release{live_listing_bytes, listing_bytes};
    for (const auto& child : listed) {
        if (result.descendants.size() >= maximum_entries) {
            throw std::runtime_error("publisher tree exceeds its entry budget");
        }
        OwnedHandle reopened(open_publisher_listed_child(directory, child));
        const auto id = handle_id(reopened.get());
        if (id.VolumeSerialNumber != volume.file_id_volume_serial) {
            throw std::runtime_error("publisher tree child moved to another volume");
        }
        std::array<std::uint8_t, 16> file_id{};
        std::copy(std::begin(id.FileId.Identifier),
            std::end(id.FileId.Identifier), file_id.begin());
        if (!seen.insert(file_id).second) {
            throw std::runtime_error("publisher tree reuses a protected file ID");
        }
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        if (!GetFileInformationByHandleEx(reopened.get(), FileAttributeTagInfo,
                &attributes, sizeof(attributes))) {
            throw std::runtime_error("publisher tree child attributes are unavailable");
        }
        const bool child_directory =
            (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        const auto streams = observe_publisher_handle_streams(reopened.get());
        require_publisher_stream_shape(streams, child_directory);
        const auto current_volume = observe_local_ntfs_volume_handle(reopened.get());
        if (current_volume.volume_label != volume.volume_label ||
            current_volume.volume_information_serial != volume.volume_information_serial ||
            current_volume.file_id_volume_serial != volume.file_id_volume_serial ||
            current_volume.filesystem_name != volume.filesystem_name ||
            current_volume.maximum_component_length != volume.maximum_component_length ||
            current_volume.filesystem_flags != volume.filesystem_flags ||
            current_volume.remote_protocol_error != volume.remote_protocol_error) {
            throw std::runtime_error("publisher tree child volume facts diverged");
        }
        const auto standard = standard_info(reopened.get());
        if (standard.EndOfFile.QuadPart < 0 || standard.NumberOfLinks != 1) {
            throw std::runtime_error("publisher tree child size or link count is invalid");
        }
        const std::uint64_t size = child_directory ? 0 :
            static_cast<std::uint64_t>(standard.EndOfFile.QuadPart);
        if (!child_directory &&
            static_cast<std::uint64_t>(streams[0].size) != size) {
            throw std::runtime_error("publisher file stream size differs from EOF");
        }
        if (size > maximum_content_bytes - content_bytes) {
            throw std::runtime_error("publisher tree exceeds its content budget");
        }
        content_bytes += size;
        const auto observed = child_directory ?
            observe_publisher_directory_handle(reopened.get()) :
            observe_publisher_file_handle(reopened.get());
        if (observed.attributes != attributes.FileAttributes ||
            observed.link_count != standard.NumberOfLinks ||
            (child_directory && observed.case_sensitive)) {
            throw std::runtime_error("publisher tree same-handle security facts diverged from identity");
        }
        const std::wstring path = prefix.empty() ? child.name :
            prefix + L"/" + child.name;
        std::size_t entry_bytes = sizeof(PublisherTreeEntry) +
            (path.size() + observed.native_name.size()) * sizeof(WCHAR) +
            observed.file_id.size() + observed.owner_sid.size() + 64;
        for (const auto& stream : streams) {
            entry_bytes += sizeof(PublisherStreamObservation) +
                stream.name.size() * sizeof(WCHAR);
        }
        for (const auto& ace : observed.dacl_aces) {
            entry_bytes += sizeof(ObservedAce) + ace.sid.size();
        }
        if (entry_bytes > maximum_evidence_bytes - evidence_bytes) {
            throw std::runtime_error("publisher tree exceeds its evidence budget");
        }
        evidence_bytes += entry_bytes;
        const std::string digest = child_directory ? std::string() :
            hash_file(reopened.get(), size);
        result.descendants.push_back({path, observed, size, digest, streams});
        if (child_directory) {
            walk(reopened.get(), path, depth + 1, volume, result, seen,
                content_bytes, evidence_bytes, live_listing_bytes);
        }
    }
}

bool same_aces(const std::vector<ObservedAce>& left,
    const std::vector<ObservedAce>& right) {
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (left[index].type != right[index].type ||
            left[index].flags != right[index].flags ||
            left[index].access_mask != right[index].access_mask ||
            left[index].sid != right[index].sid) return false;
    }
    return true;
}

bool same_streams(const std::vector<PublisherStreamObservation>& left,
    const std::vector<PublisherStreamObservation>& right) {
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (left[index].name != right[index].name ||
            left[index].size != right[index].size ||
            left[index].allocation_size != right[index].allocation_size) {
            return false;
        }
    }
    return true;
}

struct LocalFreeDeleter {
    void operator()(void* pointer) const { if (pointer) LocalFree(pointer); }
};

void require_canonical_service_sid(const std::string& service_sid) {
    PSID raw = nullptr;
    if (service_sid.empty() ||
        !ConvertStringSidToSidA(service_sid.c_str(), &raw)) {
        throw std::runtime_error("publisher security shape needs a valid service SID");
    }
    std::unique_ptr<void, LocalFreeDeleter> owned(raw);
    const SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    if (!IsValidSid(raw) || *GetSidSubAuthorityCount(raw) != 6 ||
        *GetSidSubAuthority(raw, 0) != SECURITY_SERVICE_ID_BASE_RID ||
        std::memcmp(GetSidIdentifierAuthority(raw), &nt_authority,
            sizeof(nt_authority)) != 0) {
        throw std::runtime_error("publisher security shape needs a Windows service SID");
    }
    LPSTR canonical = nullptr;
    if (!ConvertSidToStringSidA(raw, &canonical)) {
        throw std::runtime_error("publisher service SID cannot be rendered");
    }
    std::unique_ptr<void, LocalFreeDeleter> canonical_owned(canonical);
    if (service_sid != canonical) {
        throw std::runtime_error("publisher service SID is not canonical");
    }
}

void require_protected_object_shape(const PublisherHandleObservation& object,
    const std::string& service_sid) {
    const auto allowed_mask = publisher_directory_access_mask();
    if (object.owner_sid != "S-1-5-18" || !object.dacl_protected ||
        object.link_count != 1 || object.dacl_aces.size() != 2 ||
        (object.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        ((object.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            object.case_sensitive)) {
        throw std::runtime_error("publisher protected object shape differs from the profile");
    }
    const auto& system = object.dacl_aces[0];
    const auto& service = object.dacl_aces[1];
    if (system.type != ACCESS_ALLOWED_ACE_TYPE || system.flags != 0 ||
        system.access_mask != allowed_mask || system.sid != "S-1-5-18" ||
        service.type != ACCESS_ALLOWED_ACE_TYPE || service.flags != 0 ||
        service.access_mask != allowed_mask || service.sid != service_sid) {
        throw std::runtime_error("publisher protected DACL ACEs differ from the profile");
    }
}

bool same_handle_facts(const PublisherHandleObservation& left,
    const PublisherHandleObservation& right) {
    return left.file_id == right.file_id &&
        left.attributes == right.attributes &&
        left.reparse_tag == right.reparse_tag &&
        left.link_count == right.link_count &&
        left.case_sensitive == right.case_sensitive &&
        left.owner_sid == right.owner_sid &&
        left.dacl_protected == right.dacl_protected &&
        same_aces(left.dacl_aces, right.dacl_aces);
}

bool same_volume_facts(const PublisherVolumeObservation& left,
    const PublisherVolumeObservation& right) {
    return left.volume_label == right.volume_label &&
        left.volume_information_serial == right.volume_information_serial &&
        left.file_id_volume_serial == right.file_id_volume_serial &&
        left.filesystem_name == right.filesystem_name &&
        left.maximum_component_length == right.maximum_component_length &&
        left.filesystem_flags == right.filesystem_flags &&
        left.remote_protocol_error == right.remote_protocol_error;
}

std::wstring descendant_native_name(const std::wstring& root,
    const std::wstring& relative) {
    if (root.empty() || relative.empty()) {
        throw std::runtime_error("publisher phase has an empty native path");
    }
    std::wstring result = root;
    if (result.back() != L'\\') result += L'\\';
    for (const wchar_t ch : relative) result += ch == L'/' ? L'\\' : ch;
    return result;
}

void walk_directory_chain(HANDLE parent, std::size_t index,
    const std::vector<std::wstring>& components,
    PublisherDirectoryChainObservation& result,
    std::set<std::string>& seen_ids,
    const std::function<void(HANDLE,
        const PublisherDirectoryChainObservation&)>& at_leaf) {
    if (index == components.size()) {
        if (at_leaf) at_leaf(parent, result);
        return;
    }
    const auto expected_parent = index == 0 ?
        result.boundary : result.children.back().object;
    const auto parent_before = observe_publisher_directory_handle(parent);
    if (!same_handle_facts(expected_parent, parent_before) ||
        expected_parent.native_name != parent_before.native_name ||
        !same_volume_facts(result.volume, observe_local_ntfs_volume_handle(parent))) {
        throw std::runtime_error("publisher directory-chain parent drifted before traversal");
    }
    const auto& component = components[index];
    if (!is_publisher_canonical_component(component)) {
        throw std::runtime_error("publisher directory-chain component is invalid");
    }
    const PublisherDirectoryEntry selected = [&]() {
        const auto children = observe_publisher_directory_entries(parent);
        const auto found = std::find_if(children.begin(), children.end(),
            [&](const PublisherDirectoryEntry& child) {
                return child.name == component;
            });
        if (found == children.end() ||
            (found->attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            throw std::runtime_error("publisher exact directory-chain child is unavailable");
        }
        return *found;
    }();
    OwnedHandle child(open_publisher_listed_child(parent, selected));
    const auto observed = observe_publisher_directory_handle(child.get());
    const auto expected_name = descendant_native_name(parent_before.native_name, component);
    if (observed.native_name != expected_name || observed.case_sensitive ||
        observed.link_count != 1 ||
        (observed.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        !seen_ids.insert(observed.file_id).second ||
        !same_volume_facts(result.volume, observe_local_ntfs_volume_handle(child.get()))) {
        throw std::runtime_error("publisher directory-chain child facts are inadmissible");
    }
    require_publisher_stream_shape(child.get());
    result.children.push_back({component, observed});
    walk_directory_chain(child.get(), index + 1, components, result,
        seen_ids, at_leaf);
    const auto child_after = observe_publisher_directory_handle(child.get());
    const auto parent_after = observe_publisher_directory_handle(parent);
    if (!same_handle_facts(observed, child_after) ||
        observed.native_name != child_after.native_name ||
        !same_handle_facts(parent_before, parent_after) ||
        parent_before.native_name != parent_after.native_name ||
        !same_volume_facts(result.volume, observe_local_ntfs_volume_handle(child.get())) ||
        !same_volume_facts(result.volume, observe_local_ntfs_volume_handle(parent))) {
        throw std::runtime_error("publisher directory chain drifted during traversal");
    }
}

void require_directory_chain_closed(
    const PublisherDirectoryChainObservation& chain) {
    if (chain.children.empty() || chain.children.size() > 128 ||
        chain.boundary.native_name.empty()) {
        throw std::runtime_error("publisher directory-chain structure is incomplete");
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string volume_prefix(16, '0');
    for (unsigned index = 0; index < 16; ++index) {
        volume_prefix[index] = digits[
            (chain.volume.file_id_volume_serial >> ((15u - index) * 4u)) & 15u];
    }
    std::set<std::string> seen_ids;
    auto check_directory = [&](const PublisherHandleObservation& object) {
        if (object.file_id.size() != 49 ||
            object.file_id.compare(0, 16, volume_prefix) != 0 ||
            object.file_id[16] != ':' ||
            !std::all_of(object.file_id.begin() + 17, object.file_id.end(),
                [](char ch) { return (ch >= '0' && ch <= '9') ||
                    (ch >= 'a' && ch <= 'f'); }) ||
            !seen_ids.insert(object.file_id).second ||
            (object.attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (object.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            object.reparse_tag != 0 || object.case_sensitive ||
            object.link_count != 1) {
            throw std::runtime_error("publisher directory-chain identity or shape is invalid");
        }
    };
    check_directory(chain.boundary);
    std::wstring parent_name = chain.boundary.native_name;
    for (const auto& child : chain.children) {
        if (!is_publisher_canonical_component(child.component) ||
            child.object.native_name !=
                descendant_native_name(parent_name, child.component)) {
            throw std::runtime_error("publisher directory-chain native path is disconnected");
        }
        check_directory(child.object);
        parent_name = child.object.native_name;
    }
}
} // namespace

PublisherTreeObservation observe_publisher_tree(HANDLE root) {
    if (!root || root == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("publisher tree requires a held root");
    }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!GetFileInformationByHandleEx(root, FileAttributeTagInfo,
            &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        standard_info(root).NumberOfLinks != 1) {
        throw std::runtime_error("publisher tree requires an ordinary one-link directory root");
    }
    const auto volume = observe_local_ntfs_volume_handle(root);
    const auto root_id = handle_id(root);
    PublisherTreeObservation result{};
    result.volume = volume;
    result.root = observe_publisher_directory_handle(root);
    result.root_streams = observe_publisher_handle_streams(root);
    require_publisher_stream_shape(result.root_streams, true);
    if (result.root.case_sensitive) {
        throw std::runtime_error("publisher tree root has case sensitivity enabled");
    }
    std::array<std::uint8_t, 16> root_file_id{};
    std::copy(std::begin(root_id.FileId.Identifier),
        std::end(root_id.FileId.Identifier), root_file_id.begin());
    std::set<std::array<std::uint8_t, 16>> seen{root_file_id};
    std::uint64_t content_bytes = 0;
    std::size_t evidence_bytes = 0;
    std::size_t live_listing_bytes = 0;
    walk(root, L"", 0, volume, result, seen, content_bytes,
        evidence_bytes, live_listing_bytes);
    std::sort(result.descendants.begin(), result.descendants.end(),
        [](const PublisherTreeEntry& left, const PublisherTreeEntry& right) {
            const int order = CompareStringOrdinal(left.relative_path.data(),
                static_cast<int>(left.relative_path.size()),
                right.relative_path.data(),
                static_cast<int>(right.relative_path.size()), TRUE);
            if (order == 0) {
                throw std::runtime_error("publisher tree path comparison failed");
            }
            return order == CSTR_LESS_THAN;
        });
    return result;
}

void require_publisher_tree_phase_match(
    const PublisherTreeObservation& sealed,
    const PublisherTreeObservation& observed,
    const std::wstring& visible_root_name) {
    if (!same_volume_facts(sealed.volume, observed.volume) ||
        !same_handle_facts(sealed.root, observed.root) ||
        !same_streams(sealed.root_streams, observed.root_streams) ||
        sealed.descendants.size() != observed.descendants.size()) {
        throw std::runtime_error("publisher phase volume, root or closure count diverged");
    }
    const std::wstring expected_root = visible_root_name.empty() ?
        sealed.root.native_name : visible_root_name;
    if (observed.root.native_name != expected_root) {
        throw std::runtime_error("publisher phase root native path diverged");
    }
    for (std::size_t index = 0; index < sealed.descendants.size(); ++index) {
        const auto& before = sealed.descendants[index];
        const auto& after = observed.descendants[index];
        if (before.relative_path != after.relative_path ||
            !same_handle_facts(before.object, after.object) ||
            before.size != after.size || before.sha256 != after.sha256 ||
            !same_streams(before.streams, after.streams) ||
            before.object.native_name != descendant_native_name(
                sealed.root.native_name, before.relative_path) ||
            after.object.native_name != descendant_native_name(
                expected_root, after.relative_path)) {
            throw std::runtime_error("publisher phase descendant facts diverged");
        }
    }
}

void require_publisher_tree_security_shape(
    const PublisherTreeObservation& tree, const std::string& service_sid) {
    require_canonical_service_sid(service_sid);
    require_protected_object_shape(tree.root, service_sid);
    for (const auto& entry : tree.descendants) {
        require_protected_object_shape(entry.object, service_sid);
    }
}

PublisherTreeObservation observe_visible_publisher_tree_against_seal(
    HANDLE destination_parent, const std::wstring& destination_component,
    const PublisherTreeObservation& sealed) {
    if (!destination_parent || destination_parent == INVALID_HANDLE_VALUE ||
        destination_component.empty() || destination_component.size() > 255) {
        throw std::runtime_error("publisher visible parent/component inputs are invalid");
    }
    const auto before = observe_publisher_directory_handle(destination_parent);
    const auto before_volume = observe_local_ntfs_volume_handle(destination_parent);
    if (before.case_sensitive || before.link_count != 1 ||
        (before.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        before.file_id == sealed.root.file_id ||
        !same_volume_facts(before_volume, sealed.volume)) {
        throw std::runtime_error("publisher visible parent is outside the sealed boundary");
    }
    const auto children = observe_publisher_directory_entries(destination_parent);
    const auto found = std::find_if(children.begin(), children.end(),
        [&](const PublisherDirectoryEntry& child) {
            return child.name == destination_component;
        });
    if (found == children.end() ||
        (found->attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        throw std::runtime_error("publisher exact visible child is unavailable");
    }
    OwnedHandle visible(open_publisher_listed_child(destination_parent, *found));
    const auto observed = observe_publisher_tree(visible.get());
    const auto after = observe_publisher_directory_handle(destination_parent);
    const auto after_volume = observe_local_ntfs_volume_handle(destination_parent);
    if (!same_handle_facts(before, after) ||
        before.native_name != after.native_name ||
        !same_volume_facts(before_volume, after_volume)) {
        throw std::runtime_error("publisher destination parent drifted during visible observation");
    }
    const std::wstring expected_name =
        descendant_native_name(before.native_name, destination_component);
    require_publisher_tree_phase_match(sealed, observed, expected_name);
    return observed;
}

static PublisherDirectoryChainObservation observe_directory_chain_with_leaf(
    HANDLE boundary, const std::vector<std::wstring>& components,
    const std::function<void(HANDLE,
        const PublisherDirectoryChainObservation&)>& at_leaf) {
    if (!boundary || boundary == INVALID_HANDLE_VALUE || components.empty() ||
        components.size() > 128) {
        throw std::runtime_error("publisher directory chain requires a held boundary and bounded path");
    }
    PublisherDirectoryChainObservation result{};
    result.volume = observe_local_ntfs_volume_handle(boundary);
    result.boundary = observe_publisher_directory_handle(boundary);
    if (result.boundary.case_sensitive || result.boundary.link_count != 1 ||
        (result.boundary.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        throw std::runtime_error("publisher directory-chain boundary is inadmissible");
    }
    require_publisher_stream_shape(boundary);
    std::set<std::string> seen_ids{result.boundary.file_id};
    result.children.reserve(components.size());
    walk_directory_chain(boundary, 0, components, result, seen_ids, at_leaf);
    require_directory_chain_closed(result);
    return result;
}

PublisherDirectoryChainObservation observe_publisher_directory_chain(
    HANDLE boundary, const std::vector<std::wstring>& components) {
    return observe_directory_chain_with_leaf(boundary, components, {});
}

void require_publisher_directory_chain_phase_match(
    const PublisherDirectoryChainObservation& earlier,
    const PublisherDirectoryChainObservation& later) {
    require_directory_chain_closed(earlier);
    require_directory_chain_closed(later);
    if (!same_volume_facts(earlier.volume, later.volume) ||
        !same_handle_facts(earlier.boundary, later.boundary) ||
        earlier.boundary.native_name != later.boundary.native_name ||
        earlier.children.size() != later.children.size()) {
        throw std::runtime_error("publisher directory-chain phase boundary diverged");
    }
    for (std::size_t index = 0; index < earlier.children.size(); ++index) {
        const auto& before = earlier.children[index];
        const auto& after = later.children[index];
        if (before.component != after.component ||
            !same_handle_facts(before.object, after.object) ||
            before.object.native_name != after.object.native_name) {
            throw std::runtime_error("publisher directory-chain phase child diverged");
        }
    }
}

void require_publisher_directory_chain_security_shape(
    const PublisherDirectoryChainObservation& chain,
    const std::string& service_sid) {
    require_directory_chain_closed(chain);
    require_canonical_service_sid(service_sid);
    require_protected_object_shape(chain.boundary, service_sid);
    for (const auto& child : chain.children) {
        require_protected_object_shape(child.object, service_sid);
    }
}

static std::array<std::wstring, 4> anchor_components(
    const PublisherAnchorNames& names) {
    std::array<std::wstring, 4> result{
        names.staging, names.destination_parent, names.state, names.journal};
    for (std::size_t index = 0; index < result.size(); ++index) {
        if (!is_publisher_canonical_component(result[index])) {
            throw std::runtime_error("publisher anchor component is not canonical");
        }
        for (std::size_t previous = 0; previous < index; ++previous) {
            const int order = CompareStringOrdinal(result[index].data(),
                    static_cast<int>(result[index].size()),
                    result[previous].data(),
                    static_cast<int>(result[previous].size()), TRUE);
            if (order == 0 || order == CSTR_EQUAL) {
                throw std::runtime_error("publisher anchor roles have colliding names");
            }
        }
    }
    return result;
}

static std::array<PublisherDirectoryChainLink*, 4> anchor_slots(
    PublisherAnchorSetObservation& set) {
    return {&set.staging, &set.destination_parent, &set.state, &set.journal};
}

static std::array<const PublisherDirectoryChainLink*, 4> anchor_slots(
    const PublisherAnchorSetObservation& set) {
    return {&set.staging, &set.destination_parent, &set.state, &set.journal};
}

static void require_anchor_set_closed(const PublisherAnchorSetObservation& set) {
    require_directory_chain_closed(set.chain);
    std::set<std::string> ids{set.chain.boundary.file_id};
    for (const auto& child : set.chain.children) ids.insert(child.object.file_id);
    const auto& parent = set.chain.children.back().object;
    std::array<std::wstring, 4> names{};
    const auto slots = anchor_slots(set);
    for (std::size_t index = 0; index < slots.size(); ++index) {
        const auto& anchor = *slots[index];
        names[index] = anchor.component;
        const auto& object = anchor.object;
        if (object.file_id.size() != 49 ||
            object.file_id.compare(0, 17, parent.file_id, 0, 17) != 0 ||
            !std::all_of(object.file_id.begin() + 17, object.file_id.end(),
                [](char ch) { return (ch >= '0' && ch <= '9') ||
                    (ch >= 'a' && ch <= 'f'); }) ||
            !ids.insert(object.file_id).second ||
            (object.attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (object.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            object.reparse_tag != 0 || object.case_sensitive ||
            object.link_count != 1 ||
            object.native_name !=
                descendant_native_name(parent.native_name, anchor.component)) {
            throw std::runtime_error("publisher anchor role is disconnected or duplicated");
        }
    }
    (void)anchor_components({names[0], names[1], names[2], names[3]});
}

PublisherAnchorSetObservation observe_publisher_anchor_set(
    HANDLE boundary, const std::vector<std::wstring>& ancestor_components,
    const PublisherAnchorNames& names) {
    const auto requested = anchor_components(names);
    PublisherAnchorSetObservation result{};
    const auto observe_siblings = [&](HANDLE parent,
        const PublisherDirectoryChainObservation& chain) {
        const auto parent_before = observe_publisher_directory_handle(parent);
        if (!same_handle_facts(chain.children.back().object, parent_before) ||
            chain.children.back().object.native_name != parent_before.native_name ||
            !same_volume_facts(chain.volume, observe_local_ntfs_volume_handle(parent))) {
            throw std::runtime_error("publisher anchor parent drifted before sibling observation");
        }
        const auto selected = [&]() {
            const auto listed = observe_publisher_directory_entries(parent);
            std::array<PublisherDirectoryEntry, 4> entries{};
            for (std::size_t index = 0; index < requested.size(); ++index) {
                const auto found = std::find_if(listed.begin(), listed.end(),
                    [&](const PublisherDirectoryEntry& child) {
                        return child.name == requested[index];
                    });
                if (found == listed.end() ||
                    (found->attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
                    throw std::runtime_error("publisher exact anchor sibling is unavailable");
                }
                entries[index] = *found;
            }
            return entries;
        }();
        std::set<std::string> seen_ids{chain.boundary.file_id};
        for (const auto& child : chain.children) seen_ids.insert(child.object.file_id);
        std::array<std::unique_ptr<OwnedHandle>, 4> held{};
        const auto slots = anchor_slots(result);
        for (std::size_t index = 0; index < requested.size(); ++index) {
            held[index] = std::make_unique<OwnedHandle>(
                open_publisher_listed_child(parent, selected[index]));
            auto observed = observe_publisher_directory_handle(held[index]->get());
            if (observed.native_name !=
                    descendant_native_name(parent_before.native_name, requested[index]) ||
                observed.case_sensitive || observed.link_count != 1 ||
                (observed.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                !seen_ids.insert(observed.file_id).second ||
                !same_volume_facts(chain.volume,
                    observe_local_ntfs_volume_handle(held[index]->get()))) {
                throw std::runtime_error("publisher anchor sibling facts are inadmissible");
            }
            require_publisher_stream_shape(held[index]->get());
            *slots[index] = {requested[index], std::move(observed)};
        }
        for (std::size_t index = 0; index < held.size(); ++index) {
            const auto after = observe_publisher_directory_handle(held[index]->get());
            if (!same_handle_facts(slots[index]->object, after) ||
                slots[index]->object.native_name != after.native_name ||
                !same_volume_facts(chain.volume,
                    observe_local_ntfs_volume_handle(held[index]->get()))) {
                throw std::runtime_error("publisher anchor sibling drifted during observation");
            }
        }
        const auto listed_after = observe_publisher_directory_entries(parent);
        for (std::size_t index = 0; index < requested.size(); ++index) {
            const auto found = std::find_if(listed_after.begin(), listed_after.end(),
                [&](const PublisherDirectoryEntry& child) {
                    return child.name == requested[index];
                });
            if (found == listed_after.end() ||
                (found->attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
                throw std::runtime_error("publisher anchor sibling disappeared after observation");
            }
            OwnedHandle reopened(open_publisher_listed_child(parent, *found));
            const auto observed_again = observe_publisher_directory_handle(reopened.get());
            if (!same_handle_facts(slots[index]->object, observed_again) ||
                slots[index]->object.native_name != observed_again.native_name ||
                !same_volume_facts(chain.volume,
                    observe_local_ntfs_volume_handle(reopened.get()))) {
                throw std::runtime_error("publisher anchor sibling was replaced after observation");
            }
        }
        const auto parent_after = observe_publisher_directory_handle(parent);
        if (!same_handle_facts(parent_before, parent_after) ||
            parent_before.native_name != parent_after.native_name ||
            !same_volume_facts(chain.volume, observe_local_ntfs_volume_handle(parent))) {
            throw std::runtime_error("publisher anchor parent drifted during sibling observation");
        }
    };
    result.chain = observe_directory_chain_with_leaf(
        boundary, ancestor_components, observe_siblings);
    require_anchor_set_closed(result);
    return result;
}

void require_publisher_anchor_set_phase_match(
    const PublisherAnchorSetObservation& earlier,
    const PublisherAnchorSetObservation& later) {
    require_anchor_set_closed(earlier);
    require_anchor_set_closed(later);
    require_publisher_directory_chain_phase_match(earlier.chain, later.chain);
    const auto before = anchor_slots(earlier);
    const auto after = anchor_slots(later);
    for (std::size_t index = 0; index < before.size(); ++index) {
        if (before[index]->component != after[index]->component ||
            !same_handle_facts(before[index]->object, after[index]->object) ||
            before[index]->object.native_name != after[index]->object.native_name) {
            throw std::runtime_error("publisher anchor role changed across phases");
        }
    }
}

void require_publisher_anchor_set_security_shape(
    const PublisherAnchorSetObservation& set,
    const std::string& service_sid) {
    require_anchor_set_closed(set);
    require_publisher_directory_chain_security_shape(set.chain, service_sid);
    for (const auto* anchor : anchor_slots(set)) {
        require_protected_object_shape(anchor->object, service_sid);
    }
}

} // namespace usk::platform::windows
#endif
