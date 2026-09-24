// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_tree_observation.h"

#if defined(_WIN32)
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_volume_stream_observation.h"
#include "usk_sha256.h"

#include <algorithm>
#include <array>
#include <cstdint>
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
        require_publisher_stream_shape(reopened.get());
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
        if (size > maximum_content_bytes - content_bytes) {
            throw std::runtime_error("publisher tree exceeds its content budget");
        }
        content_bytes += size;
        const std::wstring path = prefix.empty() ? child.name :
            prefix + L"/" + child.name;
        const std::size_t entry_bytes = sizeof(PublisherTreeEntry) +
            path.size() * sizeof(WCHAR) + 64;
        if (entry_bytes > maximum_evidence_bytes - evidence_bytes) {
            throw std::runtime_error("publisher tree exceeds its evidence budget");
        }
        evidence_bytes += entry_bytes;
        const std::string digest = child_directory ? std::string() :
            hash_file(reopened.get(), size);
        result.descendants.push_back({path, file_id, attributes.FileAttributes,
            child_directory, size, digest});
        if (child_directory) {
            walk(reopened.get(), path, depth + 1, volume, result, seen,
                content_bytes, evidence_bytes, live_listing_bytes);
        }
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
    result.volume_serial = volume.file_id_volume_serial;
    std::copy(std::begin(root_id.FileId.Identifier),
        std::end(root_id.FileId.Identifier), result.root_file_id.begin());
    std::set<std::array<std::uint8_t, 16>> seen{result.root_file_id};
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

} // namespace usk::platform::windows
#endif
