// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_staged_stream.h"

#if defined(_WIN32)
#include "usk_publisher_anchor_create.h"
#include "usk_sha256.h"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace usk::platform::windows {
namespace {

struct SourceFacts {
    FILE_ID_INFO identity{};
    FILE_STANDARD_INFO standard{};
    FILE_BASIC_INFO basic{};
};

SourceFacts source_facts(HANDLE source)
{
    SourceFacts facts;
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!GetFileInformationByHandleEx(source, FileIdInfo, &facts.identity,
            sizeof(facts.identity)) ||
        !GetFileInformationByHandleEx(source, FileStandardInfo, &facts.standard,
            sizeof(facts.standard)) ||
        !GetFileInformationByHandleEx(source, FileBasicInfo, &facts.basic,
            sizeof(facts.basic)) ||
        !GetFileInformationByHandleEx(source, FileAttributeTagInfo, &attributes,
            sizeof(attributes)) ||
        facts.standard.Directory || facts.standard.DeletePending ||
        facts.standard.EndOfFile.QuadPart < 0 ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        throw std::runtime_error("staged source is not a stable regular file");
    }
    return facts;
}

bool same_source(const SourceFacts& before, const SourceFacts& after)
{
    return before.identity.VolumeSerialNumber == after.identity.VolumeSerialNumber &&
        std::equal(std::begin(before.identity.FileId.Identifier),
            std::end(before.identity.FileId.Identifier),
            std::begin(after.identity.FileId.Identifier)) &&
        before.standard.EndOfFile.QuadPart == after.standard.EndOfFile.QuadPart &&
        before.standard.NumberOfLinks == after.standard.NumberOfLinks &&
        before.basic.LastWriteTime.QuadPart == after.basic.LastWriteTime.QuadPart &&
        before.basic.ChangeTime.QuadPart == after.basic.ChangeTime.QuadPart;
}

bool valid_sha256(const std::string& value)
{
    if (value.size() != 64) return false;
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

} // namespace

PublisherStagedStream stream_verified_source_to_staged_file(
    HANDLE protected_parent, const std::wstring& canonical_name,
    const std::vector<unsigned char>& creation_descriptor, HANDLE source,
    std::uint64_t expected_size, const std::string& expected_sha256)
{
    constexpr std::uint64_t max_content_bytes = 16ull << 40;
    if (!source || source == INVALID_HANDLE_VALUE ||
        expected_size > max_content_bytes || !valid_sha256(expected_sha256)) {
        throw std::runtime_error("staged source declaration is invalid");
    }
    DWORD source_flags = 0;
    if (!GetHandleInformation(source, &source_flags) ||
        (source_flags & HANDLE_FLAG_INHERIT) != 0) {
        throw std::runtime_error("staged source handle is inheritable or invalid");
    }
    const SourceFacts before = source_facts(source);
    if (static_cast<std::uint64_t>(before.standard.EndOfFile.QuadPart) !=
        expected_size) {
        throw std::runtime_error("staged source size differs before creation");
    }
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(source, zero, nullptr, FILE_BEGIN)) {
        throw std::runtime_error("staged source cannot seek");
    }
    HANDLE target = create_file_relative_with_descriptor(
        protected_parent, canonical_name, creation_descriptor);
    try {
        std::array<unsigned char, 65536> buffer{};
        usk::base::Sha256 digest;
        std::uint64_t remaining = expected_size;
        while (remaining != 0) {
            const DWORD ask = static_cast<DWORD>(std::min<std::uint64_t>(
                remaining, buffer.size()));
            DWORD read = 0;
            if (!ReadFile(source, buffer.data(), ask, &read, nullptr) ||
                read == 0 || read > ask) {
                throw std::runtime_error("staged source read failed or shortened");
            }
            DWORD offset = 0;
            while (offset != read) {
                DWORD written = 0;
                if (!WriteFile(target, buffer.data() + offset, read - offset,
                        &written, nullptr) || written == 0) {
                    throw std::runtime_error("protected staged write failed");
                }
                offset += written;
            }
            digest.update(buffer.data(), read);
            remaining -= read;
        }
        unsigned char extra = 0;
        DWORD extra_read = 0;
        if (!ReadFile(source, &extra, 1, &extra_read, nullptr) ||
            extra_read != 0) {
            throw std::runtime_error("staged source grew during streaming");
        }
        if (!FlushFileBuffers(target)) {
            throw std::runtime_error("protected staged flush failed");
        }
        LARGE_INTEGER staged_size{};
        if (!GetFileSizeEx(target, &staged_size) ||
            staged_size.QuadPart < 0 ||
            static_cast<std::uint64_t>(staged_size.QuadPart) != expected_size ||
            !same_source(before, source_facts(source))) {
            throw std::runtime_error("staged source or destination changed");
        }
        const std::string actual_sha256 = digest.finish();
        if (actual_sha256 != expected_sha256) {
            throw std::runtime_error("staged source digest differs");
        }
        return {target, expected_size, actual_sha256};
    } catch (...) {
        CloseHandle(target);
        throw;
    }
}

} // namespace usk::platform::windows
#endif
