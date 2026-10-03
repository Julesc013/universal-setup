// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_PUBLISHER_RENAME_INFORMATION_H
#define USK_PUBLISHER_RENAME_INFORMATION_H

#if defined(_WIN32)
#include "usk_publisher_directory_entries.h"

#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace usk::platform::windows {

// Native rename mechanics only; this buffer confers no publication authority.
// The documented buffer includes the complete structure plus the name bytes:
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information
class PublisherRenameInformation final {
public:
    PublisherRenameInformation(HANDLE parent, const std::wstring& name) {
        if (!parent || parent == INVALID_HANDLE_VALUE ||
            !is_publisher_canonical_component(name)) {
            throw std::runtime_error("publisher rename information has invalid bound inputs");
        }
        bytes_ = static_cast<ULONG>(sizeof(FILE_RENAME_INFO) + name.size() * sizeof(WCHAR));
        storage_.resize((bytes_ + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t));
        std::memset(storage_.data(), 0, storage_.size() * sizeof(std::max_align_t));
        auto* information = static_cast<FILE_RENAME_INFO*>(data());
        information->ReplaceIfExists = FALSE;
        information->RootDirectory = parent;
        information->FileNameLength = static_cast<DWORD>(name.size() * sizeof(WCHAR));
        std::memcpy(information->FileName, name.data(), information->FileNameLength);
        information->FileName[name.size()] = L'\0';
    }
    void* data() { return storage_.data(); }
    ULONG size() const { return bytes_; }
private:
    ULONG bytes_ = 0;
    std::vector<std::max_align_t> storage_;
};

} // namespace usk::platform::windows
#endif
#endif
