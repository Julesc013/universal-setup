// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_RECORD_IO_H
#define USK_RECORD_IO_H

#include <cstddef>
#include <filesystem>
#include <functional>
#include <string>

namespace usk::record_io {

bool valid_identifier(const std::string& value);
void require_safe_directory(const std::filesystem::path& path);
void create_directory_exclusive(const std::filesystem::path& parent, const std::string& name);
void write_new_durable_text(const std::filesystem::path& path, const std::string& content);
std::string read_stable_text(const std::filesystem::path& path, std::size_t max_bytes);
void rename_no_replace(const std::filesystem::path& source, const std::filesystem::path& target);

// Internal operation-local backend. The protected publisher supplies held-
// parent creation and atomic record publication; ordinary repositories keep
// their existing writer. This is not a public SDK authorization interface.
struct RecordWriteOperations {
    std::function<void(const std::filesystem::path&, const std::string&)> create_directory;
    std::function<void(const std::filesystem::path&, const std::string&)> write_new_text;
};

class ScopedRecordWriteOperations {
public:
    explicit ScopedRecordWriteOperations(const RecordWriteOperations& operations);
    ScopedRecordWriteOperations(RecordWriteOperations&&) = delete;
    ~ScopedRecordWriteOperations();
    ScopedRecordWriteOperations(const ScopedRecordWriteOperations&) = delete;
    ScopedRecordWriteOperations& operator=(const ScopedRecordWriteOperations&) = delete;
private:
    const RecordWriteOperations* previous_;
};

#if defined(_WIN32)
struct WindowsBoundRenameProbeResult {
    std::string source_file_id;
    std::string destination_parent_file_id;
    std::string visible_file_id;
};
// Candidate OS primitive for disposable qualification fixtures only. This
// does not prove a protected namespace, service SID, complete closure, durable
// intent, or recovery; strict publication must continue to refuse.
WindowsBoundRenameProbeResult probe_windows_handle_relative_no_replace(
    const std::filesystem::path& source,
    const std::filesystem::path& destination_parent,
    const std::wstring& destination_name,
    const std::function<void()>& before_preflight = {},
    const std::function<void()>& after_absence_check = {});
#endif

} // namespace usk::record_io

#endif
