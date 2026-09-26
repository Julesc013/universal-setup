// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_record_io.h"

#include "usk_stable_file.h"
#include "usk_utf8_path.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <cwctype>
#include <stdexcept>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/fs.h>
#include <sys/syscall.h>
#endif
#endif

namespace fs = std::filesystem;

namespace usk::record_io {

namespace {
thread_local const RecordWriteOperations* record_write_operations = nullptr;
}

ScopedRecordWriteOperations::ScopedRecordWriteOperations(const RecordWriteOperations& operations)
    : previous_(record_write_operations)
{
    if (!operations.create_directory || !operations.write_new_text) {
        throw std::runtime_error("record write backend requires both operations");
    }
    record_write_operations = &operations;
}

ScopedRecordWriteOperations::~ScopedRecordWriteOperations()
{
    record_write_operations = previous_;
}

bool valid_identifier(const std::string& value)
{
    return !value.empty() && value.size() <= 128 &&
        std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return std::isalnum(ch) || ch == '.' || ch == '_' || ch == '-';
        });
}

namespace {

bool linked(const fs::path& path)
{
    std::error_code error;
    if (fs::is_symlink(fs::symlink_status(path, error)) || error) return true;
#if defined(_WIN32)
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    return false;
#endif
}

void sync_directory(const fs::path& path)
{
#if !defined(_WIN32)
    int flags = O_RDONLY;
#if defined(O_DIRECTORY)
    flags |= O_DIRECTORY;
#endif
#if defined(O_CLOEXEC)
    flags |= O_CLOEXEC;
#endif
    const int descriptor = ::open(path.c_str(), flags);
    if (descriptor < 0 || ::fsync(descriptor) != 0) {
        if (descriptor >= 0) ::close(descriptor);
        throw std::runtime_error("cannot flush durable record directory");
    }
    ::close(descriptor);
#else
    (void)path;
#endif
}

} // namespace

void require_safe_directory(const fs::path& input)
{
    base::require_native_path_capacity(input, base::NativePathKind::directory, "record directory");
    std::error_code error;
    const fs::path path = fs::absolute(input, error).lexically_normal();
    if (error || !fs::is_directory(path) || linked(path)) {
        throw std::runtime_error("record root is not an existing safe directory");
    }
#if defined(_WIN32)
    // MSVC decomposes \\?\Volume{GUID}\ as \\?\ plus a relative Volume{GUID}
    // component. That synthetic \\?\ root is not a directory. Begin the
    // ancestor walk at the complete volume root instead, after validating
    // its exact spelling.
    const std::wstring& native = path.native();
    const std::wstring prefix = L"\\\\?\\Volume{";
    if (native.rfind(prefix, 0) == 0) {
        const std::size_t guid_end = prefix.size() + 36u;
        if (native.size() < guid_end + 2u || native[guid_end] != L'}' ||
            native[guid_end + 1u] != L'\\') {
            throw std::runtime_error("record volume GUID path is malformed");
        }
        for (std::size_t index = prefix.size(); index < guid_end; ++index) {
            const bool hyphen = index == prefix.size() + 8u ||
                index == prefix.size() + 13u || index == prefix.size() + 18u ||
                index == prefix.size() + 23u;
            const wchar_t ch = native[index];
            if (hyphen ? ch != L'-' :
                !((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ||
                    (ch >= L'A' && ch <= L'F'))) {
                throw std::runtime_error("record volume GUID path is malformed");
            }
        }
        fs::path current(native.substr(0, guid_end + 2u));
        if (!fs::is_directory(current) || linked(current)) {
            throw std::runtime_error("record volume root is not a safe directory");
        }
        for (const fs::path& component : fs::path(native.substr(guid_end + 2u))) {
            current /= component;
            if (!fs::is_directory(current) || linked(current)) {
                throw std::runtime_error(
                    "record root crosses a linked or non-directory component");
            }
        }
        return;
    }
#endif
    fs::path current = path.root_path();
    for (const fs::path& component : path.relative_path()) {
        current /= component;
        if (!fs::is_directory(current) || linked(current)) {
            throw std::runtime_error("record root crosses a linked or non-directory component");
        }
    }
}

void create_directory_exclusive(const fs::path& parent, const std::string& name)
{
    require_safe_directory(parent);
    if (!valid_identifier(name)) throw std::runtime_error("record directory identifier is invalid");
    std::error_code error;
    const fs::path target = parent / name;
    base::require_native_path_capacity(target, base::NativePathKind::directory, "new record directory");
    if (record_write_operations) {
        record_write_operations->create_directory(parent, name);
        return;
    }
    if (!fs::create_directory(target, error) || error || linked(target)) {
        throw std::runtime_error("cannot exclusively create record directory");
    }
    sync_directory(parent);
}

void write_new_durable_text(const fs::path& path, const std::string& content)
{
    base::require_native_path_capacity(path, base::NativePathKind::file, "durable record");
    require_safe_directory(path.parent_path());
    if (record_write_operations) {
        record_write_operations->write_new_text(path, content);
        return;
    }
#if defined(_WIN32)
    HANDLE handle = CreateFileW(
        path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot no-clobber create durable record");
    try {
        const unsigned char* data = reinterpret_cast<const unsigned char*>(content.data());
        std::size_t remaining = content.size();
        while (remaining != 0) {
            const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(remaining, 1024u * 1024u));
            DWORD written = 0;
            if (!WriteFile(handle, data, requested, &written, nullptr) || written != requested) {
                throw std::runtime_error("cannot write durable record");
            }
            data += written;
            remaining -= written;
        }
        if (!FlushFileBuffers(handle)) throw std::runtime_error("cannot flush durable record");
        CloseHandle(handle);
    } catch (...) {
        CloseHandle(handle);
        throw;
    }
#else
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#if defined(O_CLOEXEC)
    flags |= O_CLOEXEC;
#endif
#if defined(O_NOFOLLOW)
    flags |= O_NOFOLLOW;
#endif
    const int descriptor = ::open(path.c_str(), flags, 0600);
    if (descriptor < 0) throw std::runtime_error("cannot no-clobber create durable record");
    try {
        const unsigned char* data = reinterpret_cast<const unsigned char*>(content.data());
        std::size_t remaining = content.size();
        while (remaining != 0) {
            const ssize_t written = ::write(descriptor, data, remaining);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) throw std::runtime_error("cannot write durable record");
            data += written;
            remaining -= static_cast<std::size_t>(written);
        }
        if (::fsync(descriptor) != 0) throw std::runtime_error("cannot flush durable record");
        ::close(descriptor);
    } catch (...) {
        ::close(descriptor);
        throw;
    }
    sync_directory(path.parent_path());
#endif
}

std::string read_stable_text(const fs::path& path, std::size_t max_bytes)
{
    usk::base::StableFile file(path);
    if (file.identity().size_bytes > max_bytes) throw std::runtime_error("durable record exceeds read budget");
    const std::vector<unsigned char> bytes = file.read(0, static_cast<std::size_t>(file.identity().size_bytes));
    file.verify_unchanged();
    return {bytes.begin(), bytes.end()};
}

void rename_no_replace(const fs::path& source, const fs::path& target)
{
    base::require_native_path_capacity(source, base::NativePathKind::file, "record move source");
    base::require_native_path_capacity(target, base::NativePathKind::file, "record move destination");
    require_safe_directory(source.parent_path());
    require_safe_directory(target.parent_path());
#if defined(_WIN32)
    if (!MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("no-replace record move failed");
    }
#elif defined(__linux__)
    if (::syscall(SYS_renameat2, AT_FDCWD, source.c_str(), AT_FDCWD, target.c_str(), RENAME_NOREPLACE) != 0) {
        throw std::runtime_error("platform or filesystem lacks a successful no-replace move");
    }
#elif defined(__APPLE__)
    if (::renamex_np(source.c_str(), target.c_str(), RENAME_EXCL) != 0) {
        throw std::runtime_error("no-replace record move failed");
    }
#else
    throw std::runtime_error("platform lacks a proven no-replace move primitive");
#endif
}

#if defined(_WIN32)
namespace {
class ProbeHandle {
public:
    explicit ProbeHandle(HANDLE value) : value_(value) {
        if (value_ == INVALID_HANDLE_VALUE) {
            throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                "cannot open handle for Windows rename probe");
        }
    }
    ~ProbeHandle() { CloseHandle(value_); }
    ProbeHandle(const ProbeHandle&) = delete;
    ProbeHandle& operator=(const ProbeHandle&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};

FILE_ID_INFO probe_file_id(HANDLE handle) {
    FILE_ID_INFO id{};
    if (!GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id))) {
        throw std::runtime_error("Windows rename probe cannot observe native file ID");
    }
    return id;
}

bool same_probe_file_id(const FILE_ID_INFO& first, const FILE_ID_INFO& second) {
    return first.VolumeSerialNumber == second.VolumeSerialNumber &&
        std::memcmp(first.FileId.Identifier, second.FileId.Identifier,
            sizeof(first.FileId.Identifier)) == 0;
}

std::string probe_file_id_text(const FILE_ID_INFO& id) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(16 + 1 + sizeof(id.FileId.Identifier) * 2, '0');
    for (unsigned index = 0; index < 8; ++index) {
        const unsigned shift = (7u - index) * 8u;
        const auto byte = static_cast<unsigned>((id.VolumeSerialNumber >> shift) & 0xffu);
        result[index * 2] = digits[byte >> 4];
        result[index * 2 + 1] = digits[byte & 15u];
    }
    result[16] = ':';
    for (std::size_t index = 0; index < sizeof(id.FileId.Identifier); ++index) {
        const auto byte = id.FileId.Identifier[index];
        result[17 + index * 2] = digits[byte >> 4];
        result[18 + index * 2] = digits[byte & 15u];
    }
    return result;
}

void require_probe_directory(HANDLE handle) {
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    FILE_STANDARD_INFO standard{};
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        !GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)) ||
        (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
            FILE_ATTRIBUTE_DIRECTORY || standard.NumberOfLinks != 1) {
        throw std::runtime_error("Windows rename probe requires an unlinked single-link directory");
    }
}

bool valid_probe_component(const std::wstring& name) {
    if (name.empty() || name.size() > 128 || name.back() == L'.') return false;
    for (const wchar_t ch : name) {
        if (!((ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z') ||
              (ch >= L'0' && ch <= L'9') || ch == L'_' || ch == L'-' || ch == L'.')) return false;
    }
    std::wstring stem = name.substr(0, name.find(L'.'));
    std::transform(stem.begin(), stem.end(), stem.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towupper(ch));
    });
    if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" ||
        (stem.size() == 4 && ((stem.compare(0, 3, L"COM") == 0) ||
                            (stem.compare(0, 3, L"LPT") == 0)) &&
         stem[3] >= L'1' && stem[3] <= L'9')) return false;
    return true;
}

std::wstring probe_handle_name(HANDLE handle) {
    std::vector<unsigned char> buffer(65536);
    if (!GetFileInformationByHandleEx(handle, FileNameInfo, buffer.data(),
            static_cast<DWORD>(buffer.size()))) {
        throw std::runtime_error("rename may have applied but visible handle name is unobserved");
    }
    const auto* info = reinterpret_cast<const FILE_NAME_INFO*>(buffer.data());
    if (info->FileNameLength % sizeof(WCHAR) != 0 ||
        info->FileNameLength > buffer.size() - offsetof(FILE_NAME_INFO, FileName)) {
        throw std::runtime_error("rename may have applied but visible handle name is malformed");
    }
    return {info->FileName, info->FileNameLength / sizeof(WCHAR)};
}

std::wstring probe_final_name(HANDLE handle) {
    const std::wstring path = probe_handle_name(handle);
    const auto separator = path.find_last_of(L"\\/");
    return separator == std::wstring::npos ? path : path.substr(separator + 1);
}

NTSTATUS probe_open_relative_directory(HANDLE parent, const std::wstring& name, HANDLE& result) {
    using NtOpenFileFn = NTSTATUS (NTAPI *)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto* nt_open = ntdll ? reinterpret_cast<NtOpenFileFn>(
        GetProcAddress(ntdll, "NtOpenFile")) : nullptr;
    if (!nt_open) throw std::runtime_error("Windows relative directory open entry point is unavailable");
    UNICODE_STRING object_name{};
    object_name.Length = static_cast<USHORT>(name.size() * sizeof(WCHAR));
    object_name.MaximumLength = static_cast<USHORT>((name.size() + 1) * sizeof(WCHAR));
    object_name.Buffer = const_cast<PWSTR>(name.c_str());
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = parent;
    attributes.ObjectName = &object_name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    IO_STATUS_BLOCK status{};
    result = INVALID_HANDLE_VALUE;
    const NTSTATUS outcome = nt_open(&result, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &status,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT |
            FILE_SYNCHRONOUS_IO_NONALERT);
    if (outcome != 0 && result != INVALID_HANDLE_VALUE) {
        CloseHandle(result);
        result = INVALID_HANDLE_VALUE;
    }
    return outcome;
}
} // namespace

WindowsBoundRenameProbeResult probe_windows_handle_relative_no_replace(
    const fs::path& source, const fs::path& destination_parent,
    const std::wstring& destination_name,
    const std::function<void()>& before_preflight,
    const std::function<void()>& after_absence_check)
{
    if (!valid_probe_component(destination_name)) {
        throw std::runtime_error("Windows rename probe destination is not one bounded component");
    }
    require_safe_directory(source.parent_path());
    require_safe_directory(source);
    require_safe_directory(destination_parent);
    base::require_native_path_capacity(source, base::NativePathKind::directory, "rename probe source");
    base::require_native_path_capacity(destination_parent / destination_name,
        base::NativePathKind::directory, "rename probe destination");
    ProbeHandle source_handle(CreateFileW(source.c_str(), DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    ProbeHandle parent_handle(CreateFileW(destination_parent.c_str(),
        FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    require_probe_directory(source_handle.get());
    require_probe_directory(parent_handle.get());
    const auto source_id = probe_file_id(source_handle.get());
    const auto parent_id = probe_file_id(parent_handle.get());
    const auto parent_name = probe_handle_name(parent_handle.get());
    if (source_id.VolumeSerialNumber != parent_id.VolumeSerialNumber) {
        throw std::runtime_error("Windows rename probe refuses a cross-volume parent");
    }
    if (before_preflight) before_preflight();
    if (!same_probe_file_id(parent_id, probe_file_id(parent_handle.get())) ||
        probe_handle_name(parent_handle.get()) != parent_name) {
        throw std::runtime_error("Windows rename probe destination parent changed before rename");
    }
    HANDLE preexisting = INVALID_HANDLE_VALUE;
    const NTSTATUS absent_status = probe_open_relative_directory(
        parent_handle.get(), destination_name, preexisting);
    if (absent_status == 0) {
        CloseHandle(preexisting);
        throw std::runtime_error("Windows rename probe destination already exists");
    }
    constexpr NTSTATUS name_not_found = static_cast<NTSTATUS>(0xC0000034u);
    if (absent_status != name_not_found) {
        throw std::runtime_error("Windows rename probe cannot establish absent destination; NTSTATUS " +
            std::to_string(static_cast<unsigned long>(absent_status)));
    }
    if (after_absence_check) after_absence_check();
    const auto name_bytes = destination_name.size() * sizeof(WCHAR);
    const std::size_t rename_bytes = offsetof(FILE_RENAME_INFO, FileName) + name_bytes + sizeof(WCHAR);
    std::vector<std::max_align_t> buffer(
        (rename_bytes + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t));
    auto* rename_info = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
    rename_info->ReplaceIfExists = FALSE;
    rename_info->RootDirectory = parent_handle.get();
    rename_info->FileNameLength = static_cast<DWORD>(name_bytes);
    std::memcpy(rename_info->FileName, destination_name.data(), name_bytes);
    rename_info->FileName[destination_name.size()] = L'\0';
    using NtSetInformationFileFn = NTSTATUS (NTAPI *)(
        HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, int);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto* nt_set_information = ntdll ? reinterpret_cast<NtSetInformationFileFn>(
        GetProcAddress(ntdll, "NtSetInformationFile")) : nullptr;
    if (!nt_set_information) {
        throw std::runtime_error("Windows handle-relative rename entry point is unavailable");
    }
    IO_STATUS_BLOCK status{};
    const NTSTATUS result = nt_set_information(source_handle.get(), &status,
        rename_info, static_cast<ULONG>(rename_bytes), 10 /* FileRenameInformation */);
    if (result != 0) {
        throw std::runtime_error("Windows native handle-relative no-replace rename failed; NTSTATUS " +
            std::to_string(static_cast<unsigned long>(result)) + "; outcome requires observation");
    }
    // These are post-effect observations, not durable ownership proof. A failed
    // observation must be retained for recovery by any future service caller.
    if (!same_probe_file_id(source_id, probe_file_id(source_handle.get())) ||
        !same_probe_file_id(parent_id, probe_file_id(parent_handle.get())) ||
        probe_handle_name(parent_handle.get()) != parent_name) {
        throw std::runtime_error("rename applied but source/parent handle identity changed");
    }
    auto actual_name = probe_final_name(source_handle.get());
    if (actual_name.size() != destination_name.size() ||
        !std::equal(actual_name.begin(), actual_name.end(), destination_name.begin(),
            [](wchar_t a, wchar_t b) { return std::towlower(a) == std::towlower(b); })) {
        throw std::runtime_error("rename applied but handle name is not the destination component");
    }
    HANDLE visible = INVALID_HANDLE_VALUE;
    const NTSTATUS visible_status = probe_open_relative_directory(
        parent_handle.get(), destination_name, visible);
    if (visible_status != 0) {
        throw std::runtime_error("rename applied but relative visible reopen failed; NTSTATUS " +
            std::to_string(static_cast<unsigned long>(visible_status)));
    }
    ProbeHandle visible_handle(visible);
    require_probe_directory(visible_handle.get());
    const auto visible_id = probe_file_id(visible_handle.get());
    if (!same_probe_file_id(source_id, visible_id)) {
        throw std::runtime_error("rename applied but visible root is a different native object");
    }
    return {probe_file_id_text(source_id), probe_file_id_text(parent_id),
        probe_file_id_text(visible_id)};
}
#endif

} // namespace usk::record_io
