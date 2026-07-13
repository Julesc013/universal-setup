#include "usk_record_io.h"

#include "usk_stable_file.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <stdexcept>
#include <system_error>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
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
    std::error_code error;
    const fs::path path = fs::absolute(input, error).lexically_normal();
    if (error || !fs::is_directory(path) || linked(path)) {
        throw std::runtime_error("record root is not an existing safe directory");
    }
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
    if (!fs::create_directory(target, error) || error || linked(target)) {
        throw std::runtime_error("cannot exclusively create record directory");
    }
    sync_directory(parent);
}

void write_new_durable_text(const fs::path& path, const std::string& content)
{
    require_safe_directory(path.parent_path());
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

} // namespace usk::record_io
