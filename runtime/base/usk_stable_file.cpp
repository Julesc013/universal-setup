#include "usk_stable_file.h"

#include "usk_sha256.h"

#include <array>
#include <cerrno>
#include <iomanip>
#include <limits>
#include <sstream>
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
#endif

namespace fs = std::filesystem;

namespace {

std::string hex_id(std::uint64_t value)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(16) << value;
    return out.str();
}

#if defined(_WIN32)

HANDLE as_handle(std::intptr_t value)
{
    return reinterpret_cast<HANDLE>(value);
}

std::runtime_error windows_error(const char* action)
{
    return std::runtime_error(
        std::string(action) + " (Windows error " + std::to_string(GetLastError()) + ")");
}

usk::base::StableFileIdentity identity_from_handle(HANDLE handle)
{
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info)) {
        throw windows_error("cannot inspect local archive handle");
    }
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        GetFileType(handle) != FILE_TYPE_DISK) {
        throw std::runtime_error("local archive must be a regular non-reparse disk file");
    }
    if (info.nNumberOfLinks != 1) {
        throw std::runtime_error("multiply linked source archive is not stable enough for planning");
    }
    const std::uint64_t size =
        (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    const std::uint64_t file_index =
        (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
    const std::uint64_t windows_ticks =
        (static_cast<std::uint64_t>(info.ftLastWriteTime.dwHighDateTime) << 32) |
        info.ftLastWriteTime.dwLowDateTime;
    constexpr std::uint64_t windows_to_unix_ticks = 116444736000000000ull;

    usk::base::StableFileIdentity identity;
    identity.volume_id = hex_id(info.dwVolumeSerialNumber);
    identity.file_id = hex_id(file_index);
    identity.size_bytes = size;
    identity.modified_time_ns = windows_ticks >= windows_to_unix_ticks
        ? (windows_ticks - windows_to_unix_ticks) * 100ull
        : 0;
    identity.link_count = info.nNumberOfLinks;
    return identity;
}

bool same_identity(
    const usk::base::StableFileIdentity& left,
    const usk::base::StableFileIdentity& right)
{
    return left.volume_id == right.volume_id &&
        left.file_id == right.file_id &&
        left.size_bytes == right.size_bytes &&
        left.modified_time_ns == right.modified_time_ns &&
        left.link_count == right.link_count;
}

#else

std::uint64_t modified_time_ns(const struct stat& info)
{
#if defined(__APPLE__)
    return static_cast<std::uint64_t>(info.st_mtimespec.tv_sec) * 1000000000ull +
        static_cast<std::uint64_t>(info.st_mtimespec.tv_nsec);
#else
    return static_cast<std::uint64_t>(info.st_mtim.tv_sec) * 1000000000ull +
        static_cast<std::uint64_t>(info.st_mtim.tv_nsec);
#endif
}

usk::base::StableFileIdentity identity_from_stat(const struct stat& info)
{
    if (!S_ISREG(info.st_mode)) {
        throw std::runtime_error("local archive must be a regular non-link file");
    }
    if (info.st_nlink != 1) {
        throw std::runtime_error("multiply linked source archive is not stable enough for planning");
    }
    if (info.st_size < 0) {
        throw std::runtime_error("local archive reports a negative size");
    }
    usk::base::StableFileIdentity identity;
    identity.volume_id = hex_id(static_cast<std::uint64_t>(info.st_dev));
    identity.file_id = hex_id(static_cast<std::uint64_t>(info.st_ino));
    identity.size_bytes = static_cast<std::uint64_t>(info.st_size);
    identity.modified_time_ns = modified_time_ns(info);
    identity.link_count = static_cast<std::uint32_t>(info.st_nlink);
    return identity;
}

bool same_identity(
    const usk::base::StableFileIdentity& left,
    const usk::base::StableFileIdentity& right)
{
    return left.volume_id == right.volume_id &&
        left.file_id == right.file_id &&
        left.size_bytes == right.size_bytes &&
        left.modified_time_ns == right.modified_time_ns &&
        left.link_count == right.link_count;
}

#endif

} // namespace

namespace usk::base {

StableFile::StableFile(const fs::path& path)
{
    std::error_code error;
    path_ = fs::absolute(path, error).lexically_normal();
    if (error || path_.empty()) {
        throw std::runtime_error("local archive path cannot be resolved");
    }
#if defined(_WIN32)
    HANDLE handle = CreateFileW(
        path_.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        throw windows_error("cannot open local archive without mutation sharing");
    }
    native_handle_ = reinterpret_cast<std::intptr_t>(handle);
    try {
        identity_ = identity_from_handle(handle);
    } catch (...) {
        CloseHandle(handle);
        native_handle_ = -1;
        throw;
    }
#else
    int flags = O_RDONLY;
#if defined(O_CLOEXEC)
    flags |= O_CLOEXEC;
#endif
#if defined(O_NOFOLLOW)
    flags |= O_NOFOLLOW;
#endif
    const int descriptor = ::open(path_.c_str(), flags);
    if (descriptor < 0) {
        throw std::runtime_error(
            "cannot open local archive without following links: " +
            std::error_code(errno, std::generic_category()).message());
    }
    native_handle_ = descriptor;
    struct stat info{};
    if (::fstat(descriptor, &info) != 0) {
        const int saved = errno;
        ::close(descriptor);
        native_handle_ = -1;
        throw std::runtime_error(
            "cannot inspect local archive handle: " +
            std::error_code(saved, std::generic_category()).message());
    }
    try {
        identity_ = identity_from_stat(info);
    } catch (...) {
        ::close(descriptor);
        native_handle_ = -1;
        throw;
    }
#endif
}

StableFile::~StableFile()
{
#if defined(_WIN32)
    if (native_handle_ != -1) {
        CloseHandle(as_handle(native_handle_));
    }
#else
    if (native_handle_ != -1) {
        ::close(static_cast<int>(native_handle_));
    }
#endif
}

std::vector<unsigned char> StableFile::read(
    std::uint64_t offset,
    std::size_t size) const
{
    if (offset > identity_.size_bytes ||
        size > identity_.size_bytes - offset) {
        throw std::runtime_error("local archive read exceeds stable source bounds");
    }
    std::vector<unsigned char> result(size);
    if (size != 0) {
        read_exact(offset, result.data(), size);
    }
    return result;
}

void StableFile::read_exact(
    std::uint64_t offset,
    unsigned char* output,
    std::size_t size) const
{
#if defined(_WIN32)
    HANDLE handle = as_handle(native_handle_);
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max())) {
        throw std::runtime_error("stable local archive offset exceeds platform range");
    }
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(handle, position, nullptr, FILE_BEGIN)) {
        throw windows_error("cannot seek stable local archive");
    }
    while (size != 0) {
        const DWORD chunk = static_cast<DWORD>(
            std::min<std::size_t>(size, std::numeric_limits<DWORD>::max()));
        DWORD read_count = 0;
        if (!ReadFile(handle, output, chunk, &read_count, nullptr) || read_count != chunk) {
            throw windows_error("cannot read stable local archive");
        }
        output += read_count;
        size -= read_count;
    }
#else
    while (size != 0) {
        const ssize_t count = ::pread(
            static_cast<int>(native_handle_),
            output,
            size,
            static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            throw std::runtime_error(
                "cannot read stable local archive: " +
                std::error_code(errno, std::generic_category()).message());
        }
        output += count;
        size -= static_cast<std::size_t>(count);
        offset += static_cast<std::uint64_t>(count);
    }
#endif
}

std::string StableFile::sha256_hex() const
{
    Sha256 hash;
    std::array<unsigned char, 64 * 1024> buffer{};
    std::uint64_t offset = 0;
    while (offset < identity_.size_bytes) {
        const std::size_t count = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), identity_.size_bytes - offset));
        read_exact(offset, buffer.data(), count);
        hash.update(buffer.data(), count);
        offset += count;
    }
    return hash.finish();
}

void StableFile::verify_unchanged() const
{
#if defined(_WIN32)
    const StableFileIdentity current = identity_from_handle(as_handle(native_handle_));
    if (!same_identity(identity_, current)) {
        throw std::runtime_error("local archive changed through its stable handle");
    }
    HANDLE path_handle = CreateFileW(
        path_.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (path_handle == INVALID_HANDLE_VALUE) {
        throw windows_error("local archive path no longer resolves to the stable handle");
    }
    StableFileIdentity path_identity;
    try {
        path_identity = identity_from_handle(path_handle);
    } catch (...) {
        CloseHandle(path_handle);
        throw;
    }
    CloseHandle(path_handle);
    if (!same_identity(identity_, path_identity)) {
        throw std::runtime_error("local archive path was substituted during inspection");
    }
#else
    struct stat current{};
    if (::fstat(static_cast<int>(native_handle_), &current) != 0 ||
        !same_identity(identity_, identity_from_stat(current))) {
        throw std::runtime_error("local archive changed through its stable handle");
    }
    struct stat path_info{};
    if (::lstat(path_.c_str(), &path_info) != 0 ||
        S_ISLNK(path_info.st_mode) ||
        !same_identity(identity_, identity_from_stat(path_info))) {
        throw std::runtime_error("local archive path was substituted during inspection");
    }
#endif
}

} // namespace usk::base
