// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#ifndef USK_STABLE_FILE_H
#define USK_STABLE_FILE_H

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace usk::base {

struct StableFileIdentity {
    std::string volume_id;
    std::string file_id;
    std::uint64_t size_bytes = 0;
    std::uint64_t modified_time_ns = 0;
    std::uint32_t link_count = 0;
};

class StableFile {
public:
    explicit StableFile(const std::filesystem::path& path);
    ~StableFile();

    StableFile(const StableFile&) = delete;
    StableFile& operator=(const StableFile&) = delete;

    const std::filesystem::path& path() const noexcept { return path_; }
    const StableFileIdentity& identity() const noexcept { return identity_; }
    std::vector<unsigned char> read(std::uint64_t offset, std::size_t size) const;
    std::string sha256_hex() const;
    void verify_unchanged() const;

private:
    void read_exact(std::uint64_t offset, unsigned char* output, std::size_t size) const;

    std::filesystem::path path_;
    std::intptr_t native_handle_ = -1;
    StableFileIdentity identity_;
};

} // namespace usk::base

#endif
