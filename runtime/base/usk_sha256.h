#ifndef USK_SHA256_H
#define USK_SHA256_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>

namespace usk::base {

class Sha256 {
public:
    void update(const unsigned char* data, std::size_t size);
    std::string finish();

private:
    void transform(const unsigned char* block);

    std::array<std::uint32_t, 8> state_ = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    std::array<unsigned char, 64> block_{};
    std::size_t block_size_ = 0;
    std::uint64_t total_bytes_ = 0;
    bool finished_ = false;
};

std::string sha256_hex_file(const std::filesystem::path& path);

} // namespace usk::base

#endif
