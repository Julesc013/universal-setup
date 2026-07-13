#include "usk_sha256.h"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace {

std::uint32_t rotate_right(std::uint32_t value, int bits)
{
    return (value >> bits) | (value << (32 - bits));
}

} // namespace

namespace usk::base {

void Sha256::update(const unsigned char* data, std::size_t size)
{
    if (finished_ || (data == nullptr && size != 0)) {
        throw std::logic_error("invalid SHA-256 update");
    }
    total_bytes_ += size;
    while (size > 0) {
        const std::size_t count = std::min(size, block_.size() - block_size_);
        std::copy(data, data + count, block_.begin() + block_size_);
        block_size_ += count;
        data += count;
        size -= count;
        if (block_size_ == block_.size()) {
            transform(block_.data());
            block_size_ = 0;
        }
    }
}

std::string Sha256::finish()
{
    if (finished_) {
        throw std::logic_error("SHA-256 was already finalized");
    }
    const std::uint64_t bit_length = total_bytes_ * 8u;
    const unsigned char marker = 0x80u;
    update(&marker, 1);
    const unsigned char zero = 0u;
    while (block_size_ != 56u) {
        update(&zero, 1);
    }
    std::array<unsigned char, 8> length{};
    for (std::size_t index = 0; index < length.size(); ++index) {
        length[7u - index] = static_cast<unsigned char>(
            (bit_length >> (index * 8u)) & 0xffu);
    }
    update(length.data(), length.size());
    finished_ = true;

    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::uint32_t value : state_) {
        out << std::setw(8) << value;
    }
    return out.str();
}

void Sha256::transform(const unsigned char* block)
{
    static const std::array<std::uint32_t, 64> constants = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
    std::array<std::uint32_t, 64> words{};
    for (std::size_t index = 0; index < 16u; ++index) {
        const std::size_t offset = index * 4u;
        words[index] = (static_cast<std::uint32_t>(block[offset]) << 24) |
            (static_cast<std::uint32_t>(block[offset + 1]) << 16) |
            (static_cast<std::uint32_t>(block[offset + 2]) << 8) |
            static_cast<std::uint32_t>(block[offset + 3]);
    }
    for (std::size_t index = 16; index < words.size(); ++index) {
        const std::uint32_t s0 = rotate_right(words[index - 15], 7) ^
            rotate_right(words[index - 15], 18) ^ (words[index - 15] >> 3);
        const std::uint32_t s1 = rotate_right(words[index - 2], 17) ^
            rotate_right(words[index - 2], 19) ^ (words[index - 2] >> 10);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    std::uint32_t a=state_[0],b=state_[1],c=state_[2],d=state_[3];
    std::uint32_t e=state_[4],f=state_[5],g=state_[6],h=state_[7];
    for (std::size_t index = 0; index < words.size(); ++index) {
        const std::uint32_t t1 = h +
            (rotate_right(e,6)^rotate_right(e,11)^rotate_right(e,25)) +
            ((e&f)^((~e)&g)) + constants[index] + words[index];
        const std::uint32_t t2 =
            (rotate_right(a,2)^rotate_right(a,13)^rotate_right(a,22)) +
            ((a&b)^(a&c)^(b&c));
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    const std::uint32_t values[] = {a,b,c,d,e,f,g,h};
    for (std::size_t index = 0; index < state_.size(); ++index) {
        state_[index] += values[index];
    }
}

std::string sha256_hex_file(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot open file for SHA-256: " + path.string());
    }
    Sha256 hash;
    std::array<unsigned char, 64 * 1024> buffer{};
    while (input) {
        input.read(
            reinterpret_cast<char*>(buffer.data()),
            static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count = input.gcount();
        if (count > 0) {
            hash.update(buffer.data(), static_cast<std::size_t>(count));
        }
    }
    if (!input.eof()) {
        throw std::runtime_error("failed while hashing: " + path.string());
    }
    return hash.finish();
}

} // namespace usk::base
