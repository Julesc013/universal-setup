#include "usk_stable_file.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;

int main()
{
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path root = fs::temp_directory_path() /
        ("usk-stable-file-" + std::to_string(nonce));
    std::error_code error;
    fs::create_directories(root, error);
    if (error) {
        return 1;
    }

    const fs::path source = root / "source.zip";
    {
        std::ofstream output(source, std::ios::binary);
        output << "abc";
    }
    try {
        usk::base::StableFile stable(source);
        if (stable.identity().size_bytes != 3 ||
            stable.identity().link_count != 1 ||
            stable.read(0, 3) != std::vector<unsigned char>({'a', 'b', 'c'}) ||
            stable.sha256_hex() !=
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
            return 2;
        }
        stable.verify_unchanged();
        bool refused_bounds = false;
        try {
            (void)stable.read(2, 2);
        } catch (const std::runtime_error&) {
            refused_bounds = true;
        }
        if (!refused_bounds) {
            return 3;
        }
#if !defined(_WIN32)
        {
            std::ofstream output(source, std::ios::binary | std::ios::app);
            output << "changed";
        }
        bool detected_change = false;
        try {
            stable.verify_unchanged();
        } catch (const std::runtime_error&) {
            detected_change = true;
        }
        if (!detected_change) {
            return 4;
        }
#endif
    } catch (const std::exception&) {
        return 5;
    }

    const fs::path linked_source = root / "linked.zip";
    const fs::path second_link = root / "linked-copy.zip";
    {
        std::ofstream output(linked_source, std::ios::binary);
        output << "linked";
    }
    fs::create_hard_link(linked_source, second_link, error);
    if (!error) {
        bool refused_link_count = false;
        try {
            usk::base::StableFile stable(linked_source);
        } catch (const std::runtime_error&) {
            refused_link_count = true;
        }
        if (!refused_link_count) {
            return 6;
        }
    }

    const fs::path symlink = root / "source-link.zip";
    error.clear();
    fs::create_symlink(source, symlink, error);
    if (!error) {
        bool refused_symlink = false;
        try {
            usk::base::StableFile stable(symlink);
        } catch (const std::runtime_error&) {
            refused_symlink = true;
        }
        if (!refused_symlink) {
            return 7;
        }
    }

    fs::remove_all(root, error);
    return error ? 8 : 0;
}
