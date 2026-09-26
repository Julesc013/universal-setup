// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_stable_file.h"
#include "usk_utf8_path.h"
#include "usk_record_io.h"

#include <chrono>
#include <algorithm>
#include <iterator>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace fs = std::filesystem;

int record_backend_failure_proof(const fs::path& root)
{
    // A backend refusal must never fall through to the ordinary path writer.
    // Unwinding a nested operation must restore the prior backend, then leave
    // unrelated repository writes unaffected after the outer operation ends.
    std::size_t directories = 0, outer_writes = 0, inner_writes = 0;
    usk::record_io::RecordWriteOperations outer{
        [&](const fs::path&, const std::string&) { ++directories; },
        [&](const fs::path&, const std::string&) { ++outer_writes; }};
    usk::record_io::RecordWriteOperations inner{
        [&](const fs::path&, const std::string&) { throw std::runtime_error("refused create"); },
        [&](const fs::path&, const std::string&) {
            ++inner_writes;
            throw std::runtime_error("refused publication");
        }};
    const fs::path record = root / "backend-record.json";
    {
        usk::record_io::ScopedRecordWriteOperations active(outer);
        usk::record_io::create_directory_exclusive(root, "backend-directory");
        try {
            usk::record_io::ScopedRecordWriteOperations nested(inner);
            usk::record_io::write_new_durable_text(record, "must not be published");
            return 40;
        } catch (const std::runtime_error&) {}
        if (fs::exists(record) || fs::exists(root / "backend-directory")) return 41;
        usk::record_io::write_new_durable_text(record, "outer operation");
        // An incomplete backend cannot replace the active operation.
        const usk::record_io::RecordWriteOperations incomplete{};
        try {
            usk::record_io::ScopedRecordWriteOperations invalid(incomplete);
            return 42;
        } catch (const std::runtime_error&) {}
        usk::record_io::write_new_durable_text(record, "outer restored");
    }
    if (directories != 1 || outer_writes != 2 || inner_writes != 1 || fs::exists(record)) return 43;
    usk::record_io::write_new_durable_text(record, "ordinary repository");
    if (usk::record_io::read_stable_text(record, 64) != "ordinary repository") return 44;
    return 0;
}


#if defined(_WIN32)
template <typename Operation>
bool refused_path_capacity(const Operation& operation)
{
    try { operation(); }
    catch (const usk::base::NativePathLimitExceeded&) { return true; }
    return false;
}

int native_path_capacity_proof(const fs::path& root)
{
    using usk::base::NativePathKind;
    using usk::base::require_native_path_capacity;
    if (root.native().size() >= 240u) return 20;
    const std::size_t parent_length = std::max<std::size_t>(root.native().size() + 2u, 120u);
    const std::string parent_name(parent_length - root.native().size() - 1u, 'p');
    usk::record_io::create_directory_exclusive(root, parent_name);
    const fs::path parent = root / parent_name;
    const std::string directory_name(247u - parent.native().size() - 1u, 'q');
    const fs::path directory = parent / directory_name;
    require_native_path_capacity(directory, NativePathKind::directory, "admitted boundary");
    usk::record_io::create_directory_exclusive(parent, directory_name);
    const fs::path file = directory / "payload.bin";
    if (directory.native().size() != 247u || file.native().size() != 259u) return 21;
    usk::record_io::write_new_durable_text(file, "boundary");
    if (usk::record_io::read_stable_text(file, 32) != "boundary") return 22;
    if (!refused_path_capacity([&] {
            usk::record_io::create_directory_exclusive(parent, directory_name + "x");
        }) || !refused_path_capacity([&] {
            usk::record_io::write_new_durable_text(directory / "payload.binx", "must not exist");
        }) || std::distance(fs::directory_iterator(directory), fs::directory_iterator{}) != 1 ||
        usk::record_io::read_stable_text(file, 32) != "boundary") return 23;
    if (!refused_path_capacity([&] {
            require_native_path_capacity(parent / (directory_name + "x") / "a",
                NativePathKind::file, "oversize ancestor");
        }) || !refused_path_capacity([&] {
            require_native_path_capacity(root.root_path() / std::wstring(256u, L'x'),
                NativePathKind::file, "oversize component");
        })) return 24;

    // Capacity uses UTF-16 units: each rocket is four UTF-8 bytes and two units.
    const std::string rocket = "\xf0\x9f\x9a\x80";
    const std::size_t available = 247u - root.native().size() - 1u;
    std::string leaf(available % 2u, 'u');
    for (std::size_t index = 0; index < available / 2u; ++index) leaf += rocket;
    const fs::path unicode = root / fs::u8path(leaf);
    if (unicode.native().size() != 247u || unicode.u8string().size() <= unicode.native().size()) return 25;
    require_native_path_capacity(unicode, NativePathKind::directory, "UTF-16 boundary");
    if (!fs::create_directory(unicode)) return 28;
    usk::record_io::write_new_durable_text(unicode / "payload.bin", "unicode boundary");
    if (usk::record_io::read_stable_text(unicode / "payload.bin", 32) != "unicode boundary") return 29;
    if (!refused_path_capacity([&] {
            require_native_path_capacity(root / fs::u8path(leaf + rocket),
                NativePathKind::directory, "surrogate pair beyond boundary");
        })) return 26;
    fs::path unnormalized = root;
    for (std::size_t index = 0; index < 140u; ++index) unnormalized /= ".";
    unnormalized /= "file";
    if (!refused_path_capacity([&] {
            require_native_path_capacity(unnormalized, NativePathKind::file, "unshortened native spelling");
        })) return 27;
    return 0;
}

int volume_guid_record_io_proof(const fs::path& root)
{
    wchar_t volume_root[64]{};
    if (!GetVolumeNameForVolumeMountPointW(root.root_path().c_str(),
            volume_root, static_cast<DWORD>(std::size(volume_root)))) return 30;
    const fs::path alias(std::wstring(volume_root) + root.relative_path().wstring());
    usk::record_io::require_safe_directory(alias);
    usk::record_io::write_new_durable_text(alias / "volume-bound.txt", "bound");
    if (usk::record_io::read_stable_text(root / "volume-bound.txt", 16) != "bound" ||
        usk::record_io::read_stable_text(alias / "volume-bound.txt", 16) != "bound") {
        return 31;
    }
    return 0;
}
#endif

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

#if defined(_WIN32)
    if (const int capacity = native_path_capacity_proof(root)) return capacity;
    if (const int volume_bound = volume_guid_record_io_proof(root)) return volume_bound;
#endif
    if (const int backend = record_backend_failure_proof(root)) return backend;
    fs::remove_all(root, error);
    return error ? 8 : 0;
}
