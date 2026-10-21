// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_custody_image_internal.h"
#include "usk_diagnostic_metrics.h"
#include "usk_sha256.h"
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <type_traits>
#include <vector>

namespace {
using usk::platform::windows::PublisherCustodyImage;
namespace fs = std::filesystem;
void require(bool value, const char* reason) {
    if (!value) throw std::runtime_error(reason);
}
template<class Action> void refuses(Action action) {
    bool refused = false;
    try { action(); } catch (const std::exception&) { refused = true; }
    require(refused, "expected custody image refusal");
}
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE handle) : value(handle) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    void reset() {
        if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
        value = INVALID_HANDLE_VALUE;
    }
};
struct View {
    void* value;
    ~View() { if (value) UnmapViewOfFile(value); }
};
struct Fixture {
    fs::path root, file, alias, moved;
    Fixture() {
        std::array<unsigned char, 16> nonce{};
        require(BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0, "fixture random source unavailable");
        std::string name = "usk-custody-image-";
        constexpr char digits[] = "0123456789abcdef";
        for (auto byte : nonce) { name += digits[byte >> 4]; name += digits[byte & 15]; }
        root = fs::temp_directory_path() / name;
        require(fs::create_directory(root), "fixture already exists");
        file = root / "image.bin"; alias = root / "alias.bin";
        moved = root / "moved.bin";
    }
    ~Fixture() {
        // Only individually named owned files; no recursive removal.
        std::error_code error;
        fs::remove(alias, error); fs::remove(moved, error);
        fs::remove(file, error); fs::remove(root, error);
    }
    void put(const std::vector<unsigned char>& data) const {
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        require(static_cast<bool>(out), "fixture write failed");
    }
};
HANDLE open(const fs::path& path, DWORD access) {
    return CreateFileW(path.c_str(), access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
}
void rejected_open(const fs::path& path, DWORD access) {
    Handle handle(open(path, access));
    const auto error = GetLastError();
    require(handle.value == INVALID_HANDLE_VALUE && error == ERROR_SHARING_VIOLATION,
        "write/delete capability was not refused by original held image");
}
bool sink(const usk::diagnostics::Event&) noexcept { return true; }
std::uint64_t count(usk::diagnostics::Counter counter) {
    return usk::diagnostics::snapshot().totals[static_cast<std::size_t>(counter)];
}
void controls() {
    static_assert(!std::is_copy_constructible_v<PublisherCustodyImage>);
    static_assert(!std::is_move_constructible_v<PublisherCustodyImage>);
    Fixture fixture;
    std::vector<unsigned char> data(3u * 1024u * 1024u + 71u);
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<unsigned char>(i * 131u + 19u);
    fixture.put(data);
    usk::base::Sha256 expected;
    expected.update(data.data(), data.size());
    const auto digest = expected.finish();
    {
        Handle writer(open(fixture.file, GENERIC_READ | GENERIC_WRITE));
        require(writer.value != INVALID_HANDLE_VALUE, "preexisting writer unavailable");
        refuses([&] { PublisherCustodyImage image(fixture.file); });
        Handle mapping(CreateFileMappingW(writer.value, nullptr, PAGE_READWRITE, 0, 0, nullptr));
        require(mapping.value != nullptr, "preexisting writable section unavailable");
        writer.reset();
        refuses([&] { PublisherCustodyImage image(fixture.file); });
        View view{MapViewOfFile(mapping.value, FILE_MAP_WRITE, 0, 0, 0)};
        require(view.value != nullptr, "preexisting writable view unavailable");
        mapping.reset(); // Both creating handles are gone; the live view remains.
        static_cast<unsigned char*>(view.value)[0] ^= 1u;
        refuses([&] { PublisherCustodyImage image(fixture.file); });
    }
    fixture.put(data);
    require(usk::diagnostics::enable(sink), "diagnostic counter controls unavailable");
    struct DiagnosticCloser { ~DiagnosticCloser() { usk::diagnostics::disable(sink); } } closer;
    const auto before = count(usk::diagnostics::Counter::hash_calls);
    {
        PublisherCustodyImage image(fixture.file);
        require(image.bound_sha256() == digest && image.identity().size_bytes == data.size(),
            "initial image digest does not bind actual complete bytes");
        require(count(usk::diagnostics::Counter::hash_calls) == before + 1,
            "image construction did not positively enter complete initial hash");
        const auto bytes = count(usk::diagnostics::Counter::hash_bytes);
        for (int i = 0; i < 128; ++i) require(image.bound_sha256() == digest, "bound image digest changed");
        require(count(usk::diagnostics::Counter::hash_calls) == before + 1 &&
            count(usk::diagnostics::Counter::hash_bytes) == bytes,
            "custody image endpoint unexpectedly rehashed content");
        rejected_open(fixture.file, GENERIC_WRITE);
        rejected_open(fixture.file, FILE_APPEND_DATA);
        rejected_open(fixture.file, DELETE);
        require(!MoveFileW(fixture.file.c_str(), fixture.moved.c_str()),
            "original file moved despite delete-excluding handle");
        require(CreateHardLinkW(fixture.alias.c_str(), fixture.file.c_str(), nullptr) != FALSE,
            "owned hard-link alias control unavailable");
        rejected_open(fixture.alias, GENERIC_WRITE);
        // Namespace/link-count change is a fresh refusal. Restoring it cannot
        // make this failed owner usable again.
        refuses([&] { (void)image.bound_sha256(); });
        refuses([&] { (void)image.bound_sha256(); });
    }
    require(DeleteFileW(fixture.alias.c_str()) != FALSE, "owned alias removal after release failed");
    {
        PublisherCustodyImage image(fixture.file);
        Handle attributes(open(fixture.file, FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES));
        require(attributes.value != INVALID_HANDLE_VALUE, "metadata-only change control unavailable");
        FILETIME created{}, accessed{}, modified{};
        require(GetFileTime(attributes.value, &created, &accessed, &modified) != FALSE,
            "original timestamp unavailable");
        ULARGE_INTEGER ticks{};
        ticks.LowPart = modified.dwLowDateTime; ticks.HighPart = modified.dwHighDateTime;
        ticks.QuadPart += 10000000u;
        FILETIME changed{ticks.LowPart, ticks.HighPart};
        require(SetFileTime(attributes.value, nullptr, nullptr, &changed) != FALSE,
            "metadata-only timestamp change failed");
        refuses([&] { (void)image.bound_sha256(); });
        require(SetFileTime(attributes.value, nullptr, nullptr, &modified) != FALSE,
            "original timestamp restoration failed");
        refuses([&] { (void)image.bound_sha256(); });
    }
    {
        PublisherCustodyImage image(fixture.file);
        Handle reader(open(fixture.file, GENERIC_READ));
        require(reader.value != INVALID_HANDLE_VALUE, "compatible reader unavailable");
        Handle write_mapping(CreateFileMappingW(reader.value, nullptr, PAGE_READWRITE, 0, 0, nullptr));
        require(!write_mapping.value && GetLastError() == ERROR_ACCESS_DENIED,
            "read-only handle created writable mapping");
        Handle copy_mapping(CreateFileMappingW(reader.value, nullptr, PAGE_WRITECOPY, 0, 0, nullptr));
        require(copy_mapping.value != nullptr, "copy-on-write control unavailable");
        View view{MapViewOfFile(copy_mapping.value, FILE_MAP_COPY, 0, 0, 0)};
        require(view.value != nullptr, "copy-on-write view unavailable");
        static_cast<unsigned char*>(view.value)[0] ^= 1u;
        usk::base::StableFile fresh(fixture.file);
        require(fresh.sha256_hex() == digest && image.bound_sha256() == digest,
            "copy-on-write changed underlying file content");
    }
    {
        Handle writer(open(fixture.file, GENERIC_WRITE));
        require(writer.value != INVALID_HANDLE_VALUE, "image release did not restore writer eligibility");
    }
    // The general hashing API still samples complete bytes on every call.
    usk::base::StableFile ordinary(fixture.file);
    const auto ordinary_before = count(usk::diagnostics::Counter::hash_calls);
    require(ordinary.sha256_hex() == digest && ordinary.sha256_hex() == digest &&
        count(usk::diagnostics::Counter::hash_calls) == ordinary_before + 2,
        "ordinary StableFile hashing changed to cached semantics");
}
}
int main() {
    try {
        controls();
        std::cout << "Native custody-only content binding, live write mapping refusal, aliases, sticky metadata failure, digest reuse and unchanged general hashes: PASS; no effect authority\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
