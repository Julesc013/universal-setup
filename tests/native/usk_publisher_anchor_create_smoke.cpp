// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_anchor_create.h"
#include "usk_publisher_handle_observation.h"
#include "usk_publisher_staged_stream.h"
#include "usk_sha256.h"

#include <aclapi.h>
#include <windows.h>

#include <chrono>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using usk::platform::windows::create_directory_relative_with_descriptor;
using usk::platform::windows::create_file_relative_with_descriptor;
using usk::platform::windows::observe_publisher_directory_handle;
using usk::platform::windows::observe_publisher_file_handle;
using usk::platform::windows::stream_verified_source_to_staged_file;
using usk::platform::windows::stream_verified_reader_to_staged_file;

namespace {
class Handle {
public:
    explicit Handle(HANDLE value) : value_(value) {
        if (!value_ || value_ == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("fixture handle open failed");
        }
    }
    ~Handle() { CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::vector<unsigned char> fixture_descriptor(HANDLE parent) {
    PSECURITY_DESCRIPTOR raw = nullptr;
    const DWORD status = GetSecurityInfo(parent, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        nullptr, nullptr, nullptr, nullptr, &raw);
    if (status != ERROR_SUCCESS || !raw) {
        throw std::runtime_error("disposable parent security descriptor unavailable");
    }
    const auto* first = static_cast<const unsigned char*>(raw);
    std::vector<unsigned char> bytes(first, first + GetSecurityDescriptorLength(raw));
    LocalFree(raw);
    return bytes;
}

bool refused(HANDLE parent, const std::wstring& name,
    const std::vector<unsigned char>& descriptor) {
    try {
        Handle created(create_directory_relative_with_descriptor(parent, name, descriptor));
    } catch (const std::exception&) { return true; }
    return false;
}

bool file_refused(HANDLE parent, const std::wstring& name,
    const std::vector<unsigned char>& descriptor) {
    try {
        Handle created(create_file_relative_with_descriptor(parent, name, descriptor));
    } catch (const std::exception&) { return true; }
    return false;
}
} // namespace

int main() {
    try {
        const auto root = fs::temp_directory_path() /
            ("usk-publisher-anchor-" + std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count()));
        check(fs::create_directory(root), "fixture root already exists");
        const auto parent = root / "parent";
        const auto moved = root / "moved";
        const auto source_path = root / "source.bin";
        std::vector<unsigned char> source_bytes(2u * 1024u * 1024u);
        for (std::size_t index = 0; index < source_bytes.size(); ++index) {
            source_bytes[index] = static_cast<unsigned char>(index % 251u);
        }
        {
            std::ofstream source_output(source_path, std::ios::binary);
            source_output.write(reinterpret_cast<const char*>(source_bytes.data()),
                static_cast<std::streamsize>(source_bytes.size()));
            check(source_output.good(), "fixture source write failed");
        }
        usk::base::Sha256 source_hasher;
        source_hasher.update(source_bytes.data(), source_bytes.size());
        const std::string source_sha256 = source_hasher.finish();
        check(fs::create_directory(parent), "fixture parent creation failed");
        {
            Handle parent_handle(CreateFileW(parent.c_str(),
                FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_READ_ATTRIBUTES |
                    FILE_TRAVERSE | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            const auto descriptor = fixture_descriptor(parent_handle.get());
            const auto parent_id = observe_publisher_directory_handle(parent_handle.get()).file_id;
            Handle source_handle(CreateFileW(source_path.c_str(),
                GENERIC_READ | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            {
                const auto streamed = stream_verified_source_to_staged_file(
                    parent_handle.get(), L"streamed.bin", descriptor,
                    source_handle.get(), source_bytes.size(), source_sha256);
                Handle staged(streamed.file);
                check(streamed.bytes_written == source_bytes.size() &&
                    streamed.sha256 == source_sha256 &&
                    !observe_publisher_file_handle(staged.get()).file_id.empty(),
                    "bounded staged source stream differs");
            }
            check(usk::base::sha256_hex_file(parent / "streamed.bin") ==
                source_sha256, "protected staged bytes differ");
            const auto reader = [&](std::uint64_t offset, unsigned char* output,
                std::size_t capacity) -> std::size_t {
                if (offset >= source_bytes.size()) return 0;
                const auto count = std::min(capacity,
                    source_bytes.size() - static_cast<std::size_t>(offset));
                std::copy_n(source_bytes.data() + offset, count, output);
                return count;
            };
            int source_validations = 0;
            {
                const auto streamed = stream_verified_reader_to_staged_file(
                    parent_handle.get(), L"reader.bin", descriptor,
                    source_bytes.size(), source_sha256, reader,
                    [&] { ++source_validations; });
                Handle staged(streamed.file);
                check(streamed.bytes_written == source_bytes.size() &&
                    streamed.sha256 == source_sha256 && source_validations == 2,
                    "bounded reader stream was not validated twice");
            }
            check(usk::base::sha256_hex_file(parent / "reader.bin") ==
                source_sha256, "protected reader bytes differ");
            bool reader_preflight_refused = false;
            try {
                auto bad = stream_verified_reader_to_staged_file(
                    parent_handle.get(), L"reader-preflight.bin", descriptor,
                    source_bytes.size(), source_sha256, reader,
                    [] { throw std::runtime_error("source identity changed"); });
                CloseHandle(bad.file);
            } catch (const std::exception&) { reader_preflight_refused = true; }
            check(reader_preflight_refused &&
                !fs::exists(parent / "reader-preflight.bin"),
                "reader preflight failure created a staged file");
            bool reader_digest_refused = false;
            try {
                auto bad = stream_verified_reader_to_staged_file(
                    parent_handle.get(), L"reader-digest.bin", descriptor,
                    source_bytes.size(), std::string(64, '0'), reader, [] {});
                CloseHandle(bad.file);
            } catch (const std::exception&) { reader_digest_refused = true; }
            check(reader_digest_refused &&
                fs::exists(parent / "reader-digest.bin") &&
                usk::base::sha256_hex_file(parent / "reader-digest.bin") ==
                    source_sha256, "reader digest failure did not retain bytes");
            bool retained_digest_failure = false;
            try {
                auto bad = stream_verified_source_to_staged_file(
                    parent_handle.get(), L"bad-digest.bin", descriptor,
                    source_handle.get(), source_bytes.size(), std::string(64, '0'));
                CloseHandle(bad.file);
            } catch (const std::exception&) { retained_digest_failure = true; }
            check(retained_digest_failure &&
                fs::exists(parent / "bad-digest.bin") &&
                usk::base::sha256_hex_file(parent / "bad-digest.bin") ==
                    source_sha256,
                "digest refusal removed or changed staged bytes");
            bool size_refused = false;
            try {
                auto bad = stream_verified_source_to_staged_file(
                    parent_handle.get(), L"bad-size.bin", descriptor,
                    source_handle.get(), source_bytes.size() + 1, source_sha256);
                CloseHandle(bad.file);
            } catch (const std::exception&) { size_refused = true; }
            check(size_refused && !fs::exists(parent / "bad-size.bin"),
                "source size mismatch created a staged file");
            bool collision_refused = false;
            try {
                auto bad = stream_verified_source_to_staged_file(
                    parent_handle.get(), L"streamed.bin", descriptor,
                    source_handle.get(), source_bytes.size(), source_sha256);
                CloseHandle(bad.file);
            } catch (const std::exception&) { collision_refused = true; }
            check(collision_refused &&
                usk::base::sha256_hex_file(parent / "streamed.bin") ==
                    source_sha256, "create-only stream collision changed bytes");
            std::string first_id;
            {
                Handle first(create_directory_relative_with_descriptor(
                    parent_handle.get(), L"first", descriptor));
                first_id = observe_publisher_directory_handle(first.get()).file_id;
                DWORD handle_flags = 0;
                check(fs::exists(parent / "first") &&
                    !first_id.empty() && GetHandleInformation(first.get(), &handle_flags) != FALSE &&
                    (handle_flags & HANDLE_FLAG_INHERIT) == 0,
                    "relative create did not produce a visible directory");
            }
            check(refused(parent_handle.get(), L"first", descriptor) &&
                refused(parent_handle.get(), L"CON", descriptor) &&
                refused(parent_handle.get(), L"..", descriptor) &&
                refused(parent_handle.get(), L"bad/name", descriptor),
                "collision or invalid component was accepted");
            std::string file_id;
            {
                Handle file(create_file_relative_with_descriptor(
                    parent_handle.get(), L"payload.bin", descriptor));
                const char bytes[] = "staged-file";
                DWORD written = 0;
                DWORD flags = 0;
                check(WriteFile(file.get(), bytes, sizeof(bytes) - 1, &written, nullptr) != FALSE &&
                    written == sizeof(bytes) - 1 && FlushFileBuffers(file.get()) != FALSE,
                    "parent-bound file write or flush failed");
                const auto observed = observe_publisher_file_handle(file.get());
                file_id = observed.file_id;
                check(!file_id.empty() &&
                    (observed.attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
                    GetHandleInformation(file.get(), &flags) != FALSE &&
                    (flags & HANDLE_FLAG_INHERIT) == 0,
                    "relative file create did not bind a non-inheritable regular file");
            }
            std::ifstream file_contents(parent / "payload.bin", std::ios::binary);
            std::string observed_bytes;
            std::getline(file_contents, observed_bytes);
            file_contents.close();
            check(observed_bytes == "staged-file" &&
                file_refused(parent_handle.get(), L"payload.bin", descriptor) &&
                file_refused(parent_handle.get(), L"first", descriptor) &&
                file_refused(parent_handle.get(), L"CON", descriptor) &&
                file_refused(parent_handle.get(), L"..", descriptor) &&
                file_refused(parent_handle.get(), L"bad/name", descriptor) &&
                file_refused(parent_handle.get(), L"Re\u0301sume\u0301.txt", descriptor) &&
                file_refused(parent_handle.get(), L"empty", {}),
                "file collision or invalid creation input was accepted");
            {
                Handle temporary(create_file_relative_with_descriptor(
                    parent_handle.get(), L"temporary.bin", descriptor));
                FILE_DISPOSITION_INFO disposition{};
                disposition.DeleteFile = TRUE;
                check(SetFileInformationByHandle(temporary.get(),
                    FileDispositionInfo, &disposition, sizeof(disposition)) != FALSE,
                    "protected temporary file cannot be marked for deletion");
            }
            check(!fs::exists(parent / "temporary.bin"),
                "protected temporary file remained after handle close");
            {
                Handle unchanged(CreateFileW((parent / "payload.bin").c_str(),
                    FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                    OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                check(observe_publisher_file_handle(unchanged.get()).file_id == file_id,
                    "create-only collision changed the existing file identity");
            }
            {
                std::ifstream unchanged_bytes(parent / "payload.bin", std::ios::binary);
                std::string content;
                std::getline(unchanged_bytes, content);
                unchanged_bytes.close();
                check(content == "staged-file", "create-only collision changed existing bytes");
            }
            const std::wstring unicode_name = L"R\u00e9sum\u00e9.txt";
            const std::wstring long_name = std::wstring(129, L'a') + L".bin";
            {
                Handle unicode(create_file_relative_with_descriptor(
                    parent_handle.get(), unicode_name, descriptor));
                Handle long_file(create_file_relative_with_descriptor(
                    parent_handle.get(), long_name, descriptor));
                check(fs::exists(parent / unicode_name) && fs::exists(parent / long_name),
                    "canonical Unicode or long staged-file component was refused");
            }
            {
                Handle unchanged(CreateFileW((parent / "first").c_str(),
                    FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
                        FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                check(observe_publisher_directory_handle(unchanged.get()).file_id == first_id,
                    "create-only collision changed the existing directory identity");
            }
            fs::rename(parent, moved);
            check(fs::create_directory(parent), "replacement parent fixture creation failed");
            {
                Handle bound(create_directory_relative_with_descriptor(
                    parent_handle.get(), L"bound", descriptor));
                check(fs::exists(moved / "bound") && !fs::exists(parent / "bound") &&
                    observe_publisher_directory_handle(parent_handle.get()).file_id == parent_id &&
                    !observe_publisher_directory_handle(bound.get()).file_id.empty(),
                    "parent path substitution redirected handle-relative creation");
            }
            {
                Handle bound(create_file_relative_with_descriptor(
                    parent_handle.get(), L"bound.bin", descriptor));
                check(fs::exists(moved / "bound.bin") && !fs::exists(parent / "bound.bin") &&
                    !observe_publisher_file_handle(bound.get()).file_id.empty(),
                    "parent path substitution redirected handle-relative file creation");
            }
        }
        check(fs::remove(moved / "streamed.bin") &&
            fs::remove(moved / "reader.bin") &&
            fs::remove(moved / "reader-digest.bin") &&
            fs::remove(moved / "bad-digest.bin") &&
            fs::remove(source_path) &&
            fs::remove(moved / "first") && fs::remove(moved / "bound") &&
            fs::remove(moved / "payload.bin") && fs::remove(moved / "bound.bin") &&
            fs::remove(moved / L"R\u00e9sum\u00e9.txt") &&
            fs::remove(moved / (std::wstring(129, L'a') + L".bin")) &&
            fs::remove(moved) && fs::remove(parent) && fs::remove(root),
            "disposable fixture cleanup failed");
        std::cout << "Windows publisher parent-bound create-only anchor probe PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
