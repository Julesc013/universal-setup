// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_effect_broker_internal.h"
#if defined(_WIN32)
#include <filesystem>
#include <iostream>
#include <stdexcept>

namespace {
using namespace usk::platform::windows;
using usk::json::Value;
void require(bool okay, const char* reason) { if (!okay) throw std::runtime_error(reason); }
template<class Function> void refuses(Function call) {
    bool refused = false;
    try { call(); } catch (const std::exception&) { refused = true; }
    require(refused, "native query control unexpectedly accepted a different binding");
}
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE h) : value(h) { require(h && h != INVALID_HANDLE_VALUE, "ordinary native handle unavailable"); }
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    void close() {
        require(CloseHandle(value) != FALSE, "ordinary original handle did not close");
        value = INVALID_HANDLE_VALUE;
    }
};
struct Fixture {
    std::filesystem::path path;
    explicit Fixture(std::filesystem::path p) : path(std::move(p)) {
        require(CreateDirectoryW(path.c_str(), nullptr) != FALSE, "owned ordinary query fixture directory unavailable");
    }
    ~Fixture() {
        // Only the fixed files created by this fixture; no recursive cleanup.
        for (const auto* name : {L"first.bin", L"second.bin", L"renamed.bin"})
            DeleteFileW((path / name).c_str());
        RemoveDirectoryW(path.c_str());
    }
};
void controls() {
    wchar_t temporary[32768]{}, unique[32768]{}, volume_path[32768]{};
    const auto count = GetTempPathW(static_cast<DWORD>(std::size(temporary)), temporary);
    require(count && count < std::size(temporary) && GetTempFileNameW(temporary, L"usk", 0, unique),
        "owned ordinary query fixture path unavailable");
    require(DeleteFileW(unique) != FALSE, "owned ordinary query fixture seed did not retire");
    Fixture fixture{std::filesystem::path(unique)};
    require(GetVolumePathNameW(fixture.path.c_str(), volume_path, static_cast<DWORD>(std::size(volume_path))) != FALSE,
        "actual query fixture volume unavailable");
    constexpr DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    Handle root(CreateFileW(volume_path, FILE_READ_ATTRIBUTES | READ_CONTROL, share, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    Handle directory(CreateFileW(fixture.path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, share, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    Handle first(CreateFileW((fixture.path / L"first.bin").c_str(), GENERIC_READ | GENERIC_WRITE | DELETE,
        share, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    Handle second(CreateFileW((fixture.path / L"second.bin").c_str(), GENERIC_READ | GENERIC_WRITE | DELETE,
        share, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    const auto first_facts = publisher_handle_observation_json(observe_publisher_file_handle(first.value));
    const auto second_facts = publisher_handle_observation_json(observe_publisher_file_handle(second.value));
    const auto directory_facts = publisher_handle_observation_json(observe_publisher_directory_handle(directory.value));
    {
        PublisherBrokerObjectQuery query(root.value, first_facts);
        require(usk::json::canonical(query.observation()) == usk::json::canonical(first_facts) &&
            query.granted_access() == (FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE),
            "actual by-ID query differs from independently held native file/query rights");
        refuses([&] { PublisherBrokerObjectQuery simultaneous(root.value, second_facts); });
        require(usk::json::canonical(query.observation()) == usk::json::canonical(first_facts),
            "refused second query released the original query owner");
        require(query.close() && query.close(), "query close did not confirm and latch its single result");
        refuses([&] { (void)query.observation(); });
    }
    {
        PublisherBrokerObjectQuery query(root.value, directory_facts);
        require(usk::json::canonical(query.observation()) == usk::json::canonical(directory_facts) && query.close(),
            "actual directory by-ID readback did not retain its full native binding");
    }
    auto wrong_object = first_facts;
    wrong_object.as_object().at("file_id") = second_facts.at("file_id");
    refuses([&] { PublisherBrokerObjectQuery query(root.value, wrong_object); });
    auto wrong_volume = first_facts;
    auto different_id = first_facts.at("file_id").as_string();
    different_id[0] = different_id[0] == '0' ? '1' : '0';
    wrong_volume.as_object().at("file_id") = Value(different_id);
    refuses([&] { PublisherBrokerObjectQuery query(root.value, wrong_volume); });
    auto truncated_id = first_facts;
    truncated_id.as_object().at("file_id") = Value(different_id.substr(17));
    refuses([&] { PublisherBrokerObjectQuery query(root.value, truncated_id); });
    auto changed_owner = first_facts;
    changed_owner.as_object().at("owner_sid") = Value(first_facts.at("owner_sid").as_string() ==
        "S-1-5-18" ? "S-1-1-0" : "S-1-5-18");
    refuses([&] { PublisherBrokerObjectQuery query(root.value, changed_owner); });
    auto unsupported_id = first_facts;
    auto high_id = first_facts.at("file_id").as_string();
    high_id[33] = '1';
    unsupported_id.as_object().at("file_id") = Value(high_id);
    refuses([&] { PublisherBrokerObjectQuery query(root.value, unsupported_id); });
    refuses([&] { PublisherBrokerObjectQuery query(directory.value, first_facts); });
    // All failed constructors retired their observer. The exact original
    // query still succeeds and its confirmed close leaves no open descendant
    // from the broker when this genuine ordinary directory rename executes.
    {
        PublisherBrokerObjectQuery query(root.value, first_facts);
        require(query.close(), "original post-refusal native query did not close");
    }
    first.close(); second.close(); directory.close();
    auto renamed = fixture.path;
    renamed += L"-renamed";
    require(MoveFileExW(fixture.path.c_str(), renamed.c_str(), 0) != FALSE,
        "confirmed broker query closure obstructed the actual fixture root rename");
    fixture.path = renamed;
}
}
int main() {
    try { controls(); std::cout << "read-only native file-ID query controls passed; no publisher admission\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
#else
int main() { return 0; }
#endif
