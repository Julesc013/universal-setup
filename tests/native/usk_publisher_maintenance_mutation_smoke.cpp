// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_maintenance_mutation.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_metadata.h"
#include "usk_sha256.h"
#if defined(_WIN32)
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace usk::platform::windows;
namespace {
void check(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
}
class Held {
public:
    explicit Held(HANDLE value) : value_(value) {
        check(value && value != INVALID_HANDLE_VALUE, "owned fixture handle open failed");
    }
    ~Held() { CloseHandle(value_); }
    Held(const Held&) = delete;
    Held& operator=(const Held&) = delete;
    HANDLE get() const { return value_; }
private:
    HANDLE value_;
};
Held directory(const fs::path& path) {
    return Held(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY |
        FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | READ_CONTROL | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
}
PublisherDirectoryEntry listed(HANDLE parent, const std::wstring& name) {
    for (const auto& entry : observe_publisher_directory_entries(parent))
        if (entry.name == name) return entry;
    throw std::runtime_error("owned fixture child absent");
}
PublisherHandleObservation file_facts(HANDLE parent, const std::wstring& name) {
    Held file(open_publisher_listed_child(parent, listed(parent, name)));
    return observe_publisher_file_handle(file.get());
}
PublisherHandleObservation directory_facts(HANDLE parent, const std::wstring& name) {
    Held child(open_publisher_listed_child(parent, listed(parent, name)));
    return observe_publisher_directory_handle(child.get());
}
std::string hash(const std::string& bytes) {
    usk::base::Sha256 digest;
    digest.update(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    return digest.finish();
}
void write(const fs::path& path, const std::string& bytes) {
    check(!fs::exists(path), "owned fixture file already exists");
    std::ofstream output(path, std::ios::binary);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    output.close();
    check(!output.fail(), "owned fixture file write failed");
}
bool refuses(const std::function<void()>& action) {
    try { action(); }
    catch (const PublisherRenameUnconfirmed&) { return false; }
    catch (const PublisherRemovalUnconfirmed&) { return false; }
    catch (const std::exception&) { return true; }
    return false;
}
void remove_file(HANDLE parent, const std::wstring& name, const std::string& bytes) {
    const auto file = file_facts(parent, name);
    const auto result = remove_publisher_bound_file(parent, name, file,
        observe_publisher_directory_handle(parent), bytes.size(), hash(bytes));
    check(result.native_call_attempted && result.absence_confirmed &&
        result.object_file_id == file.file_id && result.native_status == 0 && result.io_status == 0,
        "owned file removal lacked native identity/absence confirmation");
}
int proof() {
    const fs::path root = fs::temp_directory_path() /
        ("usk-maintenance-mutation-" + std::to_string(GetCurrentProcessId()) + "-" +
            std::to_string(GetTickCount64()));
    check(fs::create_directory(root), "owned fixture root already exists");
    // Failure retains this finite fixture for inspection. Cleanup is exact,
    // non-recursive and follows successful bound removal of all created data.
    std::cerr << "ordinary native mutation fixture: " << root.u8string() << '\n';
    check(fs::create_directory(root / L"source") && fs::create_directory(root / L"destination"),
        "owned fixture parents unavailable");
    const std::string original = "owned original payload\n", second = "owned second payload\n";
    write(root / L"source/original.bin", original);
    {
        auto bound_root = directory(root);
        auto source = directory(root / L"source");
        auto destination = directory(root / L"destination");
        const auto root_id = observe_publisher_directory_handle(bound_root.get()).file_id;
        const auto source_facts = observe_publisher_directory_handle(source.get());
        const auto destination_facts = observe_publisher_directory_handle(destination.get());
        unsigned fence_checks = 0;
        const std::function<void()> fence = [&] {
            ++fence_checks;
            check(observe_publisher_directory_handle(bound_root.get()).file_id == root_id,
                "owned fixture root changed under its test fence");
        };
        {
            Held file(open_publisher_listed_maintenance_file(source.get(), listed(source.get(), L"original.bin")));
            const auto before = observe_publisher_file_handle(file.get());
            check(refuses([&] { (void)rename_publisher_bound_file_no_replace(file.get(),
                source.get(), L"original.bin", destination.get(), L"original.bin", before,
                source_facts, destination_facts, original.size(), hash(original)); }),
                "missing active operation fence admitted a rename");
            check(file_facts(source.get(), L"original.bin").file_id == before.file_id &&
                observe_publisher_directory_entries(destination.get()).empty(),
                "missing-fence refusal changed the fixture namespace");
            ScopedPublisherEffectFence scope(fence);
            const auto result = rename_publisher_bound_file_no_replace(file.get(), source.get(),
                L"original.bin", destination.get(), L"original.bin", before,
                source_facts, destination_facts, original.size(), hash(original));
            check(result.file_id == before.file_id && result.sha256 == hash(original) &&
                result.size_bytes == original.size() && result.native_status == 0 && result.io_status == 0 &&
                result.native_call_end_tick >= result.native_call_start_tick && result.clock_frequency > 0 &&
                result.destination_parent_file_id == destination_facts.file_id &&
                result.source_parent_file_id == source_facts.file_id &&
                observe_publisher_directory_entries(source.get()).empty() &&
                file_facts(destination.get(), L"original.bin").file_id == before.file_id,
                "owned no-replace rename changed bytes/identity or failed its namespace postimage");
        }
        ScopedPublisherEffectFence scope(fence);
        write(root / L"source/second.bin", second);
        {
            Held file(open_publisher_listed_maintenance_file(source.get(), listed(source.get(), L"second.bin")));
            const auto before = observe_publisher_file_handle(file.get());
            const auto occupied = file_facts(destination.get(), L"original.bin");
            check(refuses([&] { (void)rename_publisher_bound_file_no_replace(file.get(), source.get(),
                L"second.bin", destination.get(), L"original.bin", before,
                source_facts, destination_facts, second.size(), hash(second)); }),
                "occupied owned destination was replaced");
            check(file_facts(source.get(), L"second.bin").file_id == before.file_id &&
                file_facts(destination.get(), L"original.bin").file_id == occupied.file_id,
                "occupied destination refusal changed either owned file");
        }
        remove_file(source.get(), L"second.bin", second);
        remove_file(destination.get(), L"original.bin", original);
        write(root / L"source/empty.bin", "");
        {
            Held file(open_publisher_listed_maintenance_file(source.get(), listed(source.get(), L"empty.bin")));
            const auto before = observe_publisher_file_handle(file.get());
            const auto result = rename_publisher_bound_file_no_replace(file.get(), source.get(),
                L"empty.bin", destination.get(), L"empty.bin", before,
                source_facts, destination_facts, 0, hash(""));
            check(result.file_id == before.file_id && result.size_bytes == 0,
                "empty owned file rename lost its original identity");
        }
        remove_file(destination.get(), L"empty.bin", "");
        check(fs::create_directory(root / L"destination/kept"), "owned retained directory creation failed");
        write(root / L"destination/kept/fixture.bin", original);
        const auto kept = directory_facts(destination.get(), L"kept");
        const auto retained = remove_publisher_bound_empty_directory(destination.get(), L"kept",
            kept, destination_facts);
        check(!retained.native_call_attempted && !retained.absence_confirmed &&
            directory_facts(destination.get(), L"kept").file_id == kept.file_id,
            "nonempty owned directory was removed or called deletion");
        {
            auto child = directory(root / L"destination/kept");
            remove_file(child.get(), L"fixture.bin", original);
        }
        const auto removed = remove_publisher_bound_empty_directory(destination.get(), L"kept",
            kept, destination_facts);
        check(removed.native_call_attempted && removed.absence_confirmed &&
            removed.object_file_id == kept.file_id, "bound empty directory removal was not confirmed");
        check(fence_checks > 0, "ordinary native fixture omitted operation fence checks");
    }
    {
        auto parent = directory(root);
        const auto parent_facts = observe_publisher_directory_handle(parent.get());
        const std::function<void()> fence = [&] {
            check(observe_publisher_directory_handle(parent.get()).file_id == parent_facts.file_id,
                "fixture root changed during exact empty parent cleanup");
        };
        ScopedPublisherEffectFence scope(fence);
        for (const auto* name : {L"source", L"destination"}) {
            const auto result = remove_publisher_bound_empty_directory(parent.get(), name,
                directory_facts(parent.get(), name), parent_facts);
            check(result.native_call_attempted && result.absence_confirmed, "empty fixture parent retained");
        }
    }
    check(fs::remove(root), "empty owned fixture root retained");
    std::cout << "owned file rename/removal, empty file, no-replace collision, nonempty retention and missing-fence controls passed\n";
    return 0;
}
}
int main() {
    try { return proof(); }
    catch (const std::exception& failure) { std::cerr << failure.what() << '\n'; return 1; }
}
#else
int main() { return 0; }
#endif
