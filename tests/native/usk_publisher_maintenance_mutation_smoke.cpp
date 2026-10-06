// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_maintenance_mutation.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_metadata.h"
#include "usk_publisher_installation_lease.h"
#include "usk_sha256.h"
#if defined(_WIN32)
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <vector>

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
void snapshot_bindings() {
    using usk::json::Value;
    // Synthetic closed data associations only. No service, native preimage,
    // lease, revision admission, original intent or maintenance grant is made.
    const std::string id = "fixture.install", operation_id = "fixture.maintenance";
    const std::string revision(64, 'a');
    Value ownership(Value::Object{{"schema", Value("usk.ownership_manifest.v1")},
        {"manifest_id", Value("fixture.ownership")}, {"install_id", Value(id)},
        {"target_root", Value("D:/fixture/installed")}, {"created_by_transaction_id", Value("fixture.original")},
        {"files", Value(Value::Array{Value(Value::Object{{"relative_path", Value("payload.bin")},
            {"sha256", Value(std::string(64, 'c'))}, {"size_bytes", Value(std::uint64_t{1})}})})},
        {"directories", Value(Value::Array{})}});
    ownership.as_object().emplace("manifest_digest", Value(usk::json::sha256_canonical(ownership)));
    Value installed(Value::Object{{"schema", Value("usk.installed_state.v1")},
        {"install_id", Value(id)}, {"product_id", Value("fixture.product")}, {"product_version", Value("1.0.0")},
        {"recipe_digest", Value(std::string(64, 'b'))}, {"source_archive_digest", Value(std::string(64, 'd'))},
        {"target_root", ownership.at("target_root")}, {"target_scope", Value("portable")},
        {"component_selection", Value(Value::Array{Value("core")})},
        {"ownership_manifest_ref", Value("ownership/fixture.ownership.json")},
        {"ownership_manifest_digest", ownership.at("manifest_digest")},
        {"entrypoints", Value(Value::Array{Value(Value::Object{{"entrypoint_id", Value("main")},
            {"relative_path", Value("payload.bin")}, {"kind", Value("application")}})})},
        {"setup_abi", Value(Value::Object{{"major", Value(std::uint64_t{1})}, {"minor", Value(std::uint64_t{0})},
            {"provider_revision", Value("fixture.provider")}})},
        {"transaction_id", Value("fixture.original")}, {"created_at", Value("2026-10-01T00:00:00Z")},
        {"last_verification", Value(Value::Object{{"report_id", Value("fixture.verify")},
            {"report_digest", Value(std::string(64, 'e'))}, {"status", Value("pass")},
            {"verified_at", Value("2026-10-01T00:00:00Z")}})},
        {"audit_chain_id", Value("fixture.audit")}, {"lifecycle_status", Value("verified")}});
    auto projection = installed;
    projection.as_object().erase("schema");
    projection.as_object().erase("last_verification");
    for (const auto kind : {PublisherOperationKind::repair, PublisherOperationKind::move, PublisherOperationKind::uninstall}) {
        const std::string operation = kind == PublisherOperationKind::repair ? "repair" :
            kind == PublisherOperationKind::move ? "move" : "uninstall";
        Value plan(Value::Object{{"created_at", Value("2026-10-02T00:00:00Z")},
            {"audit_root", Value("D:/fixture/setup/audit")}, {"install_id", Value(id)},
            {"installed_state_digest", Value(usk::json::sha256_canonical(projection))},
            {"operation", Value(operation)}, {"ownership_manifest_digest", ownership.at("manifest_digest")},
            {"policy_digest", Value(std::string(64, 'f'))}, {"plan_id", Value("fixture.plan")},
            {"staging_parent", Value("D:/fixture/setup/staging")}, {"state_root", Value("D:/fixture/setup/state")}});
        if (kind == PublisherOperationKind::repair) {
            plan.as_object().emplace("source_digest", Value(std::string(64, 'd')));
            plan.as_object().emplace("replacement_files", Value(Value::Array{}));
        } else if (kind == PublisherOperationKind::move) {
            plan.as_object().emplace("complete_files", Value(Value::Array{}));
            plan.as_object().emplace("old_root", installed.at("target_root"));
            plan.as_object().emplace("old_root_identity", Value("data-only-original-root"));
            plan.as_object().emplace("new_root", Value("D:/fixture/moved"));
        } else plan.as_object().emplace("verification", Value(Value::Object{}));
        const Value request(Value::Object{{"schema", Value("usk." + operation + "_apply_request.v1")},
            {"plan_request", Value(Value::Object{{"install_id", Value(id)}})},
            {"reviewed_plan_id", plan.at("plan_id")}, {"reviewed_plan_digest", Value(usk::json::sha256_canonical(plan))},
            {"transaction_id", Value(operation_id)}, {"applied_at", Value("2026-10-02T00:00:01Z")},
            {"confirmation", Value("APPLY")}});
        const auto root = [](char digit) { return Value(Value::Object{{"file_id", Value(std::string(32, digit))},
            {"volume_serial", Value("18446744073709551615")}}); };
        const Value snapshot(Value::Object{{"schema", Value("usk.publisher.maintenance_reviewed_snapshot.v1")},
            {"operation", Value(operation)}, {"install_id", Value(id)}, {"operation_id", Value(operation_id)},
            {"initial_state_revision", Value(revision)}, {"reviewed_plan", plan}, {"apply_request", request},
            {"installed_state", installed}, {"ownership_manifest", ownership},
            {"volume_root_identity", root('1')}, {"setup_root_identity", root('2')}, {"state_root_identity", root('3')},
            {"setup_component", Value("setup")}, {"installed_record", Value(id + ".fixture.original.json")},
            {"ownership_record", Value("fixture.ownership.json")}});
        require_publisher_maintenance_snapshot_binding(snapshot, kind, id, operation_id, revision);
        auto verification_only = snapshot;
        verification_only.as_object().at("installed_state").as_object().at("last_verification") = Value(Value::Object{});
        require_publisher_maintenance_snapshot_binding(verification_only, kind, id, operation_id, revision);
        const std::vector<std::function<void(Value&)>> changes{
            [](Value& x) { x.as_object().emplace("trusted", Value(true)); },
            [](Value& x) { x.as_object().at("schema") = Value("usk.publisher.maintenance_reviewed_snapshot.v2"); },
            [](Value& x) { x.as_object().at("operation") = Value("install_local"); },
            [](Value& x) { x.as_object().at("operation_id") = Value("different.operation"); },
            [](Value& x) { x.as_object().at("initial_state_revision") = Value(std::string(64, 'b')); },
            [](Value& x) { x.as_object().at("setup_component") = Value("../setup"); },
            [](Value& x) { x.as_object().at("installed_record") = Value("fixture.install.different.json"); },
            [](Value& x) { x.as_object().at("ownership_record") = Value("different.json"); },
            [](Value& x) { x.as_object().at("state_root_identity") = x.at("setup_root_identity"); },
            [](Value& x) { x.as_object().at("state_root_identity").as_object().at("volume_serial") = Value("1"); },
            [](Value& x) { x.as_object().at("volume_root_identity").as_object().at("volume_serial") = Value("018446744073709551615"); },
            [](Value& x) { x.as_object().at("installed_state").as_object().at("transaction_id") = Value("different.original"); },
            [](Value& x) { x.as_object().at("ownership_manifest").as_object().at("target_root") = Value("D:/different"); },
            [](Value& x) { x.as_object().at("apply_request").as_object().at("reviewed_plan_digest") = Value(std::string(64, '0')); },
            [](Value& x) { x.as_object().at("apply_request").as_object().at("transaction_id") = Value("different.operation"); },
            [](Value& x) { x.as_object().at("apply_request").as_object().at("confirmation") = Value("INSPECT"); },
            [](Value& x) { x.as_object().at("reviewed_plan").as_object().emplace("new_effect", Value(true)); },
        };
        for (const auto& change : changes) {
            auto altered = snapshot;
            change(altered);
            check(refuses([&] { require_publisher_maintenance_snapshot_binding(altered, kind, id, operation_id, revision); }),
                "changed original maintenance association accepted");
        }
        check(refuses([&] { require_publisher_maintenance_snapshot_binding(snapshot, PublisherOperationKind::install_local,
            id, operation_id, revision); }), "install intent accepted maintenance snapshot");
    }
}
int proof() {
    snapshot_bindings();
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
