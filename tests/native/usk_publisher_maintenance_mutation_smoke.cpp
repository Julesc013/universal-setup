// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_maintenance_mutation.h"
#include "usk_publisher_bound_rename.h"
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_metadata.h"
#include "usk_publisher_installation_lease.h"
#include "usk_native_maintenance_transaction_internal.h"
#include "usk_sha256.h"
#if defined(_WIN32)
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <aclapi.h>

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
    ~Held() { if (!close_attempted_) CloseHandle(value_); }
    Held(const Held&) = delete;
    Held& operator=(const Held&) = delete;
    HANDLE get() const { return value_; }
    void close_once() {
        check(!close_attempted_, "owned fixture observer already released");
        close_attempted_ = true;
        check(CloseHandle(value_) != FALSE, "owned fixture observer close unconfirmed");
        value_ = INVALID_HANDLE_VALUE;
    }
private:
    HANDLE value_;
    bool close_attempted_ = false;
};
Held directory(const fs::path& path, bool rename_source = false) {
    return Held(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY |
        FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | READ_CONTROL | SYNCHRONIZE |
        (rename_source ? DELETE : 0),
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
void protect_owned_object(const fs::path& path, bool directory_object) {
    Held object(CreateFileW(path.c_str(), READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | (directory_object ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr));
    auto before = directory_object ? observe_publisher_directory_handle(object.get()) : observe_publisher_file_handle(object.get());
    PSECURITY_DESCRIPTOR security = nullptr; PACL dacl = nullptr;
    check(GetSecurityInfo(object.get(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr,
        &dacl, nullptr, &security) == ERROR_SUCCESS && dacl && IsValidAcl(dacl),
        "owned protected-fixture DACL unavailable");
    const auto error = SetSecurityInfo(object.get(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
    LocalFree(security);
    check(error == ERROR_SUCCESS, "owned protected-fixture DACL update failed");
    const auto after = directory_object ? observe_publisher_directory_handle(object.get()) : observe_publisher_file_handle(object.get());
    before.dacl_protected = true;
    // Predict this fixture's protection postimage from the held preimage:
    // explicit ACEs precede the formerly inherited group, retaining each
    // group's order and every type, mask, SID and other flag exactly.
    std::stable_partition(before.dacl_aces.begin(), before.dacl_aces.end(), [](const auto& ace) {
        return (ace.flags & INHERITED_ACE) == 0;
    });
    for (auto& ace : before.dacl_aces) ace.flags &= static_cast<std::uint8_t>(~INHERITED_ACE);
    const auto expected = usk::json::canonical(publisher_handle_observation_json(before));
    const auto actual = usk::json::canonical(publisher_handle_observation_json(after));
    if (expected != actual) {
        std::cerr << "owned protection " << path.u8string() << " expected: " << expected << "\nactual: " << actual << '\n';
        throw std::runtime_error("owned fixture protection changed original identity or policy");
    }
    object.close_once();
}
void directory_publication_controls(const fs::path& root, HANDLE parent) {
    const auto parent_facts = observe_publisher_directory_handle(parent);
    const std::string bytes = "owned directory publication payload\n";
    check(!(observe_publisher_handle_granted_access(parent) & DELETE),
        "ordinary publication destination parent has DELETE access");
    const auto check_moved = [](PublisherHandleObservation before, const PublisherHandleObservation& after,
        const std::wstring& old_root, const std::wstring& new_root, const char* phase = "publication") {
        check(before.native_name.compare(0, old_root.size(), old_root) == 0,
            "owned publication preimage escaped its root");
        before.native_name.replace(0, old_root.size(), new_root);
        const auto expected = usk::json::canonical(publisher_handle_observation_json(before));
        const auto actual = usk::json::canonical(publisher_handle_observation_json(after));
        if (expected != actual) {
            std::cerr << "owned " << phase << " expected: " << expected << "\nactual: " << actual << '\n';
            throw std::runtime_error("owned publication changed original full facts");
        }
    };
    for (const bool release_descendants : {false, true}) {
        const auto source_name = release_descendants ? L"closed-descendants" : L"open-descendants";
        const auto target_name = release_descendants ? L"published-descendants" : L"denied-descendants";
        check(fs::create_directory(root / source_name) && fs::create_directory(root / source_name / L"nested"),
            "owned publication source creation failed");
        write(root / source_name / L"nested/payload.bin", bytes);
        // Protect only these exact self-created fixture objects. Their actual
        // actor, owner and permissions are retained; this is no birth admission.
        protect_owned_object(root / source_name, true);
        protect_owned_object(root / source_name / L"nested", true);
        protect_owned_object(root / source_name / L"nested/payload.bin", false);
        auto source = directory(root / source_name, true);
        Held nested(open_publisher_listed_child(source.get(), listed(source.get(), L"nested"), true, false, true));
        Held file(open_publisher_listed_maintenance_file(nested.get(), listed(nested.get(), L"payload.bin")));
        const auto source_before = observe_publisher_directory_handle(source.get());
        const auto nested_before = observe_publisher_directory_handle(nested.get());
        const auto file_before = observe_publisher_file_handle(file.get());
        if (!release_descendants) {
            bool unconfirmed = false;
            try { (void)probe_publisher_bound_rename_no_replace(source.get(), parent, target_name,
                source_before, parent_facts); }
            catch (const PublisherRenameUnconfirmed&) { unconfirmed = true; }
            check(unconfirmed && directory_facts(parent, source_name).file_id == source_before.file_id &&
                !fs::exists(root / target_name) && file_facts(nested.get(), L"payload.bin").file_id == file_before.file_id,
                "open descendant rename did not retain the observed source/absent target");
            // This finite owned negative fixture is never retried or adopted as
            // production recovery. Its actual unchanged namespace is observed.
            file.close_once(); nested.close_once(); source.close_once();
            auto cleanup = directory(root / source_name);
            { auto child = directory(root / source_name / L"nested"); remove_file(child.get(), L"payload.bin", bytes); }
            const auto removed = remove_publisher_bound_empty_directory(cleanup.get(), L"nested",
                directory_facts(cleanup.get(), L"nested"), observe_publisher_directory_handle(cleanup.get()));
            check(removed.absence_confirmed, "owned negative nested cleanup retained");
            cleanup.close_once();
        } else {
            file.close_once(); nested.close_once();
            const auto result = probe_publisher_bound_rename_no_replace(source.get(), parent, target_name,
                source_before, parent_facts);
            const auto source_after = observe_publisher_directory_handle(source.get());
            check(result.native_status == 0 && result.io_status == 0, "closed descendant publication unconfirmed");
            check_moved(source_before, source_after, source_before.native_name, source_after.native_name);
            // Bridge the exact root before releasing its original DELETE owner.
            Held visible(open_publisher_listed_child(parent, listed(parent, target_name), true, false, true));
            check_moved(source_before, observe_publisher_directory_handle(visible.get()),
                source_before.native_name, source_after.native_name);
            source.close_once();
            check(!(observe_publisher_handle_granted_access(visible.get()) & DELETE),
                "published root parent observer retained DELETE");
            Held child(open_publisher_listed_child(visible.get(), listed(visible.get(), L"nested"), true, false, true));
            Held payload(open_publisher_listed_maintenance_file(child.get(), listed(child.get(), L"payload.bin")));
            check_moved(nested_before, observe_publisher_directory_handle(child.get()), source_before.native_name, source_after.native_name);
            check_moved(file_before, observe_publisher_file_handle(payload.get()), source_before.native_name, source_after.native_name,
                "reopened payload");
            // A separate exact ACL observer obtains the right on the handle;
            // existing descriptor permission alone does not confer WRITE_DAC.
            check(!(observe_publisher_handle_granted_access(payload.get()) & WRITE_DAC),
                "ordinary payload observer unexpectedly has WRITE_DAC");
            Held acl(open_publisher_listed_child(child.get(), listed(child.get(), L"payload.bin"), false, false, false, true));
            const auto access = observe_publisher_handle_granted_access(acl.get());
            check((access & WRITE_DAC) && !(access & DELETE), "ordinary exact ACL observer has incorrect access");
            check_moved(file_before, observe_publisher_file_handle(acl.get()), source_before.native_name, source_after.native_name,
                "ACL preimage");
            PSECURITY_DESCRIPTOR security = nullptr; PACL dacl = nullptr;
            check(GetSecurityInfo(acl.get(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr,
                &dacl, nullptr, &security) == ERROR_SUCCESS && dacl && IsValidAcl(dacl),
                "owned ACL preimage unavailable");
            const auto error = SetSecurityInfo(acl.get(), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr, nullptr, dacl, nullptr);
            LocalFree(security);
            check(error == ERROR_SUCCESS, "owned exact ACL observer could not set its unchanged DACL");
            acl.close_once();
            check_moved(file_before, observe_publisher_file_handle(payload.get()), source_before.native_name, source_after.native_name,
                "ACL postimage");
            const auto moved = rename_publisher_bound_file_no_replace(payload.get(), child.get(), L"payload.bin",
                visible.get(), L"payload.bin", observe_publisher_file_handle(payload.get()),
                observe_publisher_directory_handle(child.get()), observe_publisher_directory_handle(visible.get()), bytes.size(), hash(bytes));
            check(moved.file_id == file_before.file_id, "published parent file rename changed original identity");
            payload.close_once(); child.close_once();
            remove_file(visible.get(), L"payload.bin", bytes);
            const auto removed = remove_publisher_bound_empty_directory(visible.get(), L"nested",
                directory_facts(visible.get(), L"nested"), observe_publisher_directory_handle(visible.get()));
            check(removed.absence_confirmed, "owned positive nested cleanup retained");
            visible.close_once();
        }
        const auto final_name = release_descendants ? target_name : source_name;
        const auto removed = remove_publisher_bound_empty_directory(parent, final_name,
            directory_facts(parent, final_name), parent_facts);
        check(removed.absence_confirmed, "owned publication fixture directory cleanup retained");
    }
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
        auto complete_snapshot = snapshot;
        Value bindings(Value::Array{
            Value(Value::Object{{"record", Value(id + ".fixture.original.json")},
                {"sha256", Value(usk::json::sha256_canonical(installed))}}),
            Value(Value::Object{{"record", Value(id + ".fixture.previous.json")},
                {"sha256", Value(std::string(64, '9'))}})});
        const auto complete_revision = usk::json::sha256_canonical(bindings);
        complete_snapshot.as_object().at("schema") = Value("usk.publisher.maintenance_reviewed_snapshot.v2");
        complete_snapshot.as_object().at("initial_state_revision") = Value(complete_revision);
        complete_snapshot.as_object().emplace("installed_record_bindings", bindings);
        require_publisher_maintenance_snapshot_binding(complete_snapshot, kind, id, operation_id, complete_revision);
        // Record-set derivation is data-only. The native owner separately pins
        // the original pending effect and actual protected creation/publication.
        auto postimage = installed;
        postimage.as_object().at("transaction_id") = Value(operation_id);
        postimage.as_object().at("created_at") = request.at("applied_at");
        const auto after_bindings = derive_publisher_maintenance_postimage_bindings(complete_snapshot, postimage);
        check(after_bindings.as_array().size() == 3 && after_bindings.as_array().front().at("record").as_string() ==
            id + "." + operation_id + ".json", "derived create-only installed bindings are not complete and ordered");
        for (const auto& original : bindings.as_array()) {
            const auto found = std::find_if(after_bindings.as_array().begin(), after_bindings.as_array().end(),
                [&](const auto& item) { return item.at("record").as_string() == original.at("record").as_string(); });
            check(found != after_bindings.as_array().end() && usk::json::canonical(*found) == usk::json::canonical(original),
                "postimage derivation replaced an original installed binding");
        }
        auto different_verification = postimage;
        different_verification.as_object().at("last_verification").as_object().at("report_digest") = Value(std::string(64, '7'));
        check(usk::json::sha256_canonical(after_bindings) != usk::json::sha256_canonical(
            derive_publisher_maintenance_postimage_bindings(complete_snapshot, different_verification)),
            "full installed revision omitted verification bytes");
        for (const auto& change : std::vector<std::function<void(Value&)>>{
                [](Value& x) { x.as_object().at("product_id") = Value("unrelated.product"); },
                [](Value& x) { x.as_object().at("transaction_id") = Value("unrelated.transaction"); },
                [](Value& x) { x.as_object().at("created_at") = Value("2026-10-02T00:00:02Z"); },
                [](Value& x) { x.as_object().emplace("trusted", Value(true)); }}) {
            auto changed = postimage; change(changed);
            check(refuses([&] { (void)derive_publisher_maintenance_postimage_bindings(complete_snapshot, changed); }),
                "postimage bindings adopted unrelated or changed original data");
        }
        check(refuses([&] { (void)derive_publisher_maintenance_postimage_bindings(snapshot, postimage); }),
            "legacy digest-only snapshot granted a derived installed revision");
        auto occupied = complete_snapshot;
        auto occupied_bindings = after_bindings;
        occupied.as_object().at("installed_record_bindings") = occupied_bindings;
        occupied.as_object().at("initial_state_revision") = Value(usk::json::sha256_canonical(occupied_bindings));
        check(refuses([&] { (void)derive_publisher_maintenance_postimage_bindings(occupied, postimage); }),
            "derived create-only installed postimage replaced an occupied record");
        const std::vector<std::function<void(Value&)>> binding_changes{
            [](Value& x) { x.as_object().erase("installed_record_bindings"); },
            [](Value& x) { x.as_object().at("installed_record_bindings") = Value(Value::Array{}); },
            [](Value& x) { auto& b = x.as_object().at("installed_record_bindings").as_array(); b.push_back(b.front()); },
            [](Value& x) { auto& b = x.as_object().at("installed_record_bindings").as_array(); std::swap(b.front(), b.back()); },
            [](Value& x) { x.as_object().at("installed_record_bindings").as_array().front().as_object().at("sha256") = Value(std::string(64, '0')); },
            [](Value& x) { x.as_object().at("installed_record_bindings").as_array().front().as_object().at("record") = Value("unrelated.install.fixture.original.json"); },
            [](Value& x) { x.as_object().at("installed_record_bindings").as_array().back().as_object().at("record") = Value("fixture.install...json"); },
            [](Value& x) { x.as_object().at("installed_record_bindings").as_array().back().as_object().emplace("trusted", Value(true)); },
            [](Value& x) { x.as_object().at("installed_state").as_object().at("last_verification") = Value(Value::Object{}); },
        };
        for (const auto& change : binding_changes) {
            auto altered = complete_snapshot;
            change(altered);
            check(refuses([&] { require_publisher_maintenance_snapshot_binding(altered, kind, id, operation_id, complete_revision); }),
                "changed complete original installed record set accepted");
            // Also recompute the data checksum so ordering, names, selected
            // bytes and closed fields are tested independently of that hash.
            if (altered.contains("installed_record_bindings")) {
                const auto changed_revision = usk::json::sha256_canonical(altered.at("installed_record_bindings"));
                altered.as_object().at("initial_state_revision") = Value(changed_revision);
                check(refuses([&] { require_publisher_maintenance_snapshot_binding(altered, kind, id, operation_id, changed_revision); }),
                    "self-consistent malformed original record bindings accepted");
            }
        }
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
void transaction_origin_lifetimes() {
    // These are inert identity tokens. They exercise the lifetime association
    // only; they cannot construct a native adapter or grant native authority.
    using usk::transaction::detail::require_native_maintenance_origin_binding;
    const std::weak_ptr<const void> absent;
    auto first = std::make_shared<const unsigned char>(static_cast<unsigned char>(0));
    const std::weak_ptr<const void> original = first;
    require_native_maintenance_origin_binding(true, original, original);
    check(refuses([&] { require_native_maintenance_origin_binding(true, original, absent); }),
        "native-origin transaction accepted missing active owner");
    auto other = std::make_shared<const unsigned char>(static_cast<unsigned char>(0));
    check(refuses([&] { require_native_maintenance_origin_binding(true, original, other); }),
        "native-origin transaction adopted a different live owner");
    first.reset();
    check(refuses([&] { require_native_maintenance_origin_binding(true, original, original); }),
        "native-origin transaction accepted its expired owner");
    check(refuses([&] { require_native_maintenance_origin_binding(true, original, other); }),
        "expired native origin adopted a replacement owner");

    // Independent lifetimes can refer to exactly the same address. Comparing
    // raw callback/owner addresses would incorrectly admit this replacement.
    const unsigned char reused_address = 0;
    const auto no_delete = [](const void*) {};
    const std::shared_ptr<const void> lifetime_one(&reused_address, no_delete);
    const std::shared_ptr<const void> lifetime_two(&reused_address, no_delete);
    check(lifetime_one.get() == lifetime_two.get(), "same-address identity control differs");
    check(refuses([&] { require_native_maintenance_origin_binding(true, lifetime_one, lifetime_two); }),
        "native-origin transaction accepted reused-address replacement lifetime");
    require_native_maintenance_origin_binding(false, absent, absent);
    require_native_maintenance_origin_binding(false, absent, original);
    check(refuses([&] { require_native_maintenance_origin_binding(false, absent, other); }),
        "ordinary-origin transaction adopted an active native owner");
}
int proof() {
    transaction_origin_lifetimes();
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
        directory_publication_controls(root, bound_root.get());
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
