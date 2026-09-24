// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_json.h"
#include "usk_record_io.h"
#include "usk_sha256.h"
#include "usk_stable_file.h"
#include "usk_transaction_session.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace fs = std::filesystem;
namespace tx = usk::transaction;
using usk::json::Value;
namespace {
std::string read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot read regression fixture");
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
std::string identity(const fs::path& path) {
    usk::base::StableFile file(path);
    return file.identity().volume_id + ":" + file.identity().file_id;
}
std::string digest(const std::string& bytes) {
    usk::base::Sha256 hash;
    hash.update(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    return hash.finish();
}
} // namespace

int original_publication_regression() {
    try {
        const fs::path root = fs::temp_directory_path() /
            ("usk-ca-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        if (!fs::create_directory(root)) throw std::runtime_error("regression fixture already exists");
        // Preserve this newly created disposable fixture for the failing oracle's raw custody.
        for (const char* name : {"stage", "target", "state/transactions", "audit"}) {
            fs::create_directories(root / name);
        }
        const tx::TransactionSpec spec{"tx", "plan", std::string(64, 'a'), "install_local",
            root / "stage", root / "target/new", root / "state", root / "audit"};
        tx::TransactionSession session(spec);
        const std::string bytes = "same-byte staged payload\n";
        std::size_t offset = 0;
        session.stage_file_stream("child/payload.bin", bytes.size(), digest(bytes), 4096,
            [&](unsigned char* output, std::size_t capacity) {
                const auto count = std::min(capacity, bytes.size() - offset);
                std::copy_n(bytes.data() + offset, count, output);
                offset += count;
                return count;
            });
        session.mark_staged();
        session.mark_verified();
        const fs::path staged = session.staging_root() / "child/payload.bin";
        const auto verified_journal = read(session.journal_path());
        usk::record_io::write_new_durable_text(root / "verified.journal.json", verified_journal);
        const auto document = usk::json::parse(verified_journal);
        const auto recorded_identity = document.at("recovery_metadata").at("stream_journal")
            .at("entries").as_array().at(0).at("output_identity").as_string();
        const auto original_identity = identity(staged);
        if (recorded_identity != original_identity || session.current_state() != "verified") {
            throw std::runtime_error("verified fixture does not bind the original output object");
        }
        const fs::path original_outside = root / "original.bin";
        fs::rename(staged, original_outside);
        usk::record_io::write_new_durable_text(staged, bytes);
        const auto replacement_identity = identity(staged);
        if (original_identity == replacement_identity || read(staged) != read(original_outside)) {
            throw std::runtime_error("replacement must be a distinct object with identical bytes");
        }
        bool returned = false;
        std::string error;
        try { session.commit(); returned = true; }
        catch (const std::exception& failure) { error = failure.what(); }
        const fs::path published = session.target_root() / "child/payload.bin";
        const auto published_identity = fs::exists(published) ? identity(published) : std::string{};
        const bool foreign_published = published_identity == replacement_identity;
        const bool claimed_replacement = foreign_published && returned && session.current_state() == "completed";
        const auto final_journal = read(session.journal_path());
        usk::record_io::write_new_durable_text(root / "final.journal.json", final_journal);
        const auto final_document = usk::json::parse(final_journal);
        const auto final_recorded_identity = final_document.at("recovery_metadata").at("stream_journal")
            .at("entries").as_array().at(0).at("output_identity").as_string();
        Value result(Value::Object{
            {"schema", Value("usk.staged_child_publication_regression.v1")},
            {"fixture_root", Value(root.generic_u8string())},
            {"original_identity", Value(original_identity)},
            {"replacement_identity", Value(replacement_identity)},
            {"recorded_identity_before", Value(recorded_identity)},
            {"recorded_identity_after", Value(final_recorded_identity)},
            {"published_identity", Value(published_identity)},
            {"identical_bytes", Value(read(original_outside) == bytes && (!fs::exists(published) || read(published) == bytes))},
            {"original_preserved_outside_staging", Value(identity(original_outside) == original_identity)},
            {"commit_returned", Value(returned)}, {"commit_exception", Value(error)},
            {"transaction_state", Value(session.current_state())},
            {"foreign_object_published", Value(foreign_published)},
            {"transaction_claimed_replacement", Value(claimed_replacement)},
            {"assertion", Value("commit must not publish or claim ownership of an identical-byte replacement")},
            {"assertion_passed", Value(!foreign_published && !claimed_replacement)}});
        std::cout << usk::json::canonical(result) << '\n';
        if (claimed_replacement) return 151;
        if (foreign_published) return 152;
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << "regression fixture failure: " << failure.what() << '\n';
        return 250;
    }
}


namespace {
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
void replace_fixture_journal(const fs::path& path, const std::string& text) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc); output << text;
    check(static_cast<bool>(output), "fixture journal replacement failed");
}
struct Fixture {
    fs::path root = fs::temp_directory_path() /
        ("usk-cb-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    tx::TransactionSpec spec;
    explicit Fixture(bool strict = false) {
        check(fs::create_directory(root), "fresh fixture required");
        for (const char* name : {"stage", "target", "state/transactions", "audit"}) fs::create_directories(root / name);
        spec = {"tx", "plan", std::string(64, 'a'), "install_local",
            root / "stage", root / "target/new", root / "state", root / "audit",
            strict ? tx::CommitAuthorityRequirement::staged_child_bound_v1 : tx::CommitAuthorityRequirement::legacy_observed};
    }
    // Retain only these exclusively created disposable fixtures as evidence.
};
void stage(tx::TransactionSession& session, bool stream) {
    const std::string bytes = "same-byte staged payload\n";
    if (stream) {
        std::size_t offset = 0;
        session.stage_file_stream("child/payload.bin", bytes.size(), digest(bytes), 4096,
            [&](unsigned char* output, std::size_t capacity) {
                const auto count = std::min(capacity, bytes.size() - offset);
                std::copy_n(bytes.data() + offset, count, output); offset += count; return count;
            });
    } else session.stage_file("child/payload.bin", {bytes.begin(), bytes.end()});
    session.mark_staged(); session.mark_verified();
}
void retained(const tx::TransactionSpec& spec, const fs::path& root) {
    const auto before = identity(root / "child/payload.bin");
    const auto observation = tx::TransactionSession::inspect_recovery(spec);
    check(observation.available_actions == std::vector<std::string>{"retain_for_operator"}, "inspection must only retain");
    bool refused = false;
    try { auto session = tx::TransactionSession::resume_rollback(spec); session->rollback(); }
    catch (const std::exception&) { refused = true; }
    check(refused && before == identity(root / "child/payload.bin"), "reopened rollback changed retained child");
}
void legacy_success() {
    for (bool stream : {false, true}) {
        Fixture fixture; tx::TransactionSession session(fixture.spec); stage(session, stream);
        const auto original = identity(session.staging_root() / "child/payload.bin"); session.commit();
        check(session.current_state() == "completed" &&
            identity(session.target_root() / "child/payload.bin") == original, "legacy valid commit failed");
    }
}
void changed_closure() {
    for (int change = 0; change != 5; ++change) {
        Fixture fixture; fs::path staged_root;
        {
            tx::TransactionSession session(fixture.spec); stage(session, false); staged_root = session.staging_root();
            const auto path = staged_root / "child/payload.bin";
            if (change <= 1) {
                const auto bytes = read(path); fs::rename(path, fixture.root / "original.bin");
                usk::record_io::write_new_durable_text(path, change == 0 ? bytes : "changed\n");
                check(identity(path) != identity(fixture.root / "original.bin"), "replacement reused original identity");
            } else if (change == 2) {
                usk::record_io::write_new_durable_text(staged_root / "extra.bin", "foreign\n");
            } else if (change == 3) {
                fs::create_directory(staged_root / "extra");
            } else {
                const auto old_id = tx::observe_directory_identity(staged_root / "child");
                fs::rename(staged_root / "child", fixture.root / "old-child");
                fs::create_directory(staged_root / "child");
                fs::rename(fixture.root / "old-child/payload.bin", path);
                check(old_id != tx::observe_directory_identity(staged_root / "child"), "directory replacement reused identity");
            }
            bool refused = false; try { session.commit(); } catch (const std::exception&) { refused = true; }
            check(refused && !fs::exists(session.target_root()) && session.current_state() == "recovery_required", "changed closure was published");
            const auto journal = usk::json::parse(read(session.journal_path()));
            check(journal.at("recovery_metadata").at("commit_cleanup_policy").as_string() == "retain_only" &&
                journal.at("recovery_metadata").at("staging_identity").type() == Value::Type::null_value, "refusal lost durable retention");
            refused = false; try { session.rollback(); } catch (const std::exception&) { refused = true; }
            check(refused && fs::exists(path), "live rollback deleted retained content");
        }
        retained(fixture.spec, staged_root);
    }
}
void strict_refusal() {
    Fixture fixture(true); fs::path staged_root, journal_path;
    {
        bool observation_hook = false;
        tx::TransactionSession session(fixture.spec, [&](const std::string&, const std::string& point) {
            if (point == "after_commit_preparation_observation") observation_hook = true;
        });
        stage(session, false); staged_root = session.staging_root(); journal_path = session.journal_path();
        bool typed = false; try { session.commit(); } catch (const tx::CommitAuthorityUnavailable&) { typed = true; }
        check(typed && !observation_hook && !fs::exists(session.target_root()), "strict mode fell back to observation/rename");
        const auto journal = usk::json::parse(read(journal_path));
        check(journal.at("required_commit_authority").as_string() == "staged_child_bound_v1", "journal lost requirement");
        bool refused = false; try { session.rollback(); } catch (const std::exception&) { refused = true; }
        check(refused && fs::exists(staged_root / "child/payload.bin"), "strict live rollback lost child");
    }
    retained(fixture.spec, staged_root);
    auto legacy = fixture.spec; legacy.required_commit_authority = tx::CommitAuthorityRequirement::legacy_observed;
    bool refused = false; try { (void)tx::TransactionSession::inspect_recovery(legacy); } catch (const std::exception&) { refused = true; }
    check(refused, "reopen silently downgraded explicit requirement");
    const auto original = usk::json::parse(read(journal_path));
    for (int change = 0; change != 3; ++change) {
        auto journal = original;
        if (change == 0) journal.as_object()["required_commit_authority"] = Value("unknown");
        if (change == 1) journal.as_object()["recovery_metadata"].as_object()["commit_cleanup_policy"] = Value(true);
        if (change == 2) journal.as_object()["recovery_metadata"].as_object()["commit_cleanup_policy"] = Value("delete");
        replace_fixture_journal(journal_path, usk::json::canonical(journal));
        refused = false; try { (void)tx::TransactionSession::inspect_recovery(fixture.spec); } catch (const std::exception&) { refused = true; }
        check(refused && fs::exists(staged_root / "child/payload.bin"), "malformed authority metadata was admitted");
    }
    auto old_reader = original;
    old_reader.as_object().erase("required_commit_authority");
    old_reader.as_object()["recovery_metadata"].as_object().erase("commit_cleanup_policy");
    replace_fixture_journal(journal_path, usk::json::canonical(old_reader));
    retained(legacy, staged_root); // Null identity refuses even when new markers are ignored/erased.
}
void interrupted_preparation_retains() {
    Fixture fixture; fs::path staged_root;
    {
        tx::TransactionSession session(fixture.spec, [&](const std::string& state, const std::string& point) {
            if (state == "committing" && point == "before_journal") throw std::runtime_error("interrupted before committing journal");
        });
        stage(session, false); staged_root = session.staging_root();
        bool interrupted = false; try { session.commit(); } catch (const std::exception&) { interrupted = true; }
        check(interrupted && session.current_state() == "verified" && !fs::exists(session.target_root()), "preparation interruption effect mismatch");
    }
    retained(fixture.spec, staged_root);
}
void strict_visible_target_cannot_finalize() {
    Fixture fixture(true); tx::TransactionSession session(fixture.spec); stage(session, false);
    try { session.commit(); } catch (const tx::CommitAuthorityUnavailable&) {}
    // Only this disposable fixture is moved. Existence cannot manufacture the unavailable capability.
    fs::rename(session.staging_root(), session.target_root());
    const auto journal = read(session.journal_path());
    bool refused = false;
    try { session.resume_committing(); } catch (const tx::CommitAuthorityUnavailable&) { refused = true; }
    check(refused && session.current_state() == "recovery_required", "strict native finalization bypassed refusal");
    refused = false;
    try { (void)tx::TransactionSession::resume_finalization(fixture.spec); }
    catch (const tx::CommitAuthorityUnavailable&) { refused = true; }
    check(refused && read(session.journal_path()) == journal, "reopen minted strict finalization authority");
    check(tx::TransactionSession::inspect_recovery(fixture.spec).available_actions ==
        std::vector<std::string>{"retain_for_operator"}, "strict visible target advertised completion");
}
void structural_bounds() {
    Fixture fixture;
    std::vector<tx::CommitClosureFile> too_many(tx::maximum_commit_closure_entries + 1u);
    bool refused = false;
    try { (void)tx::observe_commit_closure(fixture.root / "absent", too_many); }
    catch (const std::runtime_error& error) { refused = std::string(error.what()).find("entry budget") != std::string::npos; }
    check(refused, "closure count was not bounded before filesystem observation");
    fs::path path;
    for (std::size_t index = 0; index <= tx::maximum_commit_closure_depth; ++index) path /= "x";
    refused = false;
    try { (void)tx::observe_commit_closure(fixture.root / "absent", {{path, std::string(64, 'a'), 0, {}}}); }
    catch (const std::runtime_error& error) { refused = std::string(error.what()).find("depth") != std::string::npos; }
    check(refused, "closure depth was not bounded before filesystem observation");
}
#if defined(_WIN32)
void windows_bound_rename_probe() {
    const fs::path root = fs::temp_directory_path() /
        ("usk-bound-rename-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    check(fs::create_directory(root), "bound rename probe requires fresh disposable root");
    const fs::path stage = root / "stage";
    const fs::path parent = root / "parent";
    fs::create_directory(stage);
    fs::create_directory(parent);

    // Keep the Win32 RootDirectory observation executable. This is a
    // disposable comparison, never a fallback for the bound native call.
    const fs::path win32_source = stage / "win32-source";
    fs::create_directory(win32_source);
    usk::record_io::write_new_durable_text(win32_source / "payload.bin", "win32 probe\n");
    const auto win32_file = identity(win32_source / "payload.bin");
    HANDLE win32_source_handle = CreateFileW(win32_source.c_str(), DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    HANDLE win32_parent_handle = CreateFileW(parent.c_str(), FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    check(win32_source_handle != INVALID_HANDLE_VALUE &&
        win32_parent_handle != INVALID_HANDLE_VALUE,
        "cannot open disposable Win32 RootDirectory comparison handles");
    const std::wstring win32_name = L"win32-visible";
    const std::size_t win32_bytes = offsetof(FILE_RENAME_INFO, FileName) +
        (win32_name.size() + 1) * sizeof(WCHAR);
    std::vector<std::max_align_t> win32_buffer(
        (win32_bytes + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t));
    auto* win32_info = reinterpret_cast<FILE_RENAME_INFO*>(win32_buffer.data());
    win32_info->ReplaceIfExists = FALSE;
    win32_info->RootDirectory = win32_parent_handle;
    win32_info->FileNameLength = static_cast<DWORD>(win32_name.size() * sizeof(WCHAR));
    std::memcpy(win32_info->FileName, win32_name.c_str(),
        (win32_name.size() + 1) * sizeof(WCHAR));
    const BOOL win32_applied = SetFileInformationByHandle(win32_source_handle, FileRenameInfo,
        win32_info, static_cast<DWORD>(win32_bytes));
    const DWORD win32_error = win32_applied ? ERROR_SUCCESS : GetLastError();
    CloseHandle(win32_source_handle);
    CloseHandle(win32_parent_handle);
    if (win32_applied) {
        check(identity(parent / "win32-visible/payload.bin") == win32_file,
            "Win32 RootDirectory comparison moved the wrong object");
        std::cout << "Windows Win32 RootDirectory comparison: applied\n";
    } else {
        check(win32_error == ERROR_INVALID_PARAMETER &&
            identity(win32_source / "payload.bin") == win32_file &&
            !fs::exists(parent / "win32-visible"),
            "Win32 RootDirectory comparison failed outside expected no-effect error 87");
        std::cout << "Windows Win32 RootDirectory comparison: error 87, no effect\n";
    }

    const fs::path ordinary = stage / "ordinary";
    fs::create_directory(ordinary);
    usk::record_io::write_new_durable_text(ordinary / "payload.bin", "original\n");
    const auto original_file = identity(ordinary / "payload.bin");
    for (const auto* invalid_name : {L"CON.txt", L"..", L"bad:name", L"trailing."}) {
        bool refused_name = false;
        try {
            (void)usk::record_io::probe_windows_handle_relative_no_replace(
                ordinary, parent, invalid_name);
        } catch (const std::exception&) { refused_name = true; }
        check(refused_name && identity(ordinary / "payload.bin") == original_file,
            "invalid Windows destination component was not refused before mutation");
    }
    const auto ordinary_result = usk::record_io::probe_windows_handle_relative_no_replace(
        ordinary, parent, L"visible");
    check(!fs::exists(ordinary) && identity(parent / "visible/payload.bin") == original_file &&
        ordinary_result.source_file_id == ordinary_result.visible_file_id &&
        !ordinary_result.destination_parent_file_id.empty(),
        "handle-relative ordinary rename lost original native object");

    const fs::path collision = stage / "collision";
    const fs::path occupied = parent / "occupied";
    fs::create_directory(collision);
    fs::create_directory(occupied);
    usk::record_io::write_new_durable_text(collision / "payload.bin", "source\n");
    usk::record_io::write_new_durable_text(occupied / "payload.bin", "destination\n");
    const auto collision_file = identity(collision / "payload.bin");
    const auto occupied_file = identity(occupied / "payload.bin");
    bool refused = false;
    try { (void)usk::record_io::probe_windows_handle_relative_no_replace(collision, parent, L"occupied"); }
    catch (const std::exception&) { refused = true; }
    check(refused && identity(collision / "payload.bin") == collision_file &&
        identity(occupied / "payload.bin") == occupied_file &&
        read(occupied / "payload.bin") == "destination\n",
        "no-replace probe clobbered a preexisting destination");

    const fs::path raced = stage / "raced";
    fs::create_directory(raced);
    usk::record_io::write_new_durable_text(raced / "payload.bin", "raced source\n");
    const auto raced_file = identity(raced / "payload.bin");
    std::string raced_target_file;
    refused = false;
    try {
        (void)usk::record_io::probe_windows_handle_relative_no_replace(
            raced, parent, L"raced-target", {}, [&] {
                fs::create_directory(parent / "raced-target");
                usk::record_io::write_new_durable_text(
                    parent / "raced-target/payload.bin", "foreign destination\n");
                raced_target_file = identity(parent / "raced-target/payload.bin");
            });
    } catch (const std::exception&) { refused = true; }
    check(refused && identity(raced / "payload.bin") == raced_file &&
        identity(parent / "raced-target/payload.bin") == raced_target_file &&
        read(parent / "raced-target/payload.bin") == "foreign destination\n",
        "post-absence destination creation was not refused without replacement");

    const fs::path substituted = stage / "substituted";
    const fs::path outside = root / "original-outside";
    fs::create_directory(substituted);
    usk::record_io::write_new_durable_text(substituted / "payload.bin", "same bytes\n");
    const auto bound_file = identity(substituted / "payload.bin");
    const auto substituted_result = usk::record_io::probe_windows_handle_relative_no_replace(
        substituted, parent, L"bound", [&] {
            fs::rename(substituted, outside);
            fs::create_directory(substituted);
            usk::record_io::write_new_durable_text(substituted / "payload.bin", "same bytes\n");
        });
    check(!fs::exists(outside) && identity(parent / "bound/payload.bin") == bound_file &&
        identity(substituted / "payload.bin") != bound_file &&
        substituted_result.source_file_id == substituted_result.visible_file_id,
        "source-path substitution redirected the handle-bound rename");

    const fs::path parent_moved = root / "parent-moved";
    const fs::path parent_race = stage / "parent-race";
    fs::create_directory(parent_race);
    usk::record_io::write_new_durable_text(parent_race / "payload.bin", "parent race\n");
    const auto parent_race_file = identity(parent_race / "payload.bin");
    refused = false;
    try {
        (void)usk::record_io::probe_windows_handle_relative_no_replace(
            parent_race, parent, L"in-bound-parent", [&] {
                fs::rename(parent, parent_moved);
                fs::create_directory(parent);
            });
    } catch (const std::exception&) { refused = true; }
    check(refused && !fs::exists(parent / "in-bound-parent") &&
        identity(parent_race / "payload.bin") == parent_race_file &&
        !fs::exists(parent_moved / "in-bound-parent"),
        "parent-path substitution was not refused before mutation");
    std::cout << "Windows native bound rename: ordinary, collision, destination race, source substitution, parent substitution PASS\n";
}
#endif
} // namespace
int main() {
    try {
        if (const int result = original_publication_regression()) return result;
        legacy_success(); changed_closure(); strict_refusal(); interrupted_preparation_retains();
        strict_visible_target_cannot_finalize(); structural_bounds();
#if defined(_WIN32)
        windows_bound_rename_probe();
#endif
        std::cout << "commit preparation: legacy success, child/directory/closure changes, typed strict refusal, retained reopen/rollback and bounds PASS\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 251; }
}
