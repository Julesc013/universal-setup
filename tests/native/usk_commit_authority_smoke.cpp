// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_json.h"
#include "usk_record_io.h"
#include "usk_sha256.h"
#include "usk_stable_file.h"
#include "usk_transaction_session.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

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
} // namespace
int main() {
    try {
        if (const int result = original_publication_regression()) return result;
        legacy_success(); changed_closure(); strict_refusal(); interrupted_preparation_retains();
        strict_visible_target_cannot_finalize(); structural_bounds();
        std::cout << "commit preparation: legacy success, child/directory/closure changes, typed strict refusal, retained reopen/rollback and bounds PASS\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 251; }
}
