// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_transaction_session.h"
#include "usk_json.h"
#include "usk_sha256.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using usk::transaction::RecoveryInspection;
using usk::transaction::NoReplaceCommitUnavailable;
using usk::transaction::TransactionSession;
using usk::transaction::TransactionSpec;

namespace {

struct Fixture {
    fs::path root;
    fs::path staging;
    fs::path targets;
    fs::path state;
    fs::path audit;

    Fixture()
    {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        root = fs::temp_directory_path() / ("usk-transaction-" + std::to_string(nonce));
        staging = root / "staging";
        targets = root / "targets";
        state = root / "state";
        audit = root / "audit";
        fs::create_directories(staging);
        fs::create_directories(targets);
        fs::create_directories(state / "transactions");
        fs::create_directories(audit);
    }

    ~Fixture()
    {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }

    TransactionSpec spec(const std::string& id) const
    {
        return TransactionSpec{
            id,
            "plan." + id,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "install_local",
            staging,
            targets / id,
            state,
            audit};
    }
};

std::vector<unsigned char> bytes(const std::string& value)
{
    return {value.begin(), value.end()};
}

std::string read_text(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

bool contains(const std::vector<std::string>& values, const std::string& expected)
{
    for (const std::string& value : values) {
        if (value == expected) return true;
    }
    return false;
}

bool throws(const std::function<void()>& operation)
{
    try {
        operation();
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

int original_transition_extension(Fixture& fixture, bool commit_supported)
{
    const auto spec = fixture.spec("original-transition-prefix");
    TransactionSession session(spec, [](const std::string& state, const std::string& point) {
        if (state == "committing" && point == "after_journal") throw std::runtime_error("retain original committing anchor");
    });
    session.stage_file("payload.txt", bytes("original"));
    session.mark_staged(); session.mark_verified();
    if (!throws([&] { session.commit_effect(); }) || session.current_state() != "committing") return 191;
    const auto original_text = read_text(session.journal_path());
    const auto original = TransactionSession::inspect_recovery(spec);
    TransactionSession::require_recovery_transition_extension(spec, original_text,
        original.snapshot_sha256, original.snapshot_sha256);
    if (!throws([&] { TransactionSession::require_completed_transition_extension(spec, original_text,
            original.snapshot_sha256, original.snapshot_sha256); }) ||
        read_text(session.journal_path()) != original_text ||
        read_text(session.staging_root()/"payload.txt") != "original") return 195;
    session.mark_recovery_required();
    const auto current = TransactionSession::inspect_recovery(spec);
    TransactionSession::require_recovery_transition_extension(spec, original_text,
        original.snapshot_sha256, current.snapshot_sha256);
    if (!throws([&] { TransactionSession::require_recovery_transition_extension(spec, original_text,
            original.snapshot_sha256, original.snapshot_sha256); })) return 192;
    const auto hash = [](const std::string& text) {
        usk::base::Sha256 digest;
        digest.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
        return digest.finish();
    };
    for (const int change : {0, 1, 2}) {
        auto altered = usk::json::parse(original_text);
        if (change == 1) altered.as_object().at("transitions").as_array().front().as_object()["recorded_at"] =
            usk::json::Value("changed-original-transition");
        else if (change == 2) altered.as_object()["journal_digest"] = usk::json::Value(std::string(64, '0'));
        else altered.as_object()["created_at"] = usk::json::Value("changed-original-creation");
        const auto text = usk::json::canonical(altered);
        if (!throws([&] { TransactionSession::require_recovery_transition_extension(spec, text,
                hash(text), current.snapshot_sha256); })) return 193;
    }
    // Even a structurally inspectable current journal must preserve immutable
    // fields and its derived recovery presentation; no hash adoption.
    const auto current_text = read_text(session.journal_path());
    for (const bool change_immutable : {false, true}) {
        auto altered = usk::json::parse(current_text);
        if (change_immutable) altered.as_object()["created_at"] = usk::json::Value("changed-current-creation");
        else altered.as_object().at("recovery").as_object()["required"] = usk::json::Value(false);
        { std::ofstream output(session.journal_path(), std::ios::binary | std::ios::trunc);
          output << usk::json::canonical(altered); }
        const auto modified = TransactionSession::inspect_recovery(spec);
        const bool refused = throws([&] { TransactionSession::require_recovery_transition_extension(spec,
            original_text, original.snapshot_sha256, modified.snapshot_sha256); });
        { std::ofstream output(session.journal_path(), std::ios::binary | std::ios::trunc); output << current_text; }
        if (!refused) return 194;
    }
    if (commit_supported) {
        const auto visible_spec = fixture.spec("visible-transition-prefix");
        TransactionSession visible(visible_spec);
        visible.stage_file("payload.txt", bytes("visible"));
        visible.mark_staged(); visible.mark_verified(); visible.commit_effect();
        const auto anchor = TransactionSession::inspect_recovery(visible_spec);
        const auto anchor_text = read_text(visible.journal_path());
        visible.mark_recovery_required(); visible.resume_committing(); visible.mark_committed(); visible.mark_completed();
        TransactionSession::require_recovery_transition_extension(visible_spec, anchor_text,
            anchor.snapshot_sha256, TransactionSession::inspect_recovery(visible_spec).snapshot_sha256);
        const auto completed = TransactionSession::inspect_completed_history(visible_spec);
        const auto completed_text = read_text(visible.journal_path());
        TransactionSession::require_completed_transition_extension(visible_spec, anchor_text,
            anchor.snapshot_sha256, completed.snapshot_sha256);
        if (!throws([&] { TransactionSession::require_completed_transition_extension(visible_spec, anchor_text,
                anchor.snapshot_sha256, anchor.snapshot_sha256); }) ||
            read_text(visible.journal_path()) != completed_text) return 196;
#if !defined(_WIN32)
        // Completed metadata provenance does not reopen or select actions from
        // a substituted payload path. The service must separately hold and
        // verify the genuine root; this metadata helper grants no such proof.
        auto retained = visible_spec.target_root; retained += "-retained";
        fs::rename(visible_spec.target_root, retained);
        fs::create_directory_symlink(retained, visible_spec.target_root);
        TransactionSession::require_completed_transition_extension(visible_spec, anchor_text,
            anchor.snapshot_sha256, completed.snapshot_sha256);
        const bool live_refused = throws([&] { TransactionSession::require_recovery_transition_extension(
            visible_spec, anchor_text, anchor.snapshot_sha256, completed.snapshot_sha256); });
        const bool unchanged = read_text(visible.journal_path()) == completed_text &&
            read_text(retained/"payload.txt") == "visible";
        fs::remove(visible_spec.target_root); fs::rename(retained, visible_spec.target_root);
        if (!live_refused || !unchanged) return 197;
#endif
    }
    return 0;
}

int happy_path(Fixture& fixture, bool& commit_supported)
{
    TransactionSpec spec = fixture.spec("happy");
    TransactionSession session(spec);
    if (session.current_state() != "staging" || !fs::is_directory(session.staging_root())) return 10;
    session.stage_file("app/bin/tool.exe", bytes("portable-payload"));
    if (!throws([&] { session.stage_file("../escape", bytes("bad")); }) ||
        !throws([&] { session.stage_file("NUL.txt", bytes("bad")); }) ||
        !throws([&] { session.stage_file("APP/BIN/TOOL.EXE", bytes("bad")); })) {
        return 11;
    }
    session.mark_staged();
    session.mark_verified();
    try {
        session.commit();
    } catch (const NoReplaceCommitUnavailable&) {
        commit_supported = false;
        if (session.current_state() != "recovery_required" ||
            !fs::exists(session.staging_root()) || fs::exists(session.target_root())) {
            return 12;
        }
        if (!throws([&] { session.rollback(); }) ||
            TransactionSession::inspect_recovery(spec).available_actions !=
                std::vector<std::string>{"retain_for_operator"}) return 15;
        return 0;
    }
    commit_supported = true;
    if (session.current_state() != "completed" || fs::exists(session.staging_root()) ||
        read_text(session.target_root() / "app/bin/tool.exe") != "portable-payload") {
        return 12;
    }
    const RecoveryInspection recovery = TransactionSession::inspect_recovery(spec);
    if (recovery.current_state != "completed" || recovery.staging_exists ||
        !recovery.target_exists || !recovery.available_actions.empty()) {
        return 13;
    }
    const std::string journal = read_text(session.journal_path());
    return journal.find("\"current_state\":\"completed\"") == std::string::npos ? 14 : 0;
}

int no_clobber(Fixture& fixture)
{
    TransactionSpec spec = fixture.spec("no-clobber");
    TransactionSession session(spec);
    session.stage_file("payload.txt", bytes("new"));
    session.mark_staged();
    session.mark_verified();
    fs::create_directory(spec.target_root);
    {
        std::ofstream output(spec.target_root / "sentinel.txt", std::ios::binary);
        output << "old";
    }
    if (!throws([&] { session.commit(); }) || session.current_state() != "refused" ||
        read_text(spec.target_root / "sentinel.txt") != "old" ||
        !fs::exists(session.staging_root())) {
        return 20;
    }
    return 0;
}

int rollback(Fixture& fixture)
{
    TransactionSpec spec = fixture.spec("rollback");
    TransactionSession session(spec);
    session.stage_file("payload.txt", bytes("temporary"));
    session.mark_staged();
    session.mark_verified();
    session.rollback();
    const RecoveryInspection recovery = TransactionSession::inspect_recovery(spec);
    if (session.current_state() != "rolled_back" || fs::exists(session.staging_root()) ||
        fs::exists(spec.target_root) || recovery.current_state != "rolled_back") {
        return 30;
    }
    return 0;
}

int rollback_retains_foreign_content(Fixture& fixture)
{
    TransactionSpec spec = fixture.spec("rollback-foreign");
    TransactionSession session(spec);
    session.stage_file("owned.txt", bytes("owned"));
    {
        std::ofstream output(session.staging_root() / "foreign.txt", std::ios::binary);
        output << "foreign";
    }
    if (!throws([&] { session.rollback(); }) ||
        session.current_state() != "recovery_required" ||
        read_text(session.staging_root() / "owned.txt") != "owned" ||
        read_text(session.staging_root() / "foreign.txt") != "foreign") {
        return 35;
    }
    return 0;
}

int staging_substitution(Fixture& fixture)
{
    TransactionSpec spec = fixture.spec("substitution");
    TransactionSession session(spec);
    session.stage_file("payload.txt", bytes("expected"));
    const fs::path displaced = fixture.root / "displaced-stage";
    fs::rename(session.staging_root(), displaced);
    fs::create_directory(session.staging_root());
    if (!throws([&] { session.mark_staged(); })) return 40;
    return 0;
}

int target_ancestor_replacement(Fixture& fixture)
{
    TransactionSpec spec = fixture.spec("ancestor-replacement");
    TransactionSession session(spec);
    session.stage_file("payload.txt", bytes("reviewed"));
    session.mark_staged();
    session.mark_verified();

    const fs::path displaced = fixture.root / "displaced-targets";
    fs::rename(fixture.targets, displaced);
    fs::create_directory(fixture.targets);
    {
        std::ofstream sentinel(fixture.targets / "replacement-sentinel.txt", std::ios::binary);
        sentinel << "retain";
    }
    if (!throws([&] { session.commit_effect(); }) || session.current_state() != "refused" ||
        read_text(fixture.targets / "replacement-sentinel.txt") != "retain" ||
        fs::exists(spec.target_root)) {
        return 41;
    }
    return 0;
}

int partial_write_recovery(Fixture& fixture)
{
    const TransactionSpec spec = fixture.spec("partial-write");
    const fs::path expected_staging = spec.staging_parent / ".usk-stage-partial-write";
    bool injected = false;
    TransactionSession session(spec, [&](const std::string& state, const std::string& point) {
        if (!injected && state == "staging" && point == "before_stage_file") {
            injected = true;
            std::ofstream partial(expected_staging / "payload.txt", std::ios::binary);
            partial << "partial";
            partial.close();
            throw std::runtime_error("simulated partial write interruption");
        }
    });
    if (!throws([&] { session.stage_file("payload.txt", bytes("complete-payload")); }) ||
        !injected || read_text(expected_staging / "payload.txt") != "partial") {
        return 42;
    }
    const RecoveryInspection recovery = TransactionSession::inspect_recovery(spec);
    if (recovery.current_state != "staging" ||
        recovery.available_actions != std::vector<std::string>{"retain_for_operator"} ||
        !fs::is_regular_file(expected_staging / "payload.txt")) {
        return 43;
    }
    return 0;
}

int fault_after_transition(Fixture& fixture, const std::string& state, int ordinal)
{
    const std::string id = "fault-" + std::to_string(ordinal) + "-" + state;
    TransactionSpec spec = fixture.spec(id);
    bool injected = false;
    auto injector = [&](const std::string& observed_state, const std::string& point) {
        if (!injected && observed_state == state && point == "after_journal") {
            injected = true;
            throw std::runtime_error("injected transition fault");
        }
    };
    try {
        TransactionSession session(spec, injector);
        session.stage_file("payload.txt", bytes("fault-fixture"));
        session.mark_staged();
        session.mark_verified();
        session.commit();
    } catch (const std::runtime_error&) {
    }
    if (!injected) return 50 + ordinal;
    const RecoveryInspection recovery = TransactionSession::inspect_recovery(spec);
    if (recovery.current_state != state) return 70 + ordinal;
    const bool should_have_target = state == "committed" || state == "completed";
    if (recovery.target_exists != should_have_target) return 90 + ordinal;
    if (state == "committed" && !contains(recovery.available_actions, "resume")) return 110 + ordinal;
    if ((state == "staged" || state == "verified") &&
        (contains(recovery.available_actions, "resume") ||
         !contains(recovery.available_actions, "rollback"))) {
        return 130 + ordinal;
    }
    if (state == "committing") {
        const auto journal = read_text(spec.state_root / "transactions" / (id + ".journal.json"));
        if (recovery.available_actions != std::vector<std::string>{"retain_for_operator"} ||
            !throws([&] { (void)TransactionSession::resume_rollback(spec); }) ||
            read_text(spec.state_root / "transactions" / (id + ".journal.json")) != journal ||
            read_text(spec.staging_parent / (".usk-stage-" + id) / "payload.txt") != "fault-fixture") {
            return 140 + ordinal;
        }
    }
    return 0;
}

int commit_refusal_preserves_primary_error(Fixture& fixture)
{
    for (const bool refuse_recovery_record : {false, true}) {
        const auto spec = fixture.spec(refuse_recovery_record ? "commit-primary-record-refused" : "commit-primary-recorded");
        bool recovery_attempted = false;
        TransactionSession session(spec, [&](const std::string& state, const std::string& point) {
            if (state == "recovery_required" && point == "before_journal") {
                recovery_attempted = true;
                if (refuse_recovery_record) throw std::runtime_error("secondary recovery record refusal");
            }
        });
        session.stage_file("payload.txt", bytes("original"));
        session.mark_staged(); session.mark_verified();
        // Change only this fixture's staged closure after verification. The
        // primary preparation refusal must survive a second record refusal.
        std::ofstream(session.staging_root() / "foreign.txt", std::ios::binary) << "foreign";
        std::string primary;
        try { session.commit_effect(); }
        catch (const std::runtime_error& error) { primary = error.what(); }
        if (primary != "commit refuses linked, unsupported, or unrecorded content" || !recovery_attempted) return 202;
        const auto retained = TransactionSession::inspect_recovery(spec);
        if (retained.current_state != (refuse_recovery_record ? "verified" : "recovery_required") ||
            retained.available_actions != std::vector<std::string>{"retain_for_operator"} ||
            !retained.staging_exists || retained.target_exists ||
            read_text(session.staging_root() / "payload.txt") != "original" ||
            read_text(session.staging_root() / "foreign.txt") != "foreign" ||
            !throws([&] { session.rollback(); })) return 203;
    }
    return 0;
}

int fault_after_commit_effect(Fixture& fixture)
{
    TransactionSpec spec = fixture.spec("fault-after-commit-effect");
    bool injected = false;
    auto injector = [&](const std::string&, const std::string& point) {
        if (point == "after_commit_effect") {
            injected = true;
            throw std::runtime_error("injected post-rename fault");
        }
    };
    try {
        TransactionSession session(spec, injector);
        session.stage_file("payload.txt", bytes("committed"));
        session.mark_staged();
        session.mark_verified();
        session.commit();
    } catch (const std::runtime_error&) {
    }
    const RecoveryInspection recovery = TransactionSession::inspect_recovery(spec);
    if (!injected || recovery.current_state != "committing" || recovery.staging_exists ||
        !recovery.target_exists || !contains(recovery.available_actions, "resume")) {
        return 160;
    }
    auto resumed = TransactionSession::resume_finalization(spec);
    resumed->mark_committed();
    resumed->mark_completed();
    if (TransactionSession::inspect_recovery(spec).current_state != "completed") return 161;
    return 0;
}

int operational_fault_points(Fixture& fixture)
{
    {
        TransactionSpec spec = fixture.spec("fault-staging-create");
        bool injected = false;
        try {
            TransactionSession session(spec, [&](const std::string&, const std::string& point) {
                if (point == "after_staging_create") {
                    injected = true;
                    throw std::runtime_error("injected staging-create fault");
                }
            });
        } catch (const std::runtime_error&) {
        }
        const auto recovery = TransactionSession::inspect_recovery(spec);
        if (!injected || recovery.current_state != "staging" || !recovery.staging_exists) return 165;
    }
    {
        TransactionSpec spec = fixture.spec("fault-before-write");
        bool injected = false;
        TransactionSession session(spec, [&](const std::string&, const std::string& point) {
            if (point == "before_stage_file") {
                injected = true;
                throw std::runtime_error("injected write-capacity fault");
            }
        });
        if (!throws([&] { session.stage_file("payload.txt", bytes("payload")); }) ||
            !injected || fs::exists(session.staging_root() / "payload.txt")) {
            return 166;
        }
        session.rollback();
    }
    {
        TransactionSpec spec = fixture.spec("fault-after-rollback");
        bool injected = false;
        TransactionSession session(spec, [&](const std::string&, const std::string& point) {
            if (point == "after_rollback_effect") {
                injected = true;
                throw std::runtime_error("injected rollback-finalization fault");
            }
        });
        session.stage_file("payload.txt", bytes("payload"));
        if (!throws([&] { session.rollback(); }) || !injected || fs::exists(session.staging_root()) ||
            TransactionSession::inspect_recovery(spec).current_state != "recovery_required") {
            return 167;
        }
    }
    return 0;
}

int durable_recovery_rollback(Fixture& fixture)
{
    const TransactionSpec spec = fixture.spec("durable-rollback");
    bool injected = false;
    try {
        TransactionSession session(spec, [&](const std::string& state, const std::string& point) {
            if (!injected && state == "staged" && point == "after_journal") {
                injected = true;
                throw std::runtime_error("simulated process interruption");
            }
        });
        session.stage_file("nested/payload.txt", bytes("durable-owned-payload"));
        session.mark_staged();
    } catch (const std::runtime_error&) {
    }
    const RecoveryInspection inspection = TransactionSession::inspect_recovery(spec);
    if (!injected || inspection.current_state != "staged" ||
        inspection.available_actions != std::vector<std::string>{"rollback"}) {
        return 168;
    }
    auto recovered = TransactionSession::resume_rollback(spec);
    recovered->rollback();
    const RecoveryInspection final = TransactionSession::inspect_recovery(spec);
    if (final.current_state != "rolled_back" || fs::exists(recovered->staging_root()) ||
        fs::exists(spec.target_root)) {
        return 169;
    }
    return 0;
}

int durable_recovery_retains_foreign_content(Fixture& fixture)
{
    const TransactionSpec spec = fixture.spec("durable-foreign");
    fs::path staging;
    {
        TransactionSession session(spec);
        session.stage_file("owned.txt", bytes("owned"));
        session.mark_staged();
        staging = session.staging_root();
    }
    {
        std::ofstream output(staging / "foreign.txt", std::ios::binary);
        output << "foreign";
    }
    const RecoveryInspection inspection = TransactionSession::inspect_recovery(spec);
    if (inspection.available_actions != std::vector<std::string>{"retain_for_operator"} ||
        !throws([&] { (void)TransactionSession::resume_rollback(spec); }) ||
        read_text(staging / "owned.txt") != "owned" ||
        read_text(staging / "foreign.txt") != "foreign") {
        return 171;
    }
    return 0;
}

} // namespace

int initial_stream_binding_before_effects(Fixture& fixture)
{
    const std::string context = "{\"schema\":\"test.initial_stream_source.v1\"}";
    const auto source = usk::json::sha256_canonical(usk::json::parse(context));
    auto invalid = fixture.spec("initial-source-invalid");
    if (!throws([&] { TransactionSession::begin_streaming(invalid, std::string(64, '0'), context); }) ||
        fs::exists(fixture.state / "transactions" / "initial-source-invalid.journal.json") ||
        fs::exists(fixture.staging / ".usk-stage-initial-source-invalid")) return 181;
    for (const auto& phase : {"created", "validated", "planned", "staging"}) {
        auto spec = fixture.spec(std::string("initial-source-") + phase);
        if (!throws([&] {
            TransactionSession::begin_streaming(spec, source, context,
                [&](const std::string& state, const std::string& point) {
                    if (state == phase && point == "after_journal") throw std::runtime_error("interrupt initial stream");
                });
        })) return 182;
        const auto inspected = TransactionSession::inspect_recovery(spec);
        if (inspected.stream_source_digest != source || inspected.stream_source_context != context ||
            inspected.current_state != phase || inspected.target_exists || inspected.staging_exists) return 183;
        const auto replay = TransactionSession::restart_streaming(spec, spec.transaction_id + "-replay",
            inspected.snapshot_sha256, source);
        auto next = spec;
        next.transaction_id += "-replay";
        const auto lineage = TransactionSession::inspect_recovery(next);
        // Replay preserves the exact plan identity rather than inventing a new plan.
        if (replay->current_state() != "staging" || !fs::exists(replay->staging_root()) ||
            lineage.stream_source_digest != source || lineage.stream_source_context != context ||
            lineage.restart_origin_transaction_id != spec.transaction_id ||
            lineage.restart_origin_snapshot_sha256 != inspected.snapshot_sha256) return 186;
    }
    auto spec = fixture.spec("initial-source-created-stage");
    if (!throws([&] {
        TransactionSession::begin_streaming(spec, source, context,
            [](const std::string&, const std::string& point) {
                if (point == "after_staging_create") throw std::runtime_error("interrupt owned staging");
            });
    })) return 184;
    const auto inspected = TransactionSession::inspect_recovery(spec);
    if (inspected.stream_source_digest != source || inspected.stream_source_context != context ||
        !inspected.staging_exists || inspected.publication_root_identity.empty() || inspected.target_exists) return 185;
    if (!fs::remove(fixture.staging / ".usk-stage-initial-source-created-stage")) return 187;
    if (!throws([&] { TransactionSession::restart_streaming(spec, "missing-stage-replay",
            inspected.snapshot_sha256, source); })) return 188;
    return 0;
}

int main()
{
    Fixture fixture;
    if (int result = initial_stream_binding_before_effects(fixture)) return result;
    bool commit_supported = false;
    if (int result = happy_path(fixture, commit_supported)) return result;
    if (int result = original_transition_extension(fixture, commit_supported)) return result;
    if (int result = no_clobber(fixture)) return result;
    if (int result = rollback(fixture)) return result;
    if (int result = rollback_retains_foreign_content(fixture)) return result;
    if (int result = staging_substitution(fixture)) return result;
    if (int result = target_ancestor_replacement(fixture)) return result;
    if (int result = partial_write_recovery(fixture)) return result;
    if (int result = commit_refusal_preserves_primary_error(fixture)) return result;

    std::vector<std::string> states = {
        "created", "validated", "planned", "staging", "staged",
        "verified", "committing"};
    if (commit_supported) {
        states.push_back("committed");
        states.push_back("completed");
    }
    for (std::size_t index = 0; index < states.size(); ++index) {
        if (int result = fault_after_transition(fixture, states[index], static_cast<int>(index))) {
            return result;
        }
    }
    if (commit_supported) {
        if (int result = fault_after_commit_effect(fixture)) return result;
    }
    if (int result = operational_fault_points(fixture)) return result;
    if (int result = durable_recovery_rollback(fixture)) return result;
    if (int result = durable_recovery_retains_foreign_content(fixture)) return result;

    TransactionSpec duplicate = fixture.spec("duplicate-journal");
    TransactionSession original(duplicate);
    if (!throws([&] { TransactionSession repeated(duplicate); })) return 170;
    return 0;
}
