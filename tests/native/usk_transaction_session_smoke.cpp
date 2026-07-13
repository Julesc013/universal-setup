#include "usk_transaction_session.h"

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
        session.rollback();
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
        fs::exists(session.staging_root() / "owned.txt") ||
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
    if ((state == "staged" || state == "verified" || state == "committing") &&
        (!contains(recovery.available_actions, "resume") ||
         !contains(recovery.available_actions, "rollback"))) {
        return 130 + ordinal;
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
    return 0;
}

} // namespace

int main()
{
    Fixture fixture;
    bool commit_supported = false;
    if (int result = happy_path(fixture, commit_supported)) return result;
    if (int result = no_clobber(fixture)) return result;
    if (int result = rollback(fixture)) return result;
    if (int result = rollback_retains_foreign_content(fixture)) return result;
    if (int result = staging_substitution(fixture)) return result;

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

    TransactionSpec duplicate = fixture.spec("duplicate-journal");
    TransactionSession original(duplicate);
    if (!throws([&] { TransactionSession repeated(duplicate); })) return 170;
    return 0;
}
