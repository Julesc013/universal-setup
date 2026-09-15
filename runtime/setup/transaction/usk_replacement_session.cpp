// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_replacement_session.h"

#include "usk_json.h"
#include "usk_record_io.h"
#include "usk_stable_file.h"
#include "usk_transaction_session.h"

#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;
using usk::json::Value;

namespace {

constexpr std::size_t maximum_snapshot_entries = 200000u;
constexpr std::uint64_t maximum_snapshot_bytes = 1ull << 34;

bool sha256(const std::string& value)
{
    return value.size() == 64u && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

std::string normalized(const fs::path& path)
{
    return fs::absolute(path).lexically_normal().generic_u8string();
}

bool same_or_below(const fs::path& root, const fs::path& candidate)
{
    const fs::path relative = candidate.lexically_relative(root);
    if (relative.empty()) return candidate == root;
    if (relative.is_absolute()) return false;
    for (const auto& part : relative) if (part == "..") return false;
    return true;
}

std::string phase_filename(unsigned long long sequence, const std::string& phase)
{
    std::ostringstream value;
    value << std::setw(20) << std::setfill('0') << sequence << '.' << phase << ".json";
    return value.str();
}

bool valid_transition(const std::string& from, const std::string& to)
{
    return (from == "intent" && to == "old_retire_prepared") ||
           (from == "old_retire_prepared" && to == "old_retired") ||
           (from == "old_retired" && to == "new_activate_prepared") ||
           (from == "new_activate_prepared" && to == "new_active") ||
           (from == "new_active" && to == "state_published") ||
           (from == "state_published" && to == "completed");
}

Value journal_payload(const usk::transaction::ReplacementSpec& spec,
    unsigned long long sequence, const std::string& phase, const std::string& previous_digest)
{
    return Value(Value::Object{
        {"new_root_identity", Value(spec.new_root_identity)},
        {"new_snapshot_digest", Value(spec.new_snapshot_digest)},
        {"old_root_identity", Value(spec.old_root_identity)},
        {"old_snapshot_digest", Value(spec.old_snapshot_digest)},
        {"phase", Value(phase)},
        {"plan_digest", Value(spec.plan_digest)},
        {"plan_id", Value(spec.plan_id)},
        {"previous_journal_digest", previous_digest.empty() ? Value() : Value(previous_digest)},
        {"required_commit_authority", Value(usk::transaction::commit_authority_name(
            spec.required_commit_authority))},
        {"retained_root", Value(normalized(spec.retained_root))},
        {"schema", Value("usk.replacement_transaction_journal.v1")},
        {"sequence", Value(static_cast<std::uint64_t>(sequence))},
        {"staged_root", Value(normalized(spec.staged_root))},
        {"target_root", Value(normalized(spec.live_root))},
        {"transaction_id", Value(spec.transaction_id)}});
}

Value journal_document(const usk::transaction::ReplacementSpec& spec,
    unsigned long long sequence, const std::string& phase, const std::string& previous_digest)
{
    Value payload = journal_payload(spec, sequence, phase, previous_digest);
    payload.as_object().emplace("journal_digest", Value(usk::json::sha256_canonical(payload)));
    return payload;
}

bool exact_journal_members(const Value& value)
{
    static const std::set<std::string> expected = {
        "journal_digest", "new_root_identity", "new_snapshot_digest", "old_root_identity",
        "old_snapshot_digest", "phase", "plan_digest", "plan_id", "previous_journal_digest",
        "required_commit_authority", "retained_root", "schema", "sequence", "staged_root",
        "target_root", "transaction_id"};
    if (value.type() != Value::Type::object || value.as_object().size() != expected.size()) return false;
    for (const auto& member : value.as_object()) if (expected.count(member.first) == 0u) return false;
    return true;
}

bool matches_root(const fs::path& path, const std::string& identity, const std::string& snapshot)
{
    try {
        return fs::is_directory(path) && !fs::is_symlink(fs::symlink_status(path)) &&
            usk::transaction::observe_directory_identity(path) == identity &&
            usk::transaction::replacement_snapshot_digest(path) == snapshot;
    } catch (const std::exception&) {
        return false;
    }
}

std::string volume_of(const std::string& identity)
{
    const auto separator = identity.find(':');
    return separator == std::string::npos ? std::string{} : identity.substr(0, separator);
}

} // namespace

namespace usk::transaction {

std::string replacement_snapshot_digest(const fs::path& root)
{
    if (!fs::is_directory(root) || fs::is_symlink(fs::symlink_status(root))) {
        throw std::runtime_error("replacement snapshot root is unavailable or linked");
    }
    Value::Array entries;
    std::uint64_t bytes = 0;
    for (const fs::directory_entry& entry : fs::recursive_directory_iterator(root)) {
        if (entries.size() >= maximum_snapshot_entries) {
            throw std::runtime_error("replacement snapshot entry budget exceeded");
        }
        const std::string relative = entry.path().lexically_relative(root).generic_u8string();
        const auto status = entry.symlink_status();
        if (fs::is_directory(status)) {
            entries.emplace_back(Value::Object{{"relative_path", Value(relative)}, {"type", Value("directory")}});
        } else if (fs::is_regular_file(status)) {
            usk::base::StableFile file(entry.path());
            if (file.identity().size_bytes > maximum_snapshot_bytes - bytes) {
                throw std::runtime_error("replacement snapshot byte budget exceeded");
            }
            const std::string digest = file.sha256_hex();
            file.verify_unchanged();
            bytes += file.identity().size_bytes;
            entries.emplace_back(Value::Object{{"relative_path", Value(relative)},
                {"sha256", Value(digest)}, {"size_bytes", Value(file.identity().size_bytes)},
                {"type", Value("file")}});
        } else {
            throw std::runtime_error("replacement snapshot contains linked or unsupported content");
        }
    }
    std::sort(entries.begin(), entries.end(), [](const Value& left, const Value& right) {
        return left.at("relative_path").as_string() < right.at("relative_path").as_string();
    });
    return usk::json::sha256_canonical(Value(Value::Object{
        {"entries", Value(std::move(entries))}, {"schema", Value("usk.replacement_snapshot.v1")}}));
}

ReplacementSession::ReplacementSession(ReplacementSpec spec, ReplacementFaultInjector injector)
    : spec_(std::move(spec)), injector_(std::move(injector))
{
    if (!usk::record_io::valid_identifier(spec_.transaction_id) ||
        !usk::record_io::valid_identifier(spec_.plan_id) || !sha256(spec_.plan_digest) ||
        !sha256(spec_.old_snapshot_digest) || !sha256(spec_.new_snapshot_digest) ||
        spec_.old_root_identity.empty() || spec_.new_root_identity.empty()) {
        throw std::runtime_error("replacement transaction identity is invalid");
    }
    spec_.live_root = fs::absolute(spec_.live_root).lexically_normal();
    spec_.staged_root = fs::absolute(spec_.staged_root).lexically_normal();
    spec_.retained_root = fs::absolute(spec_.retained_root).lexically_normal();
    spec_.state_root = fs::absolute(spec_.state_root).lexically_normal();
    if (spec_.live_root.parent_path() != spec_.staged_root.parent_path() ||
        spec_.live_root.parent_path() != spec_.retained_root.parent_path() ||
        spec_.live_root == spec_.staged_root || spec_.live_root == spec_.retained_root ||
        spec_.staged_root == spec_.retained_root || fs::exists(spec_.retained_root) ||
        !matches_root(spec_.live_root, spec_.old_root_identity, spec_.old_snapshot_digest) ||
        !matches_root(spec_.staged_root, spec_.new_root_identity, spec_.new_snapshot_digest) ||
        volume_of(spec_.old_root_identity) != volume_of(spec_.new_root_identity) ||
        same_or_below(spec_.live_root, spec_.state_root) ||
        same_or_below(spec_.state_root, spec_.live_root) ||
        same_or_below(spec_.staged_root, spec_.state_root) ||
        same_or_below(spec_.state_root, spec_.staged_root) ||
        same_or_below(spec_.retained_root, spec_.state_root) ||
        same_or_below(spec_.state_root, spec_.retained_root)) {
        throw std::runtime_error("replacement roots do not match the reviewed same-volume identities");
    }
    const fs::path journals = spec_.state_root / "replacement-transactions";
    usk::record_io::require_safe_directory(journals);
    usk::record_io::create_directory_exclusive(journals, spec_.transaction_id);
    journal_path_ = journals / spec_.transaction_id;
    journal_directory_identity_ = observe_directory_identity(journal_path_);
    persist("intent");
}

void ReplacementSession::persist(const std::string& next_phase)
{
    if ((!phase_.empty() && !valid_transition(phase_, next_phase)) ||
        observe_directory_identity(journal_path_) != journal_directory_identity_) {
        throw std::runtime_error("replacement journal transition or identity is invalid");
    }
    std::string previous_digest;
    if (sequence_ != 0u) {
        const fs::path previous = journal_path_ / phase_filename(sequence_ - 1u, phase_);
        const Value document = usk::json::parse(usk::record_io::read_stable_text(previous, 1024u * 1024u));
        previous_digest = document.at("journal_digest").as_string();
    }
    if (injector_) injector_(next_phase, "before_journal");
    const Value document = journal_document(spec_, sequence_, next_phase, previous_digest);
    usk::record_io::write_new_durable_text(
        journal_path_ / phase_filename(sequence_, next_phase), usk::json::canonical(document) + "\n");
    phase_ = next_phase;
    ++sequence_;
    if (injector_) injector_(next_phase, "after_journal");
}

void ReplacementSession::retire_old_root()
{
    if (phase_ != "intent") throw std::logic_error("old-root retirement is out of sequence");
    require_commit_authority(spec_.required_commit_authority);
    persist("old_retire_prepared");
    if (!matches_root(spec_.live_root, spec_.old_root_identity, spec_.old_snapshot_digest) ||
        !matches_root(spec_.staged_root, spec_.new_root_identity, spec_.new_snapshot_digest) ||
        fs::exists(spec_.retained_root)) {
        throw std::runtime_error("replacement roots changed before old-root retirement");
    }
    usk::record_io::rename_no_replace(spec_.live_root, spec_.retained_root);
    if (injector_) injector_(phase_, "after_old_root_rename");
    if (!matches_root(spec_.retained_root, spec_.old_root_identity, spec_.old_snapshot_digest) ||
        fs::exists(spec_.live_root)) {
        throw std::runtime_error("retained old root cannot be proven after retirement");
    }
    persist("old_retired");
}

void ReplacementSession::activate_new_root()
{
    if (phase_ != "old_retired") throw std::logic_error("new-root activation is out of sequence");
    persist("new_activate_prepared");
    if (fs::exists(spec_.live_root) ||
        !matches_root(spec_.retained_root, spec_.old_root_identity, spec_.old_snapshot_digest) ||
        !matches_root(spec_.staged_root, spec_.new_root_identity, spec_.new_snapshot_digest)) {
        throw std::runtime_error("replacement roots changed before new-root activation");
    }
    usk::record_io::rename_no_replace(spec_.staged_root, spec_.live_root);
    if (injector_) injector_(phase_, "after_new_root_rename");
    if (!matches_root(spec_.live_root, spec_.new_root_identity, spec_.new_snapshot_digest) ||
        !matches_root(spec_.retained_root, spec_.old_root_identity, spec_.old_snapshot_digest)) {
        throw std::runtime_error("active new root cannot be proven after activation");
    }
    persist("new_active");
}

void ReplacementSession::mark_state_published()
{
    if (phase_ != "new_active") throw std::logic_error("replacement state publication is out of sequence");
    if (!matches_root(spec_.live_root, spec_.new_root_identity, spec_.new_snapshot_digest) ||
        !matches_root(spec_.retained_root, spec_.old_root_identity, spec_.old_snapshot_digest)) {
        throw std::runtime_error("replacement state publication lost exact roots");
    }
    persist("state_published");
}

void ReplacementSession::mark_completed()
{
    if (phase_ != "state_published") throw std::logic_error("replacement completion is out of sequence");
    persist("completed");
}

ReplacementInspection ReplacementSession::inspect(const ReplacementSpec& supplied)
{
    ReplacementSpec spec = supplied;
    spec.live_root = fs::absolute(spec.live_root).lexically_normal();
    spec.staged_root = fs::absolute(spec.staged_root).lexically_normal();
    spec.retained_root = fs::absolute(spec.retained_root).lexically_normal();
    spec.state_root = fs::absolute(spec.state_root).lexically_normal();
    ReplacementInspection result;
    try {
        result.live_root_exists = fs::exists(spec.live_root);
        result.staged_root_exists = fs::exists(spec.staged_root);
        result.retained_root_exists = fs::exists(spec.retained_root);
        const fs::path directory = spec.state_root / "replacement-transactions" / spec.transaction_id;
        usk::record_io::require_safe_directory(directory);
        std::vector<fs::path> records;
        for (const auto& entry : fs::directory_iterator(directory)) {
            if (!entry.is_regular_file() || entry.is_symlink() || records.size() >= 16u) {
                throw std::runtime_error("replacement journal directory is not exact");
            }
            records.push_back(entry.path());
        }
        std::sort(records.begin(), records.end());
        if (records.empty()) throw std::runtime_error("replacement journal is empty");
        std::string prior_digest;
        std::string prior_phase;
        for (std::size_t index = 0; index < records.size(); ++index) {
            const std::string text = usk::record_io::read_stable_text(records[index], 1024u * 1024u);
            const Value document = usk::json::parse(text);
            if (!exact_journal_members(document) ||
                usk::json::canonical(document) + "\n" != text ||
                document.at("schema").as_string() != "usk.replacement_transaction_journal.v1" ||
                document.at("sequence").as_unsigned() != index ||
                document.at("transaction_id").as_string() != spec.transaction_id ||
                document.at("plan_id").as_string() != spec.plan_id ||
                document.at("plan_digest").as_string() != spec.plan_digest ||
                document.at("target_root").as_string() != normalized(spec.live_root) ||
                document.at("staged_root").as_string() != normalized(spec.staged_root) ||
                document.at("retained_root").as_string() != normalized(spec.retained_root) ||
                document.at("old_root_identity").as_string() != spec.old_root_identity ||
                document.at("old_snapshot_digest").as_string() != spec.old_snapshot_digest ||
                document.at("new_root_identity").as_string() != spec.new_root_identity ||
                document.at("new_snapshot_digest").as_string() != spec.new_snapshot_digest ||
                document.at("required_commit_authority").as_string() !=
                    commit_authority_name(spec.required_commit_authority)) {
                throw std::runtime_error("replacement journal binding changed");
            }
            const std::string phase = document.at("phase").as_string();
            if ((index == 0u && phase != "intent") ||
                (index != 0u && !valid_transition(prior_phase, phase))) {
                throw std::runtime_error("replacement journal phase chain is invalid");
            }
            const Value previous = document.at("previous_journal_digest");
            if ((index == 0u && previous.type() != Value::Type::null_value) ||
                (index != 0u && previous.as_string() != prior_digest)) {
                throw std::runtime_error("replacement journal digest chain is invalid");
            }
            Value payload = document;
            const std::string digest = payload.at("journal_digest").as_string();
            payload.as_object().erase("journal_digest");
            if (!sha256(digest) || usk::json::sha256_canonical(payload) != digest ||
                records[index].filename().string() != phase_filename(index, phase)) {
                throw std::runtime_error("replacement journal digest or filename is invalid");
            }
            prior_digest = digest;
            prior_phase = phase;
        }
        result.phase = prior_phase;
        result.journal_digest = prior_digest;
    } catch (const std::exception&) {
        result.phase = "corrupt";
        result.disposition = "indeterminate";
        result.available_actions = {"retain_for_operator"};
        return result;
    }

    const bool live_old = matches_root(spec.live_root, spec.old_root_identity, spec.old_snapshot_digest);
    const bool live_new = matches_root(spec.live_root, spec.new_root_identity, spec.new_snapshot_digest);
    const bool staged_new = matches_root(spec.staged_root, spec.new_root_identity, spec.new_snapshot_digest);
    const bool retained_old = matches_root(spec.retained_root, spec.old_root_identity, spec.old_snapshot_digest);
    if (live_old && staged_new && !result.retained_root_exists &&
        (result.phase == "intent" || result.phase == "old_retire_prepared")) {
        result.disposition = "no_replacement_effect";
        result.available_actions = {"retain_for_operator"};
    } else if (!result.live_root_exists && staged_new && retained_old &&
        (result.phase == "old_retire_prepared" || result.phase == "old_retired" ||
         result.phase == "new_activate_prepared")) {
        result.disposition = "old_retired";
        result.available_actions = {"retain_for_operator"};
    } else if (live_new && !result.staged_root_exists && retained_old &&
        (result.phase == "new_activate_prepared" || result.phase == "new_active" ||
         result.phase == "state_published" || result.phase == "completed")) {
        result.disposition = result.phase == "completed" ? "completed" : "new_active";
        if (result.phase != "completed") result.available_actions = {"retain_for_operator"};
    } else {
        result.disposition = "indeterminate";
        result.available_actions = {"retain_for_operator"};
    }
    return result;
}

} // namespace usk::transaction
