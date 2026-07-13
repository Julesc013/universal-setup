#include "usk_audit_repository.h"

#include "usk_json.h"
#include "usk_record_io.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace fs = std::filesystem;
using usk::json::Value;

namespace {

bool sha256(const std::string& value)
{
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isdigit(ch) || (ch >= 'a' && ch <= 'f');
    });
}

void exact_members(const Value& value, const std::set<std::string>& required,
                   const std::set<std::string>& optional = {})
{
    std::set<std::string> actual;
    for (const auto& member : value.as_object()) actual.insert(member.first);
    std::set<std::string> allowed = required;
    allowed.insert(optional.begin(), optional.end());
    for (const std::string& member : required) {
        if (actual.count(member) == 0) throw std::runtime_error("audit event lacks a required member");
    }
    for (const std::string& member : actual) {
        if (allowed.count(member) == 0) throw std::runtime_error("audit event has an incompatible member");
    }
}

std::string filename(std::uint64_t sequence)
{
    std::ostringstream result;
    result << std::setw(20) << std::setfill('0') << sequence << ".event.json";
    return result.str();
}

void validate_input(const usk::audit::AuditInput& input)
{
    const std::set<std::string> operations = {
        "inspect", "plan", "install_local", "verify", "repair", "move", "uninstall", "recovery"};
    const std::set<std::string> phases = {
        "request", "validated", "planned", "staging", "verified", "committing",
        "completed", "refused", "failed", "recovery"};
    const std::set<std::string> statuses = {"pass", "warn", "fail", "refused", "recovery_required"};
    const std::set<std::string> subjects = {
        "source", "plan", "transaction", "installation", "ownership_manifest", "journal"};
    if (input.created_at.empty() || operations.count(input.operation) == 0 ||
        phases.count(input.phase) == 0 || statuses.count(input.status) == 0 ||
        subjects.count(input.subject_type) == 0 ||
        !usk::record_io::valid_identifier(input.subject_id) || !sha256(input.details_digest) ||
        (!input.transaction_id.empty() && !usk::record_io::valid_identifier(input.transaction_id)) ||
        (!input.plan_id.empty() && !usk::record_io::valid_identifier(input.plan_id)) ||
        input.message.size() > 4096) {
        throw std::runtime_error("audit event input is invalid");
    }
}

Value event_payload(const usk::audit::AuditEvent& event)
{
    Value::Object object{
        {"audit_chain_id", Value(event.audit_chain_id)},
        {"created_at", Value(event.created_at)},
        {"details_digest", Value(event.details_digest)},
        {"event_id", Value(event.event_id)},
        {"operation", Value(event.operation)},
        {"phase", Value(event.phase)},
        {"previous_event_digest", event.previous_event_digest.empty() ? Value() : Value(event.previous_event_digest)},
        {"schema", Value("usk.audit_event.v1")},
        {"sequence", Value(event.sequence)},
        {"status", Value(event.status)},
        {"subject", Value(Value::Object{
            {"subject_id", Value(event.subject_id)},
            {"subject_type", Value(event.subject_type)}})}};
    if (!event.transaction_id.empty()) object.emplace("transaction_id", Value(event.transaction_id));
    if (!event.plan_id.empty()) object.emplace("plan_id", Value(event.plan_id));
    if (!event.message.empty()) object.emplace("message", Value(event.message));
    return Value(std::move(object));
}

Value event_document(const usk::audit::AuditEvent& event)
{
    Value result = event_payload(event);
    result.as_object().emplace("event_digest", Value(event.event_digest));
    return result;
}

usk::audit::AuditEvent parse_event(const Value& value)
{
    exact_members(value,
        {"schema", "event_id", "event_digest", "audit_chain_id", "sequence",
         "previous_event_digest", "created_at", "operation", "phase", "status",
         "subject", "details_digest"},
        {"transaction_id", "plan_id", "message"});
    if (value.at("schema").as_string() != "usk.audit_event.v1") {
        throw std::runtime_error("audit event schema is incompatible");
    }
    usk::audit::AuditEvent event;
    event.event_id = value.at("event_id").as_string();
    event.event_digest = value.at("event_digest").as_string();
    event.audit_chain_id = value.at("audit_chain_id").as_string();
    event.sequence = value.at("sequence").as_unsigned();
    if (value.at("previous_event_digest").type() != Value::Type::null_value) {
        event.previous_event_digest = value.at("previous_event_digest").as_string();
    }
    event.created_at = value.at("created_at").as_string();
    event.operation = value.at("operation").as_string();
    event.phase = value.at("phase").as_string();
    event.status = value.at("status").as_string();
    exact_members(value.at("subject"), {"subject_type", "subject_id"});
    event.subject_type = value.at("subject").at("subject_type").as_string();
    event.subject_id = value.at("subject").at("subject_id").as_string();
    event.details_digest = value.at("details_digest").as_string();
    if (value.contains("transaction_id")) event.transaction_id = value.at("transaction_id").as_string();
    if (value.contains("plan_id")) event.plan_id = value.at("plan_id").as_string();
    if (value.contains("message")) event.message = value.at("message").as_string();
    validate_input(event);
    if (!usk::record_io::valid_identifier(event.event_id) ||
        !usk::record_io::valid_identifier(event.audit_chain_id) || !sha256(event.event_digest) ||
        (!event.previous_event_digest.empty() && !sha256(event.previous_event_digest)) ||
        usk::json::sha256_canonical(event_payload(event)) != event.event_digest) {
        throw std::runtime_error("audit event identity or canonical digest is invalid");
    }
    return event;
}

} // namespace

namespace usk::audit {

AuditRepository::AuditRepository(fs::path audit_root)
    : root_(fs::absolute(std::move(audit_root)).lexically_normal())
{
    record_io::require_safe_directory(root_);
}

void AuditRepository::initialize_layout(const fs::path& audit_root)
{
    record_io::require_safe_directory(audit_root);
    record_io::create_directory_exclusive(audit_root, "chains");
}

void AuditRepository::initialize_chain(const std::string& chain_id) const
{
    record_io::require_safe_directory(root_ / "chains");
    record_io::create_directory_exclusive(root_ / "chains", chain_id);
}

std::vector<AuditEvent> AuditRepository::read_and_validate_chain(const std::string& chain_id) const
{
    if (!record_io::valid_identifier(chain_id)) throw std::runtime_error("audit chain id is invalid");
    const fs::path chain_root = root_ / "chains" / chain_id;
    record_io::require_safe_directory(chain_root);
    std::vector<fs::path> paths;
    for (const fs::directory_entry& entry : fs::directory_iterator(chain_root)) {
        const std::string name = entry.path().filename().string();
        if (!entry.is_regular_file() || entry.is_symlink() || name.size() != 31 ||
            name.substr(20) != ".event.json" ||
            !std::all_of(name.begin(), name.begin() + 20, [](unsigned char ch) { return std::isdigit(ch); })) {
            throw std::runtime_error("audit chain contains an unrecognized or unsafe entry");
        }
        paths.push_back(entry.path());
    }
    std::sort(paths.begin(), paths.end());
    std::vector<AuditEvent> events;
    std::string previous;
    for (std::size_t index = 0; index < paths.size(); ++index) {
        const std::string text = record_io::read_stable_text(paths[index], 1024u * 1024u);
        const Value document = json::parse(text);
        if (json::canonical(document) + "\n" != text) throw std::runtime_error("audit event is not canonical");
        AuditEvent event = parse_event(document);
        if (event.audit_chain_id != chain_id || event.sequence != index ||
            event.event_id != chain_id + "." + std::to_string(index) ||
            event.previous_event_digest != previous || paths[index].filename() != filename(index)) {
            throw std::runtime_error("audit chain sequence or previous digest is invalid");
        }
        previous = event.event_digest;
        events.push_back(std::move(event));
    }
    return events;
}

AuditEvent AuditRepository::append(const std::string& chain_id, const AuditInput& input) const
{
    validate_input(input);
    std::vector<AuditEvent> chain = read_and_validate_chain(chain_id);
    AuditEvent event;
    static_cast<AuditInput&>(event) = input;
    event.audit_chain_id = chain_id;
    event.sequence = static_cast<std::uint64_t>(chain.size());
    event.event_id = chain_id + "." + std::to_string(event.sequence);
    if (!chain.empty()) event.previous_event_digest = chain.back().event_digest;
    event.event_digest = json::sha256_canonical(event_payload(event));
    record_io::write_new_durable_text(
        root_ / "chains" / chain_id / filename(event.sequence),
        json::canonical(event_document(event)) + "\n");
    return event;
}

} // namespace usk::audit
