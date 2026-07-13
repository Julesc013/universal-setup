#include "usk_transaction_session.h"

#include "usk_sha256.h"
#include "usk_stable_file.h"
#include "usk_json.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>
#include <system_error>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/fs.h>
#include <sys/syscall.h>
#endif
#endif

namespace fs = std::filesystem;

namespace {

std::string json_escape(const std::string& value)
{
    std::ostringstream out;
    for (unsigned char ch : value) {
        switch (ch) {
        case '\\': out << "\\\\"; break;
        case '"': out << "\\\""; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (ch < 0x20u) {
                out << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<unsigned int>(ch) << std::dec;
            } else {
                out << static_cast<char>(ch);
            }
        }
    }
    return out.str();
}

std::string quote(const std::string& value)
{
    return "\"" + json_escape(value) + "\"";
}

std::string iso8601_now()
{
    const std::time_t now = std::time(nullptr);
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    std::ostringstream out;
    out << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

bool valid_identifier(const std::string& value)
{
    return !value.empty() && value.size() <= 128 &&
        std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return std::isalnum(ch) || ch == '.' || ch == '_' || ch == '-';
        });
}

bool valid_sha256(const std::string& value)
{
    return value.size() == 64 &&
        std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return std::isdigit(ch) || (ch >= 'a' && ch <= 'f');
        });
}

fs::path absolute_normal(const fs::path& path)
{
    std::error_code error;
    fs::path result = fs::absolute(path, error).lexically_normal();
    if (error || result.empty() || !result.is_absolute()) {
        throw std::runtime_error("transaction root cannot be resolved as an absolute path");
    }
    return result;
}

bool reparse_or_symlink(const fs::path& path)
{
    std::error_code error;
    if (fs::is_symlink(fs::symlink_status(path, error)) || error) {
        return true;
    }
#if defined(_WIN32)
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    return false;
#endif
}

void require_safe_directory(const fs::path& path)
{
    if (!fs::is_directory(path) || reparse_or_symlink(path)) {
        throw std::runtime_error("transaction root must be an existing non-linked directory: " + path.string());
    }
    fs::path current = path.root_path();
    for (const fs::path& component : path.relative_path()) {
        current /= component;
        if (reparse_or_symlink(current) || !fs::is_directory(current)) {
            throw std::runtime_error("transaction root crosses a linked or non-directory component: " + path.string());
        }
    }
}

std::string hex_id(std::uint64_t value)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(16) << value;
    return out.str();
}

std::string directory_identity(const fs::path& path)
{
    require_safe_directory(path);
#if defined(_WIN32)
    HANDLE handle = CreateFileW(
        path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("cannot open transaction directory identity");
    }
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info)) {
        CloseHandle(handle);
        throw std::runtime_error("cannot inspect transaction directory identity");
    }
    CloseHandle(handle);
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
        FILE_ATTRIBUTE_DIRECTORY) {
        throw std::runtime_error("transaction directory identity is unsafe");
    }
    const std::uint64_t file_id =
        (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
    return hex_id(info.dwVolumeSerialNumber) + ":" + hex_id(file_id);
#else
    struct stat info{};
    if (::lstat(path.c_str(), &info) != 0 || !S_ISDIR(info.st_mode) || S_ISLNK(info.st_mode)) {
        throw std::runtime_error("cannot inspect safe transaction directory identity");
    }
    return hex_id(static_cast<std::uint64_t>(info.st_dev)) + ":" +
        hex_id(static_cast<std::uint64_t>(info.st_ino));
#endif
}

std::string volume_identity(const fs::path& path)
{
    const std::string identity = directory_identity(path);
    return identity.substr(0, identity.find(':'));
}

std::string comparable_path(const fs::path& path)
{
    std::string value = path.generic_string();
#if defined(_WIN32)
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
#endif
    while (value.size() > 1 && value.back() == '/') value.pop_back();
    return value;
}

bool path_contains(const fs::path& parent, const fs::path& child)
{
    const std::string parent_text = comparable_path(parent);
    const std::string child_text = comparable_path(child);
    return child_text == parent_text ||
        (child_text.size() > parent_text.size() &&
         child_text.rfind(parent_text + "/", 0) == 0);
}

void require_disjoint(const fs::path& left, const fs::path& right)
{
    if (path_contains(left, right) || path_contains(right, left)) {
        throw std::runtime_error("transaction state, audit, and target roots must be disjoint");
    }
}

bool safe_relative_path(const fs::path& relative)
{
    if (relative.empty() || relative.is_absolute() || relative.has_root_name()) return false;
    for (const fs::path& component : relative) {
        const std::string segment = component.string();
        if (segment.empty() || segment == "." || segment == ".." ||
            segment.find(':') != std::string::npos ||
            segment.back() == '.' || segment.back() == ' ') {
            return false;
        }
        std::string stem = segment.substr(0, segment.find('.'));
        std::transform(stem.begin(), stem.end(), stem.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        static const std::set<std::string> reserved = {
            "con", "prn", "aux", "nul", "clock$",
            "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
            "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"};
        if (reserved.count(stem) != 0) return false;
        for (unsigned char ch : segment) {
            if (ch < 0x20u || ch >= 0x7fu) return false;
        }
    }
    return true;
}

std::string sha256_bytes(const std::vector<unsigned char>& bytes)
{
    usk::base::Sha256 hash;
    hash.update(bytes.data(), bytes.size());
    return hash.finish();
}

void write_new_durable_file(const fs::path& path, const unsigned char* data, std::size_t size)
{
#if defined(_WIN32)
    HANDLE handle = CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("cannot exclusively create durable transaction file");
    }
    try {
        while (size != 0) {
            const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(size, 1024u * 1024u));
            DWORD written = 0;
            if (!WriteFile(handle, data, chunk, &written, nullptr) || written != chunk) {
                throw std::runtime_error("cannot write durable transaction file");
            }
            data += written;
            size -= written;
        }
        if (!FlushFileBuffers(handle)) {
            throw std::runtime_error("cannot flush durable transaction file");
        }
        CloseHandle(handle);
    } catch (...) {
        CloseHandle(handle);
        throw;
    }
#else
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#if defined(O_CLOEXEC)
    flags |= O_CLOEXEC;
#endif
#if defined(O_NOFOLLOW)
    flags |= O_NOFOLLOW;
#endif
    const int descriptor = ::open(path.c_str(), flags, 0600);
    if (descriptor < 0) {
        throw std::runtime_error("cannot exclusively create durable transaction file");
    }
    try {
        while (size != 0) {
            const ssize_t written = ::write(descriptor, data, size);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) throw std::runtime_error("cannot write durable transaction file");
            data += written;
            size -= static_cast<std::size_t>(written);
        }
        if (::fsync(descriptor) != 0) {
            throw std::runtime_error("cannot flush durable transaction file");
        }
        ::close(descriptor);
    } catch (...) {
        ::close(descriptor);
        throw;
    }
#endif
}

void fsync_directory(const fs::path& path)
{
#if !defined(_WIN32)
    int flags = O_RDONLY;
#if defined(O_DIRECTORY)
    flags |= O_DIRECTORY;
#endif
#if defined(O_CLOEXEC)
    flags |= O_CLOEXEC;
#endif
    const int descriptor = ::open(path.c_str(), flags);
    if (descriptor < 0 || ::fsync(descriptor) != 0) {
        if (descriptor >= 0) ::close(descriptor);
        throw std::runtime_error("cannot flush transaction journal directory");
    }
    ::close(descriptor);
#else
    (void)path;
#endif
}

void publish_journal(const fs::path& temporary, const fs::path& journal, bool first)
{
#if defined(_WIN32)
    BOOL ok = first
        ? MoveFileExW(temporary.c_str(), journal.c_str(), MOVEFILE_WRITE_THROUGH)
        : ReplaceFileW(
            journal.c_str(),
            temporary.c_str(),
            nullptr,
            REPLACEFILE_WRITE_THROUGH,
            nullptr,
            nullptr);
    if (!ok) {
        throw std::runtime_error("cannot atomically publish transaction journal");
    }
#else
    if (first) {
        if (::link(temporary.c_str(), journal.c_str()) != 0 || ::unlink(temporary.c_str()) != 0) {
            throw std::runtime_error("cannot no-clobber publish initial transaction journal");
        }
    } else {
        struct stat info{};
        if (::lstat(journal.c_str(), &info) != 0 || !S_ISREG(info.st_mode) ||
            S_ISLNK(info.st_mode) || info.st_nlink != 1) {
            throw std::runtime_error("existing transaction journal identity is unsafe");
        }
        if (::rename(temporary.c_str(), journal.c_str()) != 0) {
            throw std::runtime_error("cannot atomically replace transaction journal");
        }
    }
    fsync_directory(journal.parent_path());
#endif
}

void atomic_write_journal(
    const fs::path& journal,
    const std::string& content,
    std::uint64_t sequence,
    bool first)
{
    const fs::path temporary = journal.parent_path() /
        (journal.filename().string() + ".tmp." + std::to_string(sequence));
    write_new_durable_file(
        temporary,
        reinterpret_cast<const unsigned char*>(content.data()),
        content.size());
    try {
        publish_journal(temporary, journal, first);
    } catch (...) {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        throw;
    }
}

void rename_directory_no_replace(const fs::path& source, const fs::path& target)
{
#if defined(_WIN32)
    if (!MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("same-volume no-replace directory commit failed");
    }
#elif defined(__linux__)
    if (::syscall(SYS_renameat2, AT_FDCWD, source.c_str(), AT_FDCWD, target.c_str(), RENAME_NOREPLACE) != 0) {
        const int error = errno;
        if (error == ENOSYS || error == EINVAL || error == EOPNOTSUPP) {
            throw usk::transaction::NoReplaceCommitUnavailable(
                "platform or filesystem lacks renameat2 no-replace support");
        }
        throw std::runtime_error(
            "same-volume renameat2 no-replace commit failed: " +
            std::string(std::strerror(error)) + " (errno " + std::to_string(error) + ")");
    }
#elif defined(__APPLE__)
    if (::renamex_np(source.c_str(), target.c_str(), RENAME_EXCL) != 0) {
        throw std::runtime_error("same-volume renamex_np no-replace commit failed");
    }
#else
    throw std::runtime_error("platform lacks a proven no-replace directory rename primitive");
#endif
}

std::string read_bounded_text(const fs::path& path, std::size_t limit)
{
    if (reparse_or_symlink(path) || !fs::is_regular_file(path) || fs::file_size(path) > limit) {
        throw std::runtime_error("transaction journal is missing, linked, or over budget");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("transaction journal cannot be read");
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string json_string(const std::string& text, const std::string& key)
{
    const std::string marker = "\"" + key + "\":";
    std::size_t position = text.find(marker);
    if (position == std::string::npos) return {};
    position += marker.size();
    while (position < text.size() && std::isspace(static_cast<unsigned char>(text[position]))) ++position;
    if (position >= text.size() || text[position] != '"') return {};
    const std::size_t end = text.find('"', position + 1);
    return end == std::string::npos ? std::string() : text.substr(position + 1, end - position - 1);
}

bool valid_transition(const std::string& from, const std::string& to)
{
    if (from.empty()) return to == "created";
    if (from == "created") return to == "validated";
    if (from == "validated") return to == "planned";
    if (from == "planned") return to == "staging";
    if (from == "staging") return to == "staged" || to == "recovery_required" || to == "refused";
    if (from == "staged") return to == "verified" || to == "recovery_required" || to == "refused";
    if (from == "verified") return to == "committing" || to == "recovery_required" || to == "refused";
    if (from == "committing") return to == "committed" || to == "recovery_required";
    if (from == "committed") return to == "completed" || to == "recovery_required";
    if (from == "recovery_required") {
        return to == "committing" || to == "rolled_back" || to == "abandoned_by_operator";
    }
    return false;
}

std::vector<std::string> journal_actions(const std::string& state)
{
    if (state == "staging" || state == "staged" || state == "verified" || state == "committing") {
        return {"resume", "rollback"};
    }
    if (state == "committed") return {"resume"};
    if (state == "recovery_required" || state == "failed") {
        return {"resume", "rollback", "retain_for_operator", "abandon"};
    }
    return {};
}

} // namespace

namespace usk::transaction {

TransactionSession::TransactionSession(TransactionSpec spec, FaultInjector injector)
    : TransactionSession(std::move(spec), std::move(injector), false)
{
}

TransactionSession::TransactionSession(
    TransactionSpec spec,
    FaultInjector injector,
    bool resume_finalization)
    : spec_(std::move(spec)), injector_(std::move(injector))
{
    if (!valid_identifier(spec_.transaction_id) ||
        !valid_identifier(spec_.plan_id) ||
        !valid_sha256(spec_.plan_digest) ||
        (spec_.operation != "install_local" && spec_.operation != "repair" &&
         spec_.operation != "move" && spec_.operation != "uninstall" &&
         spec_.operation != "recovery")) {
        throw std::runtime_error("transaction identity, digest, or operation is invalid");
    }
    spec_.staging_parent = absolute_normal(spec_.staging_parent);
    spec_.target_root = absolute_normal(spec_.target_root);
    spec_.state_root = absolute_normal(spec_.state_root);
    spec_.audit_root = absolute_normal(spec_.audit_root);
    staging_root_ = spec_.staging_parent / (".usk-stage-" + spec_.transaction_id);
    journal_path_ = spec_.state_root / "transactions" /
        (spec_.transaction_id + ".journal.json");
    created_at_ = iso8601_now();

    if (resume_finalization) {
        require_safe_directory(spec_.staging_parent);
        require_safe_directory(spec_.target_root.parent_path());
        require_safe_directory(spec_.state_root);
        require_safe_directory(spec_.state_root / "transactions");
        require_safe_directory(spec_.audit_root);
        require_disjoint(spec_.target_root, spec_.state_root);
        require_disjoint(spec_.target_root, spec_.audit_root);
        require_disjoint(spec_.state_root, spec_.audit_root);
        const std::string text = read_bounded_text(journal_path_, 4u * 1024u * 1024u);
        const usk::json::Value document = usk::json::parse(text);
        if (document.at("schema").as_string() != "usk.transaction_journal.v1" ||
            document.at("transaction_id").as_string() != spec_.transaction_id ||
            document.at("plan_id").as_string() != spec_.plan_id ||
            document.at("plan_digest").as_string() != spec_.plan_digest ||
            document.at("operation").as_string() != spec_.operation) {
            throw std::runtime_error("transaction journal does not bind the requested finalization");
        }
        created_at_ = document.at("created_at").as_string();
        std::string prior;
        for (const usk::json::Value& item : document.at("transitions").as_array()) {
            const std::uint64_t sequence = item.at("sequence").as_unsigned();
            std::string from;
            if (item.at("from").type() != usk::json::Value::Type::null_value) {
                from = item.at("from").as_string();
            }
            const std::string to = item.at("to").as_string();
            if (sequence != transitions_.size() || from != prior || !valid_transition(from, to) ||
                item.at("transition_id").as_string() !=
                    spec_.transaction_id + "." + std::to_string(sequence) ||
                !item.at("durable_before_external_visibility").as_boolean()) {
                throw std::runtime_error("transaction journal transition chain is invalid");
            }
            transitions_.push_back(Transition{sequence, from, to, item.at("recorded_at").as_string()});
            prior = to;
        }
        std::ostringstream chain;
        for (const Transition& transition : transitions_) {
            chain << transition.sequence << '\0' << transition.from << '\0'
                  << transition.to << '\0' << transition.recorded_at << '\n';
        }
        usk::base::Sha256 chain_digest;
        const std::string chain_text = chain.str();
        chain_digest.update(
            reinterpret_cast<const unsigned char*>(chain_text.data()), chain_text.size());
        if (transitions_.empty() || document.at("current_state").as_string() != prior ||
            document.at("journal_digest").as_string() != chain_digest.finish() ||
            (prior != "committing" && prior != "committed" && prior != "recovery_required") ||
            fs::exists(staging_root_) || !fs::is_directory(spec_.target_root) ||
            reparse_or_symlink(spec_.target_root)) {
            throw std::runtime_error("transaction is not a visible-target finalization candidate");
        }
        current_state_ = prior;
        staging_parent_identity_ = directory_identity(spec_.staging_parent);
        target_parent_identity_ = directory_identity(spec_.target_root.parent_path());
        journal_directory_identity_ = directory_identity(spec_.state_root / "transactions");
        return;
    }

    verify_roots_for_plan();
    if (fs::exists(journal_path_)) {
        throw std::runtime_error("transaction journal already exists; recovery inspection is required");
    }
    persist_transition("created");
    persist_transition("validated");
    persist_transition("planned");
    persist_transition("staging");
    create_staging_root();
}

void TransactionSession::verify_roots_for_plan()
{
    require_safe_directory(spec_.staging_parent);
    require_safe_directory(spec_.target_root.parent_path());
    require_safe_directory(spec_.state_root);
    require_safe_directory(spec_.state_root / "transactions");
    require_safe_directory(spec_.audit_root);
    if (fs::exists(spec_.target_root) || fs::exists(staging_root_)) {
        throw std::runtime_error("target and transaction staging roots must not already exist");
    }
    require_disjoint(spec_.target_root, spec_.state_root);
    require_disjoint(spec_.target_root, spec_.audit_root);
    require_disjoint(spec_.state_root, spec_.audit_root);
    if (comparable_path(staging_root_) == comparable_path(spec_.target_root)) {
        throw std::runtime_error("staging and target roots must be distinct");
    }
    if (volume_identity(spec_.staging_parent) != volume_identity(spec_.target_root.parent_path())) {
        throw std::runtime_error("WU4 supports same-volume no-replace commit only");
    }
    staging_parent_identity_ = directory_identity(spec_.staging_parent);
    target_parent_identity_ = directory_identity(spec_.target_root.parent_path());
    journal_directory_identity_ = directory_identity(spec_.state_root / "transactions");
}

void TransactionSession::persist_transition(const std::string& next_state)
{
    if (!valid_transition(current_state_, next_state)) {
        throw std::logic_error("invalid setup transaction state transition");
    }
    if (injector_) injector_(next_state, "before_journal");
    const std::string previous = current_state_;
    transitions_.push_back(Transition{
        static_cast<std::uint64_t>(transitions_.size()),
        previous,
        next_state,
        iso8601_now()});
    current_state_ = next_state;
    const bool first = transitions_.size() == 1;
    try {
        if (!first && directory_identity(journal_path_.parent_path()) != journal_directory_identity_) {
            throw std::runtime_error("transaction journal directory identity changed");
        }
        atomic_write_journal(
            journal_path_,
            render_journal(),
            transitions_.back().sequence,
            first);
    } catch (...) {
        current_state_ = previous;
        transitions_.pop_back();
        throw;
    }
    if (injector_) injector_(next_state, "after_journal");
}

void TransactionSession::create_staging_root()
{
    if (directory_identity(spec_.staging_parent) != staging_parent_identity_ ||
        fs::exists(staging_root_)) {
        throw std::runtime_error("staging parent changed or staging root now exists");
    }
    std::error_code error;
    if (!fs::create_directory(staging_root_, error) || error) {
        throw std::runtime_error("cannot exclusively create setup-owned staging root");
    }
    staging_identity_ = directory_identity(staging_root_);
    if (injector_) injector_(current_state_, "after_staging_create");
}

void TransactionSession::verify_staging_identity() const
{
    if (staging_identity_.empty() || directory_identity(staging_root_) != staging_identity_ ||
        directory_identity(spec_.staging_parent) != staging_parent_identity_) {
        throw std::runtime_error("setup-owned staging root identity changed");
    }
}

void TransactionSession::remove_recorded_staging_closure()
{
    verify_staging_identity();
    std::vector<fs::path> directories;
    for (const StagedFile& recorded : staged_files_) {
        const fs::path file = staging_root_ / recorded.relative_path;
        {
            usk::base::StableFile actual(file);
            if (actual.identity().size_bytes != recorded.size_bytes ||
                actual.sha256_hex() != recorded.sha256) {
                throw std::runtime_error("rollback refuses changed setup-owned staging content");
            }
            actual.verify_unchanged();
        }
        std::error_code error;
        if (!fs::remove(file, error) || error) {
            throw std::runtime_error("rollback cannot remove a recorded staged file");
        }
        for (fs::path parent = file.parent_path(); parent != staging_root_;
             parent = parent.parent_path()) {
            directories.push_back(parent);
        }
    }
    std::sort(directories.begin(), directories.end(), [](const fs::path& left, const fs::path& right) {
        if (left.native().size() != right.native().size()) {
            return left.native().size() > right.native().size();
        }
        return left.generic_string() < right.generic_string();
    });
    directories.erase(std::unique(directories.begin(), directories.end()), directories.end());
    for (const fs::path& directory : directories) {
        require_safe_directory(directory);
        std::error_code error;
        if (!fs::remove(directory, error) || error) {
            throw std::runtime_error("rollback retains a staging directory containing foreign content");
        }
    }
    verify_staging_identity();
    std::error_code error;
    if (!fs::remove(staging_root_, error) || error) {
        throw std::runtime_error("rollback retains a staging root containing foreign content");
    }
}

void TransactionSession::stage_file(
    const fs::path& relative_path,
    const std::vector<unsigned char>& bytes)
{
    if (current_state_ != "staging" || !safe_relative_path(relative_path)) {
        throw std::runtime_error("staged file path or transaction state is invalid");
    }
    if (std::any_of(staged_files_.begin(), staged_files_.end(), [&](const StagedFile& file) {
            std::string existing = file.relative_path.generic_string();
            std::string candidate = relative_path.generic_string();
            std::transform(existing.begin(), existing.end(), existing.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            std::transform(candidate.begin(), candidate.end(), candidate.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            return existing == candidate;
        })) {
        throw std::runtime_error("staged file path is duplicated");
    }
    verify_staging_identity();
    fs::path current = staging_root_;
    auto end = relative_path.end();
    auto last = end;
    --last;
    for (auto iterator = relative_path.begin(); iterator != last; ++iterator) {
        current /= *iterator;
        std::error_code error;
        if (!fs::exists(current)) {
            if (!fs::create_directory(current, error) || error) {
                throw std::runtime_error("cannot create owned staging directory");
            }
        }
        require_safe_directory(current);
    }
    if (injector_) injector_(current_state_, "before_stage_file");
    const fs::path destination = staging_root_ / relative_path;
    write_new_durable_file(destination, bytes.data(), bytes.size());
    staged_files_.push_back(StagedFile{
        relative_path,
        sha256_bytes(bytes),
        static_cast<std::uint64_t>(bytes.size())});
    if (injector_) injector_(current_state_, "after_stage_file");
}

void TransactionSession::mark_staged()
{
    if (current_state_ != "staging" || staged_files_.empty()) {
        throw std::runtime_error("transaction cannot become staged without staged files");
    }
    verify_staging_identity();
    persist_transition("staged");
}

void TransactionSession::mark_verified()
{
    if (current_state_ != "staged") {
        throw std::runtime_error("only a staged transaction can be verified");
    }
    verify_staging_identity();
    for (const StagedFile& expected : staged_files_) {
        usk::base::StableFile actual(staging_root_ / expected.relative_path);
        if (actual.identity().size_bytes != expected.size_bytes ||
            actual.sha256_hex() != expected.sha256) {
            throw std::runtime_error("staged file closure changed before verification");
        }
        actual.verify_unchanged();
    }
    persist_transition("verified");
}

void TransactionSession::commit_effect()
{
    if (current_state_ != "verified") {
        throw std::runtime_error("only a verified transaction can commit");
    }
    verify_staging_identity();
    if (directory_identity(spec_.target_root.parent_path()) != target_parent_identity_ ||
        fs::exists(spec_.target_root)) {
        persist_transition("refused");
        throw std::runtime_error("target changed or now exists; reviewed plan is invalid");
    }
    persist_transition("committing");
    verify_staging_identity();
    if (directory_identity(spec_.target_root.parent_path()) != target_parent_identity_ ||
        fs::exists(spec_.target_root)) {
        persist_transition("recovery_required");
        throw std::runtime_error("target changed immediately before no-replace commit");
    }
    try {
        rename_directory_no_replace(staging_root_, spec_.target_root);
    } catch (...) {
        persist_transition("recovery_required");
        throw;
    }
    if (injector_) injector_(current_state_, "after_commit_effect");
}

void TransactionSession::mark_committed()
{
    if (current_state_ != "committing" || fs::exists(staging_root_) ||
        !fs::is_directory(spec_.target_root) || reparse_or_symlink(spec_.target_root)) {
        throw std::runtime_error("transaction commit effect is not present and stable");
    }
    persist_transition("committed");
}

void TransactionSession::mark_completed()
{
    if (current_state_ != "committed") {
        throw std::runtime_error("only a committed transaction can complete");
    }
    persist_transition("completed");
}

void TransactionSession::mark_recovery_required()
{
    if (current_state_ != "committing" && current_state_ != "committed") {
        throw std::runtime_error("transaction state cannot require finalization recovery");
    }
    persist_transition("recovery_required");
}

void TransactionSession::resume_committing()
{
    if (current_state_ != "recovery_required" || fs::exists(staging_root_) ||
        !fs::is_directory(spec_.target_root) || reparse_or_symlink(spec_.target_root)) {
        throw std::runtime_error("only visible-target recovery can resume finalization");
    }
    persist_transition("committing");
}

void TransactionSession::commit()
{
    commit_effect();
    mark_committed();
    mark_completed();
}

void TransactionSession::rollback()
{
    if (current_state_ != "staging" && current_state_ != "staged" &&
        current_state_ != "verified" && current_state_ != "committing" &&
        current_state_ != "recovery_required") {
        throw std::runtime_error("transaction state cannot be rolled back safely");
    }
    if (fs::exists(spec_.target_root)) {
        throw std::runtime_error("rollback refuses a transaction whose target is visible");
    }
    if (current_state_ != "recovery_required") persist_transition("recovery_required");
    remove_recorded_staging_closure();
    if (injector_) injector_(current_state_, "after_rollback_effect");
    persist_transition("rolled_back");
}

std::string TransactionSession::render_journal() const
{
    std::ostringstream chain;
    for (const Transition& transition : transitions_) {
        chain << transition.sequence << '\0' << transition.from << '\0'
              << transition.to << '\0' << transition.recorded_at << '\n';
    }
    const std::string chain_text = chain.str();
    usk::base::Sha256 digest;
    digest.update(
        reinterpret_cast<const unsigned char*>(chain_text.data()),
        chain_text.size());

    std::ostringstream out;
    out << "{\"schema\":\"usk.transaction_journal.v1\",";
    out << "\"journal_id\":" << quote("journal." + spec_.transaction_id) << ',';
    out << "\"journal_digest\":" << quote(digest.finish()) << ',';
    out << "\"transaction_id\":" << quote(spec_.transaction_id) << ',';
    out << "\"plan_id\":" << quote(spec_.plan_id) << ',';
    out << "\"plan_digest\":" << quote(spec_.plan_digest) << ',';
    out << "\"operation\":" << quote(spec_.operation) << ',';
    out << "\"current_state\":" << quote(current_state_) << ',';
    out << "\"created_at\":" << quote(created_at_) << ',';
    out << "\"updated_at\":" << quote(transitions_.back().recorded_at) << ',';
    out << "\"roots\":[";
    out << "{\"role\":\"target\",\"root\":" << quote(spec_.target_root.string())
        << ",\"classification\":\"operator_selected_owned_target\"},";
    out << "{\"role\":\"staging\",\"root\":" << quote(staging_root_.string())
        << ",\"classification\":\"setup_owned\"},";
    out << "{\"role\":\"setup_state\",\"root\":" << quote(spec_.state_root.string())
        << ",\"classification\":\"setup_owned\"},";
    out << "{\"role\":\"audit\",\"root\":" << quote(spec_.audit_root.string())
        << ",\"classification\":\"audit_owned\"}],";
    out << "\"transitions\":[";
    for (std::size_t index = 0; index < transitions_.size(); ++index) {
        const Transition& transition = transitions_[index];
        if (index != 0) out << ',';
        out << "{\"sequence\":" << transition.sequence << ',';
        out << "\"transition_id\":" << quote(
            spec_.transaction_id + "." + std::to_string(transition.sequence)) << ',';
        out << "\"from\":" << (transition.from.empty() ? "null" : quote(transition.from)) << ',';
        out << "\"to\":" << quote(transition.to) << ',';
        out << "\"recorded_at\":" << quote(transition.recorded_at) << ',';
        out << "\"durable_before_external_visibility\":true}";
    }
    out << "],\"recovery\":{";
    out << "\"required\":" <<
        ((current_state_ == "recovery_required" || current_state_ == "failed") ? "true" : "false") << ',';
    out << "\"available_actions\":[";
    const auto actions = journal_actions(current_state_);
    for (std::size_t index = 0; index < actions.size(); ++index) {
        if (index != 0) out << ',';
        out << quote(actions[index]);
    }
    out << "]}}";
    return out.str();
}

RecoveryInspection TransactionSession::inspect_recovery(const TransactionSpec& input)
{
    TransactionSpec spec = input;
    spec.staging_parent = absolute_normal(spec.staging_parent);
    spec.target_root = absolute_normal(spec.target_root);
    spec.state_root = absolute_normal(spec.state_root);
    const fs::path staging = spec.staging_parent / (".usk-stage-" + spec.transaction_id);
    const fs::path journal = spec.state_root / "transactions" /
        (spec.transaction_id + ".journal.json");
    const std::string text = read_bounded_text(journal, 4u * 1024u * 1024u);
    RecoveryInspection result;
    result.current_state = json_string(text, "current_state");
    if (result.current_state.empty()) {
        throw std::runtime_error("transaction journal current state is missing");
    }
    result.staging_exists = fs::exists(staging);
    result.target_exists = fs::exists(spec.target_root);
    if (result.staging_exists && reparse_or_symlink(staging)) {
        throw std::runtime_error("recovery staging root is linked or substituted");
    }
    if (result.target_exists && reparse_or_symlink(spec.target_root)) {
        throw std::runtime_error("recovery target root is linked or substituted");
    }
    if ((result.current_state == "committing" || result.current_state == "committed") &&
        result.target_exists && !result.staging_exists) {
        result.available_actions = {"resume"};
    } else if ((result.current_state == "staging" || result.current_state == "staged" ||
                result.current_state == "verified" || result.current_state == "committing") &&
               result.staging_exists && !result.target_exists) {
        result.available_actions = {"resume", "rollback"};
    } else if ((result.current_state == "created" || result.current_state == "validated" ||
                result.current_state == "planned" || result.current_state == "staging") &&
               !result.staging_exists && !result.target_exists) {
        result.available_actions = {"abandon"};
    } else if (result.current_state != "completed" && result.current_state != "rolled_back" &&
               result.current_state != "refused") {
        result.available_actions = {"retain_for_operator"};
    }
    return result;
}

std::unique_ptr<TransactionSession> TransactionSession::resume_finalization(
    const TransactionSpec& spec,
    FaultInjector injector)
{
    return std::unique_ptr<TransactionSession>(
        new TransactionSession(spec, std::move(injector), true));
}

} // namespace usk::transaction
