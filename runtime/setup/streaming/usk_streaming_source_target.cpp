// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_streaming_source_target.h"

#include "usk_audit_repository.h"
#include "usk_record_io.h"
#include "usk_sha256.h"
#include "usk_stable_file.h"

#include <algorithm>
#include <cctype>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace fs = std::filesystem;

namespace {

bool sha256(const std::string& value)
{
    return value.size() == 64u &&
        std::all_of(value.begin(), value.end(), [](unsigned char byte) {
            return std::isdigit(byte) || (byte >= 'a' && byte <= 'f');
        });
}

std::string lowercase(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char byte) {
        return static_cast<char>(std::tolower(byte));
    });
    return value;
}

std::string identity_digest(const usk::base::StableFileIdentity& identity)
{
    const std::string value = identity.volume_id + "\n" + identity.file_id + "\n" +
        std::to_string(identity.size_bytes) + "\n" +
        std::to_string(identity.modified_time_ns) + "\n" +
        std::to_string(identity.link_count);
    usk::base::Sha256 digest;
    digest.update(reinterpret_cast<const unsigned char*>(value.data()), value.size());
    return digest.finish();
}

class Integrity {
public:
    void update(const unsigned char* data, std::size_t size)
    {
        sha_.update(data, size);
        for (std::size_t index = 0; index < size; ++index) {
            crc_ ^= data[index];
            for (int bit = 0; bit < 8; ++bit) {
                crc_ = (crc_ >> 1) ^ (0xedb88320u & (0u - (crc_ & 1u)));
            }
        }
        bytes_ += size;
    }

    std::string finish_sha256() { return sha_.finish(); }
    std::uint32_t finish_crc32() const { return ~crc_; }
    std::uint64_t bytes() const { return bytes_; }

private:
    usk::base::Sha256 sha_;
    std::uint32_t crc_ = 0xffffffffu;
    std::uint64_t bytes_ = 0;
};

void validate_budget(const usk::streaming::ResourceBudget& budget)
{
    if (budget.payload_buffer_bytes != usk::streaming::kPayloadBufferBytes ||
        budget.maximum_entries == 0u || budget.maximum_entries > 1000000u) {
        throw std::runtime_error("streaming resource budget is invalid");
    }
}

void require_not_cancelled(
    const usk::streaming::CancellationView* cancellation,
    const char* boundary)
{
    if (cancellation != nullptr && cancellation->cancelled()) {
        throw std::runtime_error(std::string("stream cancelled ") + boundary);
    }
}

std::string entry_set_digest(const std::vector<usk::streaming::PayloadEntryDescriptor>& entries)
{
    usk::base::Sha256 digest;
    for (const auto& entry : entries) {
        std::string line;
        line.reserve(entry.relative_path.size() + entry.sha256.size() +
            entry.source_identity_digest.size() + 64u);
        line.append(entry.relative_path);
        line.push_back('\0');
        line.append(std::to_string(entry.size_bytes));
        line.push_back('\0');
        line.append(entry.sha256);
        line.push_back('\0');
        line.append(std::to_string(entry.crc32));
        line.push_back('\0');
        line.append(entry.source_identity_digest);
        line.push_back('\n');
        digest.update(reinterpret_cast<const unsigned char*>(line.data()), line.size());
    }
    return digest.finish();
}

void fault(
    const usk::streaming::FaultInjector& injector,
    const std::string& point,
    const std::string& path,
    std::uint64_t offset)
{
    if (injector) injector(point, path, offset);
}

std::string classify_error(const std::string& detail)
{
    if (detail.find("cancelled") != std::string::npos) return "stream_cancelled";
    if (detail.find("identity") != std::string::npos ||
        detail.find("substituted") != std::string::npos ||
        detail.find("changed") != std::string::npos) return "source_identity_changed";
    if (detail.find("short") != std::string::npos) return "source_short_read";
    if (detail.find("integrity") != std::string::npos ||
        detail.find("CRC") != std::string::npos) return "source_integrity_mismatch";
    return "streaming_io_failed";
}

} // namespace

namespace usk::streaming {

DirectorySource inspect_directory_source(const fs::path& source_root, ResourceBudget budget)
{
    validate_budget(budget);
    DirectorySource result;
    result.root = fs::absolute(source_root).lexically_normal();
    usk::record_io::require_safe_directory(result.root);
    std::set<std::string> folded;
    for (const fs::directory_entry& item : fs::recursive_directory_iterator(result.root)) {
        if (item.is_symlink()) throw std::runtime_error("directory source contains a link");
        if (item.is_directory()) {
            usk::record_io::require_safe_directory(item.path());
            continue;
        }
        if (!item.is_regular_file()) {
            throw std::runtime_error("directory source contains a non-file entry");
        }
        if (result.entries.size() >= budget.maximum_entries) {
            throw std::runtime_error("directory source exceeds the entry budget");
        }
        const fs::path relative = item.path().lexically_relative(result.root);
        const std::string relative_text = relative.generic_u8string();
        if (relative_text.empty() || relative_text.find("..") != std::string::npos ||
            !folded.insert(lowercase(relative_text)).second) {
            throw std::runtime_error("directory source path is unsafe or colliding");
        }
        usk::base::StableFile source(item.path());
        PayloadEntryDescriptor descriptor;
        descriptor.source_path = source.path();
        descriptor.relative_path = relative_text;
        descriptor.source_identity_digest = identity_digest(source.identity());
        descriptor.size_bytes = source.identity().size_bytes;
        Integrity integrity;
        std::vector<unsigned char> buffer(budget.payload_buffer_bytes);
        std::uint64_t offset = 0;
        while (offset < descriptor.size_bytes) {
            const std::size_t count = static_cast<std::size_t>(
                std::min<std::uint64_t>(buffer.size(), descriptor.size_bytes - offset));
            source.read_into(offset, buffer.data(), count);
            integrity.update(buffer.data(), count);
            offset += count;
        }
        source.verify_unchanged();
        descriptor.sha256 = integrity.finish_sha256();
        descriptor.crc32 = integrity.finish_crc32();
        result.total_bytes += descriptor.size_bytes;
        result.entries.push_back(std::move(descriptor));
    }
    std::sort(result.entries.begin(), result.entries.end(), [](const auto& left, const auto& right) {
        return left.relative_path < right.relative_path;
    });
    if (result.entries.empty()) throw std::runtime_error("directory source is empty");
    result.entry_set_digest = entry_set_digest(result.entries);
    return result;
}

StreamResult stream_directory_to_target(StreamRequest request) noexcept
{
    StreamResult result;
    result.entry_set_digest = request.source.entry_set_digest;
    std::unique_ptr<transaction::TransactionSession> transaction;
    try {
        validate_budget(request.budget);
        if (!sha256(request.source.entry_set_digest) || request.source.entries.empty() ||
            request.audit_chain_id.empty() || request.recorded_at.empty()) {
            throw std::runtime_error("streaming request identity is invalid");
        }
        if (entry_set_digest(request.source.entries) != request.source.entry_set_digest) {
            throw std::runtime_error("directory source descriptor set changed");
        }
        transaction = std::make_unique<transaction::TransactionSession>(
            request.transaction,
            [&](const std::string& state, const std::string& point) {
                fault(request.fault, "transaction:" + state + ":" + point, {}, 0);
            });
        for (const PayloadEntryDescriptor& entry : request.source.entries) {
            require_not_cancelled(request.cancellation, "before source read");
            if (!sha256(entry.sha256) || !sha256(entry.source_identity_digest)) {
                throw std::runtime_error("streaming entry identity is invalid");
            }
            usk::base::StableFile source(entry.source_path);
            if (identity_digest(source.identity()) != entry.source_identity_digest ||
                source.identity().size_bytes != entry.size_bytes) {
                throw std::runtime_error("stable source identity changed before streaming");
            }
            Integrity integrity;
            std::uint64_t offset = 0;
            const transaction::StreamStageResult staged = transaction->stage_file_stream(
                fs::u8path(entry.relative_path),
                entry.size_bytes,
                entry.sha256,
                request.budget.payload_buffer_bytes,
                [&](unsigned char* output, std::size_t capacity) -> std::size_t {
                    require_not_cancelled(request.cancellation, "mid-entry");
                    if (offset >= entry.size_bytes) return 0;
                    fault(request.fault, "before_source_read", entry.relative_path, offset);
                    const std::size_t count = static_cast<std::size_t>(
                        std::min<std::uint64_t>(capacity, entry.size_bytes - offset));
                    source.read_into(offset, output, count);
                    integrity.update(output, count);
                    offset += count;
                    fault(request.fault, "after_source_read", entry.relative_path, offset);
                    if (request.progress != nullptr) {
                        request.progress->advanced(entry.relative_path, offset, result.bytes_completed + offset);
                    }
                    return count;
                });
            require_not_cancelled(request.cancellation, "after staged-file finalization");
            source.verify_unchanged();
            if (integrity.bytes() != entry.size_bytes ||
                integrity.finish_sha256() != entry.sha256 ||
                integrity.finish_crc32() != entry.crc32 || staged.sha256 != entry.sha256) {
                throw std::runtime_error("streamed source SHA-256 or CRC integrity mismatch");
            }
            result.peak_payload_buffer_bytes = std::max(
                result.peak_payload_buffer_bytes, staged.peak_buffer_bytes);
            result.bytes_completed += staged.size_bytes;
            ++result.entries_completed;
        }
        require_not_cancelled(request.cancellation, "before staged verification");
        transaction->mark_staged();
        require_not_cancelled(request.cancellation, "after staged verification");
        transaction->mark_verified();
        require_not_cancelled(request.cancellation, "after transaction verification");
        fault(request.fault, "before_commit", {}, result.bytes_completed);
        require_not_cancelled(request.cancellation, "before target commit");
        transaction->commit();
        fault(request.fault, "after_commit_before_audit", {}, result.bytes_completed);

        if (!fs::is_directory(request.transaction.audit_root / "chains")) {
            audit::AuditRepository::initialize_layout(request.transaction.audit_root);
        }
        audit::AuditRepository audit(request.transaction.audit_root);
        if (!fs::exists(request.transaction.audit_root / "chains" / request.audit_chain_id)) {
            audit.initialize_chain(request.audit_chain_id);
        }
        const audit::AuditEvent event = audit.append(
            request.audit_chain_id,
            audit::AuditInput{
                request.recorded_at,
                "install_local",
                "completed",
                "pass",
                "transaction",
                request.transaction.transaction_id,
                request.source.entry_set_digest,
                request.transaction.transaction_id,
                request.transaction.plan_id,
                "Private bounded directory-source streaming completed"});
        result.audit_event_digest = event.event_digest;
        result.completed = true;
        result.disposition = "target_committed_audited";
        return result;
    } catch (const std::exception& error) {
        result.detail = error.what();
        result.error_code = classify_error(result.detail);
        if (fs::exists(request.transaction.target_root)) {
            result.disposition = "target_visible_recovery_or_audit_required";
            return result;
        }
        if (transaction != nullptr) {
            try {
                transaction->rollback();
                result.disposition = "rolled_back_no_target_visible";
            } catch (const std::exception& rollback_error) {
                result.disposition = "recovery_required_no_target_visible";
                result.detail += "; rollback: " + std::string(rollback_error.what());
            }
        } else {
            result.disposition = "refused_before_transaction";
        }
        return result;
    } catch (...) {
        result.error_code = "streaming_unknown_failure";
        result.detail = "unknown streaming failure";
        result.disposition = fs::exists(request.transaction.target_root)
            ? "target_visible_recovery_or_audit_required"
            : "recovery_required_no_target_visible";
        return result;
    }
}

std::uint64_t measure_generated_payload_buffer(std::uint64_t logical_bytes, ResourceBudget budget)
{
    validate_budget(budget);
    std::vector<unsigned char> buffer(budget.payload_buffer_bytes);
    std::uint64_t offset = 0;
    std::uint64_t checksum = 0;
    while (offset < logical_bytes) {
        const std::size_t count = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), logical_bytes - offset));
        buffer.front() = static_cast<unsigned char>(offset % 251u);
        buffer[count - 1u] = static_cast<unsigned char>((offset + count - 1u) % 251u);
        checksum ^= static_cast<std::uint64_t>(buffer.front()) +
            static_cast<std::uint64_t>(buffer[count - 1u]) + count + offset;
        offset += count;
    }
    if (offset != logical_bytes || (logical_bytes != 0u && checksum == logical_bytes)) {
        throw std::runtime_error("generated streaming memory proof failed");
    }
    return static_cast<std::uint64_t>(buffer.capacity());
}

} // namespace usk::streaming
