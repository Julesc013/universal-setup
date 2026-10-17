// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_CUSTODY_IMAGE_INTERNAL_H
#define USK_PUBLISHER_CUSTODY_IMAGE_INTERNAL_H
#include "usk_stable_file.h"
#if defined(_WIN32)
#include <atomic>
#include <stdexcept>

namespace usk::platform::windows {
// Private image-content binding, never an authorization result. Runtime use is
// only the wire's registration-admitted protected running publisher image;
// protected installation/admission exclude hostile preexisting pending writers.
// Ordinary fixture construction grants no service or effect admission.
// This is not a general immutable-file API. StableFile's
// private non-inheritable GENERIC_READ/FILE_SHARE_READ handle excludes existing
// write handles/mappings at admission and later write/delete opens on the same
// local NTFS file, including aliases. No reset, handle escape or digest import.
// Fresh metadata/path, peer and token checks remain at their existing callers.
class PublisherCustodyImage final {
public:
    explicit PublisherCustodyImage(const std::filesystem::path& path)
        : file_(path), sha256_(bind_content(file_)) {}
    PublisherCustodyImage(const PublisherCustodyImage&) = delete;
    PublisherCustodyImage& operator=(const PublisherCustodyImage&) = delete;

    const usk::base::StableFileIdentity& identity() const noexcept { return file_.identity(); }
    void verify_unchanged() const {
        if (failed_.load()) throw std::runtime_error("custody image binding previously failed");
        try { file_.verify_unchanged(); }
        catch (...) { failed_.store(true); throw; }
    }
    const std::string& bound_sha256() const {
        verify_unchanged();
        return sha256_;
    }

private:
    static std::string bind_content(const usk::base::StableFile& file) {
        file.require_local_ntfs();
        auto result = file.sha256_hex();
        file.verify_unchanged();
        return result;
    }
    // Destruction releases the binding with its original handle. Constructor
    // failure also closes it; no partially bound object can be returned.
    const usk::base::StableFile file_;
    const std::string sha256_;
    mutable std::atomic<bool> failed_{false};
};
} // namespace usk::platform::windows
#endif
#endif
