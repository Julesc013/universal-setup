// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_target_inspect.h"

#include "usk_sha256.h"
#include "usk_stable_file.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#elif defined(__APPLE__)
#include <sys/mount.h>
#include <sys/stat.h>
#else
#include <sys/stat.h>
#include <sys/statvfs.h>
#endif

namespace fs = std::filesystem;

namespace {

std::string hash_text(const std::string& text)
{
    usk::base::Sha256 digest;
    digest.update(reinterpret_cast<const unsigned char*>(text.data()), text.size());
    return digest.finish();
}

std::string normalized_path(const fs::path& value)
{
    return fs::absolute(value).lexically_normal().generic_u8string();
}

fs::path existing_ancestor(fs::path path)
{
    path = fs::absolute(std::move(path)).lexically_normal();
    std::error_code error;
    while (!path.empty() && !fs::exists(path, error)) {
        if (error) throw std::runtime_error("target ancestor inspection failed");
        const fs::path parent = path.parent_path();
        if (parent == path) break;
        path = parent;
    }
    if (path.empty() || !fs::is_directory(path, error) || error) {
        throw std::runtime_error("target has no stable existing directory ancestor");
    }
    return path;
}

bool same_or_below(const fs::path& root, const fs::path& candidate)
{
    if (root.empty() || candidate.empty()) return false;
    const fs::path absolute_root = fs::absolute(root).lexically_normal();
    const fs::path absolute_candidate = fs::absolute(candidate).lexically_normal();
    if (absolute_root == absolute_candidate) return true;
    const fs::path relative = absolute_candidate.lexically_relative(absolute_root);
    if (relative.empty() || relative.is_absolute()) return false;
    for (const fs::path& part : relative) if (part == "..") return false;
    return true;
}

std::vector<fs::path> existing_components(const fs::path& target)
{
    const fs::path absolute = fs::absolute(target).lexically_normal();
    std::vector<fs::path> result;
    fs::path current = absolute.root_path();
    std::error_code error;
    if (!current.empty() && fs::exists(current, error)) result.push_back(current);
    for (const fs::path& part : absolute.relative_path()) {
        current /= part;
        if (!fs::exists(current, error)) {
            if (error) throw std::runtime_error("target component inspection failed");
            break;
        }
        result.push_back(current);
    }
    return result;
}

std::vector<fs::path> protected_roots()
{
    std::vector<fs::path> roots;
#if defined(_WIN32)
    for (const char* name : {"WINDIR", "ProgramFiles", "ProgramFiles(x86)", "OneDrive", "OneDriveCommercial", "OneDriveConsumer"}) {
        const char* value = std::getenv(name);
        if (value != nullptr && *value != '\0') roots.emplace_back(value);
    }
    for (const char* name : {"ProgramFiles", "ProgramFiles(x86)"}) {
        const char* value = std::getenv(name);
        if (value != nullptr && *value != '\0') roots.emplace_back(fs::path(value) / "Steam");
    }
#else
    for (const char* value : {"/bin", "/boot", "/dev", "/etc", "/lib", "/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var"}) {
        roots.emplace_back(value);
    }
    for (const char* name : {"HOME", "XDG_DATA_HOME"}) {
        const char* value = std::getenv(name);
        if (value != nullptr && *value != '\0') {
            roots.emplace_back(fs::path(value) / ".steam");
            roots.emplace_back(fs::path(value) / ".local/share/Steam");
        }
    }
#endif
    return roots;
}

bool protected_root_absent(const fs::path& target, const fs::path& authorized_root)
{
    for (const fs::path& root : protected_roots()) {
        if (same_or_below(root, target) || same_or_below(target, root)) {
            if (!authorized_root.empty() && same_or_below(authorized_root, target) &&
                !same_or_below(root, authorized_root)) {
                continue;
            }
            return false;
        }
    }
    return true;
}

bool source_target_distinct(const fs::path& source, const fs::path& target)
{
    if (source.empty() || target.empty()) return false;
    const fs::path absolute_source = fs::absolute(source).lexically_normal();
    const fs::path absolute_target = fs::absolute(target).lexically_normal();
    if (same_or_below(absolute_target, absolute_source)) return false;
    std::error_code error;
    if (fs::exists(absolute_target, error) && !error &&
        fs::equivalent(absolute_source, absolute_target, error) && !error) return false;
    return true;
}

#if defined(_WIN32)
bool components_stable(const std::vector<fs::path>& components)
{
    for (const fs::path& path : components) {
        const DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return false;
    }
    return true;
}

std::pair<bool, std::string> filesystem_kind(const fs::path& ancestor)
{
    wchar_t volume_path[MAX_PATH]{};
    if (!GetVolumePathNameW(ancestor.c_str(), volume_path, MAX_PATH)) return {false, "unproven"};
    const UINT kind = GetDriveTypeW(volume_path);
    if (kind != DRIVE_FIXED && kind != DRIVE_RAMDISK) return {false, "nonlocal"};
    return {true, kind == DRIVE_FIXED ? "windows_fixed" : "windows_ramdisk"};
}

std::string filesystem_identity(const fs::path& ancestor, const std::string& kind)
{
    wchar_t volume_path[MAX_PATH]{};
    DWORD serial = 0;
    DWORD flags = 0;
    if (!GetVolumePathNameW(ancestor.c_str(), volume_path, MAX_PATH) ||
        !GetVolumeInformationW(volume_path, nullptr, 0, &serial, nullptr, &flags, nullptr, 0)) {
        return {};
    }
    std::ostringstream value;
    value << kind << '\n' << normalized_path(volume_path) << '\n' << serial << '\n' << flags;
    return hash_text(value.str());
}
#elif defined(__APPLE__)
bool components_stable(const std::vector<fs::path>& components)
{
    for (const fs::path& path : components) {
        struct stat info {};
        if (lstat(path.c_str(), &info) != 0 || S_ISLNK(info.st_mode)) return false;
    }
    return true;
}

std::pair<bool, std::string> filesystem_kind(const fs::path& ancestor)
{
    struct statfs info {};
    if (statfs(ancestor.c_str(), &info) != 0 || (info.f_flags & MNT_LOCAL) == 0) {
        return {false, "unproven"};
    }
    return {true, std::string("macos_") + info.f_fstypename};
}

std::string filesystem_identity(const fs::path& ancestor, const std::string& kind)
{
    struct stat info {};
    if (stat(ancestor.c_str(), &info) != 0) return {};
    return hash_text(kind + "\n" + std::to_string(info.st_dev));
}
#else
bool components_stable(const std::vector<fs::path>& components)
{
    for (const fs::path& path : components) {
        struct stat info {};
        if (lstat(path.c_str(), &info) != 0 || S_ISLNK(info.st_mode)) return false;
    }
    return true;
}

std::pair<bool, std::string> filesystem_kind(const fs::path& ancestor)
{
    std::ifstream mounts("/proc/self/mountinfo");
    if (!mounts) return {false, "unproven"};
    const std::string candidate = normalized_path(ancestor);
    std::string selected_mount;
    std::string selected_type;
    std::string line;
    while (std::getline(mounts, line)) {
        const std::size_t separator = line.find(" - ");
        if (separator == std::string::npos) continue;
        std::istringstream left(line.substr(0, separator));
        std::string field;
        std::vector<std::string> fields;
        while (left >> field) fields.push_back(field);
        std::istringstream right(line.substr(separator + 3));
        std::string type;
        right >> type;
        if (fields.size() < 5) continue;
        const std::string& mount = fields[4];
        if ((candidate == mount || (candidate.size() > mount.size() &&
             candidate.rfind(mount == "/" ? mount : mount + "/", 0) == 0)) &&
            mount.size() >= selected_mount.size()) {
            selected_mount = mount;
            selected_type = type;
        }
    }
    if (selected_type.empty()) return {false, "unproven"};
    static const std::vector<std::string> remote = {
        "9p", "afs", "ceph", "cifs", "fuse.sshfs", "nfs", "nfs4", "smb3"};
    if (std::find(remote.begin(), remote.end(), selected_type) != remote.end()) {
        return {false, "linux_" + selected_type};
    }
    return {true, "linux_" + selected_type};
}

std::string filesystem_identity(const fs::path& ancestor, const std::string& kind)
{
    struct stat info {};
    if (stat(ancestor.c_str(), &info) != 0) return {};
    return hash_text(kind + "\n" + std::to_string(info.st_dev));
}
#endif

} // namespace

namespace usk::policy {

TargetEvidence inspect_live_target(const TargetInspectionRequest& request)
{
    TargetEvidence evidence;
    evidence.target_class = request.target_class;
    evidence.target_root = request.target_root;
    evidence.authorized_acceptance_root = request.authorized_acceptance_root;
    evidence.required_bytes = request.required_bytes;
    evidence.persistent_effects = request.persistent_effects;
    evidence.persistent_effects_complete = !request.persistent_effects.empty();
    evidence.explicitly_supplied = !request.target_root.empty();

    if (request.target_root.empty() || !request.target_root.is_absolute()) return evidence;
    const fs::path ancestor = existing_ancestor(request.target_root);
    const auto components = existing_components(request.target_root);
    evidence.path_components_stable = components_stable(components);
    evidence.mount_redirection_absent = evidence.path_components_stable;
    evidence.excluded_roots_absent = protected_root_absent(
        request.target_root, request.authorized_acceptance_root);

    std::error_code error;
    if (!fs::exists(request.target_root, error)) {
        if (error) throw std::runtime_error("target state inspection failed");
        evidence.target_state = TargetState::nonexistent;
    } else if (fs::is_directory(request.target_root, error) && !error &&
               fs::is_empty(request.target_root, error) && !error) {
        evidence.target_state = TargetState::empty;
    } else {
        evidence.target_state = TargetState::nonempty;
    }

    const auto classified = filesystem_kind(ancestor);
    evidence.local_filesystem = classified.first;
    evidence.filesystem_kind = classified.second;
    evidence.filesystem_identity_digest = filesystem_identity(ancestor, classified.second);
    const fs::space_info capacity = fs::space(ancestor, error);
    if (error) throw std::runtime_error("target capacity inspection failed");
    evidence.available_bytes = capacity.available;
    evidence.source_target_distinct = source_target_distinct(
        request.source_archive, request.target_root);

    try {
        usk::base::StableFile source(request.source_archive);
        const auto& source_identity = source.identity();
        std::ostringstream identity;
        identity << normalized_path(request.target_root) << '\n'
                 << target_state_name(evidence.target_state) << '\n'
                 << normalized_path(ancestor) << '\n'
                 << evidence.filesystem_identity_digest << '\n'
                 << source_identity.volume_id << '\n' << source_identity.file_id << '\n'
                 << source_identity.size_bytes << '\n' << source_identity.modified_time_ns;
        evidence.target_identity_digest = hash_text(identity.str());
        source.verify_unchanged();
    } catch (const std::exception&) {
        evidence.source_target_distinct = false;
        evidence.target_identity_digest.clear();
    }
    return evidence;
}

InspectedTarget inspect_and_evaluate_live_target(
    Activation activation,
    const TargetInspectionRequest& request)
{
    InspectedTarget result;
    result.evidence = inspect_live_target(request);
    result.decision = evaluate_live_target(activation, result.evidence);
    return result;
}

} // namespace usk::policy
