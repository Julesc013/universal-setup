#include "usk_package_verify.h"

#include "usk/usk_result.h"
#include "usk_sha256.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace {

constexpr std::uintmax_t max_manifest_bytes = 64u * 1024u;
constexpr std::uintmax_t max_metadata_bytes = 4u * 1024u * 1024u;
constexpr std::uintmax_t max_file_bytes = 2ull * 1024ull * 1024ull * 1024ull;
constexpr std::uintmax_t max_total_bytes = 16ull * 1024ull * 1024ull * 1024ull;
constexpr std::size_t max_files = 10000u;

struct Component {
    std::string sha256;
    std::string role;
    std::uintmax_t size = 0;
};

struct Report {
    std::string command;
    std::string package_root;
    std::string profile_id;
    std::string target_os;
    std::string target_arch;
    std::string linkage_model;
    std::string integrity = "fail";
    std::string authenticity = "not_checked";
    std::string compatibility = "fail";
    std::string completeness = "fail";
    std::string target_match = "not_requested";
    std::size_t files_verified = 0;
    std::vector<std::string> problems;
};

std::string trim(const std::string& value)
{
    std::size_t first = 0;
    while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first]))) ++first;
    std::size_t last = value.size();
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1]))) --last;
    return value.substr(first, last - first);
}

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

std::string json_string(const std::string& text, const std::string& key)
{
    const std::string marker = "\"" + key + "\"";
    std::size_t position = text.find(marker);
    if (position == std::string::npos) return {};
    position = text.find(':', position + marker.size());
    if (position == std::string::npos) return {};
    position = text.find('"', position + 1);
    if (position == std::string::npos) return {};
    std::string value;
    for (++position; position < text.size(); ++position) {
        char ch = text[position];
        if (ch == '"') return value;
        if (ch != '\\') {
            value.push_back(ch);
            continue;
        }
        if (++position >= text.size()) return {};
        switch (text[position]) {
        case '"': value.push_back('"'); break;
        case '\\': value.push_back('\\'); break;
        case '/': value.push_back('/'); break;
        case 'n': value.push_back('\n'); break;
        case 'r': value.push_back('\r'); break;
        case 't': value.push_back('\t'); break;
        default: return {};
        }
    }
    return {};
}

std::uintmax_t json_integer(const std::string& text, const std::string& key, bool& found)
{
    found = false;
    const std::string marker = "\"" + key + "\"";
    std::size_t position = text.find(marker);
    if (position == std::string::npos) return 0;
    position = text.find(':', position + marker.size());
    if (position == std::string::npos) return 0;
    ++position;
    while (position < text.size() && std::isspace(static_cast<unsigned char>(text[position]))) ++position;
    std::uintmax_t value = 0;
    while (position < text.size() && std::isdigit(static_cast<unsigned char>(text[position]))) {
        found = true;
        value = value * 10u + static_cast<unsigned int>(text[position] - '0');
        ++position;
    }
    return value;
}

std::string read_bounded(const fs::path& path, std::uintmax_t limit)
{
    std::error_code error;
    const std::uintmax_t size = fs::file_size(path, error);
    if (error || size > limit) throw std::runtime_error("metadata is missing, unreadable, or over budget: " + path.string());
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("metadata cannot be opened: " + path.string());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

bool has_reparse_or_symlink(const fs::path& path)
{
    std::error_code error;
    if (fs::is_symlink(fs::symlink_status(path, error))) return true;
#if defined(_WIN32)
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    return false;
#endif
}

bool crosses_link_or_reparse(const fs::path& path)
{
    fs::path current = path.root_path();
    for (const fs::path& component : path.relative_path()) {
        current /= component;
        std::error_code error;
        if (fs::exists(current, error) && has_reparse_or_symlink(current)) return true;
        if (error) return true;
    }
    return false;
}

bool contained_relative(const fs::path& relative)
{
    if (relative.empty() || relative.is_absolute() || relative.has_root_name()) return false;
    for (const fs::path& component : relative) {
        if (component == ".." || component == "." || component.empty()) return false;
    }
    return true;
}

bool safe_path(const fs::path& root, const fs::path& relative, std::string& problem)
{
    if (!contained_relative(relative)) {
        problem = "path is absolute or escapes package root: " + relative.generic_string();
        return false;
    }
    fs::path current = root;
    for (const fs::path& component : relative) {
        current /= component;
        if (has_reparse_or_symlink(current)) {
            problem = "path crosses a link or reparse point: " + relative.generic_string();
            return false;
        }
    }
    return true;
}

std::map<std::string, std::string> parse_toml_scalars(const std::string& text)
{
    std::map<std::string, std::string> values;
    std::istringstream input(text);
    std::string line;
    while (std::getline(input, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == '[') continue;
        const std::size_t separator = line.find('=');
        if (separator == std::string::npos) throw std::runtime_error("malformed TOML scalar");
        std::string key = trim(line.substr(0, separator));
        std::string value = trim(line.substr(separator + 1));
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.size() - 2);
        }
        if (key.empty() || value.empty() || !values.emplace(key, value).second) {
            throw std::runtime_error("duplicate or empty TOML scalar: " + key);
        }
    }
    return values;
}

std::map<std::string, std::string> parse_toml_header(const std::string& text)
{
    const std::size_t section = text.find("\n[");
    return parse_toml_scalars(section == std::string::npos ? text : text.substr(0, section));
}

std::map<std::string, std::string> parse_workspace_pins(const std::string& text)
{
    std::map<std::string, std::string> pins;
    std::istringstream input(text);
    std::string line;
    std::string id;
    while (std::getline(input, line)) {
        line = trim(line);
        if (line.rfind("id = \"", 0) == 0 && line.back() == '"') {
            id = line.substr(6, line.size() - 7);
        } else if (line.rfind("pin = \"", 0) == 0 && line.back() == '"' && !id.empty()) {
            pins[id] = line.substr(7, line.size() - 8);
            id.clear();
        }
    }
    return pins;
}

bool valid_sha256(const std::string& value)
{
    return value.size() == 64u && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isdigit(ch) || (ch >= 'a' && ch <= 'f');
    });
}

bool valid_revision(const std::string& value)
{
    return value.size() == 40u && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isdigit(ch) || (ch >= 'a' && ch <= 'f');
    });
}

std::map<std::string, std::string> parse_hashes(const std::string& text)
{
    std::map<std::string, std::string> hashes;
    std::istringstream input(text);
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.size() < 67u || line[64] != ' ' || line[65] != ' ') {
            throw std::runtime_error("malformed hashes.sha256 line");
        }
        std::string hash = line.substr(0, 64);
        std::string path = line.substr(66);
        if (!valid_sha256(hash) || !contained_relative(fs::path(path)) ||
            !hashes.emplace(path, hash).second) {
            throw std::runtime_error("invalid or duplicate hashes.sha256 entry: " + path);
        }
        if (hashes.size() > max_files) throw std::runtime_error("hash entry count exceeds budget");
    }
    if (hashes.empty()) throw std::runtime_error("hash manifest is empty");
    return hashes;
}

std::map<std::string, Component> parse_components(const std::string& text)
{
    if (json_string(text, "schema") != "facman.package_components.v1") {
        throw std::runtime_error("unsupported components schema");
    }
    std::map<std::string, Component> components;
    std::size_t position = 0;
    while ((position = text.find("\"destination\"", position)) != std::string::npos) {
        const std::size_t begin = text.rfind('{', position);
        const std::size_t end = text.find('}', position);
        if (begin == std::string::npos || end == std::string::npos) {
            throw std::runtime_error("malformed component object");
        }
        const std::string object = text.substr(begin, end - begin + 1);
        const std::string destination = json_string(object, "destination");
        Component component;
        component.sha256 = json_string(object, "sha256");
        component.role = json_string(object, "runtime_role");
        bool size_found = false;
        component.size = json_integer(object, "size", size_found);
        if (!contained_relative(fs::path(destination)) || !valid_sha256(component.sha256) ||
            !size_found || (component.role != "runtime_required" &&
                            component.role != "compatibility_reference") ||
            !components.emplace(destination, component).second) {
            throw std::runtime_error(
                "runtime_role is invalid or component metadata is malformed: " + destination);
        }
        if (components.size() > max_files) throw std::runtime_error("component count exceeds budget");
        position = end + 1;
    }
    if (components.empty()) throw std::runtime_error("component manifest is empty");
    return components;
}

std::set<std::string> package_files(const fs::path& root, Report& report)
{
    std::set<std::string> files;
    std::uintmax_t total = 0;
    std::error_code error;
    fs::recursive_directory_iterator iterator(root, fs::directory_options::none, error);
    fs::recursive_directory_iterator end;
    while (!error && iterator != end) {
        const fs::path relative = fs::relative(iterator->path(), root, error);
        if (error) break;
        if (has_reparse_or_symlink(iterator->path())) {
            report.problems.push_back("package contains a link or reparse point: " + relative.generic_string());
            if (iterator->is_directory(error)) iterator.disable_recursion_pending();
        } else if (iterator->is_regular_file(error)) {
            const std::uintmax_t size = iterator->file_size(error);
            if (error || size > max_file_bytes || total > max_total_bytes - size) {
                report.problems.push_back("file or total package size exceeds budget: " + relative.generic_string());
            } else {
                total += size;
            }
            const std::string name = relative.generic_string();
            if (name != "manifest/hashes.sha256") files.insert(name);
            if (files.size() > max_files) {
                report.problems.push_back("package file count exceeds budget");
                break;
            }
        }
        iterator.increment(error);
    }
    if (error) report.problems.push_back("package traversal failed: " + error.message());
    return files;
}

std::string report_json(const Report& report)
{
    const bool required_pass = report.integrity == "pass" &&
        report.compatibility == "pass" && report.completeness == "pass" &&
        (report.target_match == "pass" || report.target_match == "not_requested");
    const std::string status = !required_pass ? "fail" :
        (report.authenticity == "verified" ? "pass" : "warn");
    std::ostringstream out;
    out << "{\"schema\":\"usk.command_response.v1\",\"status\":\"ok\",\"payload\":{";
    out << "\"schema\":\"usk.package_verify_report.v1\",";
    out << "\"command\":" << quote(report.command) << ",";
    out << "\"status\":" << quote(status) << ",";
    out << "\"package_root\":" << quote(report.package_root) << ",";
    out << "\"profile_id\":" << quote(report.profile_id) << ",";
    out << "\"target_os\":" << quote(report.target_os) << ",";
    out << "\"target_arch\":" << quote(report.target_arch) << ",";
    out << "\"linkage_model\":" << quote(report.linkage_model) << ",";
    out << "\"integrity\":" << quote(report.integrity) << ",";
    out << "\"authenticity\":" << quote(report.authenticity) << ",";
    out << "\"compatibility\":" << quote(report.compatibility) << ",";
    out << "\"completeness\":" << quote(report.completeness) << ",";
    out << "\"target_match\":" << quote(report.target_match) << ",";
    out << "\"files_verified\":" << report.files_verified << ",\"problems\":[";
    for (std::size_t index = 0; index < report.problems.size(); ++index) {
        if (index != 0) out << ',';
        out << quote(report.problems[index]);
    }
    out << "]},\"error\":null}";
    return out.str();
}

std::string refused_json(const std::string& command, const std::string& problem)
{
    return "{\"schema\":\"usk.command_response.v1\",\"status\":\"refused\",\"payload\":{"
        "\"schema\":\"usk.package_verify_report.v1\",\"command\":" + quote(command) +
        ",\"status\":\"refused\",\"package_root\":\"\",\"profile_id\":\"\","
        "\"target_os\":\"\",\"target_arch\":\"\",\"linkage_model\":\"\","
        "\"integrity\":\"not_checked\",\"authenticity\":\"not_checked\","
        "\"compatibility\":\"not_checked\",\"completeness\":\"not_checked\","
        "\"target_match\":\"not_requested\",\"files_verified\":0,\"problems\":[" + quote(problem) +
        "]},\"error\":{\"code\":\"package_verification_refused\",\"message\":" +
        quote(problem) + "}}";
}

std::string verify_package(const std::string& request, bool audit)
{
    Report report;
    report.command = audit ? "package.audit" : "package.verify";
    if (json_string(request, "schema") != "usk.package_verify_request.v1") {
        throw std::runtime_error("unsupported or missing package verification request schema");
    }
    report.package_root = json_string(request, "package_root");
    const std::string expected_os = json_string(request, "expected_target_os");
    const std::string expected_arch = json_string(request, "expected_target_arch");
    const std::string expected_linkage = json_string(request, "expected_linkage_model");
    if (report.package_root.empty()) throw std::runtime_error("package_root is required");

    fs::path root(report.package_root);
    std::error_code error;
    root = fs::absolute(root, error).lexically_normal();
    if (error || !fs::is_directory(root) || crosses_link_or_reparse(root)) {
        throw std::runtime_error("package root is missing, unreadable, or linked");
    }
    report.package_root = root.string();
    const fs::path package_manifest_path = root / "manifest" / "package.v1.toml";
    const fs::path component_path = root / "manifest" / "components.v1.json";
    const fs::path hashes_path = root / "manifest" / "hashes.sha256";
    for (const fs::path& path : {package_manifest_path, component_path, hashes_path}) {
        std::string unsafe;
        if (!safe_path(root, fs::relative(path, root), unsafe) || !fs::is_regular_file(path)) {
            throw std::runtime_error(unsafe.empty() ? "required package metadata is missing" : unsafe);
        }
    }

    const auto manifest = parse_toml_scalars(read_bounded(package_manifest_path, max_manifest_bytes));
    const std::set<std::string> allowed_manifest_keys = {
        "schema", "profile_id", "lane", "target_os", "target_arch", "package_type",
        "entrypoint", "linkage_model", "release_profile", "package_manifest",
        "workspace_lock", "source_revision", "proof_baseline_revision",
        "universal_launcher_revision", "universal_setup_revision", "artifact_level",
        "signed", "published", "source_dirty", "python_runtime", "bundles_factorio_binaries"};
    for (const auto& [key, value] : manifest) {
        (void)value;
        if (allowed_manifest_keys.find(key) == allowed_manifest_keys.end()) {
            throw std::runtime_error("unsupported package manifest field: " + key);
        }
    }
    auto required = [&](const std::string& key) -> std::string {
        const auto found = manifest.find(key);
        if (found == manifest.end()) throw std::runtime_error("package manifest is missing " + key);
        return found->second;
    };
    if (required("schema") != "facman.built_package.v1") {
        throw std::runtime_error("unsupported package manifest schema");
    }
    report.profile_id = required("profile_id");
    report.target_os = required("target_os");
    report.target_arch = required("target_arch");
    report.linkage_model = required("linkage_model");
    const std::string entrypoint = required("entrypoint");
    const std::string workspace_lock = required("workspace_lock");
    const fs::path release_profile(required("release_profile"));
    const fs::path package_definition(required("package_manifest"));
    report.authenticity = required("signed") == "false"
        ? "not_proven_unsigned"
        : "not_proven_declared_signed";

    const auto components = parse_components(read_bounded(component_path, max_metadata_bytes));
    const auto hashes = parse_hashes(read_bounded(hashes_path, max_metadata_bytes));
    const std::size_t traversal_problem_count = report.problems.size();
    const auto files = package_files(root, report);
    const bool traversal_ok = report.problems.size() == traversal_problem_count;

    bool compatibility_ok = true;
    for (const fs::path& metadata : {release_profile, package_definition}) {
        std::string metadata_problem;
        if (!safe_path(root, metadata, metadata_problem) || !fs::is_regular_file(root / metadata)) {
            compatibility_ok = false;
            report.problems.push_back(metadata_problem.empty()
                ? "declared compatibility metadata is missing: " + metadata.generic_string()
                : metadata_problem);
        }
    }
    if (compatibility_ok) {
        const auto profile = parse_toml_header(read_bounded(root / release_profile, max_manifest_bytes));
        const auto definition = parse_toml_header(read_bounded(root / package_definition, max_manifest_bytes));
        const bool profile_matches = profile.find("id") != profile.end() &&
            profile.at("id") == report.profile_id && profile.find("target_os") != profile.end() &&
            profile.at("target_os") == report.target_os && profile.find("target_arch") != profile.end() &&
            profile.at("target_arch") == report.target_arch;
        const bool definition_matches = definition.find("platform") != definition.end() &&
            definition.at("platform") == report.target_os && definition.find("architecture") != definition.end() &&
            (definition.at("architecture") == report.target_arch ||
             definition.at("architecture") == "configured_by_track") &&
            definition.find("linkage_model") != definition.end() &&
            definition.at("linkage_model") == report.linkage_model && definition.find("entrypoint") != definition.end() &&
            definition.at("entrypoint") == entrypoint;
        if (!profile_matches || !definition_matches) {
            compatibility_ok = false;
            report.problems.push_back("unknown built package profile or profile metadata mismatch");
        }
    }
    for (const auto& [path, component] : components) {
        const auto hash = hashes.find(path);
        if (hash == hashes.end() || hash->second != component.sha256) {
            compatibility_ok = false;
            report.problems.push_back("component metadata disagrees with hashes: " + path);
        }
    }
    const fs::path lock_path(workspace_lock);
    std::string unsafe;
    if (!safe_path(root, lock_path, unsafe) || !fs::is_regular_file(root / lock_path)) {
        compatibility_ok = false;
        report.problems.push_back(unsafe.empty() ? "workspace lock is missing" : unsafe);
    } else {
        const auto pins = parse_workspace_pins(read_bounded(root / lock_path, max_manifest_bytes));
        const std::map<std::string, std::string> expected_pins = {
            {"factorio_binding", required("proof_baseline_revision")},
            {"universal_launcher", required("universal_launcher_revision")},
            {"universal_setup", required("universal_setup_revision")},
        };
        for (const auto& [id, pin] : expected_pins) {
            if (pins.find(id) == pins.end() || pins.at(id) != pin || !valid_revision(pin)) {
                compatibility_ok = false;
                report.problems.push_back("source revisions disagree with workspace lock: " + id);
            }
        }
    }
    report.compatibility = compatibility_ok ? "pass" : "fail";

    bool completeness_ok = files.size() == hashes.size() && traversal_ok;
    if (!completeness_ok) report.problems.push_back("package file closure differs from hashes.sha256");
    if (hashes.find(entrypoint) == hashes.end()) {
        completeness_ok = false;
        report.problems.push_back("entrypoint is not covered by hashes.sha256");
    }
    for (const std::string& file : files) {
        if (hashes.find(file) == hashes.end()) {
            completeness_ok = false;
            report.problems.push_back("unhashed package file: " + file);
        }
    }
    report.completeness = completeness_ok ? "pass" : "fail";

    bool integrity_ok = true;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    for (const auto& [relative, expected_hash] : hashes) {
        if (std::chrono::steady_clock::now() > deadline) {
            integrity_ok = false;
            report.problems.push_back("package verification exceeded the 30 second time budget");
            break;
        }
        std::string path_problem;
        const fs::path relative_path(relative);
        const fs::path path = root / relative_path;
        if (!safe_path(root, relative_path, path_problem) || !fs::is_regular_file(path)) {
            integrity_ok = false;
            report.problems.push_back(path_problem.empty()
                ? "missing or unsafe hashed file: " + relative
                : path_problem);
            continue;
        }
        const auto component = components.find(relative);
        std::error_code size_error;
        const std::uintmax_t size = fs::file_size(path, size_error);
        if (component != components.end() && (!size_error && component->second.size != size)) {
            integrity_ok = false;
            report.problems.push_back("component size mismatch: " + relative);
        }
        if (usk::verify::sha256_hex_file(path) != expected_hash) {
            integrity_ok = false;
            report.problems.push_back("SHA-256 mismatch: " + relative);
        } else {
            ++report.files_verified;
        }
    }
    report.integrity = integrity_ok ? "pass" : "fail";

    if (!expected_os.empty() || !expected_arch.empty() || !expected_linkage.empty()) {
        const bool matches = (expected_os.empty() || expected_os == report.target_os) &&
            (expected_arch.empty() || expected_arch == report.target_arch) &&
            (expected_linkage.empty() || expected_linkage == report.linkage_model);
        report.target_match = matches ? "pass" : "fail";
        if (!matches) {
            report.problems.push_back(
                "target, linkage, or entrypoint identity does not match the request");
        }
    }
    if (report.authenticity == "not_proven_declared_signed") {
        report.problems.push_back("package declares signing but no trusted signature proof is available");
    }
    return report_json(report);
}

} // namespace

namespace usk::verify {
std::string sha256_hex_file(const fs::path& path)
{
    return usk::base::sha256_hex_file(path);
}
} // namespace usk::verify

extern "C" char* usk_package_verify_command_json(
    const char* request_json,
    size_t request_size,
    int audit_mode,
    int* out_command_status)
{
    if (out_command_status == nullptr) return nullptr;
    const std::string command = audit_mode ? "package.audit" : "package.verify";
    std::string response;
    try {
        if (request_json == nullptr || request_size == 0 || request_size > max_metadata_bytes) {
            throw std::runtime_error("bounded package verification request is required");
        }
        response = verify_package(std::string(request_json, request_size), audit_mode != 0);
        *out_command_status = USK_STATUS_OK;
    } catch (const std::exception& error) {
        response = refused_json(command, error.what());
        *out_command_status = USK_STATUS_ERROR;
    }
    char* result = static_cast<char*>(std::malloc(response.size() + 1));
    if (result == nullptr) {
        *out_command_status = USK_STATUS_ERROR;
        return nullptr;
    }
    std::memcpy(result, response.c_str(), response.size() + 1);
    return result;
}

extern "C" void usk_package_verify_command_free(char* value)
{
    std::free(value);
}
