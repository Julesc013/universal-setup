// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_product_info.h"

#include "usk_archive_payload.h"
#include "usk_json.h"
#include "usk_sha256.h"
#include "usk_utf8_path.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <initializer_list>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace usk::command {
namespace {

using usk::json::Value;
constexpr std::size_t bundle_limit = 8u * 1024u * 1024u;
constexpr std::uint64_t archive_total_limit = 1ull << 40;
constexpr std::uint64_t archive_entry_limit = 1ull << 38;

void exact_fields(const Value& value, std::initializer_list<const char*> names)
{
    const auto& fields = value.as_object();
    if (fields.size() != names.size()) throw std::runtime_error("unexpected bundle fields");
    for (const char* name : names) {
        if (!value.contains(name)) throw std::runtime_error("missing bundle field");
    }
}

void require_id(const std::string& value)
{
    if (value.empty() || value.size() > 128) throw std::runtime_error("invalid product ID");
    for (std::size_t index = 0; index < value.size(); ++index) {
        const unsigned char ch = static_cast<unsigned char>(value[index]);
        const bool alnum = (ch >= 'A' && ch <= 'Z') ||
            (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
        if (!alnum && (index == 0 || (ch != '.' && ch != '_' && ch != '-'))) {
            throw std::runtime_error("invalid product ID");
        }
    }
}

void require_sha256(const std::string& value)
{
    if (value.size() != 64 || !std::all_of(value.begin(), value.end(),
            [](char ch) { return (ch >= '0' && ch <= '9') ||
                (ch >= 'a' && ch <= 'f'); })) {
        throw std::runtime_error("invalid bundle digest");
    }
}

std::string read_bounded_file(const std::filesystem::path& path, std::size_t limit)
{
    if (std::filesystem::symlink_status(path).type() !=
            std::filesystem::file_type::regular) {
        throw std::runtime_error("bundle sidecar is not a regular file");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("bundle sidecar cannot be opened");
    std::string result;
    std::array<char, 65536> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) {
            if (result.size() > limit - static_cast<std::size_t>(count)) {
                throw std::runtime_error("bundle sidecar exceeds byte budget");
            }
            result.append(buffer.data(), static_cast<std::size_t>(count));
        }
    }
    if (input.bad()) throw std::runtime_error("bundle sidecar read failed");
    return result;
}

Value::Array ids(const Value& input, const std::set<std::string>* known = nullptr)
{
    const auto& values = input.as_array();
    Value::Array output;
    std::string previous;
    for (const auto& item : values) {
        const std::string& current = item.as_string();
        require_id(current);
        if ((!previous.empty() && current <= previous) ||
            (known != nullptr && known->count(current) == 0)) {
            throw std::runtime_error("bundle component references are invalid");
        }
        output.emplace_back(current);
        previous = current;
    }
    return output;
}

struct ComponentNode {
    bool required;
    bool default_selected;
    std::vector<std::string> dependencies;
    std::vector<std::string> conflicts;
};

using ComponentGraph = std::map<std::string, ComponentNode>;

Value::Array resolve_selection(const ComponentGraph& graph,
    const std::vector<std::string>& requested)
{
    if (requested.size() > 4096) {
        throw std::runtime_error("too many requested components");
    }
    std::map<std::string, int> state;
    std::vector<std::string> dependency_first;
    for (const auto& [start, node] : graph) {
        (void)node;
        if (state[start] == 2) continue;
        state[start] = 1;
        std::vector<std::pair<std::string, std::size_t>> stack{{start, 0}};
        while (!stack.empty()) {
            auto& frame = stack.back();
            const auto& dependencies = graph.at(frame.first).dependencies;
            if (frame.second == dependencies.size()) {
                state[frame.first] = 2;
                dependency_first.push_back(frame.first);
                stack.pop_back();
                continue;
            }
            const std::string dependency = dependencies[frame.second++];
            if (state[dependency] == 1) {
                throw std::runtime_error("component dependency cycle");
            }
            if (state[dependency] != 2) {
                state[dependency] = 1;
                stack.emplace_back(dependency, 0);
            }
        }
    }
    std::set<std::string> selected;
    std::vector<std::string> pending;
    for (const auto& [name, node] : graph) {
        if (node.required || node.default_selected) pending.push_back(name);
    }
    for (const auto& name : requested) {
        require_id(name);
        if (graph.count(name) == 0) {
            throw std::runtime_error("unknown requested component");
        }
        pending.push_back(name);
    }
    while (!pending.empty()) {
        const std::string name = pending.back();
        pending.pop_back();
        if (!selected.insert(name).second) continue;
        const auto& dependencies = graph.at(name).dependencies;
        pending.insert(pending.end(), dependencies.begin(), dependencies.end());
    }
    for (const auto& name : selected) {
        for (const auto& conflict : graph.at(name).conflicts) {
            if (selected.count(conflict) != 0) {
                throw std::runtime_error("selected components conflict");
            }
        }
    }
    Value::Array result;
    for (const auto& name : dependency_first) {
        if (selected.count(name) != 0) result.emplace_back(name);
    }
    return result;
}

} // namespace

std::string inspect_product(const std::filesystem::path& supplied,
    const std::vector<std::string>* requested)
{
    if (supplied.filename() != "product.bundle.json") {
        throw std::runtime_error("product bundle sidecar name is invalid");
    }
    const auto bundle_path = std::filesystem::absolute(supplied).lexically_normal();
    const auto archive_path = bundle_path.parent_path() / "payload.zip";
    const auto manifest_path = bundle_path.parent_path() / "prefab.manifest.json";
    const auto runtime_path = bundle_path.parent_path() / "usk_machine.exe";
    if (std::filesystem::symlink_status(archive_path).type() !=
            std::filesystem::file_type::regular) {
        throw std::runtime_error("payload sidecar is not a regular file");
    }
    const std::string source = read_bounded_file(bundle_path, bundle_limit);
    const std::string manifest_source = read_bounded_file(manifest_path, 1024u * 1024u);
    usk::json::ParseLimits limits;
    limits.max_bytes = bundle_limit;
    limits.max_string_bytes = 4096;
    limits.max_values = 300000;
    const Value bundle = usk::json::parse(source, limits);
    exact_fields(bundle, {"schema", "product_id", "publisher_id", "product_version",
        "target", "allowed_scopes", "components", "payload"});
    if (bundle.at("schema").as_string() != "usk.product_bundle.v1" ||
        bundle.at("target").as_string() != "windows-x64") {
        throw std::runtime_error("unsupported product bundle target");
    }
    require_id(bundle.at("product_id").as_string());
    require_id(bundle.at("publisher_id").as_string());
    const std::string& version = bundle.at("product_version").as_string();
    if (version.empty() || version.size() > 128) {
        throw std::runtime_error("invalid product version");
    }
    const auto& scopes = bundle.at("allowed_scopes").as_array();
    if (scopes.empty() || scopes.size() > 3) {
        throw std::runtime_error("invalid product scopes");
    }
    std::string previous_scope;
    for (const auto& scope : scopes) {
        const std::string& value = scope.as_string();
        if ((value != "portable" && value != "per_user" && value != "machine") ||
            (!previous_scope.empty() && value <= previous_scope)) {
            throw std::runtime_error("invalid product scope");
        }
        previous_scope = value;
    }
    const auto& components = bundle.at("components").as_array();
    if (components.empty() || components.size() > 4096) {
        throw std::runtime_error("invalid product component count");
    }
    std::set<std::string> component_names;
    std::string previous_component;
    for (const auto& component : components) {
        exact_fields(component, {"id", "required", "default_selected", "requires",
            "conflicts", "files"});
        const std::string& name = component.at("id").as_string();
        require_id(name);
        if ((!previous_component.empty() && name <= previous_component) ||
            component.at("required").type() != Value::Type::boolean ||
            component.at("default_selected").type() != Value::Type::boolean) {
            throw std::runtime_error("invalid product component");
        }
        component_names.insert(name);
        previous_component = name;
    }
    Value::Array component_ids;
    ComponentGraph graph;
    std::size_t relation_count = 0;
    std::map<std::string, std::pair<std::uint64_t, std::string>> expected;
    std::uint64_t total = 0;
    for (const auto& component : components) {
        const std::string& name = component.at("id").as_string();
        ComponentNode node{component.at("required").as_boolean(),
            component.at("default_selected").as_boolean(), {}, {}};
        for (const auto& reference : ids(component.at("requires"), &component_names)) {
            if (reference.as_string() == name) {
                throw std::runtime_error("self-referential component");
            }
            node.dependencies.push_back(reference.as_string());
        }
        for (const auto& reference : ids(component.at("conflicts"), &component_names)) {
            if (reference.as_string() == name) {
                throw std::runtime_error("self-referential component");
            }
            node.conflicts.push_back(reference.as_string());
        }
        relation_count += node.dependencies.size() + node.conflicts.size();
        if (relation_count > 65536) {
            throw std::runtime_error("component relation budget exceeded");
        }
        graph.emplace(name, std::move(node));
        component_ids.emplace_back(name);
        const auto& files = component.at("files").as_array();
        if (files.empty() || files.size() > 65536) {
            throw std::runtime_error("invalid component file count");
        }
        std::string previous_path;
        for (const auto& file : files) {
            exact_fields(file, {"path", "size_bytes", "sha256"});
            const std::string& path = file.at("path").as_string();
            if (path.empty() || path.size() > 4096 ||
                (!previous_path.empty() && path <= previous_path)) {
                throw std::runtime_error("invalid bundle file path order");
            }
            previous_path = path;
            const std::uint64_t size = file.at("size_bytes").as_unsigned();
            const std::string& sha256 = file.at("sha256").as_string();
            require_sha256(sha256);
            if (size > archive_entry_limit || total > archive_total_limit - size ||
                !expected.emplace(path, std::make_pair(size, sha256)).second ||
                expected.size() > 65536) {
                throw std::runtime_error("bundle file inventory exceeds limits");
            }
            total += size;
        }
    }
    const Value& payload = bundle.at("payload");
    exact_fields(payload, {"file", "size_bytes", "sha256"});
    if (payload.at("file").as_string() != "payload.zip") {
        throw std::runtime_error("payload sidecar name is invalid");
    }
    const std::uint64_t archive_size = payload.at("size_bytes").as_unsigned();
    if (archive_size == 0) throw std::runtime_error("payload sidecar is empty");
    const std::string& expected_archive_digest = payload.at("sha256").as_string();
    require_sha256(expected_archive_digest);
    usk::base::Sha256 bundle_digest;
    bundle_digest.update(reinterpret_cast<const unsigned char*>(source.data()), source.size());
    const std::string bundle_sha256 = bundle_digest.finish();
    usk::json::ParseLimits manifest_limits;
    manifest_limits.max_bytes = 1024u * 1024u;
    manifest_limits.max_string_bytes = 4096;
    const Value manifest = usk::json::parse(manifest_source, manifest_limits);
    exact_fields(manifest, {"schema", "profile", "product_id", "product_version",
        "target", "entries", "properties"});
    const std::string& profile = manifest.at("profile").as_string();
    if (manifest.at("schema").as_string() != "usk.prefab_envelope.v1" ||
        (profile != "sidecar" && profile != "one_file_carrier") ||
        manifest.at("product_id").as_string() != bundle.at("product_id").as_string() ||
        manifest.at("product_version").as_string() != version ||
        manifest.at("target").as_string() != "windows-x64") {
        throw std::runtime_error("prefab manifest differs from product bundle");
    }
    const Value& entries = manifest.at("entries");
    exact_fields(entries, {"usk_machine.exe", "payload.zip", "product.bundle.json"});
    const auto check_entry = [&](const char* name, std::uint64_t size,
        const std::string& digest) {
        const Value& entry = entries.at(name);
        exact_fields(entry, {"sha256", "size_bytes"});
        if (entry.at("sha256").as_string() != digest ||
            entry.at("size_bytes").as_unsigned() != size) {
            throw std::runtime_error("prefab member identity differs");
        }
    };
    check_entry("product.bundle.json", static_cast<std::uint64_t>(source.size()),
        bundle_sha256);
    check_entry("payload.zip", archive_size, expected_archive_digest);
    if (std::filesystem::symlink_status(runtime_path).type() !=
            std::filesystem::file_type::regular ||
        std::filesystem::file_size(runtime_path) > 256u * 1024u * 1024u) {
        throw std::runtime_error("prefab runtime member is invalid");
    }
    const std::uint64_t runtime_size = std::filesystem::file_size(runtime_path);
    const std::string runtime_sha256 = usk::base::sha256_hex_file(runtime_path);
    check_entry("usk_machine.exe", runtime_size, runtime_sha256);
    const Value& properties = manifest.at("properties");
    exact_fields(properties, {"entrypoint_count", "physical_file_count",
        "extraction_required", "installation_mode", "runtime_dependency_closure"});
    if (properties.at("installation_mode").as_string() != "inspect_only" ||
        properties.at("runtime_dependency_closure").as_string() != "unqualified" ||
        properties.at("entrypoint_count").as_unsigned() !=
            (profile == "sidecar" ? 1u : 0u) ||
        properties.at("physical_file_count").as_unsigned() !=
            (profile == "sidecar" ? 4u : 1u) ||
        properties.at("extraction_required").as_boolean() !=
            (profile != "sidecar")) {
        throw std::runtime_error("prefab delivery properties differ");
    }
    const Value budgets(Value::Object{
        {"max_entries", Value(static_cast<std::uint64_t>(expected.size()))},
        {"max_uncompressed_bytes", Value(std::max<std::uint64_t>(1, total))},
        {"max_entry_bytes", Value(archive_entry_limit)},
        {"max_depth", Value(std::uint64_t{64})},
        {"max_ratio", Value(std::uint64_t{100000})},
        {"max_elapsed_ms", Value(std::uint64_t{600000})}});
    const Value request(Value::Object{
        {"schema", Value("usk.archive_inspect_request.v1")},
        {"archive_path", Value(usk::base::path_to_utf8(archive_path))},
        {"archive_format", Value("zip")},
        {"budgets", budgets}});
    auto inspected = usk::archive::inspect_streaming_stored_payload(
        usk::json::canonical(request), "");
    if (inspected.source_sha256 != expected_archive_digest ||
        inspected.archive_size_bytes != archive_size ||
        inspected.files.size() != expected.size() ||
        inspected.uncompressed_bytes != total) {
        throw std::runtime_error("product payload identity differs from bundle");
    }
    for (const auto& file : inspected.files) {
        const auto match = expected.find(file.relative_path);
        if (match == expected.end() || match->second.first != file.size_bytes ||
            match->second.second != file.sha256 || file.compression_method != "stored") {
            throw std::runtime_error("product payload file differs from bundle");
        }
    }
    inspected.validate_source();
    if (read_bounded_file(bundle_path, bundle_limit) != source ||
        read_bounded_file(manifest_path, 1024u * 1024u) != manifest_source ||
        std::filesystem::file_size(runtime_path) != runtime_size ||
        usk::base::sha256_hex_file(runtime_path) != runtime_sha256) {
        throw std::runtime_error("product bundle changed during inspection");
    }
    const Value::Array selected_ids = resolve_selection(graph,
        requested == nullptr ? std::vector<std::string>{} : *requested);
    if (requested != nullptr) {
        Value::Array requested_ids;
        for (const auto& name : *requested) requested_ids.emplace_back(name);
        const Value result(Value::Object{
            {"schema", Value("usk.product_selection.v1")},
            {"status", Value("verified_read_only")},
            {"installation_mode", Value("inspect_only")},
            {"product_id", bundle.at("product_id")},
            {"product_version", bundle.at("product_version")},
            {"target", bundle.at("target")},
            {"requested_component_ids", Value(std::move(requested_ids))},
            {"selected_component_ids", Value(selected_ids)},
            {"bundle_sha256", Value(bundle_sha256)},
            {"payload_sha256", Value(inspected.source_sha256)}});
        return usk::json::canonical(result);
    }
    const Value result(Value::Object{
        {"schema", Value("usk.product_info.v1")},
        {"status", Value("verified_read_only")},
        {"installation_mode", Value("inspect_only")},
        {"product_id", bundle.at("product_id")},
        {"publisher_id", bundle.at("publisher_id")},
        {"product_version", bundle.at("product_version")},
        {"target", bundle.at("target")},
        {"prefab_profile", Value(profile)},
        {"allowed_scopes", bundle.at("allowed_scopes")},
        {"component_ids", Value(std::move(component_ids))},
        {"bundle_sha256", Value(bundle_sha256)},
        {"payload_sha256", Value(inspected.source_sha256)},
        {"file_count", Value(static_cast<std::uint64_t>(inspected.files.size()))},
        {"uncompressed_bytes", Value(inspected.uncompressed_bytes)}});
    return usk::json::canonical(result);
}

std::string inspect_product_info(const std::filesystem::path& bundle_path)
{
    return inspect_product(bundle_path, nullptr);
}

std::string inspect_product_selection(const std::filesystem::path& bundle_path,
    const std::vector<std::string>& requested)
{
    return inspect_product(bundle_path, &requested);
}

} // namespace usk::command
