// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_creation_observation.h"
#include "usk_publisher_process_boundary.h"
#include "usk_publisher_worker_security.h"

#if defined(_WIN32)
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_publisher_token_observation.h"
#include "usk_publisher_tree_observation.h"
#include "usk_sha256.h"
#include "usk_utf8_path.h"
#include <algorithm>
#include <filesystem>
#include <map>
#include <set>
#include <stdexcept>

namespace usk::platform::windows {
namespace {
using usk::json::Value;
thread_local PublisherCreationCapture* active_capture = nullptr;

void require(bool condition, const char* diagnostic) {
    if (!condition) throw std::runtime_error(diagnostic);
}

std::string bytes_hex(const unsigned char* bytes, std::size_t size) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string text;
    text.reserve(size * 2);
    for (std::size_t index = 0; index < size; ++index) {
        text.push_back(digits[bytes[index] >> 4]);
        text.push_back(digits[bytes[index] & 15u]);
    }
    return text;
}

std::string identity_hex(std::uint64_t number) {
    unsigned char bytes[8]{};
    for (std::size_t index = 0; index < 8; ++index) {
        bytes[7 - index] = static_cast<unsigned char>(number & 255u);
        number >>= 8;
    }
    return bytes_hex(bytes, 8);
}

std::string byte_digest(const std::vector<unsigned char>& bytes) {
    usk::base::Sha256 hash;
    hash.update(bytes.data(), bytes.size());
    return hash.finish();
}

std::string utf8(const std::wstring& text) {
    return usk::base::path_to_utf8(std::filesystem::path(text));
}

Value creator(const PublisherServiceObservation& service) {
    return Value(Value::Object{
        {"service_name", Value(utf8(service.service_name))},
        {"service_sid", Value(service.service_sid)},
        {"process_id", Value(static_cast<std::uint64_t>(service.process_id))},
        {"token_id", Value(identity_hex(service.token.identity.token_id))},
        {"authentication_id", Value(identity_hex(service.token.identity.authentication_id))},
        {"modified_id", Value(identity_hex(service.token.identity.modified_id))},
        {"token_type", Value(static_cast<std::uint64_t>(service.token.identity.token_type))}});
}

Value execution_creator(const Value& execution) {
    Value::Object result;
    for (const auto* key : {"service_name", "service_sid", "process_id", "token_id",
                           "authentication_id", "modified_id", "token_type"}) {
        result.emplace(key, execution.at("service").at(key));
    }
    return Value(std::move(result));
}

Value graph_row(const std::string& id, const std::string& parent,
    const std::string& name, bool directory) {
    const auto valid_id = [](const std::string& value) {
        return value.size() == 49 && value[16] == ':' &&
            std::all_of(value.begin(), value.begin() + 16, [](char ch) {
                return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'); }) &&
            std::all_of(value.begin() + 17, value.end(), [](char ch) {
                return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'); });
    };
    require(valid_id(id) && valid_id(parent) && id != parent &&
        id.substr(0, 16) == parent.substr(0, 16), "creation graph has invalid object/parent identities");
    const auto native_name = std::filesystem::u8path(name).wstring();
    require(is_publisher_canonical_component(native_name), "creation graph has a noncanonical child component");
    return Value(Value::Object{{"file_id", Value(id)}, {"parent_file_id", Value(parent)},
        {"name", Value(name)}, {"kind", Value(directory ? "directory" : "file")}});
}

std::string object_id(const Value& object) { return object.at("file_id").as_string(); }

Value call_profile() {
    // These are the exact bounded native primitive's arguments; it reports
    // success only for NTSTATUS 0 and IO_STATUS_BLOCK.Information FILE_CREATED.
    return Value(Value::Object{{"api", Value("NtCreateFile")},
        {"create_disposition", Value(std::uint64_t{2})},
        {"creation_result", Value(std::uint64_t{2})},
        {"ntstatus", Value(std::uint64_t{0})},
        {"object_attribute_flags", Value(std::uint64_t{0x40})},
        {"share_access", Value(std::uint64_t{7})},
        {"directory_create_options", Value(std::uint64_t{0x00200021})},
        {"file_create_options", Value(std::uint64_t{0x00200062})},
        {"directory_file_attributes", Value(std::uint64_t{FILE_ATTRIBUTE_DIRECTORY})},
        {"file_file_attributes", Value(std::uint64_t{FILE_ATTRIBUTE_NORMAL})},
        {"directory_access_mask", Value(std::uint64_t{
            FILE_READ_ATTRIBUTES | FILE_TRAVERSE | FILE_LIST_DIRECTORY | FILE_ADD_FILE |
            FILE_ADD_SUBDIRECTORY | DELETE | READ_CONTROL | SYNCHRONIZE})},
        {"file_access_mask", Value(std::uint64_t{
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES |
            DELETE | READ_CONTROL | SYNCHRONIZE})}});
}

std::vector<unsigned char> creation_descriptor(const std::string& sid) {
    return make_publisher_directory_security_descriptor(std::wstring(sid.begin(), sid.end()));
}
} // namespace

struct PublisherCreationCapture::Implementation {
    PublisherServiceObservation service;
    Value process_boundary;
    Value worker_security;
    PublisherHandleObservation boundary;
    std::vector<unsigned char> descriptor;
    std::map<std::string, Value> entries;
    std::size_t serialized_bytes = 0;

    void require_worker() const {
        const auto token = observe_current_publisher_token();
        require(has_restricted_publisher_token_facts(token, service.service_sid) &&
            GetCurrentProcessId() == service.process_id &&
            token.identity.token_id == service.token.identity.token_id &&
            token.identity.authentication_id == service.token.identity.authentication_id &&
            token.identity.modified_id == service.token.identity.modified_id &&
            token.identity.token_type == TokenPrimary,
            "publisher creation worker token changed");
        const auto process_current = observe_current_publisher_process_boundary();
        require_publisher_process_boundary(process_current, service.process_id, service.service_sid,
            service.token.process_groups);
        require(usk::json::canonical(process_current) == usk::json::canonical(process_boundary),
            "publisher creation process owner/DACL changed");
        const auto security_current = observe_current_publisher_worker_security();
        require_publisher_worker_security(security_current, service);
        require(usk::json::canonical(security_current) == usk::json::canonical(worker_security),
            "publisher creation token/default/thread security changed");
    }
};

PublisherCreationCapture::PublisherCreationCapture(HANDLE boundary, const std::wstring& service_name)
    : implementation_(std::make_unique<Implementation>()) {
    require(active_capture == nullptr, "publisher creation capture cannot nest");
    auto& state = *implementation_;
    state.service = observe_current_restricted_publisher_service(service_name);
    state.process_boundary = observe_current_publisher_process_boundary();
    require_publisher_process_boundary(state.process_boundary, state.service.process_id,
        state.service.service_sid, state.service.token.process_groups);
    state.worker_security = observe_current_publisher_worker_security();
    require_publisher_worker_security(state.worker_security, state.service);
    state.require_worker();
    state.boundary = observe_publisher_directory_handle(boundary);
    require_publisher_object_security_shape(state.boundary, state.service.service_sid);
    state.descriptor = creation_descriptor(state.service.service_sid);
    active_capture = this;
}

PublisherCreationCapture::~PublisherCreationCapture() {
    if (active_capture == this) active_capture = nullptr;
}

std::optional<PublisherCreationParentObservation> prepare_publisher_creation_observation(
    HANDLE parent, const std::vector<unsigned char>& descriptor) {
    if (!active_capture) return std::nullopt;
    auto& state = *active_capture->implementation_;
    state.require_worker();
    require(descriptor == state.descriptor, "publisher creation descriptor differs from its exact protected descriptor");
    const auto observed = observe_publisher_directory_handle(parent);
    require_publisher_object_security_shape(observed, state.service.service_sid);
    const auto found = state.entries.find(observed.file_id);
    require(observed.file_id == state.boundary.file_id ||
        (found != state.entries.end() && found->second.at("kind").as_string() == "directory"),
        "publisher creation parent has no bound creation lineage");
    return PublisherCreationParentObservation{observed};
}

void finish_publisher_creation_observation(
    const std::optional<PublisherCreationParentObservation>& before,
    HANDLE parent, HANDLE created, const std::wstring& name, bool directory,
    const PublisherCreationCallObservation& call) {
    require(before.has_value() == (active_capture != nullptr), "publisher creation capture changed across native call");
    if (!before) return;
    auto& state = *active_capture->implementation_;
    state.require_worker();
    const auto profile = call_profile();
    require(call.ntstatus == profile.at("ntstatus").as_unsigned() &&
        call.creation_result == profile.at("creation_result").as_unsigned() &&
        call.object_attribute_flags == profile.at("object_attribute_flags").as_unsigned() &&
        call.create_disposition == profile.at("create_disposition").as_unsigned() &&
        call.share_access == profile.at("share_access").as_unsigned() &&
        call.desired_access == profile.at(directory ? "directory_access_mask" : "file_access_mask").as_unsigned() &&
        call.create_options == profile.at(directory ? "directory_create_options" : "file_create_options").as_unsigned() &&
        call.file_attributes == profile.at(directory ? "directory_file_attributes" : "file_file_attributes").as_unsigned(),
        "publisher native creation arguments or actual result differ from the captured call profile");
    const auto parent_after = observe_publisher_directory_handle(parent);
    require_publisher_object_security_shape(parent_after, state.service.service_sid);
    require(parent_after.file_id == before->parent.file_id &&
        parent_after.native_name == before->parent.native_name,
        "publisher creation parent identity or name changed");
    const auto object = directory ? observe_publisher_directory_handle(created) :
        observe_publisher_file_handle(created);
    require_publisher_object_security_shape(object, state.service.service_sid);
    auto expected_name = before->parent.native_name;
    if (expected_name.empty() || expected_name.back() != L'\\') expected_name.push_back(L'\\');
    expected_name += name;
    require(object.native_name == expected_name &&
        observe_publisher_noninheritable_handle_flags(created) == 0 &&
        ((object.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == directory,
        "publisher created object differs from its supplied parent, component or handle flags");
    auto row = graph_row(object.file_id, before->parent.file_id, utf8(name), directory);
    state.require_worker();
    constexpr std::size_t maximum_objects = 200016;
    constexpr std::size_t maximum_bytes = 64u * 1024u * 1024u;
    const auto size = usk::json::canonical(row).size();
    require(state.entries.size() < maximum_objects && size <= maximum_bytes - state.serialized_bytes,
        "publisher creation capture exceeds its bounded graph budget");
    require(state.entries.emplace(object.file_id, std::move(row)).second,
        "publisher creation capture repeated a created object identity");
    state.serialized_bytes += size;
}

Value publisher_creation_graph(const Value& anchors, const Value& tree) {
    const auto& chain = anchors.at("chain").as_array();
    require(chain.size() == 1 && chain.front().at("component").as_string() == "publication",
        "publisher creation graph requires its direct publication chain");
    const auto boundary = object_id(anchors.at("boundary"));
    const auto publication = object_id(chain.front().at("object"));
    const auto staging = object_id(anchors.at("staging"));
    const auto root = object_id(tree.at("root"));
    std::map<std::string, Value> rows;
    const auto add = [&rows, &boundary](const std::string& id, const std::string& parent,
                           const std::string& name, bool directory) {
        require(id != boundary, "publisher creation graph cannot claim creation of its volume boundary");
        require(rows.emplace(id, graph_row(id, parent, name, directory)).second,
            "publisher creation graph aliases object identities");
    };
    add(publication, boundary, "publication", true);
    for (const auto& anchor : std::vector<std::pair<const char*, const char*>>{
        {"staging", "staging"}, {"destination_parent", "destination"},
        {"state", "state"}, {"journal", "journal"}}) {
        add(object_id(anchors.at(anchor.first)), publication, anchor.second, true);
    }
    add(root, staging, "candidate", true);
    std::map<std::string, std::pair<std::string, bool>> paths;
    for (const auto& entry : tree.at("descendants").as_array()) {
        auto path = entry.at("relative_path").as_string();
        std::replace(path.begin(), path.end(), '\\', '/');
        require(!path.empty() && path.front() != '/' && path.back() != '/' &&
            paths.emplace(path, std::make_pair(object_id(entry.at("object")),
                (entry.at("object").at("attributes").as_unsigned() & FILE_ATTRIBUTE_DIRECTORY) != 0)).second,
            "publisher creation graph repeats or omits a descendant path");
    }
    for (const auto& entry : paths) {
        const auto separator = entry.first.find_last_of('/');
        const auto name = entry.first.substr(separator == std::string::npos ? 0 : separator + 1);
        auto parent = root;
        if (separator != std::string::npos) {
            const auto found = paths.find(entry.first.substr(0, separator));
            require(found != paths.end() && found->second.second,
                "publisher creation graph omits an intermediate created directory");
            parent = found->second.first;
        }
        add(entry.second.first, parent, name, entry.second.second);
    }
    Value::Array result;
    for (const auto& row : rows) result.push_back(row.second);
    return Value(std::move(result));
}

Value PublisherCreationCapture::certificate(const Value& anchors,
    const Value& sealed_tree, const Value& execution) const {
    const auto& state = *implementation_;
    state.require_worker();
    require(object_id(anchors.at("boundary")) == state.boundary.file_id,
        "publisher creation certificate changed its volume boundary");
    const auto graph = publisher_creation_graph(anchors, sealed_tree);
    for (const auto& row : graph.as_array()) {
        const auto found = state.entries.find(row.at("file_id").as_string());
        require(found != state.entries.end() && usk::json::canonical(found->second) == usk::json::canonical(row),
            "publisher sealed graph contains an object without matching native creation lineage");
    }
    auto result = Value(Value::Object{{"schema", Value("usk.publisher.creation_observation.v3")},
        {"scope", Value("successful_service_file_create_calls_and_worker_security_to_bound_graph")},
        {"creator", creator(state.service)}, {"native_call", call_profile()},
        {"process_boundary", state.process_boundary},
        {"worker_security", state.worker_security},
        {"handle_flags", Value(std::uint64_t{0})},
        {"volume_boundary_file_id", Value(state.boundary.file_id)},
        {"creation_descriptor_sha256", Value(byte_digest(state.descriptor))},
        {"creation_descriptor_hex", Value(bytes_hex(state.descriptor.data(), state.descriptor.size()))},
        {"created_object_count", Value(static_cast<std::uint64_t>(graph.as_array().size()))},
        {"created_graph_sha256", Value(usk::json::sha256_canonical(graph))}});
    require_publisher_creation_certificate(result, anchors, sealed_tree, execution);
    return result;
}

void require_publisher_creation_certificate(const Value& certificate,
    const Value& anchors, const Value& tree, const Value& execution) {
    const auto descriptor = creation_descriptor(execution.at("service").at("service_sid").as_string());
    const auto graph = publisher_creation_graph(anchors, tree);
    const bool worker_bound = certificate.at("schema").as_string() == "usk.publisher.creation_observation.v3";
    const bool process_bound = worker_bound || certificate.at("schema").as_string() == "usk.publisher.creation_observation.v2";
    require((execution.at("schema").as_string() == "usk.publisher_execution_observation.v1" ||
             execution.at("schema").as_string() == "usk.publisher_execution_observation.v2" ||
             execution.at("schema").as_string() == "usk.publisher_execution_observation.v3") &&
        worker_bound == (execution.at("schema").as_string() == "usk.publisher_execution_observation.v3") &&
        process_bound == (execution.at("schema").as_string() != "usk.publisher_execution_observation.v1") &&
        process_bound == execution.contains("process_boundary") && worker_bound == execution.contains("worker_security"),
        "publisher creation certificate downgraded its original execution boundary");
    require(certificate.as_object().size() == (worker_bound ? 12u : process_bound ? 11u : 10u) &&
        (process_bound || certificate.at("schema").as_string() == "usk.publisher.creation_observation.v1") &&
        certificate.at("scope").as_string() == (worker_bound ?
            "successful_service_file_create_calls_and_worker_security_to_bound_graph" : process_bound ?
            "successful_service_file_create_calls_and_process_boundary_to_bound_graph" :
            "successful_service_file_create_calls_to_bound_graph") &&
        usk::json::canonical(certificate.at("creator")) == usk::json::canonical(execution_creator(execution)) &&
        usk::json::canonical(certificate.at("native_call")) == usk::json::canonical(call_profile()) &&
        certificate.at("handle_flags").as_unsigned() == 0 &&
        certificate.at("volume_boundary_file_id").as_string() == object_id(anchors.at("boundary")) &&
        certificate.at("creation_descriptor_sha256").as_string() == byte_digest(descriptor) &&
        certificate.at("creation_descriptor_hex").as_string() == bytes_hex(descriptor.data(), descriptor.size()) &&
        certificate.at("created_object_count").as_unsigned() == graph.as_array().size() &&
        certificate.at("created_graph_sha256").as_string() == usk::json::sha256_canonical(graph),
        "publisher retained creation certificate differs from its sealed graph or creator binding");
    if (process_bound) {
        require(usk::json::canonical(certificate.at("process_boundary")) ==
                usk::json::canonical(execution.at("process_boundary")),
            "publisher creation process boundary differs from its original prepared worker");
    }
    if (worker_bound) {
        require(usk::json::canonical(certificate.at("worker_security")) ==
            usk::json::canonical(execution.at("worker_security")),
            "publisher creation worker security differs from its original prepared worker");
    }
}
} // namespace usk::platform::windows
#endif
