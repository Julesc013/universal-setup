// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk/usk_api.h"
#include "usk_package_verify.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

namespace fs = std::filesystem;

namespace {

void write(const fs::path& path, const std::string& text)
{
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << text;
}

std::string escaped(const std::string& value)
{
    std::string result;
    for (char ch : value) {
        if (ch == '\\' || ch == '"') result.push_back('\\');
        result.push_back(ch);
    }
    return result;
}

void write_hashes(const fs::path& root)
{
    std::map<std::string, std::string> hashes;
    for (const fs::directory_entry& entry : fs::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) continue;
        const std::string relative = fs::relative(entry.path(), root).generic_string();
        if (relative == "manifest/hashes.sha256") continue;
        hashes[relative] = usk::verify::sha256_hex_file(entry.path());
    }
    std::ostringstream output;
    for (const auto& [path, hash] : hashes) output << hash << "  " << path << "\n";
    write(root / "manifest" / "hashes.sha256", output.str());
}

void create_package(const fs::path& root)
{
    write(root / "bin" / "facman", "synthetic executable\n");
    write(root / "release" / "index" / "workspace_lock.v1.toml",
        "schema = \"flaunch.workspace_lock.v1\"\n"
        "[[component]]\nid = \"factorio_binding\"\npin = \"1111111111111111111111111111111111111111\"\n"
        "[[component]]\nid = \"universal_launcher\"\npin = \"2222222222222222222222222222222222222222\"\n"
        "[[component]]\nid = \"universal_setup\"\npin = \"3333333333333333333333333333333333333333\"\n");
    write(root / "release" / "profiles" / "synthetic_linux_x64" / "profile.toml",
        "schema = \"facman.release_profile.v1\"\n"
        "id = \"synthetic_linux_x64\"\n"
        "target_os = \"linux\"\n"
        "target_arch = \"x64\"\n");
    write(root / "release" / "packaging" / "synthetic.v1.toml",
        "schema = \"facman.packaging.bundle_manifest.v1\"\n"
        "platform = \"linux\"\n"
        "architecture = \"x64\"\n"
        "linkage_model = \"static_first\"\n"
        "entrypoint = \"bin/facman\"\n");
    write(root / "manifest" / "package.v1.toml",
        "schema = \"facman.built_package.v1\"\n"
        "profile_id = \"synthetic_linux_x64\"\n"
        "target_os = \"linux\"\n"
        "target_arch = \"x64\"\n"
        "linkage_model = \"static_first\"\n"
        "entrypoint = \"bin/facman\"\n"
        "workspace_lock = \"release/index/workspace_lock.v1.toml\"\n"
        "release_profile = \"release/profiles/synthetic_linux_x64/profile.toml\"\n"
        "package_manifest = \"release/packaging/synthetic.v1.toml\"\n"
        "proof_baseline_revision = \"1111111111111111111111111111111111111111\"\n"
        "universal_launcher_revision = \"2222222222222222222222222222222222222222\"\n"
        "universal_setup_revision = \"3333333333333333333333333333333333333333\"\n"
        "signed = false\n");
    const fs::path payload = root / "bin" / "facman";
    write(root / "manifest" / "components.v1.json",
        "{\"schema\":\"facman.package_components.v1\",\"components\":[{"
        "\"destination\":\"bin/facman\",\"runtime_role\":\"runtime_required\","
        "\"sha256\":\"" + usk::verify::sha256_hex_file(payload) + "\","
        "\"size\":" + std::to_string(fs::file_size(payload)) + "}]}\n");
    write_hashes(root);
}

std::string execute(
    usk_context* context,
    const char* command,
    const fs::path& root,
    const char* os,
    const char* arch = "x64",
    const char* linkage = "static_first")
{
    const std::string payload = "{\"schema\":\"usk.package_verify_request.v1\","
        "\"package_root\":\"" + escaped(root.string()) +
        "\",\"expected_target_os\":\"" + os +
        "\",\"expected_target_arch\":\"" + arch + "\","
        "\"expected_linkage_model\":\"" + linkage + "\"}";
    usk_command_request_v1 request{};
    usk_command_response_v1 response{};
    request.struct_size = sizeof(request);
    request.command_name = {command, static_cast<usk_size>(std::char_traits<char>::length(command))};
    request.json_payload = {payload.data(), static_cast<usk_size>(payload.size())};
    request.dry_run = 1;
    response.struct_size = sizeof(response);
    usk_command_execute_v1(context, &request, &response);
    return response.json_payload.data == nullptr
        ? std::string()
        : std::string(response.json_payload.data, static_cast<std::size_t>(response.json_payload.size));
}

bool contains(const std::string& value, const std::string& fragment)
{
    return value.find(fragment) != std::string::npos;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc == 3 && std::string(argv[1]) == "--sha256") {
        std::cout << usk::verify::sha256_hex_file(fs::path(argv[2])) << "\n";
        return 0;
    }
    if (argc == 5) {
        usk_context* context = nullptr;
        if (usk_context_create_v1(nullptr, &context) != USK_STATUS_OK) return 8;
        const std::string response = execute(
            context,
            "package.verify",
            fs::path(argv[1]),
            argv[2],
            argv[3],
            argv[4]);
        usk_context_destroy_v1(context);
        std::cout << response << "\n";
        return contains(response, "\"integrity\":\"pass\"") &&
            contains(response, "\"completeness\":\"pass\"") &&
            contains(response, "\"target_match\":\"pass\"") &&
            contains(response, "\"linkage_model\":\"" + std::string(argv[4]) + "\"")
            ? 0
            : 9;
    }
    const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path root = fs::temp_directory_path() /
        ("usk package verify spaces " + std::to_string(tick));
    create_package(root);
    usk_context* context = nullptr;
    if (usk_context_create_v1(nullptr, &context) != USK_STATUS_OK) return 10;

    const std::string before_hashes = usk::verify::sha256_hex_file(root / "manifest" / "hashes.sha256");
    std::string response = execute(context, "package.verify", root, "linux");
    if (!contains(response, "\"status\":\"warn\"") ||
        !contains(response, "\"integrity\":\"pass\"") ||
        !contains(response, "\"authenticity\":\"not_proven_unsigned\"") ||
        !contains(response, "\"completeness\":\"pass\"") ||
        !contains(response, "\"target_match\":\"pass\"")) {
        std::cerr << response << "\n";
        return 20;
    }
    response = execute(context, "package.audit", root, "linux");
    if (!contains(response, "\"command\":\"package.audit\"") ||
        !contains(response, "\"compatibility\":\"pass\"")) return 21;
    if (before_hashes != usk::verify::sha256_hex_file(root / "manifest" / "hashes.sha256")) return 22;

    response = execute(context, "package.verify", root, "windows");
    if (!contains(response, "\"target_match\":\"fail\"")) return 23;

    write(root / "unexpected.bin", "extra\n");
    response = execute(context, "package.verify", root, "linux");
    if (!contains(response, "\"completeness\":\"fail\"") ||
        !contains(response, "unhashed package file")) return 24;
    fs::remove(root / "unexpected.bin");

    write(root / "bin" / "facman", "drift\n");
    response = execute(context, "package.verify", root, "linux");
    if (!contains(response, "\"integrity\":\"fail\"") ||
        !contains(response, "SHA-256 mismatch")) return 25;
    create_package(root);

    fs::remove(root / "bin" / "facman");
    response = execute(context, "package.verify", root, "linux");
    if (!contains(response, "\"integrity\":\"fail\"") ||
        !contains(response, "missing or unsafe hashed file")) return 28;
    create_package(root);

    std::string components;
    {
        std::ifstream input(root / "manifest" / "components.v1.json", std::ios::binary);
        components.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    }
    const std::string known_role = "runtime_required";
    components.replace(components.find(known_role), known_role.size(), "unknown_role");
    write(root / "manifest" / "components.v1.json", components);
    write_hashes(root);
    response = execute(context, "package.audit", root, "linux");
    if (!contains(response, "\"status\":\"refused\"") ||
        !contains(response, "runtime_role is invalid")) return 29;
    create_package(root);

    write(root / "manifest" / "hashes.sha256", std::string(4u * 1024u * 1024u + 1u, 'x'));
    response = execute(context, "package.verify", root, "linux");
    if (!contains(response, "\"status\":\"refused\"") ||
        !contains(response, "over budget")) return 30;
    create_package(root);

    write(root / "manifest" / "hashes.sha256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  ../escape\n");
    response = execute(context, "package.verify", root, "linux");
    if (!contains(response, "\"status\":\"refused\"") ||
        !contains(response, "package_verification_refused")) return 26;

    usk_context_destroy_v1(context);
    std::error_code error;
    fs::remove_all(root, error);
    return error ? 27 : 0;
}
