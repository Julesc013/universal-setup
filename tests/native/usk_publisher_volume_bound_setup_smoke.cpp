// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_public_lifecycle.h"

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;

namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

bool refused(const std::string& reviewed, const std::string& acceptance,
    HANDLE held, const std::wstring& alias) {
    try {
        usk::lifecycle::initialize_setup_root_for_publisher(reviewed,
            acceptance, "operator_acceptance_candidate", held, alias);
    } catch (const std::exception&) {
        return true;
    }
    return false;
}
} // namespace

int main() {
    wchar_t raw_temp[MAX_PATH + 1]{};
    const DWORD temp_length = GetTempPathW(MAX_PATH, raw_temp);
    if (temp_length == 0 || temp_length >= MAX_PATH) {
        std::cerr << "temporary root is unavailable\n";
        return 1;
    }
    const fs::path temp = fs::absolute(fs::path(raw_temp)).lexically_normal();
    const std::wstring drive = temp.root_name().wstring() + L"\\";
    wchar_t raw_alias[128]{};
    if (drive.size() != 3 || !GetVolumeNameForVolumeMountPointW(
            drive.c_str(), raw_alias, static_cast<DWORD>(std::size(raw_alias)))) {
        std::cerr << "temporary drive volume GUID is unavailable\n";
        return 1;
    }
    const std::wstring alias(raw_alias);
    HANDLE held = CreateFileW(alias.c_str(),
        FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (held == INVALID_HANDLE_VALUE) {
        std::cerr << "cannot open held temporary volume root\n";
        return 1;
    }
    const DWORD occupied = GetLogicalDrives();
    wchar_t unused = L'\0';
    for (wchar_t letter = L'Z'; letter >= L'D'; --letter) {
        if ((occupied & (1u << (letter - L'A'))) == 0) {
            unused = letter;
            break;
        }
    }
    if (unused == L'\0') {
        std::cerr << "no unused reviewed drive letter\n";
        CloseHandle(held);
        return 1;
    }
    const fs::path physical = temp /
        (L"usk-volume-bound-setup-" + std::to_wstring(GetCurrentProcessId()) +
            L"-" + std::to_wstring(GetTickCount64()));
    const fs::path reviewed = fs::path(std::wstring(1, unused) + L":\\") /
        temp.relative_path() / physical.filename();
    const std::string reviewed_text = reviewed.u8string();
    const std::string acceptance = fs::path(std::wstring(1, unused) + L":\\").u8string();
    try {
        check(!fs::exists(physical) && !fs::exists(reviewed),
            "test setup root identity collided");
        check(refused(reviewed_text, acceptance, held,
                L"\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\"),
            "nonexistent volume alias was accepted");
        check(!fs::exists(physical), "invalid alias created a setup root");
        HANDLE wrong_held = CreateFileW(temp.c_str(),
            FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        check(wrong_held != INVALID_HANDLE_VALUE,
            "cannot open same-volume non-root directory for identity refusal");
        const bool wrong_identity_refused = refused(reviewed_text, acceptance,
            wrong_held, alias);
        CloseHandle(wrong_held);
        check(wrong_identity_refused,
            "existing alias with different held root identity was accepted");
        check(!fs::exists(physical),
            "different held root identity created a setup root");
        usk::lifecycle::initialize_setup_root_for_publisher(reviewed_text,
            acceptance, "operator_acceptance_candidate", held, alias);
        const fs::path marker = physical / ".usk-owned-root.v1.json";
        std::ifstream input(marker, std::ios::binary);
        check(input.good(), "setup marker was not written under held volume");
        const std::string bytes((std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>());
        input.close();
        check(bytes == "{\"acceptance_root\":\"" +
                fs::path(std::wstring(1, unused) + L":\\").generic_u8string() +
                "\",\"schema\":\"usk.setup_owned_root.v1\"}\n",
            "reviewed acceptance identity was not preserved in marker");
        check(fs::is_directory(physical / "state" / "ownership") &&
                fs::is_directory(physical / "state" / "installed") &&
                fs::is_directory(physical / "audit" / "chains") &&
                !fs::exists(reviewed),
            "setup layout escaped held volume or is incomplete");
        usk::lifecycle::initialize_setup_root_for_publisher(reviewed_text,
            acceptance, "operator_acceptance_candidate", held, alias);
        std::ifstream repeated(marker, std::ios::binary);
        check(std::string((std::istreambuf_iterator<char>(repeated)),
                std::istreambuf_iterator<char>()) == bytes,
            "idempotent setup initialization changed marker");
        repeated.close();
        CloseHandle(held);
        check(fs::equivalent(physical.parent_path(), temp) &&
                physical.filename().wstring().rfind(L"usk-volume-bound-setup-", 0) == 0,
            "test cleanup root escaped owned temp parent");
        fs::remove_all(physical);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        CloseHandle(held);
        // Retain an unexpected state for diagnosis; the path is unique to this run.
        return 1;
    }
}
