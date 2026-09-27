// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_request_channel.h"
#include "usk_stable_file.h"
#include "usk_json.h"
#if defined(_WIN32)
#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <filesystem>
#include <iostream>
int wmain(int argc, wchar_t** argv) {
    if (argc != 5 || std::wstring(argv[1]) != L"--service" ||
        std::wstring(argv[3]) != L"--request-file") {
        std::cerr << "usage: usk_publisher_client --service NAME --request-file PATH\n";
        return 2;
    }
    try {
        usk::base::StableFile file{std::filesystem::path(argv[4])};
        if (!file.identity().size_bytes || file.identity().size_bytes > 1024u*1024u) {
            throw std::runtime_error("request size exceeds transport bound");
        }
        const auto bytes=file.read(0,static_cast<std::size_t>(file.identity().size_bytes));
        file.verify_unchanged();
        const auto request=usk::json::canonical(usk::json::parse(std::string(bytes.begin(),bytes.end())));
        const auto response=usk::platform::windows::submit_publisher_request(argv[2],request,120000);
        const auto result=usk::json::parse(response);
        if (_setmode(_fileno(stdout),_O_BINARY) == -1) throw std::runtime_error("binary output unavailable");
        std::cout << response;
        return result.at("status").as_string() == "pass" ? 0 : 3;
    } catch (const std::exception& error) {
        std::cerr << "usk_publisher_client: " << error.what() << '\n';
        return 2;
    }
}
#endif
