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
        usk::json::ParseLimits limits;
        limits.max_bytes=1024u*1024u;
        limits.max_string_bytes=512u*1024u;
        const auto request=usk::json::canonical(
            usk::json::parse(std::string(bytes.begin(),bytes.end()),limits));
        const auto response=usk::platform::windows::submit_publisher_request(argv[2],request,120000);
        limits.max_bytes=4u*1024u*1024u;
        limits.max_string_bytes=2u*1024u*1024u;
        const auto result=[&] {
            try {
                const auto parsed=usk::json::parse(response,limits);
                const auto status=parsed.at("status").as_string();
                if(parsed.at("schema").as_string()!= "usk.publisher_lab_service_observation.v1" ||
                    (status!="pass" && status!="failed" && status!="recovery_required")) {
                    throw std::runtime_error("unexpected publisher response shape");
                }
                return parsed;
            } catch(const std::exception& error) {
                throw usk::platform::windows::PublisherRequestOutcomeUnknown(error.what());
            }
        }();
        if (_setmode(_fileno(stdout),_O_BINARY) == -1) {
            throw usk::platform::windows::PublisherRequestOutcomeUnknown(
                "binary output unavailable");
        }
        std::cout << response;
        std::cout.flush();
        if (!std::cout) {
            throw usk::platform::windows::PublisherRequestOutcomeUnknown(
                "publisher response output failed");
        }
        return result.at("status").as_string() == "pass" ? 0 : 3;
    } catch (const usk::platform::windows::PublisherRequestOutcomeUnknown&) {
        std::cerr << "usk_publisher_client: outcome unknown; retry the same reviewed request\n";
        return 5;
    } catch (const std::exception& error) {
        std::cerr << "usk_publisher_client: " << error.what() << '\n';
        return 2;
    }
}
#endif
