// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_registration.h"
#include "usk_owned_publisher_retirement_internal.h"
#include <filesystem>
#include <iostream>
#include <string>

int wmain(int argc, wchar_t** argv)
{
    if (argc >= 2 && std::wstring(argv[1]) == L"--retire-owned") {
        if (argc != 3) {
            std::cerr << "usage: usk_publisher_service_control --retire-owned SERVICE\n";
            return 3;
        }
        try {
            using usk::json::Value;
            // Prepare the reply before native effects; supplied JSON or paths
            // cannot grant retirement. The fixed owner obtains its own custody.
            const auto response = usk::json::canonical(Value(Value::Object{
                {"schema", Value("usk.publisher_service_control.v1")},
                {"status", Value("owned_retired")},
                {"service", Value(std::filesystem::path(argv[2]).u8string())}})) + '\n';
            usk::lifecycle::detail::retire_owned_publisher(argv[2]);
            std::cout << response;
            return std::cout ? 0 : 5;
        } catch (const std::exception& error) {
            // Failure may follow a native effect. A new invocation must inspect
            // actual state; this result never claims rollback or safe replay.
            std::cerr << "usk_publisher_service_control: owned retirement incomplete; "
                << error.what() << '\n';
            return 5;
        }
    }
    return usk::platform::windows::publisher_service_control_main(argc, argv);
}
