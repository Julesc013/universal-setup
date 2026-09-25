// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_one_shot.h"
#include "usk_product_info.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
#include <cstdio>
#include <fcntl.h>
#include <io.h>
#endif

int main(int argc, char** argv)
{
    if (argc == 3 && std::string(argv[1]) == "--product-info" && argv[2][0] != '\0') {
        try {
            std::cout << usk::command::inspect_product_info(
                std::filesystem::path(argv[2])) << '\n';
            return 0;
        } catch (const std::exception&) {
            std::cerr << "usk_machine: product bundle inspection refused\n";
            return 2;
        }
    }
    if (argc >= 3 && std::string(argv[1]) == "--product-select" && argv[2][0] != '\0') {
        try {
            if ((argc - 3) % 2 != 0 || argc > 8195) {
                throw std::runtime_error("invalid component selection arguments");
            }
            std::vector<std::string> requested;
            for (int index = 3; index < argc; index += 2) {
                if (std::string(argv[index]) != "--select" || argv[index + 1][0] == '\0') {
                    throw std::runtime_error("invalid component selection arguments");
                }
                requested.emplace_back(argv[index + 1]);
            }
            std::cout << usk::command::inspect_product_selection(
                std::filesystem::path(argv[2]), requested) << '\n';
            return 0;
        } catch (const std::exception&) {
            std::cerr << "usk_machine: product selection refused\n";
            return 2;
        }
    }
    if ((argc != 2 && argc != 4) ||
        (std::string(argv[1]) != "--machine" && std::string(argv[1]) != "--framed") ||
        (argc == 4 && (std::string(argv[2]) != "--request-file" || argv[3][0] == '\0'))) {
        std::cerr << "usage: usk_machine --machine|--framed [--request-file path]"
            " | --product-info product.bundle.json"
            " | --product-select product.bundle.json [--select ID ...]\n";
        return 2;
    }
    const bool framed = std::string(argv[1]) == "--framed";
#ifdef _WIN32
    // A frame is bytes, not CRT text: Ctrl+Z and newline translation corrupt it.
    if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
        _setmode(_fileno(stdout), _O_BINARY) == -1) {
        std::cerr << "usk_machine: binary stream unavailable\n";
        return 3;
    }
#endif
    usk::command::OneShotResult result;
    try {
        std::ifstream file;
        std::istream* source = &std::cin;
        if (argc == 4) {
            file.open(argv[3], std::ios::binary);
            if (!file) throw std::runtime_error("request file unavailable");
            source = &file;
        }
        const std::string request = usk::command::read_bounded_request(*source, framed);
        result = usk::command::run_one_shot(request);
    } catch (const std::exception&) {
        result = usk::command::invalid_frame_result();
    }
    try {
        usk::command::write_result(std::cout, result.document, framed);
    } catch (const std::exception&) {
        std::cerr << "usk_machine: output failed\n";
        return 3;
    }
    if (!result.diagnostic.empty()) std::cerr << "usk_machine: " << result.diagnostic << '\n';
    return result.exit_code;
}
