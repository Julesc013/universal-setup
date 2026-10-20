// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_one_shot.h"
#include "usk_product_info.h"
#include "usk_product_install.h"
#if defined(USK_QUALIFICATION_DIAGNOSTICS)
#include "usk_qualification_trace_internal.h"
#include "usk_diagnostic_metrics.h"
#endif

#include <filesystem>
#include <fstream>
#include <iostream>
#include <array>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
#include "usk_json.h"
#include "usk_publisher_request_channel.h"
#include "usk_publisher_registration.h"
#include "usk_stable_file.h"
#include "usk_record_io.h"
#include "usk_effect_dispatch.h"
#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <shellapi.h>
#endif

namespace {
#ifdef _WIN32
SRWLOCK publisher_cancel_lock = SRWLOCK_INIT;
HANDLE publisher_cancel_event = nullptr;

BOOL WINAPI publisher_console_control(DWORD control)
{
    if (control != CTRL_C_EVENT && control != CTRL_BREAK_EVENT) return FALSE;
    AcquireSRWLockShared(&publisher_cancel_lock);
    const bool handled = publisher_cancel_event && SetEvent(publisher_cancel_event);
    ReleaseSRWLockShared(&publisher_cancel_lock);
    return handled ? TRUE : FALSE;
}

class PublisherConsoleCancellation final {
public:
    PublisherConsoleCancellation()
    {
        event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!event_) throw usk::base::EffectRequestNotDispatched();
        AcquireSRWLockExclusive(&publisher_cancel_lock);
        publisher_cancel_event = event_;
        ReleaseSRWLockExclusive(&publisher_cancel_lock);
        // Detached automation has no console signal source; API callers can
        // still supply their own borrowed cancellation event.
        registered_ = GetConsoleCP() != 0;
        if (registered_ && !SetConsoleCtrlHandler(publisher_console_control, TRUE)) {
            close();
            throw usk::base::EffectRequestNotDispatched();
        }
    }
    ~PublisherConsoleCancellation() { close(); }
    PublisherConsoleCancellation(const PublisherConsoleCancellation&) = delete;
    PublisherConsoleCancellation& operator=(const PublisherConsoleCancellation&) = delete;
    HANDLE event() const noexcept { return event_; }
private:
    void close() noexcept
    {
        if (registered_) SetConsoleCtrlHandler(publisher_console_control, FALSE);
        // Removal does not rely on joining a callback already running. The
        // lock prevents a callback from signalling a closed/reused handle.
        AcquireSRWLockExclusive(&publisher_cancel_lock);
        publisher_cancel_event = nullptr;
        if (event_) CloseHandle(event_);
        event_ = nullptr;
        ReleaseSRWLockExclusive(&publisher_cancel_lock);
    }
    HANDLE event_ = nullptr;
    bool registered_ = false;
};

bool generated_service_name(const std::wstring& name)
{
    if (name.size() != 40 || name.compare(0, 8, L"USK_PUB_") != 0) return false;
    for (std::size_t index = 8; index < name.size(); ++index) {
        const wchar_t ch = name[index];
        if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'))) return false;
    }
    return true;
}

std::string registered_publisher_request(const std::wstring& service,
    const std::string& payload, DWORD wait, const char* observation_file = nullptr)
{
    PublisherConsoleCancellation cancellation;
    usk::platform::windows::PublisherRequestOptions options;
    options.cancel_event = cancellation.event();
    options.conflict_wait_milliseconds = wait;
    const auto observed = usk::platform::windows::submit_registered_publisher_request(
        service, payload, options);
    if (observation_file != nullptr)
        usk::record_io::write_new_durable_text(std::filesystem::path(observation_file), observed);
    return observed;
}

int candidate_service_request()
{
    int count = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &count);
    const bool valid = arguments && count == 5 &&
        std::wstring(arguments[1]) == L"--candidate-service" &&
        std::wstring(arguments[3]) == L"--request-file" &&
        generated_service_name(arguments[2]) && arguments[4][0] != L'\0';
    const std::wstring service = valid ? arguments[2] : L"";
    const std::filesystem::path request_path = valid ?
        std::filesystem::path(arguments[4]) : std::filesystem::path{};
    if (arguments) LocalFree(arguments);
    if (!valid) {
        std::cerr << "usk_machine: invalid candidate service options\n";
        return 2;
    }
    try {
        usk::base::StableFile file{request_path};
        const auto size = file.identity().size_bytes;
        if (size == 0 || size > 1024u * 1024u) {
            throw std::runtime_error("request exceeds candidate transport bound");
        }
        const auto bytes = file.read(0, static_cast<std::size_t>(size));
        file.verify_unchanged();
        usk::json::ParseLimits limits;
        limits.max_bytes = 1024u * 1024u;
        limits.max_string_bytes = 512u * 1024u;
        const auto parsed = usk::json::parse(std::string(bytes.begin(), bytes.end()), limits);
        const auto schema = parsed.at("schema").as_string();
        if (schema != "usk.install_local_apply_request.v1" &&
            schema != "usk.publisher_installed_verify_request.v1" &&
            schema != "usk.publisher_recovery_request.v1") {
            throw std::runtime_error("candidate request schema is unavailable");
        }
        const auto request = usk::json::canonical(parsed);
        const auto response = usk::platform::windows::submit_publisher_request(
            service, request, 120000);
        limits.max_bytes = 4u * 1024u * 1024u;
        limits.max_string_bytes = 2u * 1024u * 1024u;
        std::string status;
        try {
            const auto result = usk::json::parse(response, limits);
            status = result.at("status").as_string();
            if (result.at("schema").as_string() !=
                    "usk.publisher_lab_service_observation.v1" ||
                (status != "pass" && status != "failed" &&
                 status != "recovery_required")) {
                throw std::runtime_error("publisher response shape differs");
            }
        } catch (const std::exception&) {
            throw usk::platform::windows::PublisherRequestOutcomeUnknown(
                "publisher response could not be classified");
        }
        if (_setmode(_fileno(stdout), _O_BINARY) == -1) {
            throw usk::platform::windows::PublisherRequestOutcomeUnknown(
                "binary output unavailable");
        }
        std::cout << response;
        std::cout.flush();
        if (!std::cout) {
            throw usk::platform::windows::PublisherRequestOutcomeUnknown(
                "publisher response output failed");
        }
        return status == "pass" ? 0 : 3;
    } catch (const usk::platform::windows::PublisherRequestOutcomeUnknown&) {
        std::cerr << "usk_machine: candidate publisher outcome unknown; retry the same reviewed request\n";
        return 5;
    } catch (const std::exception&) {
        std::cerr << "usk_machine: candidate service request refused\n";
        return 2;
    }
}
#endif
std::string read_product_document(const std::string& path, std::size_t bound)
{
    std::ifstream input(std::filesystem::path(path), std::ios::binary);
    if (!input) throw std::runtime_error("product input unavailable");
    std::string text;
    std::array<char, 65536> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = static_cast<std::size_t>(input.gcount());
        if (count > bound - text.size()) throw std::runtime_error("product input exceeds byte bound");
        text.append(buffer.data(), count);
    }
    if (!input.eof()) throw std::runtime_error("product input read failed");
    return text;
}

int product_install(int argc, char** argv, bool apply)
{
    bool dispatch_possible = false;
    try {
        if (argc < 3 || argv[2][0] == '\0' || argc > 15 || (argc - 3) % 2 != 0)
            throw std::runtime_error("invalid product installation options");
        std::map<std::string, std::string> options;
        for (int index = 3; index < argc; index += 2) {
            const std::string key(argv[index]);
            if ((key != "--request-file" && key != "--context-file" && key != "--publisher" &&
                    key != "--publisher-observation-file" && (!apply || key != "--review-file")) ||
                argv[index + 1][0] == '\0' || !options.emplace(key, argv[index + 1]).second)
                throw std::runtime_error("invalid product installation option");
        }
        const bool local = options.count("--context-file") != 0;
        const bool publisher = options.count("--publisher") != 0;
        if (!options.count("--request-file") || (apply && (!publisher || !options.count("--review-file"))) ||
            (!apply && local == publisher) || (!publisher && options.count("--publisher-observation-file")))
            throw std::runtime_error("missing product installation options");
        usk::command::OneShotContextConfig context;
        if (local) {
            std::ifstream context_input(std::filesystem::path(options.at("--context-file")), std::ios::binary);
            if (!context_input) throw std::runtime_error("planning context unavailable");
            context = usk::command::read_context_config(context_input);
        }
        const auto request = read_product_document(options.at("--request-file"), 16384);
#ifdef _WIN32
        if (_setmode(_fileno(stdout), _O_BINARY) == -1)
            throw std::runtime_error("binary output unavailable");
#endif
        usk::command::OneShotResult result;
        usk::command::CandidateTransport transport;
        if (publisher) {
#ifdef _WIN32
            const auto& name = options.at("--publisher");
            const std::wstring service(name.begin(), name.end());
            if (!generated_service_name(service)) throw std::runtime_error("invalid publisher name");
            transport = [&, service](const std::string& payload) {
                    // Conservative before any transport action. Typed pre-send
                    // refusal and UNKNOWN classification remain in the adapter.
                    const bool query = usk::json::parse(payload).at("schema").as_string() == "usk.install_local_plan_request.v1";
                    if (!query) dispatch_possible = true;
                    const char* observation = options.count("--publisher-observation-file") && (!apply || !query) ?
                        options.at("--publisher-observation-file").c_str() : nullptr;
                    return registered_publisher_request(service, payload, 0, observation);
                };
#else
            throw std::runtime_error("registered publisher requires Windows");
#endif
        }
        if (apply) {
            const auto review = read_product_document(options.at("--review-file"), usk::command::max_response_bytes);
            result = local ? usk::command::apply_product_install(std::filesystem::path(argv[2]),
                review, request, context, transport) :
                usk::command::apply_product_install_registered(std::filesystem::path(argv[2]), review, request, transport);
        } else {
            result = local ? usk::command::plan_product_install(std::filesystem::path(argv[2]), request, context) :
                usk::command::plan_product_install(std::filesystem::path(argv[2]), request, transport);
        }
        usk::command::write_result(std::cout, result.document, false);
        if (!result.diagnostic.empty()) std::cerr << "usk_machine: " << result.diagnostic << '\n';
        return result.exit_code;
    } catch (const std::exception&) {
        if (dispatch_possible) {
            std::cerr << "usk_machine: publisher outcome unknown; recover the reviewed request\n";
            return 5;
        }
        std::cerr << "usk_machine: authored installation refused before dispatch\n";
        return 2;
    }
}
} // namespace

int main(int argc, char** argv)
{
#if defined(USK_QUALIFICATION_DIAGNOSTICS)
    const usk::platform::windows::QualificationTrace qualification_trace;
    const usk::diagnostics::Scope diagnostic(usk::diagnostics::Phase::machine_request);
#endif
#ifdef _WIN32
    if (argc >= 2 && std::string(argv[1]) == "--candidate-service") {
        return candidate_service_request();
    }
#endif
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
    if (argc >= 2 && (std::string(argv[1]) == "--product-plan" ||
        std::string(argv[1]) == "--product-apply"))
        return product_install(argc, argv, std::string(argv[1]) == "--product-apply");
    if (argc < 2 ||
        (std::string(argv[1]) != "--machine" && std::string(argv[1]) != "--framed")) {
        std::cerr << "usage: usk_machine --machine|--framed [--request-file path]"
            " [--context-file path] [--candidate-service NAME]"
            " [--publisher NAME [--publisher-wait-ms 0..30000] [--publisher-observation-file PATH]]"
            " | --product-info product.bundle.json"
            " | --product-select product.bundle.json [--select ID ...]"
            " | --product-plan BUNDLE --request-file OPTIONS --context-file CONTEXT|--publisher NAME"
            " | --product-apply BUNDLE --review-file REVIEW --request-file CONFIRMATION"
            " --publisher NAME [--context-file CONTEXT] [--publisher-observation-file PATH]"
            " | --candidate-service NAME --request-file path (Windows only)\n";
        return 2;
    }
    const bool framed = std::string(argv[1]) == "--framed";
    const char* request_file = nullptr;
    const char* context_file = nullptr;
#ifdef _WIN32
    std::wstring candidate_service;
    std::wstring publisher_service;
    const char* publisher_observation_file = nullptr;
    DWORD publisher_wait_milliseconds = 0;
    bool publisher_wait_supplied = false;
#endif
    for (int index = 2; index < argc; index += 2) {
        if (index + 1 >= argc || argv[index + 1][0] == '\0') {
            std::cerr << "usk_machine: invalid options\n";
            return 2;
        }
        const std::string option(argv[index]);
        if (option == "--request-file" && request_file == nullptr) {
            request_file = argv[index + 1];
        } else if (option == "--context-file" && context_file == nullptr) {
            context_file = argv[index + 1];
#ifdef _WIN32
        } else if (option == "--candidate-service" && candidate_service.empty()) {
            const std::string value(argv[index + 1]);
            candidate_service.assign(value.begin(), value.end());
            if (!generated_service_name(candidate_service)) {
                std::cerr << "usk_machine: invalid candidate service name\n";
                return 2;
            }
        } else if (option == "--publisher" && publisher_service.empty()) {
            const std::string value(argv[index + 1]);
            publisher_service.assign(value.begin(), value.end());
            if (!generated_service_name(publisher_service)) {
                std::cerr << "usk_machine: invalid publisher service name\n";
                return 2;
            }
        } else if (option == "--publisher-observation-file" && publisher_observation_file == nullptr) {
            publisher_observation_file = argv[index + 1];
        } else if (option == "--publisher-wait-ms" && !publisher_wait_supplied) {
            const std::string value(argv[index + 1]);
            if (value.size() > 5 || value.find_first_not_of("0123456789") != std::string::npos) {
                std::cerr << "usk_machine: invalid publisher wait\n";
                return 2;
            }
            for (const char ch : value)
                publisher_wait_milliseconds = publisher_wait_milliseconds * 10u + static_cast<DWORD>(ch - '0');
            if (publisher_wait_milliseconds > usk::platform::windows::publisher_request_max_conflict_wait_milliseconds) {
                std::cerr << "usk_machine: invalid publisher wait\n";
                return 2;
            }
            publisher_wait_supplied = true;
#endif
        } else {
            std::cerr << "usk_machine: invalid options\n";
            return 2;
        }
    }
#ifdef _WIN32
    if ((!candidate_service.empty() && !publisher_service.empty()) ||
        (publisher_observation_file != nullptr && publisher_service.empty()) ||
        (publisher_wait_supplied && publisher_service.empty()) ||
        ((!candidate_service.empty() || !publisher_service.empty()) && context_file != nullptr)) {
        std::cerr << "usk_machine: publisher service and planning context options are incompatible\n";
        return 2;
    }
#endif
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
        if (request_file != nullptr) {
            file.open(request_file, std::ios::binary);
            if (!file) throw std::runtime_error("request file unavailable");
            source = &file;
        }
        const std::string request = usk::command::read_bounded_request(*source, framed);
        usk::command::OneShotContextConfig context;
        const usk::command::OneShotContextConfig* configured = nullptr;
        if (context_file != nullptr) {
            try {
                std::ifstream context_input(context_file, std::ios::binary);
                if (!context_input) throw std::runtime_error("context file unavailable");
                context = usk::command::read_context_config(context_input);
                configured = &context;
            } catch (const std::exception&) {
                result = usk::command::invalid_context_result();
            }
        }
        if (context_file == nullptr || configured != nullptr) {
#ifdef _WIN32
            if (!candidate_service.empty()) {
                result = usk::command::run_candidate_one_shot(request,
                    [&candidate_service](const std::string& payload) {
                        return usk::platform::windows::submit_publisher_request(
                            candidate_service, payload, 120000);
                    });
            } else if (!publisher_service.empty()) {
                result = usk::command::run_publisher_one_shot(request,
                    [&publisher_service, publisher_observation_file, publisher_wait_milliseconds](const std::string& payload) {
                        return registered_publisher_request(publisher_service, payload,
                            publisher_wait_milliseconds, publisher_observation_file);
                    });
            } else
#endif
            result = usk::command::run_one_shot(request, configured);
        }
    } catch (const std::exception&) {
        result = usk::command::invalid_frame_result();
    }
    try {
        usk::command::write_result(std::cout, result.document, framed);
    } catch (const std::exception&) {
#ifdef _WIN32
        if (!candidate_service.empty() || !publisher_service.empty()) {
            std::cerr << "usk_machine: publisher outcome unknown; recover the reviewed request\n";
            return 5;
        }
#endif
        std::cerr << "usk_machine: output failed\n";
        return 3;
    }
    if (!result.diagnostic.empty()) std::cerr << "usk_machine: " << result.diagnostic << '\n';
    return result.exit_code;
}
