// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_registered_client_internal.h"
#if defined(_WIN32)
#include "usk_publisher_registration_query_internal.h"
#include "usk_effect_dispatch.h"
namespace usk::platform::windows {
std::string submit_service_admitted_publisher_request(const std::wstring& name,
    const std::string& request, const PublisherRequestOptions& options) {
    using namespace detail::registration_query;
    const auto parsed = parse_registered_client_request(name, request, options);
    std::unique_ptr<ServiceHandle> service;
    std::wstring admitted_image;
    try {
        ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!manager.get()) throw std::runtime_error("SCM connection is unavailable");
        ServiceHandle opened_service(OpenServiceW(manager.get(), name.c_str(),
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL |
                (parsed.inspection_id.empty() || parsed.service_observation ? SERVICE_START : 0)));
        service = std::make_unique<ServiceHandle>(opened_service.get());
        (void)opened_service.release();
        if (!service->get()) throw std::runtime_error("publisher registration is unavailable");
        const auto before = query_configuration(service->get());
        require_profile(before);
        const auto args = command_arguments(before.binary_path);
        if (args.size() < 8) throw std::runtime_error("publisher registration is malformed");
        const bool grant = args.back() == L"--grant-client-read";
        const auto caller = args[args.size() - (grant ? 2u : 1u)];
        require_canonical_sid(caller);
        require_current_caller_sid(caller);
        require_volume(args[4]);
        if (args[args.size() - 3] != L"--service-admitted-client")
            throw std::runtime_error("ordinary publisher client requires service admission");
        admit_service_client(service->get(), name, before, args, caller,
            !parsed.inspection_id.empty() && !parsed.service_observation);
        admitted_image = args[0];
    } catch (const usk::base::EffectRequestNotDispatched&) {
        throw;
    } catch (const std::exception&) {
        throw usk::base::EffectRequestNotDispatched();
    }
    // No generic catch here can downgrade a failure after a possible write.
    return submit_publisher_request(name, request, 120000, admitted_image, options);
}
}
#endif
