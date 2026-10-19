// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#pragma once
#include <string>

namespace usk::test {
// Closed fixture predicates: an unexpected native error is a refusal, but
// cannot count as coverage of the intended held-state completion timeout.
inline bool strict_service_absence_refusal(const std::string& diagnostic) {
    return diagnostic == "owned retirement strict SCM revalidation: service is present" ||
        diagnostic == "owned retirement strict SCM revalidation: SCM absence is unconfirmed; "
            "Win32 1072; probes 1; pending-deletion observations 1";
}
inline bool bounded_service_absence_refusal(const std::string& diagnostic, bool allow_pending) {
    const std::string phase = "owned retirement post-delete-and-close SCM completion: "
        "SCM absence is unconfirmed (completion bound reached); ";
    const auto present = phase + "service is present; probes ";
    const auto pending = phase + "Win32 1072; probes ";
    return diagnostic.compare(0, present.size(), present) == 0 ||
        (allow_pending && diagnostic.compare(0, pending.size(), pending) == 0);
}
} // namespace usk::test
