// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_target_inspect.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;
using namespace usk::policy;

namespace {

int run()
{
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path root = fs::temp_directory_path() / ("usk-target-inspect-" + std::to_string(nonce));
    const fs::path acceptance = root / "acceptance";
    const fs::path target = acceptance / "product";
    const fs::path source = root / "synthetic.zip";
    fs::create_directories(acceptance);
    {
        std::ofstream output(source, std::ios::binary);
        output << "harmless synthetic archive identity";
    }

    const TargetInspectionRequest request{
        TargetClass::operator_acceptance,
        target,
        acceptance,
        source,
        4096,
        {"create target", "write installed state", "write ownership", "write audit"}};
    const InspectedTarget accepted = inspect_and_evaluate_live_target(
        Activation::operator_acceptance_candidate, request);
    if (!accepted.decision.accepted || accepted.evidence.target_state != TargetState::nonexistent ||
        !accepted.evidence.local_filesystem || !accepted.evidence.path_components_stable ||
        accepted.evidence.target_identity_digest.size() != 64) {
        return 1;
    }

    fs::create_directory(target);
    const InspectedTarget empty = inspect_and_evaluate_live_target(
        Activation::operator_acceptance_candidate, request);
    if (!empty.decision.accepted || empty.evidence.target_state != TargetState::empty ||
        empty.decision.target_binding_digest == accepted.decision.target_binding_digest) {
        return 2;
    }
    {
        std::ofstream output(target / "foreign.txt");
        output << "foreign";
    }
    const InspectedTarget nonempty = inspect_and_evaluate_live_target(
        Activation::operator_acceptance_candidate, request);
    if (nonempty.decision.accepted || nonempty.decision.code != "target_not_empty") return 3;

    TargetInspectionRequest outside = request;
    outside.target_root = root / "outside";
    const auto escaped = inspect_and_evaluate_live_target(
        Activation::operator_acceptance_candidate, outside);
    if (escaped.decision.accepted || escaped.decision.code != "target_outside_acceptance_root") return 4;

    std::error_code ignored;
    fs::remove_all(root, ignored);
    return 0;
}

} // namespace

int main()
{
    const int result = run();
    if (result != 0) std::cerr << "usk-target-inspect-smoke-stage=" << result << '\n';
    return result;
}
