# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "release" / "index" / "sdk_package_workunit.v1.toml"
ABI_MANIFEST = ROOT / "contracts" / "abi" / "usk_c_abi.v1.toml"
EXPECTED_TARGETS = [
    "UniversalSetup::Headers",
    "UniversalSetup::CoreStatic",
    "UniversalSetup::CoreShared",
]
EXPECTED_MODES = [
    "source_workspace",
    "installed_static",
    "installed_shared",
    "relocated_installed_static",
    "relocated_installed_shared",
]
EXPECTED_EXPORTS = [
    "usk_abi_version_v1",
    "usk_command_execute_v1",
    "usk_context_create_v1",
    "usk_context_destroy_v1",
]
FORBIDDEN_TARGETS = [
    "UniversalSetup::Archive",
    "UniversalSetup::Lifecycle",
    "UniversalSetup::ClientC",
    "UniversalSetup::Daemon",
]


def check_data(data: dict[str, object]) -> list[str]:
    problems: list[str] = []
    expected = {
        "schema": "universal_setup.sdk_package_workunit.v1",
        "workunit": "USK-CMAKE-SDK-PACKAGE-01",
        "base_ref": "refs/heads/dev",
        "base_revision": "7f8f2baa14e78b0329db8eef8ac872818c4cf30d",
        "task_branch": "task/cmake-sdk-package-01",
        "package_version": "1.0.0",
        "c_abi_major": 1,
        "c_abi_minor": 0,
        "contract_maturity": "fixture-qualified",
        "exported_targets": EXPECTED_TARGETS,
        "required_modes": EXPECTED_MODES,
    }
    for key, value in expected.items():
        if data.get(key) != value:
            problems.append(f"SDK WorkUnit {key} must be {value!r}")
    if data.get("status") not in {"active_implementation", "task_complete"}:
        problems.append("SDK WorkUnit status must be active_implementation or task_complete")

    scope = data.get("scope")
    if not isinstance(scope, dict):
        problems.append("SDK WorkUnit scope table is required")
    else:
        for key in (
            "new_setup_behavior",
            "network_acquisition",
            "credentials",
            "live_mutation_authority",
            "consumer_repin",
            "consumer_adoption",
            "facman_pin_change",
            "product_execution",
            "signing",
            "publication",
            "contract_maturity_advanced",
        ):
            if scope.get(key) is not False:
                problems.append(f"SDK WorkUnit scope.{key} must remain false")

    observation = data.get("consumer_observation")
    if not isinstance(observation, dict):
        problems.append("SDK WorkUnit consumer_observation table is required")
    else:
        if observation.get("facman_stable_usk_pin") != (
            "3048128963dc718a7c38c1cfcdda9e813a23b0db"
        ):
            problems.append("FacMan stable USK pin observation changed")
        if observation.get("pin_changed") is not False:
            problems.append("consumer_observation.pin_changed must remain false")
    return problems


def check() -> list[str]:
    problems: list[str] = []
    if not RECORD.is_file():
        return ["release/index/sdk_package_workunit.v1.toml is missing"]
    with RECORD.open("rb") as handle:
        problems.extend(check_data(tomllib.load(handle)))

    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    if not re.search(r"project\(universal_setup\s+VERSION\s+1\.0\.0", cmake):
        problems.append("CMake project version must be 1.0.0")
    for token in (
        "GNUInstallDirs",
        "CMakePackageConfigHelpers",
        "configure_package_config_file",
        "write_basic_package_version_file",
        "install(EXPORT UniversalSetupTargets",
        "GenerateProviderPackageManifest.cmake",
        "USK_INSTALL_PROVIDER_MANIFEST",
        "install(DIRECTORY include/usk DESTINATION",
        "$<BUILD_INTERFACE:",
        "$<INSTALL_INTERFACE:",
        "PROJECT_IS_TOP_LEVEL",
        "USK_USE_SHARED",
    ):
        if token not in cmake:
            problems.append(f"CMake SDK package is missing {token}")
    for target in FORBIDDEN_TARGETS:
        if target in cmake:
            problems.append(f"aspirational SDK target must not be exported: {target}")
    if "install(DIRECTORY runtime/" in cmake:
        problems.append("private runtime implementation must not be installed")
    if "include/usu" in cmake:
        problems.append("unimplemented USU declarations must not be installed")

    consumer_cmake = (
        ROOT / "tests" / "sdk" / "consumer" / "CMakeLists.txt"
    ).read_text(encoding="utf-8")
    for field in ("source_id", "size_bytes", "sha256"):
        if field not in consumer_cmake:
            problems.append(f"SDK consumer does not bind local-source {field}")
    if 'MATCHES "^[0-9a-f]+$"' not in consumer_cmake:
        problems.append("SDK consumer must enforce lowercase SHA-256 contract syntax")

    cpp_smoke = (ROOT / "tests" / "sdk" / "consumer" / "cpp_headers.cpp").read_text(
        encoding="utf-8"
    )
    if '"usu/' in cpp_smoke:
        problems.append("SDK header consumer must not claim the unimplemented USU surface")

    conformance = (ROOT / "tools" / "cmake_sdk_conformance.py").read_text(
        encoding="utf-8"
    )
    if "prove_stale_path_rejection" not in conformance:
        problems.append("SDK conformance must inject and reject stale absolute metadata")
    if "negative-uppercase-source-sha" not in conformance:
        problems.append("SDK conformance must reject uppercase local-source SHA-256")

    if not ABI_MANIFEST.is_file():
        problems.append("public USK ABI manifest is missing")
    else:
        with ABI_MANIFEST.open("rb") as handle:
            abi = tomllib.load(handle)
        if abi.get("abi_major") != 1 or abi.get("abi_minor") != 0:
            problems.append("USK ABI manifest must retain version 1.0")
        if abi.get("exported_functions") != EXPECTED_EXPORTS:
            problems.append("USK ABI export snapshot changed")
        layout_guards = abi.get("layout_guards")
        if not isinstance(layout_guards, dict):
            problems.append("USK ABI layout guards are missing")
        else:
            expected_layout_guards = {
                "usk_config_v1_base_bytes": 16,
                "usk_config_v1_m1_strictly_greater_than_base": True,
                "legacy_win32_x86_tail_padding_is_not_allocator_authority": True,
            }
            if layout_guards != expected_layout_guards:
                problems.append("USK ABI legacy-prefix layout guards changed")

    maturity = (ROOT / "release" / "index" / "contract_maturity.v1.toml").read_text(
        encoding="utf-8"
    )
    if maturity.count('maturity = "fixture-qualified"') != 5:
        problems.append("all five provider contracts must remain fixture-qualified")
    return problems


def main() -> int:
    problems = check()
    if problems:
        for problem in problems:
            print(f"sdk-package-check: {problem}")
        return 1
    print("sdk-package-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
