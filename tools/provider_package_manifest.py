# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_RELATIVE_PATH = Path(
    "share/universal-setup/provider-package-manifest.v1.json"
)
ABI_RELATIVE_PATH = Path(
    "share/universal-setup/contracts/abi/usk_c_abi.v1.toml"
)
EXPECTED_PACKAGE_VERSION = "1.0.0"
EXPECTED_SOURCE_REPOSITORY = "Julesc013/universal-setup"
EXPECTED_C_ABI = {"major": 1, "minor": 0}
EXPECTED_STATE_FORMATS = {
    "installed_state": {"read_versions": [1], "write_version": 1},
    "transaction_journal": {"read_versions": [1], "write_version": 1},
}
EXPECTED_TARGETS = {
    "UniversalSetup::Headers",
    "UniversalSetup::CoreStatic",
    "UniversalSetup::CoreShared",
}
AUTHORITY_EXCLUSIONS = [
    "consumer_adoption",
    "credentials",
    "daemon",
    "dynamic_provider_loading",
    "network_acquisition",
    "production_signing",
    "public_usu_spi",
    "publication",
    "release_authority",
]
QUALIFICATION_REQUIREMENTS = [
    "abi_1_0_layout_smoke",
    "authority_refusal_matrix",
    "installed_shared_consumer",
    "installed_static_consumer",
    "relocated_shared_consumer",
    "relocated_static_consumer",
    "source_workspace_consumer",
    "strict_repository_validation",
]
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class ManifestError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def inventory_digest(entries: list[dict[str, Any]]) -> str:
    return sha256_bytes(canonical_json_bytes(entries))


def inventory_entry(prefix: Path, path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(prefix).as_posix(),
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def artifact_inventory(prefix: Path) -> list[dict[str, Any]]:
    manifest = prefix / MANIFEST_RELATIVE_PATH
    paths = sorted(
        (
            path
            for path in prefix.rglob("*")
            if path.is_file() and path != manifest
        ),
        key=lambda path: path.relative_to(prefix).as_posix(),
    )
    if not paths:
        raise ManifestError("installed package contains no artifacts")
    return [inventory_entry(prefix, path) for path in paths]


def select_inventory(
    entries: list[dict[str, Any]], prefixes: tuple[str, ...]
) -> list[dict[str, Any]]:
    return [entry for entry in entries if entry["path"].startswith(prefixes)]


def installed_targets(prefix: Path) -> list[str]:
    targets: set[str] = set()
    expression = re.compile(
        r"add_library\((UniversalSetup::[A-Za-z0-9_]+)\s+"
    )
    for path in prefix.rglob("UniversalSetupTargets*.cmake"):
        content = path.read_text(encoding="utf-8", errors="replace")
        targets.update(expression.findall(content))
    if "UniversalSetup::Headers" not in targets:
        raise ManifestError("installed CMake target inventory is incomplete")
    if not targets.issubset(EXPECTED_TARGETS):
        raise ManifestError(f"unexpected installed CMake targets: {sorted(targets)}")
    return sorted(targets)


def installed_abi(prefix: Path) -> tuple[int, int, str]:
    path = prefix / ABI_RELATIVE_PATH
    if not path.is_file():
        raise ManifestError(f"installed ABI manifest is missing: {path}")
    content = path.read_text(encoding="utf-8")
    major = re.search(r"(?m)^abi_major\s*=\s*(\d+)\s*$", content)
    minor = re.search(r"(?m)^abi_minor\s*=\s*(\d+)\s*$", content)
    if not major or not minor:
        raise ManifestError("installed ABI manifest lacks a readable ABI version")
    return int(major.group(1)), int(minor.group(1)), sha256_file(path)


def licence_expression(prefix: Path) -> str:
    record = prefix / "share/licenses/universal-setup/license.v1.toml"
    if not record.is_file():
        raise ManifestError("installed machine-readable licence record is missing")
    with record.open("rb") as handle:
        data = tomllib.load(handle)
    expression = data.get("package_license_expression")
    if expression != "MIT":
        raise ManifestError("installed package licence expression must be MIT")
    return expression


def run_git(source_root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(source_root), *arguments],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise ManifestError(result.stderr.strip() or "Git source inspection failed")
    return result.stdout.strip()


def verify_source_identity(
    source_root: Path,
    source_commit: str,
    source_tree: str,
    source_ref: str,
    allow_unverifiable_source: bool,
) -> None:
    try:
        inside = run_git(source_root, "rev-parse", "--is-inside-work-tree")
    except ManifestError:
        if allow_unverifiable_source:
            return
        raise ManifestError(
            "source identity is not Git-verifiable; the archive-source override is required"
        )
    if inside != "true":
        raise ManifestError("source root is not a Git worktree")
    actual_commit = run_git(source_root, "rev-parse", "HEAD")
    actual_tree = run_git(source_root, "rev-parse", "HEAD^{tree}")
    if actual_commit != source_commit:
        raise ManifestError(
            f"configured source commit {source_commit} does not match HEAD {actual_commit}"
        )
    if actual_tree != source_tree:
        raise ManifestError(
            f"configured source tree {source_tree} does not match HEAD tree {actual_tree}"
        )
    symbolic = subprocess.run(
        ["git", "-C", str(source_root), "symbolic-ref", "--quiet", "HEAD"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    actual_ref = (
        symbolic.stdout.strip()
        if symbolic.returncode == 0
        else f"refs/detached/{actual_commit}"
    )
    if actual_ref != source_ref:
        raise ManifestError(
            f"configured source ref {source_ref} does not match checkout ref {actual_ref}"
        )
    dirty = run_git(source_root, "status", "--porcelain=v1", "--untracked-files=normal")
    if dirty:
        raise ManifestError("provider package source worktree is not clean")


def validate_identity(source_commit: str, source_tree: str, source_ref: str) -> None:
    if not HEX_40.fullmatch(source_commit):
        raise ManifestError("source commit must be exact lowercase 40-hex")
    if not HEX_40.fullmatch(source_tree):
        raise ManifestError("source tree must be exact lowercase 40-hex")
    if not source_ref.startswith("refs/"):
        raise ManifestError("source ref must be a complete refs/... identity")


def build_manifest(
    *,
    prefix: Path,
    source_repository: str,
    source_commit: str,
    source_tree: str,
    source_ref: str,
    package_version: str,
    os_name: str,
    architecture: str,
    linkage: str,
    configuration: str,
    toolchain_id: str,
    toolchain_version: str,
    compiler: str,
) -> dict[str, Any]:
    prefix = prefix.resolve()
    validate_identity(source_commit, source_tree, source_ref)
    if source_repository != EXPECTED_SOURCE_REPOSITORY:
        raise ManifestError(
            "source repository must be "
            f"{EXPECTED_SOURCE_REPOSITORY}, got {source_repository}"
        )
    if package_version != EXPECTED_PACKAGE_VERSION:
        raise ManifestError(
            f"package version must be {EXPECTED_PACKAGE_VERSION}, got {package_version}"
        )
    if linkage not in {"static", "shared", "combined"}:
        raise ManifestError("linkage must be static, shared, or combined")
    artifacts = artifact_inventory(prefix)
    headers = select_inventory(artifacts, ("include/usk/",))
    contracts = select_inventory(
        artifacts, ("share/universal-setup/contracts/",)
    )
    licences = select_inventory(
        artifacts, ("share/licenses/universal-setup/",)
    )
    if not headers or not contracts or not licences:
        raise ManifestError("header, contract, and licence inventories must be non-empty")
    abi_major, abi_minor, abi_digest = installed_abi(prefix)
    if {"major": abi_major, "minor": abi_minor} != EXPECTED_C_ABI:
        raise ManifestError("installed C ABI must remain exactly 1.0")
    targets = installed_targets(prefix)
    expected_by_linkage = {
        "static": {"UniversalSetup::Headers", "UniversalSetup::CoreStatic"},
        "shared": {"UniversalSetup::Headers", "UniversalSetup::CoreShared"},
        "combined": EXPECTED_TARGETS,
    }
    if set(targets) != expected_by_linkage[linkage]:
        raise ManifestError(
            f"installed target inventory does not match {linkage} linkage: {targets}"
        )
    return {
        "schema": "usk.provider_package_manifest.v1",
        "provider": {
            "authority_exclusions": AUTHORITY_EXCLUSIONS,
            "c_abi": {
                "major": abi_major,
                "manifest_path": ABI_RELATIVE_PATH.as_posix(),
                "manifest_sha256": abi_digest,
                "minor": abi_minor,
            },
            "id": "universal-setup",
            "maturity": "fixture-qualified",
            "package_version": package_version,
            "state_formats": EXPECTED_STATE_FORMATS,
        },
        "source": {
            "commit": source_commit,
            "ref": source_ref,
            "repository": source_repository,
            "tree": source_tree,
        },
        "package": {
            "architecture": architecture,
            "configuration": configuration or "unspecified",
            "installed_targets": targets,
            "linkage": linkage,
            "os": os_name,
            "toolchain": {
                "compiler": compiler.replace("\\", "/"),
                "id": toolchain_id,
                "version": toolchain_version,
            },
        },
        "inventories": {
            "algorithm": "sha256-canonical-json-v1",
            "artifacts": artifacts,
            "artifacts_sha256": inventory_digest(artifacts),
            "contracts": contracts,
            "contracts_sha256": inventory_digest(contracts),
            "public_headers": headers,
            "public_headers_sha256": inventory_digest(headers),
        },
        "licence": {
            "expression": licence_expression(prefix),
            "files": licences,
            "files_sha256": inventory_digest(licences),
        },
        "qualification": {
            "requirements": QUALIFICATION_REQUIREMENTS,
            "tck_revision": source_commit,
        },
    }


def manifest_path(prefix: Path) -> Path:
    return prefix.resolve() / MANIFEST_RELATIVE_PATH


def write_manifest(prefix: Path, manifest: dict[str, Any]) -> Path:
    destination = manifest_path(prefix)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(canonical_json_bytes(manifest))
    return destination


def load_manifest(prefix: Path) -> dict[str, Any]:
    path = manifest_path(prefix)
    if not path.is_file():
        raise ManifestError(f"provider package manifest is missing: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ManifestError(f"provider package manifest is unreadable: {error}") from error
    if not isinstance(data, dict):
        raise ManifestError("provider package manifest root must be an object")
    return data


def require_path(data: dict[str, Any], *path: str) -> Any:
    value: Any = data
    for field in path:
        if not isinstance(value, dict) or field not in value:
            raise ManifestError(f"provider package manifest is missing {'.'.join(path)}")
        value = value[field]
    return value


def verify_manifest(
    prefix: Path,
    *,
    expected_source_commit: str | None = None,
    expected_source_tree: str | None = None,
    expected_source_ref: str | None = None,
    expected_package_version: str | None = None,
    expected_c_abi: str | None = None,
    expected_installed_state_read_versions: list[int] | None = None,
    expected_installed_state_write_version: int | None = None,
    expected_transaction_journal_read_versions: list[int] | None = None,
    expected_transaction_journal_write_version: int | None = None,
    expected_linkage: str | None = None,
) -> dict[str, Any]:
    prefix = prefix.resolve()
    data = load_manifest(prefix)
    if data.get("schema") != "usk.provider_package_manifest.v1":
        raise ManifestError("provider package manifest schema is unsupported")
    if require_path(data, "provider", "id") != "universal-setup":
        raise ManifestError("provider identity is not universal-setup")
    if require_path(data, "provider", "package_version") != EXPECTED_PACKAGE_VERSION:
        raise ManifestError("provider package version is not exact 1.0.0 truth")
    if require_path(data, "provider", "state_formats") != EXPECTED_STATE_FORMATS:
        raise ManifestError("provider state-format identity is not exact v1 truth")
    if require_path(data, "provider", "maturity") != "fixture-qualified":
        raise ManifestError("provider maturity identity changed")
    if require_path(data, "provider", "authority_exclusions") != AUTHORITY_EXCLUSIONS:
        raise ManifestError("provider authority exclusions changed")
    if require_path(data, "source", "repository") != EXPECTED_SOURCE_REPOSITORY:
        raise ManifestError("provider source repository identity changed")
    source_commit = require_path(data, "source", "commit")
    source_tree = require_path(data, "source", "tree")
    source_ref = require_path(data, "source", "ref")
    validate_identity(source_commit, source_tree, source_ref)
    actual_artifacts = artifact_inventory(prefix)
    recorded_artifacts = require_path(data, "inventories", "artifacts")
    if recorded_artifacts != actual_artifacts:
        raise ManifestError("installed artifact inventory or digest changed")
    if require_path(data, "inventories", "artifacts_sha256") != inventory_digest(
        actual_artifacts
    ):
        raise ManifestError("installed artifact inventory digest changed")
    for field, prefixes in (
        ("public_headers", ("include/usk/",)),
        ("contracts", ("share/universal-setup/contracts/",)),
    ):
        actual = select_inventory(actual_artifacts, prefixes)
        if require_path(data, "inventories", field) != actual:
            raise ManifestError(f"{field} inventory changed")
        if require_path(data, "inventories", f"{field}_sha256") != inventory_digest(
            actual
        ):
            raise ManifestError(f"{field} inventory digest changed")
    actual_licences = select_inventory(
        actual_artifacts, ("share/licenses/universal-setup/",)
    )
    if require_path(data, "licence", "files") != actual_licences:
        raise ManifestError("licence inventory changed")
    if require_path(data, "licence", "files_sha256") != inventory_digest(
        actual_licences
    ):
        raise ManifestError("licence inventory digest changed")
    abi_major, abi_minor, abi_digest = installed_abi(prefix)
    if require_path(data, "provider", "c_abi", "manifest_sha256") != abi_digest:
        raise ManifestError("ABI manifest digest changed")
    if require_path(data, "provider", "c_abi", "major") != abi_major or require_path(
        data, "provider", "c_abi", "minor"
    ) != abi_minor:
        raise ManifestError("ABI version does not match the installed ABI manifest")
    actual_targets = installed_targets(prefix)
    if require_path(data, "package", "installed_targets") != actual_targets:
        raise ManifestError("installed CMake target inventory changed")
    linkage = require_path(data, "package", "linkage")
    expected_by_linkage = {
        "static": {"UniversalSetup::Headers", "UniversalSetup::CoreStatic"},
        "shared": {"UniversalSetup::Headers", "UniversalSetup::CoreShared"},
        "combined": EXPECTED_TARGETS,
    }
    if linkage not in expected_by_linkage or set(actual_targets) != expected_by_linkage[linkage]:
        raise ManifestError("linkage identity does not match installed CMake targets")
    if require_path(data, "licence", "expression") != licence_expression(prefix):
        raise ManifestError("licence expression changed")
    if require_path(data, "inventories", "algorithm") != "sha256-canonical-json-v1":
        raise ManifestError("installed artifact inventory algorithm changed")
    if require_path(data, "qualification", "requirements") != QUALIFICATION_REQUIREMENTS:
        raise ManifestError("provider qualification requirements changed")
    expectations = [
        ("source commit", expected_source_commit, source_commit),
        ("source tree", expected_source_tree, source_tree),
        ("source ref", expected_source_ref, source_ref),
        (
            "package version",
            expected_package_version,
            require_path(data, "provider", "package_version"),
        ),
        ("linkage", expected_linkage, linkage),
    ]
    for label, expected, actual in expectations:
        if expected is not None and expected != actual:
            raise ManifestError(f"{label} mismatch: expected {expected}, got {actual}")
    if expected_c_abi is not None:
        actual_c_abi = f"{abi_major}.{abi_minor}"
        if expected_c_abi != actual_c_abi:
            raise ManifestError(
                f"C ABI mismatch: expected {expected_c_abi}, got {actual_c_abi}"
            )
    state_formats = require_path(data, "provider", "state_formats")
    format_expectations = (
        ("installed_state", "read_versions", expected_installed_state_read_versions),
        ("installed_state", "write_version", expected_installed_state_write_version),
        (
            "transaction_journal",
            "read_versions",
            expected_transaction_journal_read_versions,
        ),
        (
            "transaction_journal",
            "write_version",
            expected_transaction_journal_write_version,
        ),
    )
    for format_name, field, expected in format_expectations:
        actual = state_formats[format_name][field]
        if expected is not None and expected != actual:
            raise ManifestError(
                f"{format_name} {field.replace('_', '-')} identity mismatch"
            )
    if require_path(data, "qualification", "tck_revision") != source_commit:
        raise ManifestError("qualification revision does not match provider source")
    return data


def check_repository() -> list[str]:
    problems: list[str] = []
    required_files = [
        ROOT / "cmake" / "GenerateProviderPackageManifest.cmake.in",
        ROOT / "contracts" / "schema" / "package" / "provider_package_manifest.v1.schema.json",
        ROOT / "tests" / "test_provider_package_manifest.py",
    ]
    for path in required_files:
        if not path.is_file():
            problems.append(f"provider package manifest surface is missing {path.relative_to(ROOT)}")
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    for anchor in (
        "project(universal_setup VERSION 1.0.0",
        "USK_INSTALL_PROVIDER_MANIFEST",
        "GenerateProviderPackageManifest.cmake",
    ):
        if anchor not in cmake:
            problems.append(f"CMake package truth is missing {anchor}")
    for path in (ROOT / "README.md", ROOT / "cmake" / "README-SDK.md"):
        content = path.read_text(encoding="utf-8")
        if "provider-package-manifest.v1.json" not in content:
            problems.append(
                f"{path.relative_to(ROOT)} must document installed provider identity"
            )
    consumer = (ROOT / "tests" / "sdk" / "consumer" / "CMakeLists.txt").read_text(
        encoding="utf-8"
    )
    if 'USK_FIND_VERSION "1.0.0"' not in consumer:
        problems.append("SDK consumer default must require package 1.0.0")
    state_schema = (
        ROOT / "contracts" / "schema" / "setup" / "installed_state.v1.schema.json"
    ).read_text(encoding="utf-8")
    journal_schema = (
        ROOT / "contracts" / "schema" / "setup" / "transaction_journal.v1.schema.json"
    ).read_text(encoding="utf-8")
    if '"usk.installed_state.v1"' not in state_schema:
        problems.append("installed-state package truth must remain schema v1")
    if '"usk.transaction_journal.v1"' not in journal_schema:
        problems.append("transaction-journal package truth must remain schema v1")
    abi = (ROOT / "contracts" / "abi" / "usk_c_abi.v1.toml").read_text(
        encoding="utf-8"
    )
    if "abi_major = 1" not in abi or "abi_minor = 0" not in abi:
        problems.append("provider package manifest requires exact C ABI 1.0")
    return problems


def parse_versions(value: str) -> list[int]:
    try:
        versions = [int(item) for item in value.split(",")]
    except ValueError as error:
        raise argparse.ArgumentTypeError("versions must be comma-separated integers") from error
    if not versions:
        raise argparse.ArgumentTypeError("at least one version is required")
    return versions


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("check")
    generate = commands.add_parser("generate")
    generate.add_argument("--prefix", type=Path, required=True)
    generate.add_argument("--source-root", type=Path, required=True)
    generate.add_argument("--source-repository", required=True)
    generate.add_argument("--source-commit", required=True)
    generate.add_argument("--source-tree", required=True)
    generate.add_argument("--source-ref", required=True)
    generate.add_argument("--package-version", required=True)
    generate.add_argument("--os", dest="os_name", required=True)
    generate.add_argument("--architecture", required=True)
    generate.add_argument("--linkage", required=True)
    generate.add_argument("--configuration", default="unspecified")
    generate.add_argument("--toolchain-id", required=True)
    generate.add_argument("--toolchain-version", required=True)
    generate.add_argument("--compiler", required=True)
    generate.add_argument("--allow-unverifiable-source", action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("--prefix", type=Path, required=True)
    verify.add_argument("--expected-source-commit")
    verify.add_argument("--expected-source-tree")
    verify.add_argument("--expected-source-ref")
    verify.add_argument("--expected-package-version")
    verify.add_argument("--expected-c-abi")
    verify.add_argument(
        "--expected-installed-state-read-versions", type=parse_versions
    )
    verify.add_argument("--expected-installed-state-write-version", type=int)
    verify.add_argument(
        "--expected-transaction-journal-read-versions", type=parse_versions
    )
    verify.add_argument("--expected-transaction-journal-write-version", type=int)
    verify.add_argument("--expected-linkage")
    return root


def main_for_check() -> int:
    problems = check_repository()
    if problems:
        for problem in problems:
            print(f"provider-package-manifest-check: {problem}")
        return 1
    print("provider-package-manifest-check: ok")
    return 0


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "check":
            return main_for_check()
        if args.command == "generate":
            verify_source_identity(
                args.source_root.resolve(),
                args.source_commit,
                args.source_tree,
                args.source_ref,
                args.allow_unverifiable_source,
            )
            manifest = build_manifest(
                prefix=args.prefix,
                source_repository=args.source_repository,
                source_commit=args.source_commit,
                source_tree=args.source_tree,
                source_ref=args.source_ref,
                package_version=args.package_version,
                os_name=args.os_name,
                architecture=args.architecture,
                linkage=args.linkage,
                configuration=args.configuration,
                toolchain_id=args.toolchain_id,
                toolchain_version=args.toolchain_version,
                compiler=args.compiler,
            )
            destination = write_manifest(args.prefix, manifest)
            print(
                "provider-package-manifest: generated "
                f"{destination} sha256={sha256_file(destination)}"
            )
            return 0
        manifest = verify_manifest(
            args.prefix,
            expected_source_commit=args.expected_source_commit,
            expected_source_tree=args.expected_source_tree,
            expected_source_ref=args.expected_source_ref,
            expected_package_version=args.expected_package_version,
            expected_c_abi=args.expected_c_abi,
            expected_installed_state_read_versions=(
                args.expected_installed_state_read_versions
            ),
            expected_installed_state_write_version=(
                args.expected_installed_state_write_version
            ),
            expected_transaction_journal_read_versions=(
                args.expected_transaction_journal_read_versions
            ),
            expected_transaction_journal_write_version=(
                args.expected_transaction_journal_write_version
            ),
            expected_linkage=args.expected_linkage,
        )
        print(
            "provider-package-manifest: verified "
            f"{manifest_path(args.prefix)} source={manifest['source']['commit']}"
        )
        return 0
    except ManifestError as error:
        print(f"provider-package-manifest: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
