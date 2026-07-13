from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ALLOWED_TOP_LEVEL = {
    ".github",
    ".gitignore",
    "CMakeLists.txt",
    "README.md",
    "apps",
    "archive",
    "cmake",
    "content",
    "contracts",
    "docs",
    "include",
    "release",
    "runtime",
    "tests",
    "tools",
}

IGNORED_TOP_LEVEL = {".git", "__pycache__", ".pytest_cache", "build", "dist", "out", "bin", "obj"}
RETIRED_ROOTS = {"core", "data", "factorio", "launcher", "packages", "packaging", "schema", "schemas", "setup", "source", "src", "ui"}
ALLOWED_RUNTIME_ROOTS = {"base", "command", "diagnostics", "setup", "platform"}
ALLOWED_SETUP_MODULES = {
    "audit",
    "fetch",
    "kernel",
    "manifest",
    "ownership",
    "package",
    "plan",
    "policy",
    "resolver",
    "rollback",
    "state",
    "transaction",
    "verify",
}
ALLOWED_CONTRACT_ROOTS = {"abi", "command", "diagnostic", "policy", "refusal", "result", "schema"}
ALLOWED_SCHEMA_ROOTS = {"audit", "common", "install", "package", "setup", "state", "transaction"}
ALLOWED_CONTENT_ROOTS = {"policy", "templates"}
ALLOWED_RELEASE_ROOTS = {"packaging", "profiles"}
ALLOWED_PACKAGING_ROOTS = {"bsd", "linux", "macos", "portable", "windows"}
ALLOWED_APPS = {"cli", "daemon", "gui", "tui"}


def main() -> int:
    problems: list[str] = []
    problems.extend(check_top_level())
    problems.extend(check_retired_roots())
    problems.extend(check_no_src_source_dirs())
    problems.extend(check_children("runtime", ALLOWED_RUNTIME_ROOTS))
    problems.extend(check_children("runtime/setup", ALLOWED_SETUP_MODULES))
    problems.extend(check_children("contracts", ALLOWED_CONTRACT_ROOTS))
    problems.extend(check_children("contracts/schema", ALLOWED_SCHEMA_ROOTS))
    problems.extend(check_children("content", ALLOWED_CONTENT_ROOTS))
    problems.extend(check_children("release", ALLOWED_RELEASE_ROOTS))
    problems.extend(check_children("release/packaging", ALLOWED_PACKAGING_ROOTS))
    problems.extend(check_children("apps", ALLOWED_APPS))
    problems.extend(check_children("apps/gui", set()))
    problems.extend(check_no_language_version_runtime_buckets())
    problems.extend(check_required_paths())
    problems.extend(check_forbidden_product_semantics())
    if problems:
        for problem in problems:
            print(f"structure-check: {problem}", file=sys.stderr)
        return 1
    print("structure-check: ok")
    return 0


def check_top_level() -> list[str]:
    problems: list[str] = []
    for path in ROOT.iterdir():
        if path.name in IGNORED_TOP_LEVEL:
            continue
        if path.name not in ALLOWED_TOP_LEVEL:
            problems.append(f"unexpected top-level path {path.name}")
    return problems


def check_retired_roots() -> list[str]:
    return [f"retired or product-specific root must not exist: {name}/" for name in sorted(RETIRED_ROOTS) if (ROOT / name).exists()]


def check_no_src_source_dirs() -> list[str]:
    problems: list[str] = []
    for path in ROOT.rglob("*"):
        if path.is_dir() and path.name in {"src", "source"}:
            problems.append(f"forbidden implementation bucket: {path.relative_to(ROOT)}")
    return problems


def check_no_language_version_runtime_buckets() -> list[str]:
    problems: list[str] = []
    forbidden = {"c11", "c17", "cpp98", "cpp11", "cpp17", "cxx98", "cxx11", "cxx17"}
    for path in (ROOT / "runtime").rglob("*"):
        if path.is_dir() and path.name.lower() in forbidden:
            problems.append(f"runtime folders must be domain-based, not language-version buckets: {path.relative_to(ROOT)}")
    return problems


def check_children(relative_root: str, allowed: set[str]) -> list[str]:
    root = ROOT / relative_root
    if not root.exists():
        return [f"missing required root {relative_root}/"]
    problems: list[str] = []
    for child in root.iterdir():
        if child.name == "README.md":
            continue
        if child.is_dir() and child.name in allowed:
            continue
        problems.append(f"{relative_root}/ contains unexpected path {child.name}")
    return problems


def check_required_paths() -> list[str]:
    required = [
        ROOT / "include" / "usk" / "usk_api.h",
        ROOT / "include" / "usu" / "usu_api.h",
        ROOT / "runtime" / "setup" / "kernel" / "usk_api.c",
        ROOT / "runtime" / "setup" / "plan" / "README.md",
        ROOT / "contracts" / "schema" / "install" / "install_manifest.v1.schema.json",
        ROOT / "contracts" / "schema" / "transaction" / "transaction_plan.v1.schema.json",
        ROOT / "contracts" / "schema" / "state" / "installed_state.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "install_plan.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "recipe.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "source.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "archive_inspect_request.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "archive_inspection.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "operation_plan.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "installed_state.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "ownership_manifest.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "transaction_journal.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "audit_event.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "verification_report.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "repair_report.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "move_report.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "uninstall_report.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "recovery_report.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "verify_report.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "audit_log.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "transaction.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "rollback.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "ownership.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "refusal.v1.schema.json",
        ROOT / "contracts" / "schema" / "setup" / "policy.v1.schema.json",
        ROOT / "docs" / "architecture" / "boundary.md",
        ROOT / "docs" / "architecture" / "command_graph.md",
        ROOT / "docs" / "architecture" / "ecosystem_vision.md",
        ROOT / "docs" / "architecture" / "root_grammar.md",
        ROOT / "docs" / "architecture" / "setup_contracts.md",
        ROOT / "docs" / "roadmap.md",
    ]
    return [f"missing required path {path.relative_to(ROOT)}" for path in required if not path.exists()]


def check_forbidden_product_semantics() -> list[str]:
    forbidden = ["factorio", "mod_portal", "modset", "save_manager", "server_manager"]
    problems: list[str] = []
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT).as_posix().lower()
        if rel.startswith(".git/"):
            continue
        for token in forbidden:
            if token in rel:
                problems.append(f"universal-setup must not contain product semantic path {path.relative_to(ROOT)}")
    return problems


if __name__ == "__main__":
    raise SystemExit(main())
