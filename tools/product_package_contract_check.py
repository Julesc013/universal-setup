# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "contracts" / "schema"
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "product-package"
MATURITY = ROOT / "release" / "index" / "contract_maturity.v1.toml"
REQUIRED_SCHEMAS = {
    "package/component_manifest.v1.schema.json": "usk.component_manifest.v1",
    "package/source_manifest.v1.schema.json": "usk.source_manifest.v1",
    "package/product_package.v1.schema.json": "usk.product_package.v1",
    "setup/product_setup_recipe.v1.schema.json": "usk.setup_recipe.v1",
    "state/installed_state_compatibility.v1.schema.json":
        "usk.installed_state_compatibility.v1",
}
FORBIDDEN_TERMS = {
    "factorio",
    "dominium",
    "c3",
    "catalogue",
    "release_channel",
    "download_url",
    "launch_intent",
    "execution_session",
}
EXPECTED_MATURITY = {
    "product_package.v1",
    "component_manifest.v1",
    "source_manifest.v1",
    "setup_recipe.v1",
    "installed_state_compatibility.v1",
}


def _local_refs(value: object) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str) and "://" not in child:
                refs.append(child)
            else:
                refs.extend(_local_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.extend(_local_refs(child))
    return refs


def _load(path: Path, problems: list[str]) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(f"invalid JSON in {path.relative_to(ROOT)}: {error}")
        return None


def check() -> list[str]:
    problems: list[str] = []
    for relative, identity in REQUIRED_SCHEMAS.items():
        path = SCHEMA_ROOT / relative
        schema = _load(path, problems)
        if not isinstance(schema, dict):
            continue
        if schema.get("properties", {}).get("schema", {}).get("const") != identity:
            problems.append(f"{relative} does not bind {identity}")
        if schema.get("additionalProperties") is not False:
            problems.append(f"{relative} must reject unknown top-level fields")
        serialized = json.dumps(schema, sort_keys=True).lower()
        for forbidden in FORBIDDEN_TERMS:
            if forbidden in serialized:
                problems.append(f"{relative} contains forbidden contract term {forbidden}")
        for reference in _local_refs(schema):
            reference_path = unquote(reference.split("#", 1)[0])
            if not reference_path:
                continue
            target = (path.parent / reference_path).resolve()
            if not target.is_relative_to(SCHEMA_ROOT.resolve()) or not target.is_file():
                problems.append(f"{relative} has unresolved local ref {reference}")

    package = _load(FIXTURE_ROOT / "neutral-product.v1.json", problems)
    recipe = _load(FIXTURE_ROOT / "neutral-recipe.v1.json", problems)
    if isinstance(package, dict):
        if package.get("product_id") != "org.example.fixture":
            problems.append("neutral product fixture must use org.example.fixture")
        if len(package.get("components", [])) != 1:
            problems.append("neutral product fixture must contain one component")
        if "url" in json.dumps(package, sort_keys=True).lower():
            problems.append("neutral product fixture must not contain URL authority")
        if package.get("mutable_paths") != ["data"]:
            problems.append("neutral product fixture must bind its mutable data path")
        package_ref = package.get("source", {}).get("package_ref", "")
        if ":" in package_ref or package_ref.startswith(("/", "\\")) or ".." in package_ref.split("/"):
            problems.append("neutral source must be a local relative package reference")
    if isinstance(recipe, dict):
        expected = ["install", "verify", "repair", "update", "uninstall"]
        if recipe.get("lifecycle_operations") != expected:
            problems.append("neutral recipe must declare the exact lifecycle operation set")
        if recipe.get("rollback_disposition") != "required":
            problems.append("neutral recipe must require rollback disposition")
        if len(recipe.get("migrations", [])) != 1:
            problems.append("neutral recipe must contain one 1.0.0 to 1.1.0 migration")

    try:
        with MATURITY.open("rb") as handle:
            maturity = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        problems.append(f"contract maturity record is unavailable or invalid: {error}")
        maturity = {}
    contracts = maturity.get("contract", [])
    observed = {
        contract.get("id")
        for contract in contracts
        if contract.get("maturity") == "fixture-qualified" and contract.get("evidence")
    }
    if maturity.get("provider") != "universal-setup" or observed != EXPECTED_MATURITY:
        problems.append("package and recipe contracts must be recorded individually as fixture-qualified")
    return problems


def main() -> int:
    problems = check()
    if problems:
        for problem in problems:
            print(f"product-package-contract-check: {problem}", file=sys.stderr)
        return 1
    print("product-package-contract-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
