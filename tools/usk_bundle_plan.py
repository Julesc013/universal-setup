# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Compose a read-only machine install plan request from a verified local bundle.

The author supplies the entrypoint and target. This tool does not authorize a
target, install files, sign a bundle, or weaken the protected publisher gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

if __package__:
    from .usk_bundle_author import AuthoringError, MAX_SOURCE_BYTES, inspect_bundle
    from .usk_component_resolver import ResolutionError, resolve_component_ids
else:
    from usk_bundle_author import AuthoringError, MAX_SOURCE_BYTES, inspect_bundle
    from usk_component_resolver import ResolutionError, resolve_component_ids


class PlanCompositionError(ValueError):
    pass


def host_target() -> str:
    """Return the bounded authoring target of this read-only process host."""
    architecture = platform.machine().lower()
    suffix = ({"amd64": "x64", "x86_64": "x64", "arm64": "arm64",
               "aarch64": "arm64"}).get(architecture)
    prefix = ({"win32": "windows", "linux": "linux",
               "darwin": "macos"}).get(sys.platform)
    if prefix is None or suffix is None:
        raise PlanCompositionError("host target is not supported by this planner")
    return f"{prefix}-{suffix}"


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while block := source.read(min(65536, MAX_SOURCE_BYTES + 1 - total)):
            total += len(block)
            if total > MAX_SOURCE_BYTES:
                raise PlanCompositionError("bundle metadata exceeds its byte budget")
            digest.update(block)
    return digest.hexdigest()


def compose_plan(bundle_path: Path, target_root: Path, *, request_id: str,
                 install_id: str, created_at: str, entrypoint_id: str,
                 entrypoint_kind: str, entrypoint_path: str) -> dict[str, Any]:
    if not target_root.is_absolute():
        raise PlanCompositionError("target root must be absolute")
    bundle_path = bundle_path.resolve(strict=True)
    target_root = target_root.resolve(strict=False)
    initial_bundle_hash = _hash(bundle_path)
    bundle = inspect_bundle(bundle_path)
    if _hash(bundle_path) != initial_bundle_hash:
        raise PlanCompositionError("bundle changed during verification")
    if "portable" not in bundle["allowed_scopes"]:
        raise PlanCompositionError("bundle does not admit the portable plan scope")
    if bundle["target"] != host_target():
        raise PlanCompositionError("bundle target differs from this host")
    components = bundle["components"]
    try:
        selected = resolve_component_ids(components)
    except ResolutionError as error:
        raise PlanCompositionError(str(error)) from error
    declared = {component["id"] for component in components}
    if set(selected) != declared:
        raise PlanCompositionError("bundle has unselected components; finalize selection first")
    files = [item for component in components for item in component["files"]]
    if (len(files) > 4096 or
            any(len(item["path"].encode("utf-8")) > 1024 for item in files) or
            sum(len(item["path"].encode("utf-8")) for item in files) > 1024 * 1024):
        raise PlanCompositionError("bundle exceeds native lifecycle file or path budget")
    paths = {item["path"] for item in files}
    if entrypoint_path not in paths:
        raise PlanCompositionError("entrypoint is not a file in the selected bundle")
    if not entrypoint_id or not entrypoint_kind or not request_id or not install_id or not created_at:
        raise PlanCompositionError("plan identifiers and entrypoint kind are required")
    if entrypoint_kind not in {"application", "tool", "server"}:
        raise PlanCompositionError("entrypoint kind is not supported by native lifecycle")
    entrypoint = {"entrypoint_id": entrypoint_id, "kind": entrypoint_kind,
                  "relative_path": entrypoint_path}
    bundle_hash = initial_bundle_hash
    recipe_material = {"schema": "usk.bundle_recipe.v1",
                       "bundle_sha256": bundle_hash,
                       "entrypoints": [entrypoint]}
    recipe_digest = hashlib.sha256(_canonical(recipe_material)).hexdigest()
    payload_path = (bundle_path.parent / "payload.zip").resolve(strict=True)
    budgets = {
        "max_entries": len(files),
        "max_uncompressed_bytes": max(1, sum(item["size_bytes"] for item in files)),
        "max_entry_bytes": max(1, max(item["size_bytes"] for item in files)),
        "max_depth": max(item["path"].count("/") + 1 for item in files),
        "max_ratio": 100,
        "max_elapsed_ms": 300000,
    }
    payload = {
        "schema": "usk.install_local_plan_request.v1",
        "request_id": request_id,
        "created_at": created_at,
        "install_id": install_id,
        "archive": {"path": str(payload_path), "format": "zip",
                    "expected_sha256": bundle["payload"]["sha256"],
                    "strip_prefix": "", "budgets": budgets},
        "target": {"root": str(target_root), "class": "operator_acceptance"},
        "recipe": {"product_id": bundle["product_id"],
                   "product_version": bundle["product_version"],
                   "recipe_digest": recipe_digest,
                   "provider_revision": bundle_hash,
                   "components": list(selected),
                   "entrypoints": [entrypoint]},
        "required_commit_authority": "staged_child_bound_v1",
    }
    return {"schema": "usk.oneshot_request.v1", "request_id": request_id,
            "command": "install_local.plan", "payload": payload, "dry_run": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--install-id", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--entrypoint-id", required=True)
    parser.add_argument("--entrypoint-kind", required=True)
    parser.add_argument("--entrypoint-path", required=True)
    args = parser.parse_args(argv)
    try:
        request = compose_plan(args.bundle, args.target_root,
                               request_id=args.request_id, install_id=args.install_id,
                               created_at=args.created_at,
                               entrypoint_id=args.entrypoint_id,
                               entrypoint_kind=args.entrypoint_kind,
                               entrypoint_path=args.entrypoint_path)
    except (AuthoringError, PlanCompositionError, OSError, ValueError) as error:
        parser.exit(2, f"bundle plan: {error}\n")
    sys.stdout.buffer.write(_canonical(request))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
