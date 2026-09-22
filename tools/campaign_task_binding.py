#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Create and validate exact WorkUnit bindings derived from campaign authority."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = ROOT / "release/index/campaign_authority.v1.toml"
SPECCTL_PATH = ROOT / "spec/tools/specctl.py"
INTEGRITY_PATH = ROOT / "spec/integrity.json"
OID_RE = re.compile(r"^[0-9a-f]{40}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
SCOPE_FIELDS = ("context_paths", "allowed_paths", "read_only_paths", "forbidden_paths", "forbidden_operations")


class BindingError(ValueError):
    pass


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def repository_path(value: str) -> Path:
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or "\\" in value:
        raise BindingError("binding path must be repository-relative POSIX: " + value)
    path = ROOT.joinpath(*relative.parts)
    if not path.is_file() or path.is_symlink():
        raise BindingError("binding path is missing or unsafe: " + value)
    return path


def load_specctl() -> Any:
    module_spec = importlib.util.spec_from_file_location("usk_specctl_binding", SPECCTL_PATH)
    if module_spec is None or module_spec.loader is None:
        raise BindingError("cannot load specification tooling")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


def load_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    with AUTHORITY_PATH.open("rb") as handle:
        authority = tomllib.load(handle)
    if authority.get("status") != "active":
        raise BindingError("campaign authority is not active")
    specctl = load_specctl()
    bundle = specctl.load_bundle(ROOT / "spec")
    integrity = json.loads(INTEGRITY_PATH.read_text(encoding="utf-8"))
    return authority, bundle, integrity


def git_oid(expression: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--end-of-options", expression], cwd=ROOT, check=False,
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise BindingError("cannot resolve Git identity: " + expression)
    value = result.stdout.strip()
    if not OID_RE.fullmatch(value):
        raise BindingError("resolved Git identity is malformed: " + expression)
    return value


def source_identity_errors(source_commit: str, source_tree: str) -> list[str]:
    try:
        observed_commit = git_oid(source_commit + "^{commit}")
        observed_tree = git_oid(source_commit + "^{tree}")
    except BindingError:
        return ["source commit is not an available commit object"]
    errors = []
    if observed_commit != source_commit:
        errors.append("source commit is not canonical")
    if observed_tree != source_tree:
        errors.append("source tree does not belong to source commit")
    return errors


def predecessor_receipts(values: list[str]) -> dict[str, dict[str, str]]:
    receipts: dict[str, dict[str, str]] = {}
    for value in values:
        if "=" not in value:
            raise BindingError("predecessor receipt must use WORKUNIT=path")
        workunit, relative = value.split("=", 1)
        if not re.fullmatch(r"USK-WU-\d{3}", workunit) or workunit in receipts:
            raise BindingError("invalid or duplicate predecessor receipt: " + workunit)
        path = repository_path(relative)
        receipts[workunit] = {"path": relative, "sha256": sha256(path)}
    return receipts


def create_binding(
    workunit_id: str,
    source_commit: str,
    source_tree: str,
    predecessor_values: list[str],
    environment: str,
    effectful: bool,
    effect_target_receipt: str | None,
) -> dict[str, Any]:
    authority, bundle, integrity = load_inputs()
    task = bundle["tasks"].get(workunit_id)
    if task is None:
        raise BindingError("unknown WorkUnit: " + workunit_id)
    if not OID_RE.fullmatch(source_commit) or not OID_RE.fullmatch(source_tree):
        raise BindingError("source commit and tree must be exact Git object IDs")
    source_errors = source_identity_errors(source_commit, source_tree)
    if source_errors:
        raise BindingError("; ".join(source_errors))
    receipts = predecessor_receipts(predecessor_values)
    target_receipt = None
    if effect_target_receipt is not None:
        path = repository_path(effect_target_receipt)
        target_receipt = {"path": effect_target_receipt, "sha256": sha256(path)}
    if effectful and target_receipt is None:
        raise BindingError("effectful binding requires an exact target/environment receipt")
    task_path = ROOT / "spec" / task["definition_path"]
    binding = {
        "schema": "universal.campaign_task_binding/1",
        "campaign": authority["campaign"],
        "campaign_authority": {
            "path": AUTHORITY_PATH.relative_to(ROOT).as_posix(),
            "sha256": sha256(AUTHORITY_PATH),
        },
        "workunit": workunit_id,
        "task_definition": {
            "path": task_path.relative_to(ROOT).as_posix(),
            "sha256": sha256(task_path),
        },
        "source": {"commit": source_commit, "tree": source_tree},
        "specification": {
            "path": INTEGRITY_PATH.relative_to(ROOT).as_posix(),
            "aggregate_sha256": integrity["aggregate_sha256"],
        },
        "scope": {field: copy.deepcopy(task[field]) for field in SCOPE_FIELDS},
        "predecessors": receipts,
        "environment": {
            "kind": environment,
            "effectful": effectful,
            "target_receipt": target_receipt,
        },
        "authorization": {
            "derived_from_active_campaign": True,
            "fresh_owner_approval_required": False,
            "template_itself_authorizes_execution": False,
            "scope_may_widen_template": False,
        },
        "created_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    errors = binding_errors(binding, authority, bundle, integrity)
    if errors:
        raise BindingError("; ".join(errors))
    return binding


def binding_errors(
    binding: dict[str, Any],
    authority: dict[str, Any],
    bundle: dict[str, Any],
    integrity: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    expected_top = {
        "schema", "campaign", "campaign_authority", "workunit", "task_definition",
        "source", "specification", "scope", "predecessors", "environment",
        "authorization", "created_at",
    }
    if set(binding) != expected_top:
        errors.append("binding top-level fields are incomplete or unknown")
    if binding.get("schema") != "universal.campaign_task_binding/1":
        errors.append("unsupported binding schema")
    if binding.get("campaign") != authority.get("campaign") or authority.get("status") != "active":
        errors.append("binding campaign is not active or does not match")
    authority_ref = binding.get("campaign_authority")
    if not isinstance(authority_ref, dict) or authority_ref != {
        "path": AUTHORITY_PATH.relative_to(ROOT).as_posix(), "sha256": sha256(AUTHORITY_PATH)
    }:
        errors.append("campaign authority binding is stale")
    task = bundle["tasks"].get(binding.get("workunit"))
    if task is None:
        errors.append("binding names an unknown WorkUnit")
    else:
        task_path = ROOT / "spec" / task["definition_path"]
        if binding.get("task_definition") != {
            "path": task_path.relative_to(ROOT).as_posix(), "sha256": sha256(task_path)
        }:
            errors.append("task definition binding is stale")
        expected_scope = {field: copy.deepcopy(task[field]) for field in SCOPE_FIELDS}
        if binding.get("scope") != expected_scope:
            errors.append("task scope differs from the immutable template")
        predecessors = binding.get("predecessors")
        if not isinstance(predecessors, dict) or set(predecessors) != set(task.get("depends_on", [])):
            errors.append("accepted predecessor receipts do not match dependencies")
        elif isinstance(predecessors, dict):
            for receipt in predecessors.values():
                try:
                    path = repository_path(str(receipt.get("path")))
                except (BindingError, AttributeError):
                    errors.append("predecessor receipt is missing or unsafe")
                    continue
                if receipt.get("sha256") != sha256(path):
                    errors.append("predecessor receipt digest is stale")
    source = binding.get("source")
    if not isinstance(source, dict) or set(source) != {"commit", "tree"} or any(
        not OID_RE.fullmatch(str(source.get(field, ""))) for field in ("commit", "tree")
    ):
        errors.append("source binding must contain exact commit and tree IDs")
    else:
        errors.extend(source_identity_errors(source["commit"], source["tree"]))
    spec = binding.get("specification")
    if not isinstance(spec, dict) or spec != {
        "path": INTEGRITY_PATH.relative_to(ROOT).as_posix(),
        "aggregate_sha256": integrity.get("aggregate_sha256"),
    }:
        errors.append("specification aggregate binding is stale")
    environment = binding.get("environment")
    if not isinstance(environment, dict) or set(environment) != {"kind", "effectful", "target_receipt"}:
        errors.append("environment binding is malformed")
    elif environment.get("effectful") is True:
        receipt = environment.get("target_receipt")
        if not isinstance(receipt, dict):
            errors.append("effectful binding lacks target receipt")
        else:
            try:
                path = repository_path(str(receipt.get("path")))
            except BindingError:
                errors.append("effect target receipt is missing or unsafe")
            else:
                if receipt.get("sha256") != sha256(path):
                    errors.append("effect target receipt digest is stale")
    authorization = binding.get("authorization")
    if authorization != {
        "derived_from_active_campaign": True,
        "fresh_owner_approval_required": False,
        "template_itself_authorizes_execution": False,
        "scope_may_widen_template": False,
    }:
        errors.append("binding authorization semantics are invalid")
    try:
        stamp = dt.datetime.fromisoformat(str(binding.get("created_at")).replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError
    except ValueError:
        errors.append("created_at must be timezone-aware")
    return errors


def load_binding(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_binding(path: Path, binding: dict[str, Any]) -> None:
    if path.exists():
        raise BindingError("refusing to overwrite existing binding: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json_text(binding), encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    bind = commands.add_parser("bind")
    bind.add_argument("workunit")
    bind.add_argument("--source-commit", default="HEAD")
    bind.add_argument("--source-tree", default="HEAD^{tree}")
    bind.add_argument("--predecessor-receipt", action="append", default=[])
    bind.add_argument("--environment", default="repository-development")
    bind.add_argument("--effectful", action="store_true")
    bind.add_argument("--effect-target-receipt")
    bind.add_argument("--output", type=Path)
    check = commands.add_parser("check")
    check.add_argument("binding", type=Path)
    args = parser.parse_args(argv)
    try:
        authority, bundle, integrity = load_inputs()
        if args.command == "bind":
            commit = git_oid(args.source_commit) if not OID_RE.fullmatch(args.source_commit) else args.source_commit
            tree = git_oid(args.source_tree) if not OID_RE.fullmatch(args.source_tree) else args.source_tree
            value = create_binding(
                args.workunit, commit, tree, args.predecessor_receipt, args.environment,
                args.effectful, args.effect_target_receipt,
            )
            if args.output:
                write_binding(args.output, value)
                print(json_text({"status": "PASS", "output": str(args.output), "binding_sha256": sha256(args.output)}), end="")
            else:
                print(json_text(value), end="")
        else:
            value = load_binding(args.binding)
            errors = binding_errors(value, authority, bundle, integrity)
            if errors:
                raise BindingError("; ".join(errors))
            print(json_text({"status": "PASS", "binding": str(args.binding)}), end="")
        return 0
    except (BindingError, OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print("campaign-task-binding: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
