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
EFFECT_RE = re.compile(r"^[a-z][a-z0-9_.:-]{2,127}$")
MAX_WORKUNIT_EVIDENCE = 32


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
    try:
        specctl.seal(ROOT / "spec", True)
    except specctl.SpecError as exc:
        raise BindingError("specification seal is stale: " + str(exc)) from exc
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


def git_file_bytes(commit: str, relative: str) -> bytes:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or "\\" in relative:
        raise BindingError("Git path must be repository-relative POSIX: " + relative)
    result = subprocess.run(
        ["git", "show", commit + ":" + relative], cwd=ROOT, check=False,
        capture_output=True, timeout=30,
    )
    if result.returncode != 0:
        raise BindingError("source commit does not contain required path: " + relative)
    return result.stdout


def git_is_ancestor(ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant], cwd=ROOT,
        check=False, capture_output=True, timeout=30,
    )
    return result.returncode == 0


def current_checkout_errors(source_commit: str, source_tree: str) -> list[str]:
    errors = source_identity_errors(source_commit, source_tree)
    if errors:
        return errors
    if git_oid("HEAD") != source_commit or git_oid("HEAD^{tree}") != source_tree:
        errors.append("source must equal the current checkout HEAD and tree")
    return errors


def receipt_document(path: Path) -> dict[str, Any]:
    try:
        if path.suffix == ".toml":
            with path.open("rb") as handle:
                value = tomllib.load(handle)
        elif path.suffix == ".json":
            value = json.loads(path.read_text(encoding="utf-8"))
        else:
            raise BindingError("receipt must be TOML or JSON: " + path.as_posix())
    except (tomllib.TOMLDecodeError, json.JSONDecodeError) as exc:
        raise BindingError("receipt is malformed: " + path.as_posix()) from exc
    if not isinstance(value, dict):
        raise BindingError("receipt root must be an object/table: " + path.as_posix())
    return value


def workunit_evidence_errors(
    workunit: str, item: Any, source_commit: str, source_tree: str, index: int,
    containing_commit: str,
) -> list[str]:
    """Bind leaf evidence to the task checkout and its earlier implementation source."""
    prefix = "accepted WorkUnit receipt evidence[" + str(index) + "]"
    if (not isinstance(item, dict) or set(item) != {"path", "sha256", "kind"} or
            not isinstance(item.get("path"), str) or not item["path"].startswith("release/evidence/") or
            not item["path"].endswith(".json") or not SHA_RE.fullmatch(str(item.get("sha256", ""))) or
            item.get("kind") not in {"acceptance", "qualification", "integration", "review"}):
        return [prefix + " is not a typed governed receipt"]
    try:
        path = repository_path(item["path"])
    except BindingError as exc:
        return [prefix + " is missing or unsafe: " + str(exc)]
    errors: list[str] = []
    if sha256(path) != item["sha256"]:
        errors.append(prefix + " digest is stale")
        return errors
    try:
        if hashlib.sha256(git_file_bytes(containing_commit, item["path"])).hexdigest() != item["sha256"]:
            errors.append(prefix + " is not bound to the exact task source")
            return errors
        nested = receipt_document(path)
    except BindingError as exc:
        return [prefix + " is unreadable from the predecessor source: " + str(exc)]
    expected = {
        "schema", "status", "campaign", "workunit", "kind", "claim", "source_commit", "source_tree", "details",
    }
    if set(nested) != expected:
        errors.append(prefix + " fields are incomplete or unknown")
        return errors
    if (nested.get("schema") != "universal.workunit_evidence.v1" or nested.get("status") != "accepted" or
            nested.get("campaign") != "USK-SPEC-TO-RELEASE-01" or nested.get("workunit") != workunit or
            nested.get("kind") != item["kind"] or nested.get("claim") != "workunit:" + workunit + ":" + item["kind"] or
            nested.get("source_commit") != source_commit or nested.get("source_tree") != source_tree or
            not isinstance(nested.get("details"), dict)):
        errors.append(prefix + " schema, kind, claim or source binding is invalid")
    errors.extend(prefix + " " + error for error in source_identity_errors(
        str(nested.get("source_commit", "")), str(nested.get("source_tree", ""))
    ))
    return errors


def predecessor_receipt_errors(
    workunit: str, path: Path, document: dict[str, Any], source_commit: str,
) -> list[str]:
    errors: list[str] = []
    relative = path.relative_to(ROOT).as_posix()
    if not relative.startswith(("release/index/", "release/evidence/")):
        errors.append("predecessor receipt must be repository-governed release evidence")
        return errors
    if document.get("schema") == "universal.specification_baseline_receipt.v1":
        expected = {
            "schema", "status", "workunits", "repository", "integrated_head",
            "merge_commit", "merge_tree", "pull_request", "post_merge_ci_run",
            "post_merge_ci_conclusion", "technical_review_kind", "technical_review_id",
            "human_product_acceptance", "runtime_qualification", "claim",
        }
        if set(document) != expected:
            errors.append("specification baseline receipt fields are incomplete or unknown")
        if document.get("status") != "accepted_source_reconciliation":
            errors.append("specification baseline receipt is not accepted")
        if document.get("repository") != "Julesc013/universal-setup":
            errors.append("specification baseline receipt repository is invalid")
        if workunit not in document.get("workunits", []):
            errors.append("specification baseline receipt does not cover " + workunit)
        if type(document.get("post_merge_ci_run")) is not int or document["post_merge_ci_run"] <= 0 or document.get("post_merge_ci_conclusion") != "success":
            errors.append("specification baseline receipt requires successful post-merge CI provenance")
        if (document.get("technical_review_kind") not in {"agent_comment_review", "human_pull_request_review"} or
                type(document.get("technical_review_id")) is not int or document["technical_review_id"] <= 0):
            errors.append("specification baseline receipt requires typed technical review provenance")
        commit = str(document.get("merge_commit", ""))
        tree = str(document.get("merge_tree", ""))
    elif document.get("schema") == "universal.workunit_receipt.v1":
        if document.get("status") != "accepted" or document.get("workunit") != workunit:
            errors.append("WorkUnit receipt identity or accepted status is invalid")
        commit = str(document.get("source_commit", ""))
        tree = str(document.get("source_tree", ""))
        evidence = document.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            errors.append("accepted WorkUnit receipt requires typed evidence")
        elif len(evidence) > MAX_WORKUNIT_EVIDENCE:
            errors.append("accepted WorkUnit receipt exceeds bounded evidence count")
        else:
            for index, item in enumerate(evidence):
                errors.extend(workunit_evidence_errors(
                    workunit, item, commit, tree, index, source_commit))
    else:
        errors.append("unsupported predecessor receipt schema")
        return errors
    if not OID_RE.fullmatch(commit) or not OID_RE.fullmatch(tree):
        errors.append("predecessor receipt source identity is malformed")
    else:
        errors.extend("predecessor " + error for error in source_identity_errors(commit, tree))
        if not git_is_ancestor(commit, source_commit):
            errors.append("predecessor receipt source is not an ancestor of task source")
    return errors


def target_receipt_errors(
    workunit: str, path: Path, document: dict[str, Any], environment: str,
    requested_effects: list[str],
) -> list[str]:
    relative = path.relative_to(ROOT).as_posix()
    errors: list[str] = []
    if not relative.startswith("release/evidence/"):
        errors.append("effect target receipt must be under release/evidence/")
    expected = {
        "schema", "status", "campaign", "workunits", "environment_kind",
        "effect_class", "target_identity", "authorized_effects", "issued_at", "expires_at",
    }
    if set(document) != expected:
        errors.append("effect target receipt fields are incomplete or unknown")
    if document.get("schema") != "universal.effect_target_receipt.v1" or document.get("status") != "admitted":
        errors.append("effect target receipt schema/status is invalid")
    if document.get("campaign") != "USK-SPEC-TO-RELEASE-01" or workunit not in document.get("workunits", []):
        errors.append("effect target receipt does not cover the campaign and WorkUnit")
    if document.get("environment_kind") != environment:
        errors.append("effect target receipt environment does not match")
    if document.get("effect_class") not in {"disposable_lab", "endpoint", "user_state"}:
        errors.append("effect target receipt effect_class is invalid")
    if not isinstance(document.get("target_identity"), str) or not document["target_identity"]:
        errors.append("effect target receipt needs an exact target identity")
    effects = document.get("authorized_effects")
    if (not isinstance(effects, list) or not effects or len(effects) != len(set(effects)) or
            any(not isinstance(item, str) or not EFFECT_RE.fullmatch(item) or item == "anything" for item in effects)):
        errors.append("effect target receipt needs exact authorized effects")
    if (not isinstance(requested_effects, list) or not requested_effects or
            len(requested_effects) != len(set(requested_effects)) or
            any(not isinstance(item, str) or not EFFECT_RE.fullmatch(item) or item == "anything" for item in requested_effects) or
            set(effects) != set(requested_effects)):
        errors.append("effect target receipt authorized effects must exactly bind requested effects")
    try:
        issued = dt.datetime.fromisoformat(str(document.get("issued_at", "")).replace("Z", "+00:00"))
        expires = dt.datetime.fromisoformat(str(document.get("expires_at", "")).replace("Z", "+00:00"))
        now = dt.datetime.now(dt.timezone.utc)
        if issued.tzinfo is None or expires.tzinfo is None or issued > now or expires <= issued or expires <= now:
            raise ValueError
    except ValueError:
        errors.append("effect target receipt timestamps are invalid or expired")
    return errors


def predecessor_receipts(values: list[str], source_commit: str) -> dict[str, dict[str, str]]:
    receipts: dict[str, dict[str, str]] = {}
    for value in values:
        if "=" not in value:
            raise BindingError("predecessor receipt must use WORKUNIT=path")
        workunit, relative = value.split("=", 1)
        if not re.fullmatch(r"USK-WU-\d{3}", workunit) or workunit in receipts:
            raise BindingError("invalid or duplicate predecessor receipt: " + workunit)
        path = repository_path(relative)
        document = receipt_document(path)
        errors = predecessor_receipt_errors(workunit, path, document, source_commit)
        if errors:
            raise BindingError("; ".join(errors))
        if hashlib.sha256(git_file_bytes(source_commit, relative)).hexdigest() != sha256(path):
            raise BindingError("predecessor receipt is not part of the exact task source: " + relative)
        receipts[workunit] = {"path": relative, "sha256": sha256(path)}
    return receipts


def create_binding(
    workunit_id: str,
    source_commit: str,
    source_tree: str,
    predecessor_values: list[str],
    environment: str,
    effect_target_receipt: str | None,
    requested_effects: list[str] | None = None,
) -> dict[str, Any]:
    authority, bundle, integrity = load_inputs()
    task = bundle["tasks"].get(workunit_id)
    if task is None:
        raise BindingError("unknown WorkUnit: " + workunit_id)
    if not OID_RE.fullmatch(source_commit) or not OID_RE.fullmatch(source_tree):
        raise BindingError("source commit and tree must be exact Git object IDs")
    source_errors = current_checkout_errors(source_commit, source_tree)
    if source_errors:
        raise BindingError("; ".join(source_errors))
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,63}", environment):
        raise BindingError("environment kind must be a non-empty stable identifier")
    receipts = predecessor_receipts(predecessor_values, source_commit)
    target_receipt = None
    effect_class = "none"
    requested_effects = requested_effects or []
    if effect_target_receipt is not None:
        path = repository_path(effect_target_receipt)
        document = receipt_document(path)
        target_errors = target_receipt_errors(workunit_id, path, document, environment, requested_effects)
        if target_errors:
            raise BindingError("; ".join(target_errors))
        if hashlib.sha256(git_file_bytes(source_commit, effect_target_receipt)).hexdigest() != sha256(path):
            raise BindingError("effect target receipt is not part of the exact task source")
        target_receipt = {"path": effect_target_receipt, "sha256": sha256(path)}
        effect_class = document["effect_class"]
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
            "sha256": sha256(INTEGRITY_PATH),
            "aggregate_sha256": integrity["aggregate_sha256"],
        },
        "scope": {field: copy.deepcopy(task[field]) for field in SCOPE_FIELDS},
        "predecessors": receipts,
        "environment": {
            "kind": environment,
            "effect_class": effect_class,
            "target_receipt": target_receipt,
            "requested_effects": requested_effects,
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
    source = binding.get("source")
    if not isinstance(source, dict) or set(source) != {"commit", "tree"} or any(
        not OID_RE.fullmatch(str(source.get(field, ""))) for field in ("commit", "tree")
    ):
        errors.append("source binding must contain exact commit and tree IDs")
        source_commit = ""
    else:
        source_commit = source["commit"]
        errors.extend(current_checkout_errors(source["commit"], source["tree"]))
    authority_ref = binding.get("campaign_authority")
    if not isinstance(authority_ref, dict) or authority_ref != {
        "path": AUTHORITY_PATH.relative_to(ROOT).as_posix(), "sha256": sha256(AUTHORITY_PATH)
    }:
        errors.append("campaign authority binding is stale")
    elif source_commit and hashlib.sha256(git_file_bytes(source_commit, authority_ref["path"])).hexdigest() != authority_ref["sha256"]:
        errors.append("campaign authority is not bound to the exact task source")
    task = bundle["tasks"].get(binding.get("workunit"))
    if task is None:
        errors.append("binding names an unknown WorkUnit")
    else:
        task_path = ROOT / "spec" / task["definition_path"]
        if binding.get("task_definition") != {
            "path": task_path.relative_to(ROOT).as_posix(), "sha256": sha256(task_path)
        }:
            errors.append("task definition binding is stale")
        elif source_commit and hashlib.sha256(git_file_bytes(source_commit, task_path.relative_to(ROOT).as_posix())).hexdigest() != sha256(task_path):
            errors.append("task definition is not bound to the exact task source")
        expected_scope = {field: copy.deepcopy(task[field]) for field in SCOPE_FIELDS}
        if binding.get("scope") != expected_scope:
            errors.append("task scope differs from the immutable template")
        predecessors = binding.get("predecessors")
        if not isinstance(predecessors, dict) or set(predecessors) != set(task.get("depends_on", [])):
            errors.append("accepted predecessor receipts do not match dependencies")
        elif isinstance(predecessors, dict):
            for predecessor, receipt in predecessors.items():
                try:
                    path = repository_path(str(receipt.get("path")))
                except (BindingError, AttributeError):
                    errors.append("predecessor receipt is missing or unsafe")
                    continue
                if receipt.get("sha256") != sha256(path):
                    errors.append("predecessor receipt digest is stale")
                elif source_commit:
                    try:
                        document = receipt_document(path)
                        errors.extend(predecessor_receipt_errors(predecessor, path, document, source_commit))
                        if hashlib.sha256(git_file_bytes(source_commit, receipt["path"])).hexdigest() != receipt["sha256"]:
                            errors.append("predecessor receipt is not bound to the exact task source")
                    except BindingError as exc:
                        errors.append(str(exc))
    spec = binding.get("specification")
    if not isinstance(spec, dict) or spec != {
        "path": INTEGRITY_PATH.relative_to(ROOT).as_posix(),
        "sha256": sha256(INTEGRITY_PATH),
        "aggregate_sha256": integrity.get("aggregate_sha256"),
    }:
        errors.append("specification aggregate binding is stale")
    elif source_commit:
        source_integrity = git_file_bytes(source_commit, spec["path"])
        if hashlib.sha256(source_integrity).hexdigest() != spec["sha256"]:
            errors.append("specification integrity record is not bound to the exact task source")
        else:
            try:
                source_record = json.loads(source_integrity)
            except json.JSONDecodeError:
                errors.append("source specification integrity record is malformed")
            else:
                if source_record.get("aggregate_sha256") != spec["aggregate_sha256"]:
                    errors.append("source specification aggregate does not match binding")
    environment = binding.get("environment")
    if not isinstance(environment, dict) or set(environment) != {"kind", "effect_class", "target_receipt", "requested_effects"}:
        errors.append("environment binding is malformed")
    elif not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,63}", str(environment.get("kind", ""))):
        errors.append("environment kind is invalid")
    elif environment.get("effect_class") == "none":
        if environment.get("target_receipt") is not None or environment.get("requested_effects") != []:
            errors.append("non-effectful binding must not carry a target receipt")
    elif environment.get("effect_class") not in {"disposable_lab", "endpoint", "user_state"}:
        errors.append("environment effect class is invalid")
    else:
        receipt = environment.get("target_receipt")
        if not isinstance(receipt, dict) or set(receipt) != {"path", "sha256"}:
            errors.append("effectful binding lacks an exact target receipt")
        else:
            try:
                path = repository_path(str(receipt.get("path")))
            except BindingError:
                errors.append("effect target receipt is missing or unsafe")
            else:
                if receipt.get("sha256") != sha256(path):
                    errors.append("effect target receipt digest is stale")
                else:
                    document = receipt_document(path)
                    errors.extend(target_receipt_errors(
                        str(binding.get("workunit")), path, document, environment["kind"],
                        environment.get("requested_effects")
                    ))
                    if document.get("effect_class") != environment["effect_class"]:
                        errors.append("effect target receipt class differs from binding")
                    if source_commit and hashlib.sha256(git_file_bytes(source_commit, receipt["path"])).hexdigest() != receipt["sha256"]:
                        errors.append("effect target receipt is not bound to the exact task source")
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
    bind.add_argument("--effect-target-receipt")
    bind.add_argument("--requested-effect", action="append", default=[])
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
                args.effect_target_receipt, args.requested_effect,
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
