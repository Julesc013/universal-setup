# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Bind an authored native plan to the selected protected publisher candidate.

This creates the exact request and service envelope consumed by the restricted
publisher. It does not grant service rights, start a service, or qualify the
candidate for an ordinary customer installation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PureWindowsPath
from typing import Any


class BindingError(ValueError):
    pass


def _windows_path(value: str) -> str:
    if not isinstance(value, str) or not value or "/./" in value.replace("\\", "/"):
        raise BindingError("binding path is invalid")
    path = PureWindowsPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise BindingError("binding path is not absolute and normalized")
    return str(path).replace("\\", "/")


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def compose_binding(request: dict[str, Any], response: dict[str, Any], *,
                    acceptance_root: str, state_root: str,
                    transaction_id: str, applied_at: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Use only a successful native plan for the existing selected NTFS profile."""
    try:
        if (request["schema"] != "usk.oneshot_request.v1" or
                request["command"] != "install_local.plan" or
                request["dry_run"] is not True or
                response["schema"] != "usk.oneshot_response.v1" or
                response["status"] != "ok" or response["result"]["status"] != "ok"):
            raise BindingError("native planning did not succeed")
        planned = response["result"]["payload"]
        source = request["payload"]
        if (source["schema"] != "usk.install_local_plan_request.v1" or
                planned["schema"] != "usk.install_plan.v1" or
                source["request_id"] != request["request_id"] or
                planned["plan_id"] != source["request_id"] or
                source["required_commit_authority"] != "staged_child_bound_v1" or
                planned["required_commit_authority"] != "staged_child_bound_v1" or
                planned["commit_authority_available"] is not False or
                planned["operation"] != "install_local" or
                not _sha256(planned["plan_digest"])):
            raise BindingError("native plan authority or identity differs")
        if not re.fullmatch(r"[A-Za-z]:[\\/]", acceptance_root):
            raise BindingError("selected publisher requires a drive-root acceptance boundary")
        acceptance = str(PureWindowsPath(acceptance_root))
        selected_target = source["target"]["root"]
        if not isinstance(selected_target, str):
            raise BindingError("selected destination target is not a path")
        selected_target = selected_target.replace("\\", "/")
        target_match = re.fullmatch(
            r"[A-Za-z]:/publication/destination/([A-Za-z0-9_][A-Za-z0-9_.-]{0,254})",
            selected_target)
        if not target_match:
            raise BindingError("selected target is outside the exact protected destination")
        component = target_match.group(1)
        stem = component.split(".", 1)[0].upper()
        if (component.endswith(".") or
                stem in {"CON", "PRN", "AUX", "NUL"} or
                re.fullmatch(r"(?:COM|LPT)[1-9]", stem)):
            raise BindingError("selected destination child is not canonical")
        expected_target = _windows_path(str(PureWindowsPath(acceptance) /
            "publication" / "destination" / component))
        if (selected_target != expected_target or
                _windows_path(planned["target"]["root"]) != expected_target or
                _windows_path(state_root) !=
                    _windows_path(str(PureWindowsPath(acceptance) / "setup-state"))):
            raise BindingError("native target or setup state differs from selected profile")
        if (not _sha256(source["archive"]["expected_sha256"]) or
                _windows_path(source["archive"]["path"]) !=
                    _windows_path(planned["source"]["path"]) or
                source["archive"]["expected_sha256"] != planned["source"]["sha256"] or
                source["recipe"]["components"] != planned["component_selection"] or
                source["recipe"]["provider_revision"] !=
                    planned["input_identity"]["provider_revision"] or
                source["recipe"]["recipe_digest"] !=
                    planned["input_identity"]["recipe_digest"]):
            raise BindingError("native source or selection differs from authored request")
        if (not transaction_id or not applied_at or
                not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", applied_at)):
            raise BindingError("apply transaction identity or time is invalid")
        apply = {"schema": "usk.install_local_apply_request.v1",
                 "plan_request": source, "reviewed_plan_id": planned["plan_id"],
                 "reviewed_plan_digest": planned["plan_digest"],
                 "transaction_id": transaction_id, "applied_at": applied_at,
                 "confirmation": "APPLY"}
        envelope = {"schema": "usk.publisher.lab_reviewed_plan_envelope.v2",
                    "activation": "operator_acceptance_candidate",
                    "acceptance_root": acceptance, "state_root": state_root,
                    "reviewed_plan_digest": planned["plan_digest"],
                    "plan_request": source, "apply_request": apply}
        return apply, envelope
    except (KeyError, TypeError, AttributeError) as error:
        raise BindingError("native plan or authored request is malformed") from error


def _read_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 1024 * 1024:
        raise BindingError("planning input exceeds byte budget")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise BindingError("planning input is not an object")
    return value


def _bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("request-file", "response-file", "acceptance-root", "state-root",
                 "transaction-id", "applied-at", "output-dir"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        apply, envelope = compose_binding(
            _read_json(Path(args.request_file)), _read_json(Path(args.response_file)),
            acceptance_root=args.acceptance_root, state_root=args.state_root,
            transaction_id=args.transaction_id, applied_at=args.applied_at)
        output = Path(args.output_dir)
        if not output.is_absolute() or not output.parent.is_dir() or output.parent.is_symlink():
            raise BindingError("output must be a new directory under an ordinary absolute parent")
        envelope_bytes = _bytes(envelope)
        if len(envelope_bytes) > 1024 * 1024:
            raise BindingError("reviewed envelope exceeds service byte budget")
        output.mkdir(mode=0o700)
        apply_path, envelope_path = output / "apply.json", output / "envelope.json"
        with apply_path.open("xb") as target:
            target.write(_bytes(apply))
        with envelope_path.open("xb") as target:
            target.write(envelope_bytes)
        print(json.dumps({"schema": "usk.publisher.candidate_binding.v1",
                          "apply_file": str(apply_path), "envelope_file": str(envelope_path),
                          "envelope_sha256": hashlib.sha256(envelope_bytes).hexdigest()},
                         sort_keys=True))
    except (BindingError, OSError, ValueError) as error:
        parser.exit(2, f"bundle apply binding: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
