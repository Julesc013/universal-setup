#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Discriminate native authored review/apply composition, not publisher safety."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "tools")]
from tests.test_bundle_author import project, write_project
from usk_bundle_author import compile_bundle
from usk_bundle_plan import compose_plan
from usk_prefab_envelope import build_envelope


def main(machine: str, adapter: str) -> None:
    with tempfile.TemporaryDirectory(prefix="usk-product-install-") as directory:
        root = Path(directory).resolve()
        definition = project()
        # Current authoring/archive paths are printable ASCII, including spaces.
        entry_path = "bin/app main.bin"
        definition["components"][0]["variants"][0]["files"][0]["path"] = entry_path
        source = write_project(root / "source", definition)
        compiled, packaged = root / "compiled", root / "packaged"
        compiled.mkdir()
        packaged.mkdir()
        compile_bundle(source, "windows-x64", compiled)
        build_envelope(compiled / "product.bundle.json", Path(machine), "sidecar", packaged)
        bundle = packaged / "product.bundle.json"
        target, state = root / "installed", root / "state"
        context_file, options_file = root / "context.json", root / "options.json"
        review_file, confirmation_file = root / "review.json", root / "confirmation.json"
        context = {"schema": "usk.oneshot_context.v1", "state_root": str(state),
                   "authorized_acceptance_root": str(root),
                   "target_policy_activation": "operator_acceptance_candidate"}
        options = {"schema": "usk.authored_install_options.v1", "request_id": "authored.preview",
                   "install_id": "org.example.authored", "created_at": "2026-10-21T00:00:00Z",
                   "target_root": str(target), "entrypoint": {
                       "entrypoint_id": "main", "kind": "application", "relative_path": entry_path}}
        def write(path: Path, value: dict) -> None:
            path.write_text(json.dumps(value, ensure_ascii=True), encoding="utf-8")
        write(context_file, context)
        write(options_file, options)
        planned = subprocess.run([machine, "--product-plan", str(bundle), "--request-file",
                                  str(options_file), "--context-file", str(context_file)],
                                 capture_output=True, timeout=40)
        assert planned.returncode == 0, (planned.returncode, planned.stdout, planned.stderr)
        review = json.loads(planned.stdout)
        assert review["schema"] == "usk.authored_install_review.v1", review
        expected = compose_plan(bundle, target, request_id=options["request_id"],
                                install_id=options["install_id"], created_at=options["created_at"],
                                entrypoint_id="main", entrypoint_kind="application",
                                entrypoint_path=entry_path)
        assert review["request"] == expected, (review["request"], expected)
        plan = review["response"]["result"]["payload"]
        confirmation = {"schema": "usk.authored_install_confirmation.v1", "request_id": "authored.apply",
                        "reviewed_plan_id": plan["plan_id"], "reviewed_plan_digest": plan["plan_digest"],
                        "transaction_id": "authored.tx", "applied_at": "2026-10-21T01:00:00Z",
                        "confirmation": "APPLY"}
        write(review_file, review)
        write(confirmation_file, confirmation)
        def run(mode: str) -> dict:
            result = subprocess.run([adapter, mode, str(bundle), str(review_file),
                                     str(confirmation_file), str(context_file)],
                                    capture_output=True, timeout=40, check=True)
            return json.loads(result.stdout)
        for mode, code, status in [("pass", 0, "ok"), ("unknown", 5, "unknown"),
                                   ("refuse", 2, "refused")]:
            result = run(mode)
            assert result["code"] == code and result["calls"] == 1 and not result["refused"], result
            assert result["response"]["status"] == status, result
            sent = result["submitted"]
            assert sent["plan_request"] == expected["payload"], sent
            for key in ("reviewed_plan_id", "reviewed_plan_digest", "transaction_id", "applied_at", "confirmation"):
                assert sent[key] == confirmation[key], (key, sent)
            assert result["response"]["request_id"] == "authored.apply", result
        def no_dispatch() -> None:
            result = run("pass")
            assert result["refused"] and result["calls"] == 0, result
        # Tampered review cannot retain an old digest and trick the preview consumer.
        changed = copy.deepcopy(review)
        changed["response"]["result"]["payload"]["planned_entries"][0]["sha256"] = "a" * 64
        write(review_file, changed)
        no_dispatch()
        changed = copy.deepcopy(review)
        changed["request"]["payload"]["archive"]["budgets"]["max_entries"] += 1
        write(review_file, changed)
        no_dispatch()
        write(review_file, review)
        for key, value in [("reviewed_plan_digest", "b" * 64), ("reviewed_plan_id", "other"),
                           ("confirmation", "apply"), ("transaction_id", None),
                           ("transaction_id", ""), ("transaction_id", "../other"),
                           ("applied_at", []), ("applied_at", ""), ("applied_at", "tomorrow"),
                           ("request_id", None), ("request_id", "")]:
            changed = dict(confirmation, **{key: value})
            write(confirmation_file, changed)
            no_dispatch()
        write(confirmation_file, confirmation)
        write(context_file, dict(context, state_root=str(root / "different-state")))
        no_dispatch()
        write(context_file, context)
        # Actual registered transport is reached; an absent registration refuses.
        # Run before source mutation: restoring bytes does not restore file identity.
        actual = subprocess.run([machine, "--product-apply", str(bundle),
            "--review-file", str(review_file), "--request-file", str(confirmation_file),
            "--context-file", str(context_file), "--publisher", "USK_PUB_" + "0" * 32],
            capture_output=True, timeout=40)
        assert actual.returncode == 2, (actual.returncode, actual.stdout, actual.stderr)
        assert actual.stdout, (actual.returncode, actual.stderr)
        assert json.loads(actual.stdout)["error"]["code"] == "publisher_admission_refused", actual.stdout
        # An existing target invalidates the reviewed plan before transport.
        target.mkdir()
        no_dispatch()
        target.rmdir()
        payload = packaged / "payload.zip"
        original = payload.read_bytes()
        payload.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        no_dispatch()
        payload.write_bytes(original)
        assert not target.exists() and not state.exists()
        assert not target.exists() and not state.exists()
        print("native-authored-review-apply-pass; real planner, controlled transport; no installation qualification")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
