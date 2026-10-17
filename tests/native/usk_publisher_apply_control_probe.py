# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Changed registered requests must refuse before starting an SCM service."""

from __future__ import annotations

import hashlib
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid


def write_json(path: Path, value: dict) -> str:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    executable = Path(sys.argv[1]).resolve(strict=True)
    service = "USK_PUB_" + uuid.uuid4().hex
    volume = r"\\?\Volume{00000000-0000-0000-0000-000000000000}" + "\\"
    identity = subprocess.run(["whoami.exe", "/user", "/fo", "csv", "/nh"],
                              capture_output=True, text=True, timeout=10, check=True)
    caller = next(csv.reader(identity.stdout.splitlines()))[1]
    with tempfile.TemporaryDirectory(prefix="usk-reviewed-apply-") as directory:
        root = Path(directory)
        envelope_file = root / "envelope.json"
        apply_file = root / "apply.json"
        apply = {"schema": "usk.install_local_apply_request.v1",
                 "confirmation": "APPLY", "transaction_id": "original"}
        envelope = {"schema": "usk.publisher.lab_reviewed_plan_envelope.v2",
                    "activation": "operator_acceptance_candidate",
                    "apply_request": apply}
        digest = write_json(envelope_file, envelope)
        changed = dict(apply, transaction_id="substituted")
        write_json(apply_file, changed)
        args = [str(executable), "--apply-registered", service,
                str(executable), volume, str(envelope_file), digest,
                caller, "0" * 64, str(apply_file)]
        before = subprocess.run(["sc.exe", "query", service],
                                capture_output=True, timeout=10, check=False)
        if before.returncode != 1060:
            raise AssertionError("generated test service absence was not established")
        # Exercise the real controller parser and request checks in every mode,
        # including the admitted route. The distinct diagnostic proves these
        # refusals reached the request check rather than an unsupported option.
        for mode in ([], ["--admit-client-observer"], ["--grant-client-read"],
                     ["--service-admitted-client"]):
            result = subprocess.run(
                args + mode, capture_output=True, text=True, timeout=10, check=False,
            )
            if result.returncode != 3 or "apply request differs" not in result.stderr:
                raise AssertionError(f"reviewed apply substitution was admitted in {mode}: {result}")
            for operation, expected_schema in (
                ("--recover-registered", "usk.publisher_recovery_request.v1"),
                ("--verify-registered", "usk.publisher_installed_verify_request.v1"),
            ):
                wrong_request = root / (operation[2:] + ".json")
                write_json(wrong_request, {"schema": "usk.install_local_apply_request.v1"})
                result = subprocess.run(
                    [str(executable), operation, service, str(executable), volume,
                     caller, "0" * 64, str(wrong_request)] + mode,
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if result.returncode != 3 or "request mode differs" not in result.stderr:
                    raise AssertionError(
                        f"{operation} accepted a request other than {expected_schema} in {mode}: {result}"
                    )
        # Admitted requests must bind the current caller before reading input.
        # A different canonical account SID is insufficient, even with this mode.
        wrong_caller_args = list(args)
        wrong_caller_args[7] = "S-1-5-18" if caller != "S-1-5-18" else "S-1-5-19"
        result = subprocess.run(
            wrong_caller_args + ["--service-admitted-client"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode != 3 or "caller differs from this process identity" not in result.stderr:
            raise AssertionError(f"admitted controller did not reject the actual caller mismatch: {result}")
        # The mode is deliberately unavailable on legacy configure/start verbs.
        # Opting in must never turn these into SCM mutations for an admitted target.
        for operation in ("--recover", "--verify", "--start"):
            result = subprocess.run(
                [str(executable), operation, service, str(executable), volume,
                 caller, "--service-admitted-client"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if result.returncode != 3 or "caller access mode is invalid" not in result.stderr:
                raise AssertionError(f"admitted mode reached legacy {operation}: {result}")
        after = subprocess.run(["sc.exe", "query", service],
                               capture_output=True, timeout=10, check=False)
        if after.returncode != 1060:
            raise AssertionError("invalid apply left a service or unknown SCM state")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
