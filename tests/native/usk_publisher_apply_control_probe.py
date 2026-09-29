# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""A changed reviewed apply must refuse before starting an SCM service."""

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
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=10, check=False)
        if result.returncode != 3 or "differs" not in result.stderr:
            raise AssertionError(f"reviewed apply substitution was admitted: {result}")
        after = subprocess.run(["sc.exe", "query", service],
                               capture_output=True, timeout=10, check=False)
        if after.returncode != 1060:
            raise AssertionError("invalid apply left a service or unknown SCM state")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
