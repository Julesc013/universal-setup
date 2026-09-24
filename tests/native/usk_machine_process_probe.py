#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Exercise the command host across a real stdin/stdout process boundary."""

from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def run(executable: str, mode: str, payload: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [executable, mode], input=payload, capture_output=True, timeout=20, check=False
    )


def main() -> int:
    executable = sys.argv[1]
    request = {
        "schema": "usk.oneshot_request.v1",
        "request_id": "process-probe",
        "command": "command_graph.inspect",
        "payload": {},
        "dry_run": True,
    }
    encoded = json.dumps(request, separators=(",", ":")).encode("utf-8")
    plain = run(executable, "--machine", encoded)
    assert plain.returncode == 0, plain.stderr
    assert plain.stderr == b"", plain.stderr
    assert plain.stdout.endswith(b"\n") and plain.stdout.count(b"\n") == 1
    document = json.loads(plain.stdout)
    assert document["schema"] == "usk.oneshot_response.v1"
    assert document["request_id"] == "process-probe"
    assert document["status"] == "ok"
    assert isinstance(document["result"], dict)

    framed = run(executable, "--framed", struct.pack(">I", len(encoded)) + encoded)
    assert framed.returncode == 0, framed.stderr
    assert framed.stderr == b"", framed.stderr
    assert len(framed.stdout) >= 4
    body_size = struct.unpack(">I", framed.stdout[:4])[0]
    assert body_size == len(framed.stdout) - 4
    assert json.loads(framed.stdout[4:]) == document

    with tempfile.TemporaryDirectory(prefix="usk-machine-process-") as temporary:
        source = Path(temporary) / "request.json"
        source.write_bytes(encoded)
        from_file = subprocess.run(
            [executable, "--machine", "--request-file", str(source)],
            input=b"SECRET_CANARY_FROM_STDIN",
            capture_output=True,
            timeout=20,
            check=False,
        )
        assert from_file.returncode == 0, from_file.stderr
        assert json.loads(from_file.stdout) == document
        assert b"SECRET_CANARY_FROM_STDIN" not in from_file.stdout + from_file.stderr
        source.write_bytes(struct.pack(">I", len(encoded)) + encoded)
        framed_file = run(executable, "--framed", b"")
        assert framed_file.returncode != 0
        framed_file = subprocess.run(
            [executable, "--framed", "--request-file", str(source)],
            input=b"", capture_output=True, timeout=20, check=False
        )
        assert framed_file.returncode == 0, framed_file.stderr
        assert json.loads(framed_file.stdout[4:]) == document

    canary = b'SECRET_CANARY'
    malformed = run(executable, "--machine", b'{"schema":"usk.oneshot_request.v1","schema":"SECRET_CANARY"}')
    assert malformed.returncode != 0
    assert canary not in malformed.stdout + malformed.stderr
    assert json.loads(malformed.stdout)["error"]["code"] == "invalid_request"

    trailing = run(executable, "--framed", struct.pack(">I", len(encoded)) + encoded + b"x")
    assert trailing.returncode != 0
    assert json.loads(trailing.stdout[4:])["error"]["code"] == "invalid_frame"
    assert struct.unpack(">I", trailing.stdout[:4])[0] == len(trailing.stdout) - 4

    malformed_utf8 = encoded.replace(b'"process-probe"', b'"\xff"')
    invalid_utf8 = run(
        executable, "--framed", struct.pack(">I", len(malformed_utf8)) + malformed_utf8
    )
    assert invalid_utf8.returncode != 0
    assert json.loads(invalid_utf8.stdout[4:])["error"]["code"] == "invalid_request"
    assert b"\xff" not in invalid_utf8.stdout + invalid_utf8.stderr

    overlong = run(executable, "--framed", struct.pack(">I", 1024 * 1024 + 1))
    assert overlong.returncode != 0
    assert json.loads(overlong.stdout[4:])["error"]["code"] == "invalid_frame"
    return 0


if __name__ == "__main__":
    sys.exit(main())
