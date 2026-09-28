# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Check that the packaged publisher accepts only its registered CLI grammar."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


def run(binary: Path, *arguments: str) -> int:
    completed = subprocess.run([str(binary), *arguments], capture_output=True,
                               text=True, timeout=5, check=False)
    return completed.returncode


def main() -> int:
    binary = Path(sys.argv[1]).resolve(strict=True)
    volume = "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\"
    digest = "0" * 64
    if run(binary, "--service", "USK_WU006_" + "a" * 32,
           r"C:\USK-Lab\lab-receipt.json", volume) != 2:
        raise AssertionError("production service admitted disposable lab grammar")
    if run(binary, "--service", "USK_PUB_" + "a" * 32,
           "--no-receipt", volume, "--reviewed-plan-envelope",
           r"C:\USK-Lab\plan.json", digest,
           "--authorized-client-sid", "S-1-5-18") != 3:
        raise AssertionError("production service did not recognize registered grammar")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
