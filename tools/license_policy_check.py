# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_LICENSE = """MIT License

Copyright (c) 2026 Jules C

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
SPDX_COPYRIGHT = "SPDX-FileCopyrightText: 2026 Jules C"
SPDX_LICENSE = "SPDX-License-Identifier: MIT"
COVERED_SUFFIXES = {".c", ".cmake", ".cpp", ".h", ".py", ".toml", ".yaml", ".yml"}
IGNORED_PARTS = {".git", ".pytest_cache", "__pycache__", "build", "dist", "out"}


def covered_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in IGNORED_PARTS for part in path.parts):
            continue
        if path.name == "CMakeLists.txt" or path.suffix.lower() in COVERED_SUFFIXES:
            files.append(path)
    return sorted(files)


def validate() -> list[str]:
    problems: list[str] = []
    license_path = ROOT / "LICENSE"
    if not license_path.is_file():
        problems.append("repository-root LICENSE is missing")
    elif license_path.read_text(encoding="utf-8").replace("\r\n", "\n") != EXPECTED_LICENSE:
        problems.append("repository-root LICENSE does not match the authorized MIT text")

    contract_path = ROOT / "release" / "license.v1.toml"
    if not contract_path.is_file():
        problems.append("release/license.v1.toml is missing")
    else:
        with contract_path.open("rb") as handle:
            contract = tomllib.load(handle)
        expected = {
            "schema": "universal_setup.license.v1",
            "project_id": "universal_setup",
            "spdx_license_expression": "MIT",
            "package_license_expression": "MIT",
            "license_file": "LICENSE",
            "publication_status": "unpublished",
            "publisher_authenticity": "not_proven_unsigned",
        }
        for key, value in expected.items():
            if contract.get(key) != value:
                problems.append(f"license contract {key} must be {value!r}")

    for path in covered_files():
        header = "\n".join(path.read_text(encoding="utf-8").splitlines()[:8])
        relative = path.relative_to(ROOT)
        if SPDX_COPYRIGHT not in header:
            problems.append(f"{relative} lacks the SPDX copyright header")
        if SPDX_LICENSE not in header:
            problems.append(f"{relative} lacks the SPDX MIT header")
    return problems


def main() -> int:
    problems = validate()
    if problems:
        for problem in problems:
            print(f"license-policy-check: {problem}")
        return 1
    print(f"license-policy-check: ok ({len(covered_files())} covered files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
