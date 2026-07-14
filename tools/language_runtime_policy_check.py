# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cs", ".h", ".hpp", ".m", ".mm", ".swift"}
FORBIDDEN_SUFFIXES = {".cs", ".m", ".mm", ".swift"}
FORBIDDEN_MARKERS = (
    "System.Windows.Forms",
    "Microsoft.UI.Xaml",
    "SwiftUI",
    "AppKit",
    "<gtk/",
    "gtk/gtk.h",
    "<QApplication",
    "<QtWidgets",
)


def main() -> int:
    problems: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        if ".git" in path.parts:
            continue
        rel = path.relative_to(ROOT)
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            problems.append(f"universal-setup must not contain GUI runtime source {rel}")
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for marker in FORBIDDEN_MARKERS:
            if marker in text:
                problems.append(f"GUI toolkit marker {marker} must not leak into {rel}")
    if problems:
        for problem in problems:
            print(f"language-runtime-policy-check: {problem}", file=sys.stderr)
        return 1
    print("language-runtime-policy-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
