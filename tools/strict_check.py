from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import language_runtime_policy_check, structure_policy_check


def main() -> int:
    checks: list[tuple[str, Callable[[], int]]] = [
        ("structure", structure_policy_check.main),
        ("language-runtime-policy", language_runtime_policy_check.main),
    ]
    failed: list[str] = []
    for name, check in checks:
        if check() != 0:
            failed.append(name)
    if failed:
        print(f"strict-check: failed checks: {', '.join(failed)}", file=sys.stderr)
        return 1
    print("strict-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
