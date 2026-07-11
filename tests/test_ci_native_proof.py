from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class NativeCiProofTests(unittest.TestCase):
    def test_standalone_ci_builds_and_runs_native_tests(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        required = [
            "actions/checkout@v6",
            "actions/setup-python@v6",
            "cmake -S . -B build/smoke",
            "cmake --build build/smoke",
            "ctest --test-dir build/smoke --output-on-failure",
            "python tools/strict_check.py",
        ]
        positions = [workflow.index(command) for command in required]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("actions/checkout@v4", workflow)
        self.assertNotIn("actions/setup-python@v5", workflow)


if __name__ == "__main__":
    unittest.main()
