# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import unittest
from pathlib import Path

from tools import structure_policy_check

ROOT = Path(__file__).resolve().parents[1]


class StructurePolicyTests(unittest.TestCase):
    def test_structure_policy_check(self) -> None:
        self.assertEqual(structure_policy_check.main(), 0)

    def test_bootstrap_prompt_was_preserved(self) -> None:
        self.assertTrue((ROOT / "docs" / "planning" / "bootstrap_prompt.md").is_file())
        self.assertFalse((ROOT / "unisetup.txt").exists())


if __name__ == "__main__":
    unittest.main()
