# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import unittest
from pathlib import Path

from tools import license_policy_check


class LicensePolicyTests(unittest.TestCase):
    def test_mit_identity_and_spdx_headers_are_complete(self) -> None:
        self.assertEqual([], license_policy_check.validate())
        covered = {
            path.relative_to(license_policy_check.ROOT)
            for path in license_policy_check.covered_files()
        }
        self.assertIn(Path("include/usk/usk_api.h"), covered)
        self.assertIn(Path("runtime/setup/kernel/usk_api.c"), covered)
        self.assertIn(Path("tools/license_policy_check.py"), covered)


if __name__ == "__main__":
    unittest.main()
