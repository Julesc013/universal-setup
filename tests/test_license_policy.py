# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import unittest

from tools import license_policy_check


class LicensePolicyTests(unittest.TestCase):
    def test_mit_identity_and_spdx_headers_are_complete(self) -> None:
        self.assertEqual([], license_policy_check.validate())


if __name__ == "__main__":
    unittest.main()
