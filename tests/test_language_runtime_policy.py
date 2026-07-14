# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import unittest

from tools import language_runtime_policy_check


class LanguageRuntimePolicyTests(unittest.TestCase):
    def test_language_runtime_policy_check(self) -> None:
        self.assertEqual(language_runtime_policy_check.main(), 0)


if __name__ == "__main__":
    unittest.main()
