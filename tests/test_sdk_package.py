# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import unittest

from tools import sdk_package_check


class SdkPackageTests(unittest.TestCase):
    def test_sdk_package_is_bounded_relocatable_and_authority_neutral(self) -> None:
        self.assertEqual([], sdk_package_check.check())


if __name__ == "__main__":
    unittest.main()
