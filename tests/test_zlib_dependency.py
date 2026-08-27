# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import unittest

from tools import zlib_dependency_check


class ZlibDependencyTests(unittest.TestCase):
    def test_exact_private_inflate_subset_is_current(self) -> None:
        self.assertEqual([], zlib_dependency_check.validate())


if __name__ == "__main__":
    unittest.main()
