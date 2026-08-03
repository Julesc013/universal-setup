# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import copy
import tomllib
import unittest

from tools import branch_policy_check


class BranchPolicyTests(unittest.TestCase):
    def test_canonical_policy_is_valid(self) -> None:
        self.assertEqual(branch_policy_check.check(), [])

    def test_provider_dev_cannot_become_a_consumer_pin(self) -> None:
        with branch_policy_check.POLICY.open("rb") as handle:
            policy = tomllib.load(handle)
        invalid = copy.deepcopy(policy)
        invalid["invariants"]["consumer_pins_may_reference_dev"] = True
        self.assertIn(
            "branch policy invariants.consumer_pins_may_reference_dev must be False",
            branch_policy_check.check_data(invalid),
        )


if __name__ == "__main__":
    unittest.main()
