# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import unittest
from pathlib import Path

from contracts.schema.transaction.compat import (
    LEGACY_OPERATIONS,
    VERSION_TWO_OPERATIONS,
    convert,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "setup" / "transaction-compat"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def schema(path: str) -> dict:
    return json.loads((ROOT / "contracts" / "schema" / path).read_text(encoding="utf-8"))


class LifecycleContractCompatibilityTests(unittest.TestCase):
    def test_v1_vocabularies_remain_closed_and_v2_is_additive(self) -> None:
        for directory, name, prefix in (
            ("transaction", "transaction_plan", "usk.transaction_plan"),
            ("setup", "transaction", "usk.transaction"),
        ):
            old = schema(f"{directory}/{name}.v1.schema.json")
            new = schema(f"{directory}/{name}.v2.schema.json")
            self.assertEqual(old["properties"]["schema"]["const"], f"{prefix}.v1")
            self.assertEqual(new["properties"]["schema"]["const"], f"{prefix}.v2")
            self.assertEqual(set(old["properties"]["operation"]["enum"]), LEGACY_OPERATIONS)
            self.assertEqual(set(new["properties"]["operation"]["enum"]), VERSION_TWO_OPERATIONS)
            self.assertEqual(old["required"], new["required"])
            self.assertEqual(old["additionalProperties"], new["additionalProperties"])
            for field in old["properties"]:
                if field not in {"schema", "operation"}:
                    self.assertEqual(old["properties"][field], new["properties"][field])

    def test_legacy_fixtures_round_trip_without_losing_extensions(self) -> None:
        for kind, name in (("transaction_plan", "v1-plan.json"), ("transaction", "v1-transaction.json")):
            old = fixture(name)
            upgraded = convert(old, kind, 2)
            self.assertEqual(upgraded["schema"], f"usk.{kind}.v2")
            self.assertEqual(convert(upgraded, kind, 1), old)
            self.assertEqual(old["schema"], f"usk.{kind}.v1")

    def test_new_operations_cannot_be_downgraded_or_spoofed_as_v1(self) -> None:
        for kind, name in (("transaction_plan", "v2-move-plan.json"),
                           ("transaction", "v2-update-transaction.json")):
            newer = fixture(name)
            self.assertEqual(convert(newer, kind, 2), newer)
            with self.assertRaisesRegex(ValueError, "no v1 representation"):
                convert(newer, kind, 1)
            forged = dict(newer, schema=f"usk.{kind}.v1")
            with self.assertRaisesRegex(ValueError, "outside its contract"):
                convert(forged, kind, 2)

    def test_command_graph_v2_exposes_legacy_aliases_and_nullable_category(self) -> None:
        graph = schema("setup/command_graph.v2.schema.json")
        self.assertEqual(graph["properties"]["schema"]["const"], "usk.command_graph.v2")
        self.assertEqual(graph["properties"]["legacy_v1_operations"]["const"],
                         ["install_local", "verify", "repair", "uninstall", "adopt", "audit"])
        item = graph["properties"]["commands"]["items"]
        self.assertIn("operation", item["required"])
        self.assertTrue(VERSION_TWO_OPERATIONS <= set(item["properties"]["operation"]["enum"]))
        self.assertIn(None, item["properties"]["operation"]["enum"])


if __name__ == "__main__":
    unittest.main()
