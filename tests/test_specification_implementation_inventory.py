# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import unittest


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs" / "architecture" / "specification_implementation_inventory.v1.json"
SPECCTL = ROOT / "spec" / "tools" / "specctl.py"
SOURCE_HASH_CONTRACT = "sha256-lf-text-v1"


def canonical_text_bytes(data: bytes) -> bytes:
    if b"\x00" in data:
        raise AssertionError("inventory source is not text")
    return data.replace(b"\r\n", b"\n")


def canonical_source_bytes(path: Path) -> bytes:
    return canonical_text_bytes(path.read_bytes())

module_spec = importlib.util.spec_from_file_location("usk_specctl_inventory", SPECCTL)
assert module_spec is not None and module_spec.loader is not None
specctl = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(specctl)


class SpecificationImplementationInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        cls.bundle = specctl.load_bundle(ROOT / "spec")

    def test_every_requirement_is_classified_once(self) -> None:
        rows = self.inventory["requirements"]
        ids = [row["requirement_id"] for row in rows]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), set(self.bundle["requirements"]))
        allowed = {"implemented", "partial", "absent", "unverified", "outside_selected_release"}
        self.assertTrue(all(row["classification"] in allowed for row in rows))
        expected_counts = {
            classification: sum(row["classification"] == classification for row in rows)
            for classification in sorted(allowed)
        }
        self.assertEqual(self.inventory["counts"], expected_counts)

    def test_traceability_matches_current_spec(self) -> None:
        for row in self.inventory["requirements"]:
            requirement = self.bundle["requirements"][row["requirement_id"]]
            self.assertEqual(row["spec_id"], requirement["spec_id"])
            self.assertEqual(row["acceptance_ids"], requirement["acceptance_ids"])
            self.assertEqual(row["acceptance_status"], "not_run")
            expected_tasks = sorted(
                task_id
                for task_id, task in self.bundle["tasks"].items()
                if row["requirement_id"] in task.get("requirement_ids", [])
            )
            self.assertEqual(row["planned_workunits"], expected_tasks)

    def test_all_source_observations_are_exact_and_local(self) -> None:
        self.assertEqual(self.inventory["source_hash_contract"], SOURCE_HASH_CONTRACT)
        for row in self.inventory["requirements"]:
            references = [row["spec_source"], *row["source_observations"]]
            self.assertTrue(row["source_observations"], row["requirement_id"])
            for reference in references:
                relative = PurePosixPath(reference["path"])
                self.assertFalse(relative.is_absolute())
                self.assertNotIn("..", relative.parts)
                path = ROOT.joinpath(*relative.parts)
                self.assertTrue(path.is_file(), reference["path"])
                self.assertEqual(
                    hashlib.sha256(canonical_source_bytes(path)).hexdigest(),
                    reference["sha256"],
                )

    def test_source_hashes_are_checkout_line_ending_stable(self) -> None:
        fixture = b"first\r\nsecond\r\n"
        self.assertEqual(canonical_text_bytes(fixture), b"first\nsecond\n")

    def test_inventory_binds_current_sealed_spec(self) -> None:
        integrity = json.loads((ROOT / "spec" / "integrity.json").read_text(encoding="utf-8"))
        self.assertEqual(self.inventory["spec_aggregate_sha256"], integrity["aggregate_sha256"])
        self.assertTrue(self.inventory["release_scope"].startswith("selected: Universal Setup 1.1"))
        self.assertEqual(self.inventory["release_selection_ref"], "spec/plan/release-selection.json")
        self.assertEqual(self.inventory["counts"]["outside_selected_release"], 0)

    def test_every_requirement_has_an_independent_release_disposition(self) -> None:
        allowed = {
            "required_for_selected_release",
            "optional_for_selected_release",
            "scheduled_later",
            "unresolved",
        }
        rows = self.inventory["requirements"]
        self.assertTrue(all(row["release_disposition"] in allowed for row in rows))
        expected_counts = {
            disposition: sum(row["release_disposition"] == disposition for row in rows)
            for disposition in sorted(allowed)
        }
        self.assertEqual(self.inventory["release_disposition_counts"], expected_counts)
        for row in rows:
            self.assertIn(row["classification"], self.inventory["classification_definitions"])
            self.assertIn(row["release_disposition"], self.inventory["release_disposition_definitions"])


if __name__ == "__main__":
    unittest.main()
