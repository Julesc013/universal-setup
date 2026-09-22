# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "setup" / "wu004-windows-ntfs-publication-oracles.v1.json"
MODEL = ROOT / "tests" / "publication_authority_reference.py"
module_spec = importlib.util.spec_from_file_location("publication_authority_reference", MODEL)
assert module_spec is not None and module_spec.loader is not None
oracle = importlib.util.module_from_spec(module_spec)
sys.modules[module_spec.name] = oracle
module_spec.loader.exec_module(oracle)


class PublicationAuthorityReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_schema_and_unique_ids(self) -> None:
        self.assertEqual(self.fixture["schema"], "usk.wu004.windows-ntfs-publication-oracles/1")
        self.assertEqual(self.fixture["authority"], "deterministic-reference-model-only")
        self.assertEqual(self.fixture["runtime_results"], "not_run")
        cases = self.fixture["cases"]
        ids = [case["id"] for case in cases]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(set(case) == {"id", "initial", "steps", "expected_result", "expected_phase"}
                            for case in cases))
        self.assertTrue(all(case["expected_result"] in oracle.DISPOSITIONS for case in cases))

    def test_fixture_replay_has_exact_expected_results(self) -> None:
        for case in self.fixture["cases"]:
            result = oracle.replay(oracle.initial_state(**case["initial"]), case["steps"])
            self.assertEqual(result.disposition, case["expected_result"], case["id"])
            self.assertEqual(result.state.phase.value, case["expected_phase"], case["id"])
            self.assertEqual(oracle.invariant_errors(result.state), (), case["id"])

    def test_attack_and_ineligibility_loops_never_complete(self) -> None:
        attacks = [
            {"action": "confirm_visible", "identity": "foreign"},
            {"action": "confirm_visible", "closure": ["foreign"]},
        ]
        prefix = ["preflight", "publish_prepared", "rename"]
        for attack in attacks:
            result = oracle.replay(oracle.initial_state(available=True, eligible=True), prefix + [attack, "metadata"])
            self.assertEqual(result.disposition, "recovery_required")
            self.assertNotEqual(result.state.phase, oracle.Phase.COMPLETED)
        for label in ("reparse", "hardlink", "ads", "sid", "remote", "cross-volume", "hostile-handle"):
            state = oracle.initial_state(available=True, eligible=False)
            result = oracle.transition(state, "preflight")
            self.assertEqual(result.disposition, "no_effect_refusal", label)
            self.assertIs(result.state, state, label)

    def test_crash_prefixes_retain_and_never_manufacture_capability(self) -> None:
        for prefix in (["preflight"], ["preflight", "publish_prepared"],
                       ["preflight", "publish_prepared", "rename"],
                       ["preflight", "publish_prepared", "rename", "confirm_visible"]):
            result = oracle.replay(oracle.initial_state(available=True, eligible=True), prefix + ["crash"])
            self.assertEqual(result.disposition, "recovery_required")
            self.assertTrue(result.state.retained)
            self.assertNotEqual(result.state.phase, oracle.Phase.COMPLETED)
        unavailable = oracle.initial_state()
        result = oracle.replay(unavailable, ["preflight", "publish_prepared", "rename"])
        self.assertEqual(result.disposition, "invalid_trace")
        self.assertEqual(result.state, unavailable)

    def test_completion_requires_identity_closure_and_one_generation(self) -> None:
        completed = oracle.replay(oracle.initial_state(available=True, eligible=True),
                                  ["preflight", "publish_prepared", "rename", "confirm_visible", "metadata"])
        self.assertEqual(completed.disposition, "completed")
        self.assertEqual(oracle.invariant_errors(completed.state), ())
        second = oracle.transition(completed.state, "metadata")
        self.assertEqual(second.disposition, "invalid_trace")
        bad = oracle.initial_state(phase=oracle.Phase.COMPLETED, available=True, eligible=True,
                                   renamed=True, metadata_written=True, visible_identity="foreign",
                                   visible_closure=("payload.bin",), completed_generations={"generation-1"})
        self.assertIn("completed visible identity differs from verified identity", oracle.invariant_errors(bad))

    def test_retained_legacy_cpp_negative_control_remains_present(self) -> None:
        legacy = ROOT / "tests" / "native" / "usk_commit_authority_smoke.cpp"
        text = legacy.read_text(encoding="utf-8")
        self.assertIn("original_publication_regression", text)
        self.assertIn("commit must not publish or claim ownership", text)


if __name__ == "__main__":
    unittest.main()
