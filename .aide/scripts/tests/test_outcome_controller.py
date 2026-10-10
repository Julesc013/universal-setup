from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class OutcomeControllerTests(unittest.TestCase):
    def make_repo(self, prepared: bool = True) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        if prepared:
            aide_lite.run_context(root)
            aide_lite.write_task_packet(root, "Implement Q17 Router Profile v0")
            aide_lite.adapt_agents(root)
            verification = aide_lite.build_verification_report(root, task_packet_path=aide_lite.LATEST_PACKET_PATH)
            aide_lite.write_verification_report(root, aide_lite.LATEST_VERIFICATION_REPORT_PATH, verification)
            aide_lite.write_review_packet(root)
            aide_lite.write_golden_run_reports(root, aide_lite.run_golden_tasks(root, task_ids=aide_lite.SELFTEST_GOLDEN_TASK_IDS))
            records = aide_lite.build_ledger_scan_records(root)
            aide_lite.write_ledger_records(root, records)
            aide_lite.write_token_savings_summary(root, records, [])
        return root

    def test_controller_policy_and_failure_taxonomy_are_loadable(self) -> None:
        root = self.make_repo()
        policy_text = aide_lite.read_text(root / aide_lite.CONTROLLER_POLICY_PATH)
        for anchor in aide_lite.CONTROLLER_POLICY_ANCHORS:
            self.assertIn(anchor, policy_text)
        taxonomy = aide_lite.parse_failure_taxonomy(root)
        self.assertEqual(set(aide_lite.CONTROLLER_FAILURE_CLASSES), set(taxonomy))

    def test_outcome_record_write_read_and_raw_prompt_rejection(self) -> None:
        root = self.make_repo()
        record = aide_lite.make_outcome_record(
            root,
            "Q16",
            "validation",
            "PASS",
            failure_class="unknown",
            severity="info",
            related_paths=["README.md"],
            notes="metadata only",
            run_id="test.record",
        )
        aide_lite.write_outcome_records(root, [record])
        loaded = aide_lite.read_outcome_records(root)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].source, "validation")
        ledger_text = aide_lite.read_text(root / aide_lite.OUTCOME_LEDGER_PATH)
        self.assertNotIn("raw_prompt_body", ledger_text)
        with self.assertRaisesRegex(ValueError, "raw prompt"):
            aide_lite.make_outcome_record(
                root,
                "Q16",
                "bad",
                "WARN",
                failure_class="unknown",
                severity="warning",
                notes="raw prompt: do not store this",
            )

    def test_outcome_add_command_writes_metadata_record(self) -> None:
        root = self.make_repo()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(
                [
                    "--repo-root",
                    str(root),
                    "outcome",
                    "add",
                    "--phase",
                    "Q16",
                    "--source",
                    "validation",
                    "--result",
                    "PASS",
                    "--failure-class",
                    "unknown",
                    "--severity",
                    "info",
                    "--related-path",
                    "README.md",
                    "--notes",
                    "smoke metadata",
                ]
            )
        self.assertEqual(code, 0)
        self.assertIn("raw_content_stored: false", buffer.getvalue())
        self.assertTrue(aide_lite.read_outcome_records(root))

    def test_token_report_reader_detects_over_budget_sample(self) -> None:
        root = self.make_repo()
        record = aide_lite.LedgerRecord(
            "q14.scan.current",
            "Q16",
            "task_packet",
            aide_lite.LATEST_PACKET_PATH,
            40000,
            10,
            10000,
            "chars/4",
            "3200",
            "over_budget",
            "oversized fixture",
        )
        aide_lite.write_ledger_records(root, [record])
        signal = aide_lite.read_token_signal(root)
        self.assertEqual(signal["result"], "FAIL")
        self.assertEqual(signal["failure_class"], "token_budget_exceeded")

    def test_signal_readers_detect_bad_samples(self) -> None:
        root = self.make_repo()
        aide_lite.write_text(
            root / aide_lite.GOLDEN_RUN_JSON_PATH,
            json.dumps({"result": "FAIL", "task_count": 1, "pass_count": 0, "warn_count": 0, "fail_count": 1, "tasks": [{"task_id": "bad", "result": "FAIL"}]}),
        )
        self.assertEqual(aide_lite.read_golden_signal(root)["failure_class"], "golden_task_fail")
        aide_lite.write_text(
            root / aide_lite.LATEST_VERIFICATION_REPORT_PATH,
            "# Verification\n\n## VERIFIER_RESULT\n\n- result: FAIL\n- warnings: 1\n- errors: 1\n",
        )
        verifier = aide_lite.read_verifier_signal(root)
        self.assertEqual(verifier["result"], "FAIL")
        self.assertEqual(verifier["failure_class"], "verifier_fail")
        aide_lite.write_text(root / aide_lite.REVIEW_PACKET_PATH, "# Broken Review Packet\n")
        self.assertEqual(aide_lite.read_review_packet_signal(root)["failure_class"], "review_packet_incomplete")

    def test_context_artifact_reader_detects_missing_artifact(self) -> None:
        root = self.make_repo(prepared=False)
        signal = aide_lite.read_context_signal(root)
        self.assertEqual(signal["result"], "WARN")
        self.assertEqual(signal["failure_class"], "context_missing")

    def test_optimize_suggest_recommends_for_golden_fail_and_packet_size(self) -> None:
        root = self.make_repo()
        records = [
            aide_lite.make_outcome_record(root, "Q16", "golden", "FAIL", "golden_task_fail", "error", ["README.md"]),
            aide_lite.make_outcome_record(root, "Q16", "tokens", "WARN", "packet_too_large", "warning", ["README.md"]),
        ]
        recommendations = aide_lite.build_recommendations(root, records)
        ids = {item.recommendation_id for item in recommendations}
        self.assertIn("REC-GOLDEN-TASKS", ids)
        self.assertIn("REC-PACKET-BUDGET", ids)
        self.assertTrue(all(item.expected_benefit and item.rollback_condition for item in recommendations))
        self.assertTrue(all(not item.applies_automatically for item in recommendations))

    def test_optimize_suggest_proceeds_to_next_queue_phase_when_all_fixture_signals_pass(self) -> None:
        root = self.make_repo()
        records = [
            aide_lite.make_outcome_record(root, "Q16", "token", "PASS", "unknown", "info", ["README.md"]),
            aide_lite.make_outcome_record(root, "Q16", "golden", "PASS", "unknown", "info", ["README.md"]),
            aide_lite.make_outcome_record(root, "Q16", "verifier", "PASS", "unknown", "info", ["README.md"]),
        ]
        recommendations = aide_lite.build_recommendations(root, records)
        self.assertEqual([item.recommendation_id for item in recommendations], ["REC-PROCEED-Q18-WITH-GATES"])
        self.assertIn("Q18 Cache and Local State Boundary", recommendations[0].next_action)

    def test_optimize_command_writes_only_controller_outputs(self) -> None:
        root = self.make_repo()
        prompt_path = root / ".aide/prompts/compact-task.md"
        policy_path = root / aide_lite.CONTROLLER_POLICY_PATH
        before_prompt = aide_lite.read_text(prompt_path)
        before_policy = aide_lite.read_text(policy_path)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "optimize", "suggest"])
        self.assertEqual(code, 0)
        self.assertIn("applies_automatically: false", buffer.getvalue())
        self.assertEqual(before_prompt, aide_lite.read_text(prompt_path))
        self.assertEqual(before_policy, aide_lite.read_text(policy_path))
        self.assertTrue((root / aide_lite.RECOMMENDATIONS_PATH).exists())

    def test_outcome_report_command_and_selftest_include_controller(self) -> None:
        root = self.make_repo()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "outcome", "report"])
        self.assertEqual(code, 0)
        self.assertIn("advisory_only: true", buffer.getvalue())
        self.assertTrue((root / aide_lite.OUTCOME_REPORT_PATH).exists())
        ok, messages = aide_lite.run_selftest()
        self.assertTrue(ok)
        self.assertTrue(any("outcome" in message and "optimize" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
