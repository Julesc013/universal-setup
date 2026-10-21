from __future__ import annotations

import importlib.util
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


class TokenLedgerTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        aide_lite.write_task_packet(root, "Implement Q15 Golden Tasks v0")
        aide_lite.run_context(root)
        verification = aide_lite.build_verification_report(root, task_packet_path=aide_lite.LATEST_PACKET_PATH)
        aide_lite.write_verification_report(root, aide_lite.LATEST_VERIFICATION_REPORT_PATH, verification)
        aide_lite.write_review_packet(root)
        return root

    def test_budget_status_classification(self) -> None:
        self.assertEqual(aide_lite.classify_budget_status(10, None), "unknown_budget")
        self.assertEqual(aide_lite.classify_budget_status(80, 100), "within_budget")
        self.assertEqual(aide_lite.classify_budget_status(81, 100), "near_budget")
        self.assertEqual(aide_lite.classify_budget_status(101, 100), "over_budget")

    def test_near_budget_is_watchlist_not_warning(self) -> None:
        near = aide_lite.LedgerRecord("run", "Q", "task_packet", "near.md", 324, 1, 81, "chars/4", "100", "near_budget", "near")
        over = aide_lite.LedgerRecord("run", "Q", "task_packet", "over.md", 404, 1, 101, "chars/4", "100", "over_budget", "over")
        self.assertEqual(aide_lite.ledger_budget_watchlist([near, over]), ["near budget: task_packet `near.md` 81/100"])
        self.assertEqual(aide_lite.ledger_budget_warnings([near, over]), ["over budget: task_packet `over.md` 101/100"])

    def test_eval_report_has_explicit_budget(self) -> None:
        root = self.make_repo()
        self.assertEqual(aide_lite.budget_for_surface(root, "eval_report"), 4800)

    def test_ledger_record_generation_and_jsonl_omit_raw_content(self) -> None:
        root = self.make_repo()
        raw_marker = "UNIQUE_RAW_PROMPT_BODY_SHOULD_NOT_BE_STORED"
        aide_lite.write_text(root / "README.md", f"# Readme\n\n{raw_marker}\n")
        record = aide_lite.ledger_record_for_file(root, "README.md", surface="baseline_surface", run_id="test")
        self.assertEqual(record.method, "chars/4")
        self.assertGreater(record.approx_tokens, 0)
        aide_lite.write_ledger_records(root, [record])
        ledger_text = aide_lite.read_text(root / aide_lite.TOKEN_LEDGER_PATH)
        self.assertIn('"path":"README.md"', ledger_text)
        self.assertNotIn(raw_marker, ledger_text)

    def test_ledger_add_refuses_missing_and_ignored_paths(self) -> None:
        root = self.make_repo()
        with self.assertRaisesRegex(ValueError, "file does not exist"):
            aide_lite.assert_ledger_safe_path(root, "missing.md")
        with self.assertRaisesRegex(ValueError, "ignored/local/secret"):
            aide_lite.assert_ledger_safe_path(root, ".env")
        with self.assertRaisesRegex(ValueError, "ignored/local/secret"):
            aide_lite.assert_ledger_safe_path(root, ".aide.local/state.json")

    def test_baseline_calculation_and_comparison(self) -> None:
        root = self.make_repo()
        baseline = aide_lite.calculate_baseline(root, aide_lite.baseline_by_name(root, "root_history_baseline"))
        self.assertGreater(baseline.approx_tokens, 0)
        comparison = aide_lite.compare_to_baseline(root, aide_lite.LATEST_PACKET_PATH, "root_history_baseline")
        self.assertIsNotNone(comparison.reduction_percent)
        self.assertEqual(comparison.compact.surface, "task_packet")
        self.assertEqual(comparison.baseline.name, "root_history_baseline")

    def test_missing_baseline_file_reports_warning(self) -> None:
        root = self.make_repo()
        aide_lite.write_text(
            root / aide_lite.TOKEN_BASELINES_PATH,
            """schema_version: test
baselines:
  - name: broken
    purpose: missing path fixture
    paths:
      - README.md
      - missing-baseline.md
""",
        )
        result = aide_lite.calculate_baseline(root, aide_lite.baseline_by_name(root, "broken"))
        self.assertTrue(any("missing-baseline.md" in warning for warning in result.warnings))
        self.assertGreater(result.approx_tokens, 0)

    def test_regression_warning_threshold(self) -> None:
        old = aide_lite.LedgerRecord("old", "Q", "task_packet", "packet.md", 400, 10, 100, "chars/4", "3200", "within_budget", "old")
        new = aide_lite.LedgerRecord("q14.scan.current", "Q", "task_packet", "packet.md", 520, 10, 130, "chars/4", "3200", "within_budget", "new")
        warnings = aide_lite.regression_warnings([old], [new], 20)
        self.assertTrue(warnings)

    def test_scan_report_and_summary_rendering(self) -> None:
        root = self.make_repo()
        records = aide_lite.build_ledger_scan_records(root)
        self.assertTrue(records)
        self.assertTrue(all("contents" not in aide_lite.ledger_record_to_dict(record) for record in records))
        write_result, merged, existing = aide_lite.merge_ledger_records(root, records, "q14.scan.current")
        self.assertIn(write_result.action, {"written", "unchanged"})
        self.assertIsInstance(existing, list)
        summary_result = aide_lite.write_token_savings_summary(root, merged, [])
        self.assertIn(summary_result.action, {"written", "unchanged"})
        summary = aide_lite.read_text(root / aide_lite.TOKEN_SUMMARY_PATH)
        self.assertIn("raw_prompt_storage: false", summary)
        self.assertIn("Compact-To-Baseline Comparisons", summary)
        self.assertNotIn("print('hello')", aide_lite.read_text(root / aide_lite.TOKEN_LEDGER_PATH))

    def test_selftest_mentions_ledger(self) -> None:
        ok, messages = aide_lite.run_selftest()
        self.assertTrue(ok)
        self.assertTrue(any("ledger" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
