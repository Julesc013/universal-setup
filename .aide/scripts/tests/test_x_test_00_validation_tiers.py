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


class ValidationTierCommandTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        return root

    def run_cli(self, root: Path, *args: str) -> tuple[int, str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), *args])
        return code, buffer.getvalue()

    def test_existing_test_command_remains_selftest_alias(self) -> None:
        root = self.make_repo()
        code, output = self.run_cli(root, "test")
        self.assertEqual(code, 0)
        self.assertIn("AIDE Lite test", output)
        self.assertIn("status: PASS", output)

    def test_tiers_and_tier_plan_are_report_only(self) -> None:
        root = self.make_repo()
        code, output = self.run_cli(root, "test", "tiers")
        self.assertEqual(code, 0)
        self.assertIn("mode: report_only", output)
        self.assertIn("- T3:", output)

        code, output = self.run_cli(root, "test", "tier-plan")
        self.assertEqual(code, 0)
        self.assertIn("report_only: true", output)
        plan = json.loads(aide_lite.read_text(root / aide_lite.LATEST_TEST_TIER_PLAN_JSON_PATH))
        self.assertEqual(plan["normal_post_task"], ["T0", "T1"])
        self.assertEqual(plan["full_suite_default"], "T3_promotion_only")

    def test_impact_plan_is_plan_not_proof(self) -> None:
        root = self.make_repo()
        code, output = self.run_cli(root, "test", "impact-plan", "--from", "HEAD~1")
        self.assertEqual(code, 0)
        self.assertIn("proof_status: plan_not_proof", output)
        plan = json.loads(aide_lite.read_text(root / aide_lite.LATEST_TEST_IMPACT_PLAN_JSON_PATH))
        self.assertEqual(plan["mode"], "report_only")
        self.assertFalse(plan["target_test_execution"])

    def test_summary_validate_accepts_compact_and_rejects_raw_log(self) -> None:
        root = self.make_repo()
        code, output = self.run_cli(root, "test", "summary-validate", "--file", aide_lite.TEST_SUMMARY_EXAMPLE_PATH)
        self.assertEqual(code, 0, output)
        self.assertIn("result: PASS", output)

        code, output = self.run_cli(root, "test", "summary-validate", "--file", aide_lite.TEST_SUMMARY_INVALID_EXAMPLE_PATH)
        self.assertNotEqual(code, 0)
        self.assertIn("summary does not embed raw log payload fields", output)

    def test_telemetry_and_handoff_commands_write_reports_without_running_full_suite(self) -> None:
        root = self.make_repo()
        code, output = self.run_cli(root, "test", "telemetry-status")
        self.assertEqual(code, 0, output)
        self.assertIn("target_test_execution: false", output)

        code, output = self.run_cli(root, "test", "full-discovery-handoff", "--reason", "unit test")
        self.assertEqual(code, 0, output)
        self.assertIn("WAITING_FOR_EXTERNAL_FULL_DISCOVERY", output)
        handoff = json.loads(aide_lite.read_text(root / aide_lite.LATEST_FULL_DISCOVERY_HANDOFF_JSON_PATH))
        self.assertFalse(handoff["full_suite_executed"])
        self.assertFalse(handoff["target_test_execution"])

    def test_slow_report_validate_accepts_example(self) -> None:
        root = self.make_repo()
        code, output = self.run_cli(root, "test", "slow-report-validate", "--file", aide_lite.SLOW_TEST_REPORT_EXAMPLE_PATH)
        self.assertEqual(code, 0, output)
        self.assertIn("result: PASS", output)


if __name__ == "__main__":
    unittest.main()
