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


REPORT_SMOKE_TASK_IDS = (
    "compact-task-packet-required-sections",
    "context-packet-no-full-repo-dump",
    "verifier-detects-bad-evidence",
    "review-packet-evidence-only",
    "token-ledger-budget-check",
    "adapter-managed-section-determinism",
    "commit_message_standard_golden",
    "branch_role_detection_golden",
    "git_workflow_policy_golden",
    "intent_compile_vague_prompt_golden",
)


class GoldenTaskTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        aide_lite.run_context(root)
        aide_lite.write_task_packet(root, "Implement Q16 Outcome Controller v0")
        aide_lite.adapt_agents(root)
        report = aide_lite.build_verification_report(root, task_packet_path=aide_lite.LATEST_PACKET_PATH)
        aide_lite.write_verification_report(root, aide_lite.LATEST_VERIFICATION_REPORT_PATH, report)
        aide_lite.write_review_packet(root)
        records = aide_lite.build_ledger_scan_records(root)
        aide_lite.write_ledger_records(root, records)
        aide_lite.write_token_savings_summary(root, records, [])
        return root

    def test_catalog_loading(self) -> None:
        root = self.make_repo()
        tasks = aide_lite.parse_golden_task_catalog(root)
        self.assertGreaterEqual(len(tasks), 5)
        self.assertEqual([task.task_id for task in tasks], sorted(task.task_id for task in tasks))
        self.assertIn("compact-task-packet-required-sections", {task.task_id for task in tasks})

    def test_eval_list_command(self) -> None:
        root = self.make_repo()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "eval", "list"])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("task_count:", output)
        self.assertIn("token-ledger-budget-check", output)

    def test_run_one_golden_task(self) -> None:
        root = self.make_repo()
        result = aide_lite.run_golden_task(root, "compact-task-packet-required-sections")
        self.assertEqual(result.result, "PASS")
        self.assertGreater(result.checks_run, 0)
        self.assertEqual(result.errors, ())

    def test_report_subset_writes_json_and_markdown_reports(self) -> None:
        root = self.make_repo()
        run = aide_lite.run_golden_tasks(root, task_ids=REPORT_SMOKE_TASK_IDS)
        self.assertEqual(run.result, "PASS")
        json_result, md_result = aide_lite.write_golden_run_reports(root, run)
        self.assertIn(json_result.action, {"written", "unchanged"})
        self.assertIn(md_result.action, {"written", "unchanged"})
        data = json.loads(aide_lite.read_text(root / aide_lite.GOLDEN_RUN_JSON_PATH))
        self.assertEqual(data["schema_version"], "aide.golden-tasks-run.v0")
        self.assertEqual(data["result"], "PASS")
        self.assertEqual(data["task_count"], len(REPORT_SMOKE_TASK_IDS))
        markdown = aide_lite.read_text(root / aide_lite.GOLDEN_RUN_MD_PATH)
        self.assertIn("# Latest Golden Tasks", markdown)
        self.assertIn("Token reduction remains valid only if golden tasks pass.", markdown)

    def test_fail_result_rendering_from_bad_packet_fixture(self) -> None:
        root = self.make_repo()
        aide_lite.write_text(root / aide_lite.LATEST_PACKET_PATH, "# Broken\n")
        result = aide_lite.run_golden_task(root, "compact-task-packet-required-sections")
        self.assertEqual(result.result, "FAIL")
        self.assertTrue(result.errors)

    def test_eval_command_returns_nonzero_on_fail(self) -> None:
        root = self.make_repo()
        aide_lite.write_text(root / aide_lite.LATEST_PACKET_PATH, "# Broken\n")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(
                [
                    "--repo-root",
                    str(root),
                    "eval",
                    "run",
                    "--task",
                    "compact-task-packet-required-sections",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("result: FAIL", buffer.getvalue())

    def test_reports_are_deterministic_and_metadata_only(self) -> None:
        root = self.make_repo()
        run = aide_lite.run_golden_tasks(root, task_ids=REPORT_SMOKE_TASK_IDS)
        aide_lite.write_golden_run_reports(root, run)
        first_json = aide_lite.read_text(root / aide_lite.GOLDEN_RUN_JSON_PATH)
        first_md = aide_lite.read_text(root / aide_lite.GOLDEN_RUN_MD_PATH)
        aide_lite.write_golden_run_reports(root, aide_lite.run_golden_tasks(root, task_ids=REPORT_SMOKE_TASK_IDS))
        self.assertEqual(first_json, aide_lite.read_text(root / aide_lite.GOLDEN_RUN_JSON_PATH))
        self.assertEqual(first_md, aide_lite.read_text(root / aide_lite.GOLDEN_RUN_MD_PATH))
        data = json.loads(first_json)
        self.assertFalse(data["raw_prompt_storage"])
        self.assertFalse(data["raw_response_storage"])
        self.assertNotIn("raw_prompt_body", first_json)
        self.assertNotIn("raw_response_body", first_json)
        self.assertNotIn("print('hello')", first_md)

    def test_eval_report_command_reads_latest_report(self) -> None:
        root = self.make_repo()
        aide_lite.write_golden_run_reports(root, aide_lite.run_golden_tasks(root, task_ids=REPORT_SMOKE_TASK_IDS))
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "eval", "report"])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("result: PASS", output)
        self.assertIn(aide_lite.GOLDEN_RUN_JSON_PATH, output)

    def test_selftest_includes_eval_checks(self) -> None:
        ok, messages = aide_lite.run_selftest()
        self.assertTrue(ok)
        self.assertTrue(any("eval" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
