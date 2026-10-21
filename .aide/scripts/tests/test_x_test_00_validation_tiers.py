from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
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
        # Exercise the admitted source or validated export, not an unowned scaffold.
        code, output = self.run_cli(REPO_ROOT, "test")
        self.assertEqual(code, 0, output)
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

    def git(self, root: Path, *args: str) -> str:
        return subprocess.check_output(
            ["git", "-c", "commit.gpgsign=false", "-c", "user.name=AIDE fixture",
             "-c", "user.email=aide-fixture@example.invalid", "-c",
             f"core.hooksPath={root / '.git/no-hooks'}", *args], cwd=root,
            stderr=subprocess.PIPE, text=True, encoding="utf-8",
        ).strip()

    def make_git_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.git(root, "init", "--quiet")
        (root / "docs").mkdir()
        (root / "docs/guide.md").write_text("original\n", encoding="utf-8")
        self.git(root, "add", "docs/guide.md")
        self.git(root, "commit", "--quiet", "-m", "fixture baseline")
        return root

    def test_successful_empty_observation_is_distinct_from_unknown(self) -> None:
        root = self.make_git_repo()
        before = self.git(root, "status", "--porcelain")
        plan = aide_lite.build_test_impact_plan(root, "HEAD")
        self.assertEqual(plan["changed_paths"], [])
        self.assertEqual(plan["recommended_tier"], "T0")
        self.assertEqual(plan["changed_path_observation"], "available")
        self.assertEqual(plan["mapping_coverage"], "heuristic_incomplete")
        self.assertEqual(plan["warnings"], ["no_changed_paths_detected"])
        self.assertEqual(self.git(root, "status", "--porcelain"), before)

    def test_missing_base_retains_known_paths_and_requires_reconciliation(self) -> None:
        root = self.make_git_repo()
        (root / "docs/guide.md").write_text("changed\n", encoding="utf-8")
        (root / "docs/new.md").write_text("new\n", encoding="utf-8")
        for base in ("refs/heads/base-not-present", ""):
            with self.subTest(base=base):
                plan = aide_lite.build_test_impact_plan(root, base)
                self.assertEqual(plan["recommended_tier"], "T2")
                self.assertEqual(plan["changed_path_observation"], "incomplete")
                self.assertEqual(set(plan["changed_paths"]), {"docs/guide.md", "docs/new.md"})
                self.assertNotIn("no_changed_paths_detected", plan["warnings"])
                self.assertIn("Reconcile", plan["next_action"])
                self.assertFalse(plan["target_test_execution"])

    def test_known_staged_working_and_untracked_paths_keep_existing_mapping(self) -> None:
        root = self.make_git_repo()
        (root / "docs/guide.md").write_text("changed\n", encoding="utf-8")
        (root / "docs/staged.md").write_text("staged\n", encoding="utf-8")
        self.git(root, "add", "docs/staged.md")
        (root / "docs/untracked.md").write_text("untracked\n", encoding="utf-8")
        plan = aide_lite.build_test_impact_plan(root, "HEAD")
        self.assertEqual(set(plan["changed_paths"]),
                         {"docs/guide.md", "docs/staged.md", "docs/untracked.md"})
        self.assertEqual(plan["recommended_tier"], "T1")
        self.assertEqual(plan["changed_path_observation"], "available")
        self.assertEqual({entry["reason"] for entry in plan["entries"]}, {"documentation_change"})
        self.assertEqual(plan["warnings"], [])

    def test_failed_staged_observation_does_not_discard_other_paths(self) -> None:
        root = self.make_git_repo()
        (root / "docs/guide.md").write_text("changed\n", encoding="utf-8")
        (root / "docs/new.md").write_text("new\n", encoding="utf-8")
        actual_run = subprocess.run
        def fail_staged(command, *args, **kwargs):
            if command[3:] == ["diff", "--name-only", "--cached"]:
                return subprocess.CompletedProcess(command, 1, "", "fixture index unavailable")
            return actual_run(command, *args, **kwargs)
        with mock.patch.object(aide_lite.subprocess, "run", side_effect=fail_staged):
            plan = aide_lite.build_test_impact_plan(root, "HEAD")
        self.assertEqual(set(plan["changed_paths"]), {"docs/guide.md", "docs/new.md"})
        self.assertEqual(plan["recommended_tier"], "T2")
        self.assertEqual(plan["changed_path_observation"], "incomplete")
        self.assertIn("staged_diff_unavailable", " ".join(plan["warnings"]))
        self.assertNotIn("no_changed_paths_detected", plan["warnings"])

    def test_observation_exception_is_unknown_not_empty_scope(self) -> None:
        root = self.make_git_repo()
        actual_run = subprocess.run
        def unavailable(command, *args, **kwargs):
            if len(command) > 3 and command[3] in {"diff", "ls-files"}:
                raise OSError("fixture observation unavailable")
            return actual_run(command, *args, **kwargs)
        with mock.patch.object(aide_lite.subprocess, "run", side_effect=unavailable):
            plan = aide_lite.build_test_impact_plan(root, "HEAD")
        self.assertEqual(plan["changed_paths"], [])
        self.assertEqual(plan["recommended_tier"], "T2")
        self.assertEqual(plan["changed_path_observation"], "incomplete")
        self.assertNotIn("no_changed_paths_detected", plan["warnings"])

    def test_unrelated_history_endpoint_fallback_is_explicit(self) -> None:
        root = self.make_git_repo()
        orphan = self.git(root, "commit-tree", "HEAD^{tree}", "-m", "unrelated fixture history")
        plan = aide_lite.build_test_impact_plan(root, orphan)
        self.assertEqual(plan["changed_paths"], [])
        self.assertEqual(plan["recommended_tier"], "T2")
        self.assertEqual(plan["changed_path_observation"], "incomplete")
        self.assertIn("base_diff_unavailable", " ".join(plan["warnings"]))
        self.assertIn("endpoint_comparison_fallback", " ".join(plan["warnings"]))
        self.assertNotIn("no_changed_paths_detected", plan["warnings"])

    def test_actual_cli_reports_incomplete_observation_in_all_outputs(self) -> None:
        root = self.make_git_repo()
        result = subprocess.run(
            [sys.executable, "-B", str(MODULE_PATH), "--repo-root", str(root),
             "test", "impact-plan", "--from", "refs/heads/base-not-present"],
            capture_output=True, text=True, encoding="utf-8", timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("result: WARN", result.stdout)
        self.assertIn("changed_path_observation: incomplete", result.stdout)
        self.assertIn("recommended_tier: T2", result.stdout)
        self.assertIn("next_action: Reconcile", result.stdout)
        report = json.loads((root / aide_lite.LATEST_TEST_IMPACT_PLAN_JSON_PATH).read_text(encoding="utf-8"))
        self.assertEqual(report["changed_path_observation"], "incomplete")
        self.assertEqual(report["proof_status"], "plan_not_proof")
        self.assertFalse(report["target_test_execution"])
        markdown = (root / aide_lite.LATEST_TEST_IMPACT_PLAN_MD_PATH).read_text(encoding="utf-8")
        self.assertIn("changed_path_observation: incomplete", markdown)
        self.assertNotIn("no_changed_paths_detected", markdown)

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
