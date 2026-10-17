from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_q28", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q28"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


def git_fixture(args: list[str]) -> tuple[bool, str, str]:
    key = tuple(args)
    outputs = {
        ("branch", "--show-current"): "main",
        ("rev-parse", "HEAD"): "abc123",
        ("branch", "--format=%(refname:short)"): "main\ndev\ntask/example",
        ("branch", "--remotes", "--format=%(refname:short)"): "origin/main\norigin/dev",
        ("tag", "--list"): "",
        ("remote", "-v"): "origin https://github.com/Julesc013/aide.git (fetch)\norigin https://github.com/Julesc013/aide.git (push)",
        ("status", "--short"): " M README.md",
    }
    if key in outputs:
        return True, outputs[key], ""
    return False, "", f"unexpected git args: {' '.join(args)}"


class Q28GitWorkflowTests(unittest.TestCase):
    def test_branch_role_classification(self) -> None:
        expected = {
            "main": "canonical",
            "dev": "integration",
            "task/foo": "task",
            "codex/foo": "task",
            "review/foo": "review",
            "release/1.0": "release",
            "hotfix/1.0.1": "hotfix",
            "gh-pages": "deploy",
            "weird": "unknown",
        }
        for branch, role in expected.items():
            with self.subTest(branch=branch):
                self.assertEqual(aide_lite.classify_branch_role(branch), role)

    def test_workflow_detection_heuristics(self) -> None:
        self.assertEqual(aide_lite.detect_workflow_model(["main"], [])[0], "trunk_without_dev")
        self.assertEqual(aide_lite.detect_workflow_model(["main", "dev"], [])[0], "trunk_with_dev_integration")
        self.assertIn("gitflow_like_detected", aide_lite.detect_workflow_model(["main", "develop"], [])[2])
        self.assertIn("release_lines_detected", aide_lite.detect_workflow_model(["main", "release/1.0"], [])[2])

    def test_policy_validation_anchors(self) -> None:
        checks = aide_lite.validate_git_policy_files(REPO_ROOT)
        failures = [check.message for check in checks if check.severity == "FAIL"]
        self.assertEqual(failures, [])

    def test_git_detect_writes_report_with_mocked_git(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with mock.patch.object(aide_lite, "run_git_capture", side_effect=lambda _root, args: git_fixture(args)):
                code_buffer = io.StringIO()
                with contextlib.redirect_stdout(code_buffer):
                    code = aide_lite.main(["--repo-root", str(root), "git", "detect"])
            self.assertEqual(code, 0)
            data = json.loads(aide_lite.read_text(root / aide_lite.GIT_WORKFLOW_DETECTION_JSON_PATH))
            self.assertEqual(data["schema_version"], "aide.git-workflow-detection.v0")
            self.assertEqual(data["branch_role_for_current_branch"], "canonical")
            self.assertEqual(data["detected_workflow"], "trunk_with_dev_integration")
            self.assertTrue(data["non_mutating"])
            self.assertTrue((root / aide_lite.GIT_WORKFLOW_DETECTION_MD_PATH).exists())

    def test_git_doctor_and_status_print_role(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with mock.patch.object(aide_lite, "run_git_capture", side_effect=lambda _root, args: git_fixture(args)):
                doctor_buffer = io.StringIO()
                with contextlib.redirect_stdout(doctor_buffer):
                    doctor_code = aide_lite.main(["--repo-root", str(root), "git", "doctor"])
                status_buffer = io.StringIO()
                with contextlib.redirect_stdout(status_buffer):
                    status_code = aide_lite.main(["--repo-root", str(root), "git", "status"])
            self.assertEqual(doctor_code, 0)
            self.assertEqual(status_code, 0)
            self.assertIn("current_branch_role: canonical", doctor_buffer.getvalue())
            self.assertIn("dirty_tree: true", status_buffer.getvalue())

    def test_git_command_surface_has_no_mutation_subcommands(self) -> None:
        parser = aide_lite.build_parser(REPO_ROOT)
        root_subparsers = next(action for action in parser._actions if action.__class__.__name__ == "_SubParsersAction")
        git_parser = root_subparsers.choices["git"]
        git_subparsers = next(action for action in git_parser._actions if action.__class__.__name__ == "_SubParsersAction")
        expected = {"workflow", "doctor", "status", "detect", "roles", "policy", "plan", "sync", "land", "promote", "prune"}
        self.assertEqual(set(git_subparsers.choices), expected)
        self.assertFalse({"merge", "push", "delete"} & set(git_subparsers.choices))

    def test_git_detect_does_not_call_fetch_push_or_merge(self) -> None:
        seen: list[tuple[str, ...]] = []

        def recorder(_root: Path, args: list[str]) -> tuple[bool, str, str]:
            seen.append(tuple(args))
            return git_fixture(args)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with mock.patch.object(aide_lite, "run_git_capture", side_effect=recorder):
                aide_lite.main(["--repo-root", str(root), "git", "detect"])
        flattened = " ".join(" ".join(args) for args in seen)
        for forbidden in ["fetch", "push", "merge", "rebase", "branch -d", "branch -D"]:
            self.assertNotIn(forbidden, flattened)

    def test_q28_golden_tasks_pass(self) -> None:
        for task_id in [
            "git_workflow_policy_golden",
            "branch_role_detection_golden",
            "promotion_rules_golden",
            "sync_policy_golden",
            "prune_policy_golden",
        ]:
            with self.subTest(task_id=task_id):
                result = aide_lite.run_golden_task(REPO_ROOT, task_id)
                self.assertEqual(result.result, "PASS", result.errors)


if __name__ == "__main__":
    unittest.main()
