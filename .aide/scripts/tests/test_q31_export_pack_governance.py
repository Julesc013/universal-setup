from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_q31", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q31"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


def copy_file(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(source.read_bytes())


def make_source_repo(parent: Path) -> Path:
    root = parent / "source"
    root.mkdir()
    for rel in [*aide_lite.PORTABLE_SOURCE_FILES, *aide_lite.Q21_REQUIRED_FILES]:
        source = REPO_ROOT / rel
        if source.exists() and source.is_file():
            copy_file(source, root / rel)
    for directory in [*aide_lite.PORTABLE_SOURCE_DIRS, ".aide/import"]:
        source_root = REPO_ROOT / directory
        if not source_root.exists():
            continue
        for source in sorted(source_root.rglob("*")):
            if source.is_file():
                copy_file(source, root / source.relative_to(REPO_ROOT))
    aide_lite.write_text(root / "README.md", "# Source Fixture\n")
    aide_lite.write_text(root / "AGENTS.md", "# Source Agents\n")
    aide_lite.write_text(root / ".gitignore", ".aide.local/\n.aide.local/**\n.env\n")
    return root


def run_git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        encoding="utf-8",
    )


def init_target_git(root: Path) -> None:
    run_git(root, "init")
    run_git(root, "config", "user.email", "fixture@example.invalid")
    run_git(root, "config", "user.name", "Fixture User")
    aide_lite.write_text(root / "COMMIT_MSG", aide_lite.COMMIT_GOOD_EXAMPLE)
    aide_lite.write_text(root / "README.md", "# Target Fixture\n")
    run_git(root, "add", "README.md", "COMMIT_MSG")
    run_git(root, "commit", "-F", "COMMIT_MSG")
    run_git(root, "branch", "-M", "main")


def run_target_command(target: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(target / ".aide/scripts/aide_lite.py"), "--repo-root", str(target), *args],
        cwd=target,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        encoding="utf-8",
    )


class Q31ExportPackGovernanceTests(unittest.TestCase):
    def build_pack(self, temp_root: Path) -> Path:
        source = make_source_repo(temp_root)
        pack_root, report = aide_lite.build_export_pack(source)
        self.assertEqual(report["boundary_violations"], [])
        return pack_root

    def test_export_policy_names_q27_to_q30_governance_classes(self) -> None:
        policy = aide_lite.read_text(REPO_ROOT / aide_lite.EXPORT_IMPORT_POLICY_PATH)
        for anchor in [
            "commit_message_policy",
            "commit_hook_template",
            "commit_template",
            "changelog_preview_support",
            "task_resumption_policy",
            "workunit_policy",
            "recovery_policy",
            "git_workflow_policy",
            "branch_roles_policy",
            "promotion_rules_policy",
            "sync_policy",
            "prune_policy",
            "git_helper_policy",
            "project_workflow_profiles",
            "source_repo_git_detection",
            "source_repo_git_helper_plan",
            "source_repo_branch_policy",
        ]:
            self.assertIn(anchor, policy)

    def test_manifest_includes_commit_task_and_git_governance(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            pack_root = self.build_pack(Path(temp))
            manifest = aide_lite.read_text(pack_root / "manifest.yaml")
            for rel in aide_lite.Q31_REQUIRED_EXPORTED_SOURCE_FILES:
                payload = aide_lite.q31_pack_payload_path(rel)
                self.assertTrue((pack_root / payload).exists(), payload)
                self.assertIn(payload, manifest)

    def test_manifest_excludes_source_branch_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = make_source_repo(Path(temp))
            for rel in aide_lite.Q31_FORBIDDEN_EXPORTED_SOURCE_FILES:
                aide_lite.write_text(source / rel, "source-only\n")
            pack_root, _report = aide_lite.build_export_pack(source)
            manifest = aide_lite.read_text(pack_root / "manifest.yaml")
            for rel in aide_lite.Q31_FORBIDDEN_EXPORTED_SOURCE_FILES:
                payload = aide_lite.q31_pack_payload_path(rel)
                self.assertFalse((pack_root / payload).exists(), payload)
                self.assertNotIn(payload, manifest)

    def test_exported_checksums_validate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            pack_root = self.build_pack(Path(temp))
            ok, problems = aide_lite.validate_pack_checksums(pack_root)
            self.assertTrue(ok, problems)

    def test_q31_golden_tasks_pass(self) -> None:
        for task_id in aide_lite.Q31_GOLDEN_TASK_IDS:
            with self.subTest(task_id=task_id):
                result = aide_lite.run_golden_task(REPO_ROOT, task_id)
                self.assertEqual(result.result, "PASS", result.errors)

    def test_fixture_import_runs_governance_commands_without_hook_install(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_root = Path(temp)
            pack_root = self.build_pack(temp_root)
            target = temp_root / "target"
            target.mkdir()
            init_target_git(target)
            result = aide_lite.apply_import_pack(pack_root, target, dry_run=False, mode="safe")
            self.assertFalse(result["conflicts"])
            for rel in [
                aide_lite.COMMIT_MESSAGE_POLICY_PATH,
                aide_lite.TASK_RESUMPTION_POLICY_PATH,
                aide_lite.WORK_UNITS_POLICY_PATH,
                aide_lite.RECOVERY_POLICY_PATH,
                aide_lite.GIT_WORKFLOW_POLICY_PATH,
                aide_lite.BRANCH_ROLES_POLICY_PATH,
                aide_lite.GIT_HELPER_POLICY_PATH,
                aide_lite.COMMIT_MESSAGE_HOOK_TEMPLATE_PATH,
                "docs/reference/commit-discipline.md",
                "docs/reference/git-workflow-policy.md",
            ]:
                self.assertTrue((target / rel).exists(), rel)
            for rel in [
                aide_lite.AIDE_BRANCH_POLICY_PATH,
                aide_lite.AIDE_DEV_MAIN_PLAN_JSON_PATH,
                aide_lite.GIT_WORKFLOW_DETECTION_JSON_PATH,
                ".aide/queue/index.yaml",
                aide_lite.LATEST_PACKET_PATH,
            ]:
                self.assertFalse((target / rel).exists(), rel)
            self.assertFalse((target / ".git/hooks/commit-msg").exists())
            self.assertFalse((target / "core").exists())
            self.assertTrue((target / "docs/reference/workunit-idempotency.md").exists())
            self.assertFalse((target / "docs/roadmap").exists())

            aide_lite.write_text(target / "INVALID_COMMIT_MSG", "update\n")
            aide_lite.write_text(
                target / ".aide/queue/TARGET-TASK/task.yaml",
                "id: TARGET-TASK\nacceptance:\n  - fixture\n",
            )
            aide_lite.write_text(target / ".aide/queue/TARGET-TASK/status.yaml", "status: running\n")
            aide_lite.write_text(
                target / ".aide/queue/index.yaml",
                """items:
  - id: TARGET-TASK
    status: running
    task: .aide/queue/TARGET-TASK/task.yaml
    evidence: .aide/queue/TARGET-TASK/evidence
""",
            )

            expected_pass = [
                ("commit", "template"),
                ("commit", "check", "--message-file", "COMMIT_MSG"),
                ("changelog", "preview", "--range", "HEAD"),
                ("task", "inspect", "--task-id", "TARGET-TASK"),
                ("git", "policy"),
                ("git", "detect"),
                ("git", "plan"),
            ]
            for command in expected_pass:
                with self.subTest(command=command):
                    completed = run_target_command(target, *command)
                    self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            invalid = run_target_command(target, "commit", "check", "--message-file", "INVALID_COMMIT_MSG")
            self.assertNotEqual(invalid.returncode, 0)


if __name__ == "__main__":
    unittest.main()
