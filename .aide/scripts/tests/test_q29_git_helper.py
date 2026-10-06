from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_q29", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q29"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def init_git_repo(root: Path) -> None:
    git(root, "init")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "user.name", "Fixture User")
    write(root, "README.md", "# Fixture\n")
    git(root, "add", "README.md")
    git(root, "commit", "-m", "initial")
    git(root, "branch", "-M", "main")
    git(root, "checkout", "-b", "dev")
    git(root, "checkout", "main")


def seed_helper_policy(root: Path) -> None:
    for rel in [
        *aide_lite.GIT_HELPER_POLICY_FILES,
        aide_lite.GIT_HELPER_COMMANDS_MD_PATH,
    ]:
        source = REPO_ROOT / rel
        if source.exists():
            aide_lite.write_text(root / rel, aide_lite.read_text(source))
    git(root, "add", ".aide")
    git(root, "commit", "-m", "seed aide helper policy")
    branches = set(git(root, "branch", "--format=%(refname:short)").splitlines())
    current = git(root, "branch", "--show-current")
    if "dev" in branches:
        git(root, "checkout", "dev")
        git(root, "merge", "--ff-only", current)
        git(root, "checkout", current)


def create_task_branch(root: Path, branch: str = "task/example", filename: str = "task.txt") -> None:
    git(root, "checkout", "dev")
    git(root, "checkout", "-b", branch)
    write(root, filename, f"{branch}\n")
    git(root, "add", filename)
    git(root, "commit", "-m", f"task commit {branch}")


class Q29GitHelperTests(unittest.TestCase):
    def test_helper_policy_anchors(self) -> None:
        checks = aide_lite.validate_git_helper_policy_files(REPO_ROOT)
        failures = [check.message for check in checks if check.severity == "FAIL"]
        self.assertEqual(failures, [])

    def test_helper_role_classification_path(self) -> None:
        self.assertEqual(aide_lite.classify_branch_role("task/example"), "task")
        self.assertEqual(aide_lite.classify_branch_role("dev"), "integration")
        self.assertEqual(aide_lite.classify_branch_role("main"), "canonical")

    def test_current_repo_plan_is_non_mutating(self) -> None:
        before = git(REPO_ROOT, "rev-parse", "HEAD")
        plan = aide_lite.make_git_helper_plan(REPO_ROOT, "plan", dry_run=True)
        after = git(REPO_ROOT, "rev-parse", "HEAD")
        self.assertEqual(before, after)
        self.assertTrue(plan["dry_run"])
        self.assertFalse(plan["remote_mutation"])
        self.assertFalse(plan["force_push_allowed"])

    def test_sync_dry_run_does_not_mutate(self) -> None:
        before = git(REPO_ROOT, "rev-parse", "HEAD")
        plan = aide_lite.make_git_helper_plan(REPO_ROOT, "sync", dry_run=True)
        after = git(REPO_ROOT, "rev-parse", "HEAD")
        self.assertEqual(before, after)
        self.assertTrue(plan["dry_run"])
        self.assertEqual(plan["executed_commands"], [])

    def test_land_dry_run_and_apply_in_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_git_repo(root)
            seed_helper_policy(root)
            create_task_branch(root)
            dry = aide_lite.make_git_helper_plan(root, "land", dry_run=True, target="dev", validation_ok=True)
            self.assertEqual(dry["status"], "ready_dry_run")
            self.assertIn("git merge --no-ff task/example", "\n".join(dry["planned_commands"]))
            apply_plan = aide_lite.make_git_helper_plan(root, "land", dry_run=False, apply_requested=True, target="dev", validation_ok=True)
            applied = aide_lite.execute_git_helper_plan(root, apply_plan)
            self.assertEqual(applied["status"], "applied", applied.get("blockers"))
            self.assertIn("task commit task/example", git(root, "log", "dev", "--oneline"))

    def test_promote_dry_run_and_apply_in_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_git_repo(root)
            seed_helper_policy(root)
            git(root, "checkout", "dev")
            write(root, "dev.txt", "dev change\n")
            git(root, "add", "dev.txt")
            git(root, "commit", "-m", "dev integration commit")
            dry = aide_lite.make_git_helper_plan(root, "promote", dry_run=True, source="dev", target="main", validation_ok=True, review_ok=True)
            self.assertEqual(dry["status"], "ready_dry_run")
            apply_plan = aide_lite.make_git_helper_plan(root, "promote", dry_run=False, apply_requested=True, source="dev", target="main", validation_ok=True, review_ok=True)
            applied = aide_lite.execute_git_helper_plan(root, apply_plan)
            self.assertEqual(applied["status"], "applied", applied.get("blockers"))
            self.assertIn("dev integration commit", git(root, "log", "main", "--oneline"))

    def test_prune_contained_branch_apply_deletes_local_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_git_repo(root)
            seed_helper_policy(root)
            create_task_branch(root)
            apply_land = aide_lite.make_git_helper_plan(root, "land", dry_run=False, apply_requested=True, target="dev", validation_ok=True)
            aide_lite.execute_git_helper_plan(root, apply_land)
            prune = aide_lite.make_git_helper_plan(root, "prune", dry_run=True, target="dev")
            eligible = [item for item in prune["prune_candidates"] if item["branch"] == "task/example"]
            self.assertTrue(eligible and eligible[0]["eligible"])
            apply_prune = aide_lite.make_git_helper_plan(root, "prune", dry_run=False, apply_requested=True, target="dev")
            applied = aide_lite.execute_git_helper_plan(root, apply_prune)
            self.assertEqual(applied["status"], "applied", applied.get("blockers"))
            self.assertNotIn("task/example", git(root, "branch", "--format=%(refname:short)"))

    def test_prune_refuses_unmerged_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_git_repo(root)
            seed_helper_policy(root)
            create_task_branch(root)
            git(root, "checkout", "dev")
            prune = aide_lite.make_git_helper_plan(root, "prune", dry_run=True, target="dev")
            task = next(item for item in prune["prune_candidates"] if item["branch"] == "task/example")
            self.assertFalse(task["eligible"])
            self.assertEqual(task["reason"], "ancestor_containment_not_proven")

    def test_protected_branches_never_pruned(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_git_repo(root)
            seed_helper_policy(root)
            git(root, "checkout", "-b", "release/1.0", "main")
            git(root, "checkout", "-b", "gh-pages", "main")
            git(root, "checkout", "dev")
            prune = aide_lite.make_git_helper_plan(root, "prune", dry_run=True, target="main")
            protected = {item["branch"]: item for item in prune["prune_candidates"] if item["branch"] in {"main", "dev", "release/1.0", "gh-pages"}}
            self.assertEqual(set(protected), {"main", "dev", "release/1.0", "gh-pages"})
            self.assertTrue(all(not item["eligible"] for item in protected.values()))

    def test_dirty_tree_blocks_land_and_promote(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_git_repo(root)
            seed_helper_policy(root)
            create_task_branch(root)
            write(root, "dirty.txt", "dirty\n")
            land = aide_lite.make_git_helper_plan(root, "land", dry_run=True, target="dev", validation_ok=True)
            promote = aide_lite.make_git_helper_plan(root, "promote", dry_run=True, source="dev", target="main", validation_ok=True, review_ok=True)
            self.assertIn("dirty_tree_blocks_land", land["blockers"])
            self.assertIn("dirty_tree_blocks_promote", promote["blockers"])

    def test_unknown_branch_role_blocks_land(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_git_repo(root)
            seed_helper_policy(root)
            git(root, "checkout", "-b", "weird")
            plan = aide_lite.make_git_helper_plan(root, "land", dry_run=True, target="dev", validation_ok=True)
            self.assertEqual(plan["status"], "blocked")
            self.assertIn("source_role_not_landable: unknown", plan["blockers"])

    def test_no_push_or_force_push_is_executed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_git_repo(root)
            seed_helper_policy(root)
            create_task_branch(root)
            dry = aide_lite.make_git_helper_plan(root, "land", dry_run=True, push_requested=True, target="dev", validation_ok=True)
            self.assertIn("git push origin dev", dry["planned_commands"])
            apply_plan = aide_lite.make_git_helper_plan(root, "land", dry_run=False, apply_requested=True, push_requested=True, target="dev", validation_ok=True)
            applied = aide_lite.execute_git_helper_plan(root, apply_plan)
            self.assertEqual(applied["status"], "blocked")
            self.assertEqual(applied["executed_commands"], [])
            serialized = json.dumps(applied)
            self.assertNotIn("--force", serialized)

    def test_helper_output_json_and_markdown_shape(self) -> None:
        plan = aide_lite.make_git_helper_plan(REPO_ROOT, "plan", dry_run=True)
        rendered = aide_lite.render_git_helper_plan_md(plan)
        self.assertEqual(plan["schema_version"], "aide.git-helper-plan.v0")
        self.assertIn("state", plan)
        self.assertIn("planned_commands", plan)
        self.assertIn("# AIDE Git Helper Plan", rendered)

    def test_q29_golden_tasks_pass(self) -> None:
        for task_id in [
            "git_helper_policy_golden",
            "git_land_plan_golden",
            "git_promote_plan_golden",
            "git_prune_guard_golden",
            "git_live_repo_no_mutation_golden",
        ]:
            with self.subTest(task_id=task_id):
                result = aide_lite.run_golden_task(REPO_ROOT, task_id)
                self.assertEqual(result.result, "PASS", result.errors)


if __name__ == "__main__":
    unittest.main()
