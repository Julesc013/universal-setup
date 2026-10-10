from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_q45", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q45"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class Q45UpgradeModelTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for rel in [*aide_lite.Q45_POLICY_FILES, *aide_lite.Q45_SCHEMA_FILES, aide_lite.UPGRADE_README_PATH]:
            source = REPO_ROOT / rel
            self.write(root, rel, source.read_text(encoding="utf-8"))
        self.write(root, ".gitignore", ".aide.local/\n.aide.local/**\n.env\n")
        self.write(root, "AGENTS.md", "manual target guidance\n")
        self.write(root, ".aide/scripts/aide_lite.py", "# old script\n")
        self.write(root, ".aide/memory/project.md", "target memory\n")
        self.write(root, ".aide/queue/TARGET/status.yaml", "status: target_specific\n")
        self.write(root, ".aide/evals/golden-tasks/target-local/task.yaml", "id: target-local\n")
        self.write(root, ".aide/context/latest-task-packet.md", "target generated packet\n")
        self.write(root, ".aide/old-schema.yaml", "schema_version: unsupported\nstatus: old\n")
        self.write(root, ".aide.local/config.yaml", "local: true\n")
        self.write(root, ".env", "EXAMPLE_ONLY=1\n")
        self.pack(root, ".aide/scripts/aide_lite.py", "# new script\n")
        self.pack(root, ".aide/new-upgrade-policy.yaml", "schema_version: aide.fixture.v0\n")
        self.pack(root, ".aide/context/latest-task-packet.md", "source generated packet\n")
        self.pack(root, ".aide/upgrade/latest-upgrade-plan.json", "{}\n")
        self.pack(root, ".aide/evals/golden-tasks/target-local/task.yaml", "id: pack-target-local\n")
        self.pack(root, ".aide.local/config.yaml", "local: true\n")
        self.pack(root, ".env", "EXAMPLE_ONLY=1\n")
        self.pack(root, "private/credential.key", "not-a-real-secret\n")
        return root

    def write(self, root: Path, rel: str, text: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def pack(self, root: Path, rel: str, text: str) -> None:
        self.write(root, f"{aide_lite.EXPORT_PACK_FILES_ROOT}/{rel}", text)

    def run_cmd(self, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(root), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def files_outside_upgrade(self, root: Path) -> dict[str, str]:
        result: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = aide_lite.normalize_rel(path.relative_to(root))
            if rel.startswith(".aide/upgrade/latest-"):
                continue
            result[rel] = path.read_text(encoding="utf-8")
        return result

    def test_upgrade_policy_and_schema_validation(self) -> None:
        root = self.make_repo()
        checks = aide_lite.validate_upgrade_files(root, require_latest=False)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")
        policy = (root / aide_lite.UPGRADE_POLICY_PATH).read_text(encoding="utf-8")
        compatibility = (root / aide_lite.UPGRADE_COMPATIBILITY_POLICY_PATH).read_text(encoding="utf-8")
        self.assertIn("observe_compare_plan_dry_run_only", policy)
        self.assertIn("compatible_with_warnings", compatibility)
        self.assertIn("migration_required_future", compatibility)

    def test_upgrade_comparison_classifies_fixture_differences(self) -> None:
        root = self.make_repo()
        current = aide_lite.build_upgrade_current_observation(root)
        source = aide_lite.build_upgrade_source_pack_observation(root)
        comparison, conflict_report, migration_report = aide_lite.build_upgrade_comparison(root, current, source)
        actions = {diff["path"]: diff["action"] for diff in comparison["differences"]}
        self.assertEqual(actions[".aide/scripts/aide_lite.py"], "update_portable_file_future")
        self.assertEqual(actions[".aide/new-upgrade-policy.yaml"], "add_missing_portable_future")
        self.assertEqual(actions[".aide/context/latest-task-packet.md"], "skip_source_generated_state")
        self.assertEqual(actions[".aide/evals/golden-tasks/target-local/task.yaml"], "preserve_target_specific")
        self.assertTrue(any(conflict["conflict_type"] == "local_state_tracked" for conflict in conflict_report["conflicts"]))
        self.assertTrue(any(conflict["conflict_type"] == "secret_like_path" for conflict in conflict_report["conflicts"]))
        self.assertTrue(any(item["reason"] == "unsupported schema version" for item in migration_report["required_migrations"]))
        self.assertTrue(all(item["automatic"] is False and item["apply_allowed"] is False for item in migration_report["required_migrations"]))

    def test_upgrade_plan_and_dry_run_are_no_apply(self) -> None:
        root = self.make_repo()
        current = aide_lite.build_upgrade_current_observation(root)
        source = aide_lite.build_upgrade_source_pack_observation(root)
        comparison, _conflicts, migration_report = aide_lite.build_upgrade_comparison(root, current, source)
        plan = aide_lite.build_upgrade_plan(root, current, source, comparison, migration_report)
        dry_run = aide_lite.build_upgrade_dry_run(root, plan)
        self.assertTrue(plan["no_apply"])
        self.assertTrue(dry_run["no_apply"])
        self.assertGreaterEqual(dry_run["planned_updates"], 2)
        self.assertGreaterEqual(dry_run["planned_skips"], 2)
        self.assertGreaterEqual(dry_run["planned_preservations"], 1)
        self.assertTrue(all(operation["apply_allowed"] is False for operation in plan["operations"]))
        self.assertTrue(all(operation["overwrite_allowed"] is False for operation in plan["operations"]))
        self.assertTrue(all(operation["delete_allowed"] is False for operation in plan["operations"]))

    def test_upgrade_validate_rejects_apply_overwrite_or_delete_enabled_operations(self) -> None:
        root = self.make_repo()
        plan = aide_lite.build_upgrade_plan(root)
        plan["operations"][0]["apply_allowed"] = True
        checks = aide_lite.validate_upgrade_plan_data(root, plan)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")
        plan["operations"][0]["apply_allowed"] = False
        plan["operations"][0]["overwrite_allowed"] = True
        checks = aide_lite.validate_upgrade_plan_data(root, plan)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")
        plan["operations"][0]["overwrite_allowed"] = False
        plan["operations"][0]["delete_allowed"] = True
        checks = aide_lite.validate_upgrade_plan_data(root, plan)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_upgrade_commands_write_only_upgrade_outputs(self) -> None:
        root = self.make_repo()
        before = self.files_outside_upgrade(root)
        for args in [("upgrade", "observe-current"), ("upgrade", "observe-source"), ("upgrade", "compare"), ("upgrade", "plan"), ("upgrade", "dry-run"), ("upgrade", "validate")]:
            result = self.run_cmd(root, *args)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = self.files_outside_upgrade(root)
        self.assertEqual(before, after)

    def test_status_compatibility_conflicts_migrations_and_explain(self) -> None:
        root = self.make_repo()
        for args in [("upgrade", "observe-current"), ("upgrade", "observe-source"), ("upgrade", "compare"), ("upgrade", "plan"), ("upgrade", "dry-run")]:
            self.assertEqual(self.run_cmd(root, *args).returncode, 0)
        for args in [
            ("upgrade", "status"),
            ("upgrade", "compatibility"),
            ("upgrade", "conflicts"),
            ("upgrade", "migrations"),
            ("upgrade", "explain", ".aide/scripts/aide_lite.py"),
        ]:
            result = self.run_cmd(root, *args)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("no_apply: true", result.stdout)


if __name__ == "__main__":
    unittest.main()
