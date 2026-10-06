from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_q46", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q46"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class Q46RollbackUninstallModelTests(unittest.TestCase):
    def make_repo(self, *, ledger: bool = True) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for rel in [*aide_lite.Q46_POLICY_FILES, *aide_lite.Q46_SCHEMA_FILES, aide_lite.ROLLBACK_README_PATH, aide_lite.UNINSTALL_README_PATH]:
            source = REPO_ROOT / rel
            self.write(root, rel, source.read_text(encoding="utf-8"))
        self.write(root, ".gitignore", ".aide.local/\n.aide.local/**\n.env\nsecrets/\n")
        self.write(root, "AGENTS.md", "manual target guidance\n<!-- AIDE-GENERATED:BEGIN section=test -->\nmanaged\n<!-- AIDE-GENERATED:END section=test -->\n")
        self.write(root, ".aide/scripts/aide_lite.py", "# installed aide lite\n")
        self.write(root, ".aide/policies/install.yaml", "schema_version: aide.install-policy.v0\n")
        self.write(root, ".aide/new-portable.py", "# future new portable\n")
        self.write(root, ".aide/memory/project.md", "target memory\n")
        self.write(root, ".aide/queue/TARGET/status.yaml", "status: target_specific\n")
        self.write(root, ".aide/evals/golden-tasks/target-local/task.yaml", "id: target-local\n")
        self.write(root, ".aide/reports/latest.md", "target evidence\n")
        self.write(root, "tools/local_tool.py", "print('target tool')\n")
        self.write(root, ".aide.local/config.yaml", "local: true\n")
        self.write(root, ".env", "EXAMPLE_ONLY=1\n")
        self.write(root, "secrets/example.txt", "not-a-real-secret\n")
        if ledger:
            self.write(root, aide_lite.INSTALL_OWNERSHIP_LEDGER_EXAMPLE_JSON_PATH, aide_lite.stable_json_text({
                "schema_version": "aide.ownership-ledger.v0",
                "target_repo": ".",
                "generated_by": "fixture",
                "source_pack_ref": {},
                "no_apply": True,
                "records": [
                    self.record(".aide/scripts/aide_lite.py", "installed_file"),
                    self.record(".aide/policies/install.yaml", "installed_file"),
                    self.record("AGENTS.md", "managed_section", managed=True),
                    self.record(".aide/memory/project.md", "preserved_target_artifact", preserve=True, target_specific=True),
                    self.record(".aide/queue/TARGET/status.yaml", "preserved_target_artifact", preserve=True, target_specific=True),
                    self.record(".aide/evals/golden-tasks/target-local/task.yaml", "preserved_target_artifact", preserve=True, target_specific=True),
                    self.record("tools/local_tool.py", "external_manual_artifact", preserve=True, target_specific=True),
                ],
            }))
        self.write(root, aide_lite.UPGRADE_PLAN_JSON_PATH, aide_lite.stable_json_text({
            "schema_version": "aide.upgrade-plan.v0",
            "plan_id": "fixture-upgrade",
            "generated_by": "fixture",
            "source_commit": "fixture",
            "target_root": ".",
            "mode": "dry_run_only",
            "status": "candidate",
            "source_pack_ref": {},
            "current_install_ref": {},
            "operations": [
                self.upgrade_operation(".aide/scripts/aide_lite.py", "update_portable_file_future", False),
                self.upgrade_operation(".aide/new-portable.py", "add_missing_portable_future", False),
                self.upgrade_operation(".aide/queue/TARGET/status.yaml", "preserve_target_specific", True),
            ],
            "preserved_paths": [".aide/queue/TARGET/status.yaml"],
            "conflicts": [],
            "required_migrations": [],
            "optional_migrations": [],
            "verification_plan": [],
            "rollback_prerequisites": [],
            "evidence_required": [],
            "no_apply": True,
        }))
        return root

    def record(self, path: str, ownership_class: str, *, managed: bool = False, preserve: bool = False, target_specific: bool = False) -> dict[str, object]:
        return {
            "path": path,
            "ownership_class": ownership_class,
            "source": f"files/{path}",
            "installed_by": "fixture",
            "managed_section": managed,
            "preserve": preserve,
            "target_specific": target_specific,
            "local_only": False,
            "evidence_refs": [path],
        }

    def upgrade_operation(self, path: str, action: str, preserve: bool) -> dict[str, object]:
        return {
            "operation_id": f"upgrade-{path.replace('/', '-')}",
            "operation_type": "fixture",
            "current_path": path,
            "source_pack_path": f"files/{path}",
            "target_path": path,
            "target_class": "portable",
            "ownership": "installed_file",
            "action": action,
            "reason": "fixture",
            "compatibility_level": "compatible_with_warnings",
            "conflict_status": "none",
            "preserve_target_state": preserve,
            "overwrite_allowed": False,
            "delete_allowed": False,
            "migration_required": False,
            "apply_allowed": False,
            "validation_required": [],
            "rollback_hint": "fixture",
        }

    def write(self, root: Path, rel: str, text: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def run_cmd(self, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(root), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def files_outside_q46_outputs(self, root: Path) -> dict[str, str]:
        result: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = aide_lite.normalize_rel(path.relative_to(root))
            if rel.startswith(".aide/rollback/latest-") or rel.startswith(".aide/uninstall/latest-"):
                continue
            result[rel] = path.read_text(encoding="utf-8")
        return result

    def test_policy_and_schema_validation(self) -> None:
        root = self.make_repo()
        rollback_checks = aide_lite.validate_rollback_files(root, require_latest=False)
        uninstall_checks = aide_lite.validate_uninstall_files(root, require_latest=False)
        self.assertEqual(aide_lite.result_from_checks(rollback_checks), "PASS")
        self.assertEqual(aide_lite.result_from_checks(uninstall_checks), "PASS")

    def test_missing_ownership_ledger_blocks_rollback_and_uninstall(self) -> None:
        root = self.make_repo(ledger=False)
        rollback_plan = aide_lite.build_rollback_plan(root)
        uninstall_plan = aide_lite.build_uninstall_plan(root)
        self.assertTrue(rollback_plan["missing_ledger"])
        self.assertIn("blocked_missing_ledger", rollback_plan["blocked_reasons"])
        self.assertIn("blocked_missing_ledger", uninstall_plan["blocked_reasons"])
        self.assertTrue(all(operation["apply_allowed"] is False for operation in rollback_plan["operations"]))
        self.assertTrue(all(operation["apply_allowed"] is False for operation in uninstall_plan["operations"]))

    def test_known_portable_files_are_future_uninstall_candidates_only(self) -> None:
        root = self.make_repo()
        observation = aide_lite.build_uninstall_observation(root)
        plan = aide_lite.build_uninstall_plan(root, observation)
        by_path = {operation["target_path"]: operation for operation in plan["operations"]}
        self.assertEqual(by_path[".aide/scripts/aide_lite.py"]["uninstall_class"], "remove_portable_file_future")
        self.assertFalse(by_path[".aide/scripts/aide_lite.py"]["delete_allowed"])
        self.assertFalse(by_path[".aide/scripts/aide_lite.py"]["apply_allowed"])

    def test_target_state_manual_content_and_tools_are_preserved(self) -> None:
        root = self.make_repo()
        plan = aide_lite.build_uninstall_plan(root)
        by_path = {operation["target_path"]: operation for operation in plan["operations"]}
        for rel in [
            ".aide/memory/project.md",
            ".aide/queue/TARGET/status.yaml",
            ".aide/evals/golden-tasks/target-local/task.yaml",
            "AGENTS.md",
            "tools/local_tool.py",
        ]:
            self.assertIn(rel, by_path)
            self.assertTrue(by_path[rel]["preserve_target_state"])
            self.assertFalse(by_path[rel]["delete_allowed"])

    def test_local_state_and_secret_paths_are_safe_only(self) -> None:
        self.assertTrue(aide_lite.q46_rel_is_local_or_secret(".aide.local/config.yaml"))
        self.assertTrue(aide_lite.q46_rel_is_local_or_secret(".env"))
        self.assertTrue(aide_lite.q46_rel_is_local_or_secret("secrets/example.txt"))
        operation = aide_lite.uninstall_operation(".env", "preserve_local_state_ignored", "local_state", "preserve_local_state_ignored", "fixture", True)
        checks = aide_lite.validate_uninstall_operation_data(operation)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")

    def test_validation_rejects_apply_delete_overwrite_and_blanket_aide_delete(self) -> None:
        root = self.make_repo()
        rollback_plan = aide_lite.build_rollback_plan(root)
        rollback_plan["operations"][0]["overwrite_allowed"] = True
        self.assertEqual(aide_lite.result_from_checks(aide_lite.validate_rollback_plan_data(root, rollback_plan)), "FAIL")
        rollback_plan["operations"][0]["overwrite_allowed"] = False
        rollback_plan["operations"][0]["delete_allowed"] = True
        self.assertEqual(aide_lite.result_from_checks(aide_lite.validate_rollback_plan_data(root, rollback_plan)), "FAIL")
        uninstall_plan = aide_lite.build_uninstall_plan(root)
        uninstall_plan["operations"][0]["delete_allowed"] = True
        self.assertEqual(aide_lite.result_from_checks(aide_lite.validate_uninstall_plan_data(root, uninstall_plan)), "FAIL")
        uninstall_plan["operations"][0]["delete_allowed"] = False
        uninstall_plan["operations"].append(aide_lite.uninstall_operation(".aide", "remove_portable_file_future", "installed_file", "remove_portable_file_future", "blanket fixture", False))
        self.assertEqual(aide_lite.result_from_checks(aide_lite.validate_uninstall_plan_data(root, uninstall_plan)), "FAIL")

    def test_commands_write_only_q46_outputs(self) -> None:
        root = self.make_repo()
        before = self.files_outside_q46_outputs(root)
        commands = [
            ("rollback", "observe"),
            ("rollback", "plan"),
            ("rollback", "dry-run"),
            ("rollback", "validate"),
            ("rollback", "status"),
            ("rollback", "classes"),
            ("rollback", "explain", ".aide/scripts/aide_lite.py"),
            ("uninstall", "observe"),
            ("uninstall", "plan"),
            ("uninstall", "dry-run"),
            ("uninstall", "validate"),
            ("uninstall", "status"),
            ("uninstall", "classes"),
            ("uninstall", "explain", ".aide/scripts/aide_lite.py"),
        ]
        for args in commands:
            result = self.run_cmd(root, *args)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("no_apply: true", result.stdout)
        after = self.files_outside_q46_outputs(root)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
