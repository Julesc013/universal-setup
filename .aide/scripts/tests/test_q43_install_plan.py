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
SPEC = importlib.util.spec_from_file_location("aide_lite_q43", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q43"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class Q43InstallPlanTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for rel in [*aide_lite.Q43_POLICY_FILES, *aide_lite.Q43_SCHEMA_FILES, aide_lite.INSTALL_README_PATH]:
            source = REPO_ROOT / rel
            self.write(root, rel, source.read_text(encoding="utf-8"))
        self.write(root, ".gitignore", ".aide.local/\n.aide.local/**\n.env\n")
        self.write(root, "AGENTS.md", "# Fixture Agents\n\nManual content outside managed sections.\n")
        self.write(root, ".aide/memory/project-state.md", "target memory\n")
        self.write(root, ".aide/queue/TARGET-1/status.yaml", "status: running\n")
        self.write(root, ".aide/old-schema.yaml", "schema_version: unsupported\nstatus: old\n")
        self.pack(root, ".aide/policies/install.yaml", (REPO_ROOT / aide_lite.INSTALL_POLICY_PATH).read_text(encoding="utf-8"))
        self.pack(root, ".aide/new-portable-policy.yaml", "schema_version: aide.fixture.v0\n")
        self.pack(root, ".aide/context/latest-task-packet.md", "source generated context\n")
        self.pack(root, ".aide.local/config.yaml", "local state\n")
        self.pack(root, ".env", "TOKEN=example\n")
        self.pack(root, "secrets/key.txt", "example\n")
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

    def files_outside_install(self, root: Path) -> dict[str, str]:
        result: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = aide_lite.normalize_rel(path.relative_to(root))
            if rel.startswith(".aide/install/latest-"):
                continue
            result[rel] = path.read_text(encoding="utf-8")
        return result

    def test_install_policy_and_schema_validation(self) -> None:
        root = self.make_repo()
        checks = aide_lite.validate_install_files(root, require_latest=False)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")
        policy = (root / aide_lite.INSTALL_POLICY_PATH).read_text(encoding="utf-8")
        self.assertIn("observe_plan_dry_run_only", policy)
        self.assertIn("no_file_overwrite", policy)

    def test_plan_preserves_target_state_and_candidates_missing_pack_files(self) -> None:
        root = self.make_repo()
        observation = aide_lite.build_install_observation(root)
        plan, _ledger, _conflicts = aide_lite.build_install_plan(root, observation)
        operations = plan["operations"]
        self.assertTrue(any(op["target_path"] == ".aide/new-portable-policy.yaml" and op["action"] == "install_candidate" for op in operations))
        preserved = set(plan["preserved_paths"])
        self.assertIn(".aide/memory/project-state.md", preserved)
        self.assertIn(".aide/queue/TARGET-1/status.yaml", preserved)
        self.assertIn("AGENTS.md", preserved)

    def test_source_generated_local_and_secret_pack_paths_are_skipped(self) -> None:
        root = self.make_repo()
        plan, _ledger, _conflicts = aide_lite.build_install_plan(root)
        by_path = {op["target_path"]: op for op in plan["operations"]}
        self.assertEqual(by_path[".aide/context/latest-task-packet.md"]["action"], "skip_source_generated_state")
        self.assertEqual(by_path[".aide.local/config.yaml"]["action"], "skip_local_state")
        self.assertEqual(by_path[".env"]["action"], "skip_local_state")
        self.assertEqual(by_path["secrets/key.txt"]["action"], "skip_local_state")

    def test_unsupported_schema_requires_future_migration_only(self) -> None:
        root = self.make_repo()
        observation = aide_lite.build_install_observation(root)
        plan, _ledger, conflict_report = aide_lite.build_install_plan(root, observation)
        self.assertTrue(any(conflict["conflict_type"] == "unsupported_old_schema" for conflict in conflict_report["conflicts"]))
        migrations = plan["required_migrations"]
        self.assertTrue(migrations)
        self.assertTrue(all(migration["automatic"] is False for migration in migrations))
        self.assertTrue(all(migration["apply_allowed"] is False for migration in migrations))

    def test_install_validate_rejects_apply_or_overwrite_enabled_operations(self) -> None:
        root = self.make_repo()
        plan, _ledger, _conflicts = aide_lite.build_install_plan(root)
        plan["operations"][0]["apply_allowed"] = True
        checks = aide_lite.validate_install_plan_data(root, plan)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")
        plan["operations"][0]["apply_allowed"] = False
        plan["operations"][0]["overwrite_allowed"] = True
        checks = aide_lite.validate_install_plan_data(root, plan)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_install_commands_write_only_install_outputs(self) -> None:
        root = self.make_repo()
        before = self.files_outside_install(root)
        for args in [("install", "observe"), ("install", "plan"), ("install", "dry-run"), ("install", "validate")]:
            result = self.run_cmd(root, *args)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = self.files_outside_install(root)
        self.assertEqual(before, after)

    def test_status_ownership_conflicts_and_explain_commands(self) -> None:
        root = self.make_repo()
        for args in [("install", "observe"), ("install", "plan"), ("install", "dry-run")]:
            self.assertEqual(self.run_cmd(root, *args).returncode, 0)
        status = self.run_cmd(root, "install", "status")
        ownership = self.run_cmd(root, "install", "ownership")
        conflicts = self.run_cmd(root, "install", "conflicts")
        explain = self.run_cmd(root, "install", "explain", ".aide/new-portable-policy.yaml")
        self.assertEqual(status.returncode, 0, status.stdout)
        self.assertEqual(ownership.returncode, 0, ownership.stdout)
        self.assertEqual(conflicts.returncode, 0, conflicts.stdout)
        self.assertEqual(explain.returncode, 0, explain.stdout)
        self.assertIn("no_apply: true", explain.stdout)


if __name__ == "__main__":
    unittest.main()
