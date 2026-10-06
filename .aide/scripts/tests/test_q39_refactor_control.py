from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_q39", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q39"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class Q39RefactorControlTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for rel in [*aide_lite.Q39_POLICY_FILES, *aide_lite.Q39_SCHEMA_FILES, aide_lite.REFACTOR_README_PATH]:
            source = REPO_ROOT / rel
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
        self.write(root, "app/source.py", "def value():\n    return 1\n")
        self.write(root, "README.md", "# Fixture\n")
        return root

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

    def minimal_fixture(self, schema_rel: str) -> dict[str, object]:
        required = aide_lite.schema_required_fields(REPO_ROOT, schema_rel)
        return {field: True for field in required}

    def test_refactor_and_migration_policy_anchors(self) -> None:
        root = self.make_repo()
        checks = aide_lite.validate_refactor_files(root, require_latest=False)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")
        refactor_policy = (root / aide_lite.REFACTOR_POLICY_PATH).read_text(encoding="utf-8")
        migration_policy = (root / aide_lite.MIGRATION_POLICY_PATH).read_text(encoding="utf-8")
        self.assertIn("no_apply_in_q39", refactor_policy)
        self.assertIn("mandatory_migration_in_q39: false", migration_policy)

    def test_schema_files_exist_and_required_fields_are_declared(self) -> None:
        root = self.make_repo()
        for rel in aide_lite.Q39_SCHEMA_FILES:
            schema = json.loads((root / rel).read_text(encoding="utf-8"))
            self.assertEqual(schema["type"], "object", rel)
            self.assertIn("required", schema, rel)
            self.assertTrue(schema["required"], rel)

    def test_valid_refactor_plan_fixture_passes(self) -> None:
        root = self.make_repo()
        readiness = aide_lite.build_refactor_readiness(root)
        plan = aide_lite.build_refactor_plan_example(root, readiness)
        checks = aide_lite.validate_refactor_plan_data(root, plan)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")

    def test_invalid_plan_with_apply_allowed_true_fails(self) -> None:
        root = self.make_repo()
        plan = aide_lite.build_refactor_plan_example(root, aide_lite.build_refactor_readiness(root))
        plan["operations"][0]["apply_allowed"] = True
        checks = aide_lite.validate_refactor_plan_data(root, plan)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_invalid_plan_with_final_deletion_approval_fails(self) -> None:
        root = self.make_repo()
        plan = aide_lite.build_refactor_plan_example(root, aide_lite.build_refactor_readiness(root))
        plan["blocked_reasons"] = ["final deletion approved"]
        checks = aide_lite.validate_refactor_plan_data(root, plan)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_move_salvage_alias_and_migration_schema_fixtures(self) -> None:
        fixtures = {
            aide_lite.MOVE_MAP_SCHEMA_PATH: ["map_id", "entries", "no_apply"],
            aide_lite.SALVAGE_MAP_SCHEMA_PATH: ["map_id", "fates", "no_apply"],
            aide_lite.PATH_ALIASES_SCHEMA_PATH: ["alias_id", "old_path", "new_path", "no_apply"],
            aide_lite.MIGRATION_LEDGER_SCHEMA_PATH: ["event_id", "operation", "rollback"],
        }
        for schema_rel, expected in fixtures.items():
            fixture = self.minimal_fixture(schema_rel)
            for field in expected:
                self.assertIn(field, fixture)

    def test_refactor_status_plan_validate_and_dry_run_commands(self) -> None:
        root = self.make_repo()
        status = self.run_cmd(root, "refactor", "status")
        self.assertEqual(status.returncode, 0, status.stderr or status.stdout)
        self.assertIn("no_apply: true", status.stdout)
        plan = self.run_cmd(root, "refactor", "plan")
        self.assertEqual(plan.returncode, 0, plan.stderr or plan.stdout)
        for rel in aide_lite.Q39_GENERATED_OUTPUT_FILES:
            self.assertTrue((root / rel).exists(), rel)
        validate = self.run_cmd(root, "refactor", "validate")
        self.assertEqual(validate.returncode, 0, validate.stderr or validate.stdout)
        dry_run = self.run_cmd(root, "refactor", "dry-run")
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr or dry_run.stdout)
        self.assertIn("file_moves: false", dry_run.stdout)
        self.assertIn("file_deletes: false", dry_run.stdout)
        self.assertIn("reference_rewrites: false", dry_run.stdout)

    def test_refactor_commands_do_not_mutate_source_files(self) -> None:
        root = self.make_repo()
        source = root / "app/source.py"
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        result = self.run_cmd(root, "refactor", "plan")
        dry_run = self.run_cmd(root, "refactor", "dry-run")
        after = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr or dry_run.stdout)
        self.assertEqual(before, after)
        self.assertIn("source_files_changed: false", dry_run.stdout)


if __name__ == "__main__":
    unittest.main()
