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
SPEC = importlib.util.spec_from_file_location("aide_lite_q44", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q44"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class Q44RepairDoctorTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for rel in [*aide_lite.Q44_POLICY_FILES, *aide_lite.Q44_SCHEMA_FILES, aide_lite.REPAIR_README_PATH]:
            source = REPO_ROOT / rel
            self.write(root, rel, source.read_text(encoding="utf-8"))
        self.write(root, ".gitignore", ".aide.local/\n.aide.local/**\n.env\n")
        self.write(root, "AGENTS.md", "<!-- AIDE-GENERATED:BEGIN section=broken -->\nmanual content\n")
        self.write(root, ".aide/queue/TARGET/status.yaml", "state: malformed\n")
        self.write(root, ".aide/old-schema.yaml", "schema_version: unsupported\nstatus: old\n")
        self.write(root, aide_lite.INSTALL_CONFLICT_REPORT_JSON_PATH, json.dumps({
            "schema_version": "aide.install-conflict-report.v0",
            "conflicts": [
                {
                    "conflict_id": "fixture-source-state",
                    "path": ".aide/install/latest-install-plan.json",
                    "conflict_type": "source_state_leak",
                    "blocking": True,
                    "evidence_refs": [".aide/install/latest-install-plan.json"],
                }
            ],
            "conflict_count": 1,
            "blocking_count": 1,
            "warnings": [],
            "no_apply": True,
        }))
        self.pack(root, ".aide/new-portable-policy.yaml", "schema_version: aide.fixture.v0\n")
        self.pack(root, ".aide/hooks/commit-msg", "# hook\n")
        self.pack(root, aide_lite.REPAIR_POLICY_PATH, "schema_version: aide.repair-policy.v0\nchanged: true\n")
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

    def files_outside_repair(self, root: Path) -> dict[str, str]:
        result: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = aide_lite.normalize_rel(path.relative_to(root))
            if rel.startswith(".aide/repair/latest-"):
                continue
            result[rel] = path.read_text(encoding="utf-8")
        return result

    def test_repair_policy_class_and_schema_validation(self) -> None:
        root = self.make_repo()
        checks = aide_lite.validate_repair_files(root, require_latest=False)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")
        policy = (root / aide_lite.REPAIR_POLICY_PATH).read_text(encoding="utf-8")
        classes = (root / aide_lite.REPAIR_CLASSES_POLICY_PATH).read_text(encoding="utf-8")
        self.assertIn("observe_plan_dry_run_only", policy)
        self.assertIn("missing_portable_file", classes)
        self.assertIn("tracked_local_state", classes)

    def test_repair_observation_classifies_fixture_issues(self) -> None:
        root = self.make_repo()
        observation = aide_lite.build_repair_observation(root)
        classes = {issue["repair_class"] for issue in observation["detected_issues"]}
        self.assertIn("missing_portable_file", classes)
        self.assertIn("missing_hook_template", classes)
        self.assertIn("stale_policy", classes)
        self.assertIn("malformed_managed_section", classes)
        self.assertIn("source_state_contamination", classes)
        self.assertIn("unsupported_schema_version", classes)
        self.assertIn("invalid_queue_status", classes)

    def test_local_state_and_secrets_are_blocked_or_manual_review_only(self) -> None:
        root = self.make_repo()
        issues = aide_lite.repair_local_secret_issues(root, [".aide.local/config.yaml", ".env", "secrets/key.txt"])
        self.assertEqual({issue["repair_class"] for issue in issues}, {"tracked_local_state", "secret_like_file"})
        self.assertTrue(all(issue["blocker"] is True for issue in issues))
        diagnosis = {
            "issue_id": issues[0]["issue_id"],
            "repair_class": issues[0]["repair_class"],
            "reason": issues[0]["reason"],
            "mandatory_migration_candidate": False,
        }
        operation = aide_lite.repair_operation_from_diagnosis(diagnosis, issues[0])
        self.assertIn(operation["action"], {"blocked", "manual_review_required", "quarantine_source_state_future"})
        self.assertFalse(operation["apply_allowed"])
        self.assertFalse(operation["overwrite_allowed"])
        self.assertFalse(operation["delete_allowed"])

    def test_unsupported_schema_requires_future_migration_only(self) -> None:
        root = self.make_repo()
        observation = aide_lite.build_repair_observation(root)
        diagnosis = aide_lite.build_repair_diagnosis(root, observation)
        plan = aide_lite.build_repair_plan(root, observation, diagnosis)
        migrations = plan["required_migrations"]
        self.assertTrue(any(item["repair_class"] == "unsupported_schema_version" for item in migrations))
        self.assertTrue(all(item["automatic"] is False for item in migrations))
        self.assertTrue(all(item["apply_allowed"] is False for item in migrations))

    def test_repair_validate_rejects_apply_overwrite_or_delete_enabled_operations(self) -> None:
        root = self.make_repo()
        plan = aide_lite.build_repair_plan(root)
        plan["operations"][0]["apply_allowed"] = True
        checks = aide_lite.validate_repair_plan_data(root, plan)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")
        plan["operations"][0]["apply_allowed"] = False
        plan["operations"][0]["overwrite_allowed"] = True
        checks = aide_lite.validate_repair_plan_data(root, plan)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")
        plan["operations"][0]["overwrite_allowed"] = False
        plan["operations"][0]["delete_allowed"] = True
        checks = aide_lite.validate_repair_plan_data(root, plan)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_repair_commands_write_only_repair_outputs(self) -> None:
        root = self.make_repo()
        before = self.files_outside_repair(root)
        for args in [("repair", "observe"), ("repair", "diagnose"), ("repair", "plan"), ("repair", "dry-run"), ("repair", "validate")]:
            result = self.run_cmd(root, *args)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = self.files_outside_repair(root)
        self.assertEqual(before, after)

    def test_status_classes_doctor_and_explain_commands(self) -> None:
        root = self.make_repo()
        for args in [("repair", "observe"), ("repair", "diagnose"), ("repair", "plan"), ("repair", "dry-run")]:
            self.assertEqual(self.run_cmd(root, *args).returncode, 0)
        status = self.run_cmd(root, "repair", "status")
        classes = self.run_cmd(root, "repair", "classes")
        doctor = self.run_cmd(root, "repair", "doctor")
        explain = self.run_cmd(root, "repair", "explain", ".aide/new-portable-policy.yaml")
        self.assertEqual(status.returncode, 0, status.stdout)
        self.assertEqual(classes.returncode, 0, classes.stdout)
        self.assertEqual(doctor.returncode, 0, doctor.stdout)
        self.assertEqual(explain.returncode, 0, explain.stdout)
        self.assertIn("no_apply: true", explain.stdout)

    def test_dry_run_reports_counts_without_apply(self) -> None:
        root = self.make_repo()
        observation = aide_lite.build_repair_observation(root)
        diagnosis = aide_lite.build_repair_diagnosis(root, observation)
        plan = aide_lite.build_repair_plan(root, observation, diagnosis)
        dry_run = aide_lite.build_repair_dry_run(root, plan)
        self.assertTrue(dry_run["planned_writes"] >= 1)
        self.assertTrue(dry_run["planned_conflicts"] >= 1)
        self.assertTrue(dry_run["blocking_issues"])
        self.assertTrue(dry_run["no_apply"])


if __name__ == "__main__":
    unittest.main()
