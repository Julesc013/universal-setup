from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_apply_01", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_apply_01"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


COMMAND_VECTORS = [
    ["managed-section", "status"],
    ["managed-section", "validate"],
    ["managed-section", "fixture-plan"],
    ["managed-section", "fixture-verify"],
]


class AIDEApply01ManagedSectionsTests(unittest.TestCase):
    def test_parser_accepts_managed_section_commands(self) -> None:
        parser = aide_lite.build_parser(REPO_ROOT)
        for command in COMMAND_VECTORS:
            parsed = parser.parse_args(command)
            self.assertTrue(callable(getattr(parsed, "handler", None)), command)

    def test_fixture_plan_output_is_fixture_only_and_no_apply(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            aide_lite.copy_pack_file(REPO_ROOT / ".aide/examples/apply/managed-section-fixtures/valid_input.md", root / ".aide/examples/apply/managed-section-fixtures/valid_input.md")
            aide_lite.copy_pack_file(REPO_ROOT / ".aide/examples/apply/managed-section-fixtures/replacement.md", root / ".aide/examples/apply/managed-section-fixtures/replacement.md")
            aide_lite.copy_pack_file(REPO_ROOT / ".aide/examples/apply/managed-section-fixtures/expected_output.md", root / ".aide/examples/apply/managed-section-fixtures/expected_output.md")
            aide_lite.copy_pack_file(REPO_ROOT / ".aide/examples/apply/managed-section-fixtures/missing_marker.md", root / ".aide/examples/apply/managed-section-fixtures/missing_marker.md")
            aide_lite.copy_pack_file(REPO_ROOT / ".aide/examples/apply/managed-section-fixtures/duplicate_marker.md", root / ".aide/examples/apply/managed-section-fixtures/duplicate_marker.md")
            aide_lite.copy_pack_file(REPO_ROOT / "core/apply/managed_sections.py", root / "core/apply/managed_sections.py")
            for rel in aide_lite.MANAGED_SECTION_POLICY_FILES + aide_lite.MANAGED_SECTION_SCHEMA_FILES + aide_lite.MANAGED_SECTION_EXAMPLE_FILES + aide_lite.MANAGED_SECTION_DOC_FILES:
                source = REPO_ROOT / rel
                if source.exists():
                    aide_lite.copy_pack_file(source, root / rel)
            json_result, md_result, conflict_result, plan = aide_lite.write_managed_section_fixture_plan_outputs(root)
            self.assertIn(json_result.action, {"written", "unchanged"})
            self.assertIn(md_result.action, {"written", "unchanged"})
            self.assertIn(conflict_result.action, {"written", "unchanged"})
            self.assertEqual(plan["schema_version"], "aide.managed-section-report.v0")
            self.assertEqual(plan["mode"], "fixture_only")
            boundary = plan["no_real_apply_boundary"]
            self.assertIs(boundary["active_repo_managed_section_apply"], False)
            self.assertIs(boundary["real_repo_apply_allowed"], False)
            self.assertIs(boundary["target_mutation"], False)
            self.assertIs(boundary["branch_mutation"], False)
            self.assertEqual(boundary["provider_or_model_calls"], "none")
            self.assertEqual(boundary["network_calls"], "none")
            report = json.loads((root / aide_lite.MANAGED_SECTION_FIXTURE_PLAN_JSON_PATH).read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "PASS")
            for operation in report["operations"]:
                self.assertFalse(operation["real_repo_apply_allowed"])
                self.assertEqual(operation["operation_class"], "update_managed_section")

    def test_current_repo_managed_section_validation_passes_without_reports(self) -> None:
        checks = aide_lite.validate_managed_section_files(REPO_ROOT, require_reports=False)
        failures = [check.message for check in checks if check.severity == "FAIL"]
        self.assertEqual(failures, [])

    def test_fixture_verification_current_repo_passes(self) -> None:
        aide_lite.write_managed_section_fixture_plan_outputs(REPO_ROOT)
        checks = aide_lite.managed_section_fixture_verification_checks(REPO_ROOT)
        failures = [check.message for check in checks if check.severity == "FAIL"]
        self.assertEqual(failures, [])

    def test_managed_section_golden_runners_are_registered(self) -> None:
        definitions = {task.task_id for task in aide_lite.parse_golden_task_catalog(REPO_ROOT)}
        for task_id in aide_lite.MANAGED_SECTION_GOLDEN_TASK_IDS:
            self.assertIn(task_id, definitions)

    def test_no_active_apply_command_is_registered(self) -> None:
        parser = aide_lite.build_parser(REPO_ROOT)
        with self.assertRaises(SystemExit):
            parser.parse_args(["managed-section", "apply"])


if __name__ == "__main__":
    unittest.main()
