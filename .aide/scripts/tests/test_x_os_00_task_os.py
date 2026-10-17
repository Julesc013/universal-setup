from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_x_os_00", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_x_os_00"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


EXAMPLE_SCHEMA_MAP = {
    ".aide/examples/task-os/workunit.example.json": ".aide/tasks/workunit.schema.json",
    ".aide/examples/task-os/task-attempt.example.json": ".aide/tasks/task-attempt.schema.json",
    ".aide/examples/task-os/blocker.example.json": ".aide/tasks/blocker.schema.json",
    ".aide/examples/task-os/repair-task.example.json": ".aide/tasks/repair-task.schema.json",
    ".aide/examples/task-os/wave.example.json": ".aide/tasks/wave.schema.json",
    ".aide/examples/task-os/checkpoint.example.json": ".aide/tasks/checkpoint.schema.json",
    ".aide/examples/task-os/capability-ledger.example.json": ".aide/ledgers/capability-ledger.schema.json",
    ".aide/examples/task-os/branch-provenance.example.json": ".aide/ledgers/branch-provenance.schema.json",
}


class XOS00TaskOSTests(unittest.TestCase):
    def read_json(self, rel: str) -> dict[str, object]:
        return json.loads((REPO_ROOT / rel).read_text(encoding="utf-8"))

    def test_schema_files_exist_and_parse(self) -> None:
        for rel in [*aide_lite.TASK_OS_SCHEMA_FILES, *aide_lite.TASK_OS_LEDGER_SCHEMA_FILES]:
            data = self.read_json(rel)
            self.assertEqual(data["type"], "object", rel)
            self.assertIsInstance(data["required"], list, rel)

    def test_example_records_satisfy_required_fields(self) -> None:
        for example_rel, schema_rel in EXAMPLE_SCHEMA_MAP.items():
            example = self.read_json(example_rel)
            schema = self.read_json(schema_rel)
            required = schema["required"]
            self.assertIsInstance(required, list)
            for field in required:
                self.assertIn(field, example, f"{example_rel} missing {field}")
            self.assertIn("example", (REPO_ROOT / example_rel).read_text(encoding="utf-8").lower())

    def test_lifecycle_policy_contains_required_states(self) -> None:
        text = (REPO_ROOT / ".aide/policies/task-lifecycle.yaml").read_text(encoding="utf-8")
        for state in aide_lite.TASK_OS_LIFECYCLE_STATES:
            self.assertIn(state, text)
        for anchor in [
            "partial_is_not_failure",
            "blocked_is_not_deletion",
            "unsafe_blockers_should_quarantine",
            "no_state_transition_applies_branch_or_file_mutation_in_x_os_00",
        ]:
            self.assertIn(anchor, text)

    def test_blocker_policy_contains_classes_and_repair_mapping(self) -> None:
        text = (REPO_ROOT / ".aide/policies/blockers.yaml").read_text(encoding="utf-8")
        for blocker_class in aide_lite.TASK_OS_BLOCKER_CLASSES:
            self.assertIn(blocker_class, text)
        self.assertIn("blocker_to_repair_task_conversion", text)
        self.assertIn("repair_apply_forbidden", text)

    def test_capability_reality_policy_contains_states_and_boundaries(self) -> None:
        text = (REPO_ROOT / ".aide/policies/capability-reality.yaml").read_text(encoding="utf-8")
        for state in aide_lite.TASK_OS_CAPABILITY_STATES:
            self.assertIn(state, text)
        for anchor in [
            "docs_only_claims_are_not_implementation_proof",
            "fixture_only_behavior_is_not_production_behavior",
            "report_only_commands_are_not_apply_behavior",
            "release_draft_is_not_publication",
            "install_dry_run_is_not_install_apply",
        ]:
            self.assertIn(anchor, text)

    def test_no_apply_boundary_text_and_no_command_group(self) -> None:
        corpus = "\n".join((REPO_ROOT / rel).read_text(encoding="utf-8") for rel in [*aide_lite.TASK_OS_POLICY_FILES, *aide_lite.TASK_OS_DOC_FILES])
        for marker in ["report_only", "no_apply", "branch_creation_allowed: false", "merge_allowed: false", "push_allowed: false", "promotion_allowed: false"]:
            self.assertIn(marker, corpus)
        script = (REPO_ROOT / ".aide/scripts/aide_lite.py").read_text(encoding="utf-8")
        self.assertNotIn('add_parser("task-os"', script)

    def test_golden_catalog_and_runner_include_task_os(self) -> None:
        definitions = {task.task_id for task in aide_lite.parse_golden_task_catalog(REPO_ROOT)}
        for task_id in aide_lite.TASK_OS_GOLDEN_TASK_IDS:
            self.assertIn(task_id, definitions)
            result = aide_lite.run_golden_task(REPO_ROOT, task_id)
            self.assertEqual(result.result, "PASS", result.errors)

    def test_validate_task_os_files_passes(self) -> None:
        checks = aide_lite.validate_task_os_files(REPO_ROOT)
        failures = [check.message for check in checks if check.severity == "FAIL"]
        self.assertEqual(failures, [])

    def test_export_pack_lists_task_os_portable_sources(self) -> None:
        for rel in [
            ".aide/policies/task-lifecycle.yaml",
            ".aide/tasks/workunit.schema.json",
            ".aide/ledgers/capability-ledger.schema.json",
            "docs/reference/task-os-v0.md",
        ]:
            self.assertIn(rel, aide_lite.TASK_OS_PORTABLE_SOURCE_FILES)
            self.assertIn(rel, aide_lite.Q31_REQUIRED_EXPORTED_SOURCE_FILES)


if __name__ == "__main__":
    unittest.main()
