from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_apply_00", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_apply_00"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


COMMAND_VECTORS = [
    ["transaction", "status"],
    ["transaction", "validate"],
    ["transaction", "fixture-plan"],
    ["transaction", "fixture-verify"],
]


class AIDEApply00TransactionModelTests(unittest.TestCase):
    def test_parser_accepts_transaction_commands(self) -> None:
        parser = aide_lite.build_parser(REPO_ROOT)
        for command in COMMAND_VECTORS:
            parsed = parser.parse_args(command)
            self.assertTrue(callable(getattr(parsed, "handler", None)), command)

    def test_fixture_plan_output_is_fixture_only_and_no_apply(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            json_result, md_result, plan = aide_lite.write_transaction_fixture_plan_outputs(root)
            self.assertIn(json_result.action, {"written", "unchanged"})
            self.assertIn(md_result.action, {"written", "unchanged"})
            self.assertEqual(plan["schema_version"], "aide.transaction.v0")
            self.assertEqual(plan["mode"], "fixture_only")
            boundary = plan["no_apply_boundary"]
            self.assertIs(boundary["real_repo_apply_allowed"], False)
            self.assertIs(boundary["target_mutation"], False)
            self.assertIs(boundary["branch_mutation"], False)
            self.assertEqual(boundary["provider_or_model_calls"], "none")
            self.assertEqual(boundary["network_calls"], "none")
            report = json.loads((root / aide_lite.TRANSACTION_FIXTURE_PLAN_JSON_PATH).read_text(encoding="utf-8"))
            for operation in report["operations"]:
                self.assertFalse(operation["real_repo_apply_allowed"])
                self.assertTrue(operation["path"].startswith(".aide/examples/apply/fixture-root/"))

    def test_current_repo_transaction_validation_passes_without_reports(self) -> None:
        checks = aide_lite.validate_transaction_files(REPO_ROOT, require_reports=False)
        failures = [check.message for check in checks if check.severity == "FAIL"]
        self.assertEqual(failures, [])

    def test_fixture_verification_current_repo_passes(self) -> None:
        aide_lite.write_transaction_fixture_plan_outputs(REPO_ROOT)
        checks = aide_lite.transaction_fixture_verification_checks(REPO_ROOT)
        failures = [check.message for check in checks if check.severity == "FAIL"]
        self.assertEqual(failures, [])

    def test_transaction_golden_runners_are_registered(self) -> None:
        definitions = {task.task_id for task in aide_lite.parse_golden_task_catalog(REPO_ROOT)}
        for task_id in aide_lite.TRANSACTION_GOLDEN_TASK_IDS:
            self.assertIn(task_id, definitions)


if __name__ == "__main__":
    unittest.main()
