from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
import importlib.util


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_q35", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q35"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class Q35GithubAdvisoryTests(unittest.TestCase):
    def test_github_advisory_is_report_only(self) -> None:
        data = aide_lite.make_github_advisory(REPO_ROOT)
        for key in [
            "github_api_mutation",
            "branch_protection_applied",
            "workflow_file_written",
            "workflow_installation",
            "release_publishing",
            "tag_creation",
            "branch_mutation",
            "network_calls",
            "provider_or_model_calls",
        ]:
            self.assertIs(data[key], False, key)
        self.assertEqual(data["advisory_mode"], "report_only")

    def test_branch_protection_plan_contains_main_and_dev_roles(self) -> None:
        plan = aide_lite.make_github_protection_plan(REPO_ROOT)
        targets = {item["branch"]: item for item in plan["branch_targets"]}
        self.assertEqual(targets["main"]["role"], "canonical")
        self.assertEqual(targets["dev"]["role"], "integration")
        self.assertIs(plan["github_api_mutation"], False)
        self.assertIs(plan["branch_protection_applied"], False)

    def test_ci_plan_contains_expected_gates_without_workflow_install(self) -> None:
        plan = aide_lite.make_github_ci_plan(REPO_ROOT)
        commands = "\n".join(item["command"] for item in plan["jobs"])
        self.assertIn("aide_lite.py validate", commands)
        self.assertIn("aide_lite.py eval run", commands)
        self.assertIn("aide_lite.py github validate", commands)
        self.assertIn("pack-status", commands)
        self.assertIs(plan["workflow_installation"], False)
        self.assertIs(plan["workflow_file_written"], False)

    def test_write_and_validate_github_advisory_outputs(self) -> None:
        aide_lite.write_github_advisory_reports(REPO_ROOT)
        checks = aide_lite.validate_github_advisory_files(REPO_ROOT)
        self.assertNotEqual(aide_lite.result_from_checks(checks), "FAIL")
        advisory = json.loads(aide_lite.read_text(REPO_ROOT / aide_lite.GITHUB_ADVISORY_JSON_PATH))
        self.assertTrue(advisory["preview_only"])
        self.assertFalse(advisory["github_api_mutation"])

    def test_github_commands_run_without_mutation(self) -> None:
        for command in [
            ["github", "advisory"],
            ["github", "status"],
            ["github", "protection"],
            ["github", "ci"],
            ["github", "validate"],
        ]:
            result = subprocess.run(
                [sys.executable, str(MODULE_PATH), *command],
                cwd=REPO_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertIn("false", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
