from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_q41", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q41"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class Q41ToolAbsorptionTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for rel in [*aide_lite.Q41_POLICY_FILES, *aide_lite.Q41_SCHEMA_FILES, aide_lite.TOOLS_README_PATH]:
            source = REPO_ROOT / rel
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
        self.write(root, ".aide/scripts/aide_lite.py", "#!/usr/bin/env python\nprint('fixture aide')\n")
        self.write(root, "scripts/aide", "#!/bin/sh\necho aide\n")
        self.write(root, "scripts/validate_repo.py", "print('validate')\n")
        self.write(root, "scripts/run_tests.py", "print('tests')\n")
        self.write(root, "scripts/build_project.sh", "#!/bin/sh\necho build\n")
        self.write(root, "scripts/lint_code.py", "print('lint')\n")
        self.write(root, "scripts/format_code.py", "print('format')\n")
        self.write(root, "scripts/context_pack.py", "print('context')\n")
        self.write(root, "tools/audit_report.py", "print('audit')\n")
        self.write(root, "tools/generate_assets.py", "print('generate')\n")
        self.write(root, "tools/migrate_old.py", "print('migrate')\n")
        self.write(root, "tools/publish_release.py", "print('release')\n")
        self.write(root, "tools/package_dist.py", "print('package')\n")
        self.write(root, "tools/security_scan.py", "print('security')\n")
        self.write(root, "tools/layout_policy.py", "print('repo policy')\n")
        self.write(root, "tools/delete_prune_deploy.py", "print('danger')\n")
        self.write(root, ".aide/scripts/toolbox.py", "print('unknown candidate')\n")
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

    def write_all_tool_outputs(self, root: Path, inventory: dict[str, object] | None = None, classification: dict[str, object] | None = None, wrap_plan: dict[str, object] | None = None, adapter_map: dict[str, object] | None = None) -> None:
        inventory = inventory or aide_lite.build_tool_inventory(root)
        classification = classification or aide_lite.build_tool_classification(root, inventory)
        if wrap_plan is None or adapter_map is None:
            wrap_plan, adapter_map = aide_lite.build_tool_wrap_outputs(root, classification)
        aide_lite.write_tool_inventory_outputs(root, inventory)
        aide_lite.write_tool_classification_outputs(root, classification)
        aide_lite.write_tool_wrap_outputs(root, wrap_plan, adapter_map)

    def test_tool_policy_anchors_and_fates(self) -> None:
        root = self.make_repo()
        checks = aide_lite.validate_tool_files(root, require_latest=False)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")
        fates = (root / aide_lite.TOOL_FATES_POLICY_PATH).read_text(encoding="utf-8")
        self.assertIn("drop_candidate_is_not_deletion_approval: true", fates)
        self.assertIn("wrap_is_plan_not_execution: true", fates)

    def test_tool_inventory_and_classification_from_fixture_repo(self) -> None:
        root = self.make_repo()
        inventory = aide_lite.build_tool_inventory(root)
        paths = {tool["path"] for tool in inventory["tools"]}
        self.assertIn("scripts/validate_repo.py", paths)
        self.assertIn(".aide/scripts/aide_lite.py", paths)
        self.assertTrue(inventory["no_apply"])
        classification = aide_lite.build_tool_classification(root, inventory)
        self.assertFalse(any(tool["execution_allowed"] for tool in classification["tools"]))
        self.assertFalse(any(tool["apply_allowed"] for tool in classification["tools"]))

    def test_capability_detection_for_expected_families(self) -> None:
        root = self.make_repo()
        inventory = aide_lite.build_tool_inventory(root)
        by_path = {tool["path"]: set(tool["capability_families"]) for tool in inventory["tools"]}
        expected = {
            "scripts/validate_repo.py": "validate",
            "scripts/run_tests.py": "test",
            "scripts/build_project.sh": "build",
            "tools/audit_report.py": "audit",
            "tools/generate_assets.py": "generate",
            "tools/migrate_old.py": "migrate",
            "tools/publish_release.py": "release",
            "tools/package_dist.py": "package",
            "tools/security_scan.py": "security",
            "tools/layout_policy.py": "repo_policy",
            "scripts/context_pack.py": "context",
            "scripts/lint_code.py": "lint",
            "scripts/format_code.py": "format",
        }
        for path, family in expected.items():
            self.assertIn(family, by_path[path], path)

    def test_high_risk_detection_for_destructive_deploy_publish_prune_names(self) -> None:
        root = self.make_repo()
        inventory = aide_lite.build_tool_inventory(root)
        danger = next(tool for tool in inventory["tools"] if tool["path"] == "tools/delete_prune_deploy.py")
        self.assertIn(danger["risk_class"], {"destructive", "release", "high"})
        self.assertFalse(danger["execution_allowed"])

    def test_tools_wrap_plan_no_execution_behavior(self) -> None:
        root = self.make_repo()
        inventory = aide_lite.build_tool_inventory(root)
        classification = aide_lite.build_tool_classification(root, inventory)
        wrap_plan, adapter_map = aide_lite.build_tool_wrap_outputs(root, classification)
        self.assertTrue(wrap_plan["no_apply"])
        self.assertFalse(wrap_plan["execution_allowed"])
        self.assertFalse(adapter_map["execution_allowed"])
        self.assertEqual(aide_lite.result_from_checks(aide_lite.validate_tool_wrap_data(root, wrap_plan, adapter_map)), "PASS")

    def test_tools_validate_rejects_execution_enabled_unknown_tool(self) -> None:
        root = self.make_repo()
        inventory = aide_lite.build_tool_inventory(root)
        classification = aide_lite.build_tool_classification(root, inventory)
        unknown = next(tool for tool in classification["tools"] if "unknown" in tool["capability_families"])
        unknown["execution_allowed"] = True
        self.write_all_tool_outputs(root, inventory=inventory, classification=classification)
        checks = aide_lite.validate_tool_files(root, require_latest=True)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_tools_validate_rejects_deletion_rename_migration_approval(self) -> None:
        root = self.make_repo()
        inventory = aide_lite.build_tool_inventory(root)
        classification = aide_lite.build_tool_classification(root, inventory)
        wrap_plan, adapter_map = aide_lite.build_tool_wrap_outputs(root, classification)
        wrap_plan["warnings"] = ["deletion approved", "rename approved", "migration approved"]
        self.write_all_tool_outputs(root, inventory=inventory, classification=classification, wrap_plan=wrap_plan, adapter_map=adapter_map)
        checks = aide_lite.validate_tool_files(root, require_latest=True)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_tools_commands_and_explain_output(self) -> None:
        root = self.make_repo()
        self.assertEqual(self.run_cmd(root, "tools", "inventory").returncode, 0)
        self.assertEqual(self.run_cmd(root, "tools", "classify").returncode, 0)
        self.assertEqual(self.run_cmd(root, "tools", "wrap-plan").returncode, 0)
        validate = self.run_cmd(root, "tools", "validate")
        self.assertEqual(validate.returncode, 0, validate.stderr or validate.stdout)
        explain = self.run_cmd(root, "tools", "explain-tool", ".aide/scripts/aide_lite.py")
        self.assertEqual(explain.returncode, 0, explain.stderr or explain.stdout)
        self.assertIn("execution_allowed: False", explain.stdout)
        capabilities = self.run_cmd(root, "tools", "capabilities")
        self.assertEqual(capabilities.returncode, 0, capabilities.stderr or capabilities.stdout)
        self.assertIn("validate:", capabilities.stdout)

    def test_local_state_tool_path_is_flagged_if_tracked(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git unavailable")
        root = self.make_repo()
        self.write(root, ".aide.local/run_tool.py", "print('local')\n")
        subprocess.run(["git", "init"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        subprocess.run(["git", "add", "-f", ".aide.local/run_tool.py"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        inventory = aide_lite.build_tool_inventory(root)
        local_tool = next(tool for tool in inventory["tools"] if tool["path"] == ".aide.local/run_tool.py")
        self.assertEqual(local_tool["risk_class"], "security")
        checks = aide_lite.validate_tool_files(root, require_latest=False)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_tools_commands_do_not_execute_or_mutate_fixture_tool(self) -> None:
        root = self.make_repo()
        marker = root / "executed.marker"
        tool = root / "scripts/validate_repo.py"
        tool.write_text("from pathlib import Path\nPath('executed.marker').write_text('ran')\n", encoding="utf-8", newline="\n")
        before = hashlib.sha256(tool.read_bytes()).hexdigest()
        self.assertEqual(self.run_cmd(root, "tools", "inventory").returncode, 0)
        self.assertEqual(self.run_cmd(root, "tools", "classify").returncode, 0)
        self.assertEqual(self.run_cmd(root, "tools", "wrap-plan").returncode, 0)
        after = hashlib.sha256(tool.read_bytes()).hexdigest()
        self.assertEqual(before, after)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
