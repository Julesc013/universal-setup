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
SPEC = importlib.util.spec_from_file_location("aide_lite_q40", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q40"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class Q40RootRecyclingTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for rel in [*aide_lite.Q40_POLICY_FILES, *aide_lite.Q40_SCHEMA_FILES, aide_lite.ROOTS_README_PATH]:
            source = REPO_ROOT / rel
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
        self.write(root, "mixed/source.py", "def value():\n    return 1\n")
        self.write(root, "mixed/test_source.py", "def test_value():\n    assert True\n")
        self.write(root, "mixed/README.md", "# Mixed root\n")
        self.write(root, "mixed/data.unknown", "unknown\n")
        self.write(root, "packs/manifest.json", "{\"name\": \"fixture\"}\n")
        self.write(root, "native/CMakeLists.txt", "cmake_minimum_required(VERSION 3.20)\n")
        self.write(root, "governance/policy.md", "# Policy\n")
        self.write(root, ".aide/context/latest-task-packet.md", "# Generated\n")
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

    def test_root_policy_anchors_and_fates(self) -> None:
        root = self.make_repo()
        checks = aide_lite.validate_root_files(root, require_latest=False)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")
        fates = (root / aide_lite.ROOT_FATES_POLICY_PATH).read_text(encoding="utf-8")
        self.assertIn("drop_candidate_is_deletion_approval: false", fates)
        self.assertIn("drop_candidate_is_not_safe_to_delete: true", fates)

    def test_root_inventory_from_fixture_repo(self) -> None:
        root = self.make_repo()
        inventory = aide_lite.build_root_inventory(root)
        roots = {record["root"]: record for record in inventory["roots"]}
        self.assertIn("mixed", roots)
        self.assertIn("packs", roots)
        self.assertEqual(inventory["no_apply"], True)
        self.assertEqual(roots["mixed"]["root_status"], "mixed")

    def test_root_classification_and_risk_heuristics(self) -> None:
        root = self.make_repo()
        inventory = aide_lite.build_root_inventory(root)
        classification = aide_lite.build_root_classification(root, inventory)
        records = classification["file_classifications"]
        self.assertTrue(records)
        self.assertFalse(any(record["apply_allowed"] for record in records))
        self.assertIn("unknown", {record["recommended_fate"] for record in records})
        roots = {record["root"]: record for record in classification["roots"]}
        self.assertEqual(roots["mixed"]["root_status"], "mixed")
        self.assertIn(roots["mixed"]["risk_class"], {"high", "medium"})

    def test_root_sensitivity_detection(self) -> None:
        root = self.make_repo()
        records, _mode = aide_lite.root_source_records(root)
        by_root: dict[str, list[dict[str, object]]] = {}
        for record in records:
            by_root.setdefault(aide_lite.root_name_for_path(str(record["path"])), []).append(record)
        self.assertTrue(aide_lite.root_sensitive_flags("packs", by_root["packs"])[0]["identity_sensitive"])
        self.assertTrue(aide_lite.root_sensitive_flags("native", by_root["native"])[0]["build_sensitive"])
        self.assertTrue(aide_lite.root_sensitive_flags("governance", by_root["governance"])[0]["authority_sensitive"])
        self.assertTrue(aide_lite.root_sensitive_flags(".aide", by_root[".aide"])[0]["generated_sensitive"])

    def test_roots_plan_no_apply_behavior(self) -> None:
        root = self.make_repo()
        inventory = aide_lite.build_root_inventory(root)
        classification = aide_lite.build_root_classification(root, inventory)
        plan = aide_lite.build_root_recycling_plan(root, classification)
        self.assertTrue(plan["no_apply"])
        self.assertFalse(plan["file_moves"])
        self.assertFalse(plan["file_deletes"])
        self.assertFalse(plan["reference_rewrites"])
        self.assertEqual(aide_lite.result_from_checks(aide_lite.validate_root_plan_data(root, plan)), "PASS")

    def test_roots_validate_rejects_apply_enabled_classification(self) -> None:
        root = self.make_repo()
        inventory = aide_lite.build_root_inventory(root)
        classification = aide_lite.build_root_classification(root, inventory)
        classification["file_classifications"][0]["apply_allowed"] = True
        exceptions = aide_lite.build_root_exceptions(root, classification)
        plan = aide_lite.build_root_recycling_plan(root, classification)
        aide_lite.write_root_inventory_outputs(root, inventory)
        aide_lite.write_root_classification_outputs(root, classification, exceptions)
        aide_lite.write_root_plan_outputs(root, plan)
        checks = aide_lite.validate_root_files(root, require_latest=True)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_roots_validate_rejects_deletion_approval(self) -> None:
        root = self.make_repo()
        inventory = aide_lite.build_root_inventory(root)
        classification = aide_lite.build_root_classification(root, inventory)
        exceptions = aide_lite.build_root_exceptions(root, classification)
        plan = aide_lite.build_root_recycling_plan(root, classification)
        plan["blocked_reasons"] = ["final deletion approved"]
        aide_lite.write_root_inventory_outputs(root, inventory)
        aide_lite.write_root_classification_outputs(root, classification, exceptions)
        aide_lite.write_root_plan_outputs(root, plan)
        checks = aide_lite.validate_root_files(root, require_latest=True)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_roots_commands_and_explain_output(self) -> None:
        root = self.make_repo()
        self.assertEqual(self.run_cmd(root, "roots", "inventory").returncode, 0)
        self.assertEqual(self.run_cmd(root, "roots", "classify").returncode, 0)
        self.assertEqual(self.run_cmd(root, "roots", "plan").returncode, 0)
        validate = self.run_cmd(root, "roots", "validate")
        self.assertEqual(validate.returncode, 0, validate.stderr or validate.stdout)
        explain_root = self.run_cmd(root, "roots", "explain-root", "mixed")
        self.assertEqual(explain_root.returncode, 0, explain_root.stderr or explain_root.stdout)
        self.assertIn("root: mixed", explain_root.stdout)
        explain_file = self.run_cmd(root, "roots", "explain-file", "mixed/source.py")
        self.assertEqual(explain_file.returncode, 0, explain_file.stderr or explain_file.stdout)
        self.assertIn("apply_allowed: False", explain_file.stdout)

    def test_local_state_path_is_flagged_if_tracked(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git unavailable")
        root = self.make_repo()
        self.write(root, ".aide.local/state.json", "{}\n")
        subprocess.run(["git", "init"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        subprocess.run(["git", "add", "-f", ".aide.local/state.json"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        subprocess.run(["git", "commit", "-m", "fixture"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        inventory = aide_lite.build_root_inventory(root)
        local_root = next(record for record in inventory["roots"] if record["root"] == ".aide.local")
        self.assertEqual(local_root["risk_class"], "critical")
        self.assertEqual(local_root["root_status"], "local_only")

    def test_roots_commands_do_not_move_or_delete_source_files(self) -> None:
        root = self.make_repo()
        source = root / "mixed/source.py"
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(self.run_cmd(root, "roots", "inventory").returncode, 0)
        self.assertEqual(self.run_cmd(root, "roots", "classify").returncode, 0)
        self.assertEqual(self.run_cmd(root, "roots", "plan").returncode, 0)
        after = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(before, after)
        self.assertTrue(source.exists())


if __name__ == "__main__":
    unittest.main()
