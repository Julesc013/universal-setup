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
SPEC = importlib.util.spec_from_file_location("aide_lite_q37", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q37"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class Q37RepoIntelligenceTests(unittest.TestCase):
    def make_repo(self, include_unknown: bool = False) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for rel in [*aide_lite.Q37_POLICY_FILES, *aide_lite.Q37_SCHEMA_FILES, aide_lite.REPO_INTELLIGENCE_README_PATH]:
            source = REPO_ROOT / rel
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
        self.write(root, "app/main.py", "import os\nfrom app import helper\n# see docs/guide.md\n")
        self.write(root, "app/helper.py", "VALUE = 1\n")
        self.write(root, "app/tests/test_main.py", "from app import main\n\ndef test_main():\n    assert main\n")
        self.write(root, "docs/guide.md", "# Guide\n\nSee [main](../app/main.py) and [missing](docs/missing.md).\n")
        self.write(root, ".aide/policies/custom.yaml", "schema_version: custom.policy.v0\n")
        self.write(root, "contracts/example.schema.json", "{}\n")
        self.write(root, ".aide/queue/Q/evidence/report.md", "# Evidence\n")
        self.write(root, ".aide/intake/latest-intent-packet.json", "{}\n")
        self.write(root, "docs/templates/card.md.template", "template\n")
        if include_unknown:
            self.write(root, "misc/NOTICE", "unknown\n")
        self.write(root, ".aide.local/trace.txt", "local state\n")
        self.write(root, ".git/HEAD", "ref: refs/heads/main\n")
        return root

    def write(self, root: Path, rel: str, text: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def test_classify_source_test_doc_policy_schema_evidence_generated_template_unknown(self) -> None:
        root = self.make_repo(include_unknown=True)
        cases = {
            "app/main.py": "source",
            "app/tests/test_main.py": "test",
            "docs/guide.md": "doc",
            ".aide/policies/custom.yaml": "policy",
            "contracts/example.schema.json": "schema",
            ".aide/queue/Q/evidence/report.md": "evidence",
            ".aide/intake/latest-intent-packet.json": "generated",
            "docs/templates/card.md.template": "template",
            "misc/NOTICE": "unknown",
        }
        for rel, expected_kind in cases.items():
            with self.subTest(rel=rel):
                self.assertEqual(aide_lite.classify_repo_file(root, rel)["kind"], expected_kind)
        local = aide_lite.classify_repo_file(root, ".aide.local/trace.txt")
        self.assertEqual(local["kind"], "local")
        self.assertTrue(local["local_state"])

    def test_inventory_fixture_excludes_git_and_aide_local(self) -> None:
        root = self.make_repo(include_unknown=True)
        files, mode = aide_lite.repo_inventory_source_files(root)
        self.assertEqual(mode, "filesystem_walk")
        self.assertNotIn(".git/HEAD", files)
        self.assertNotIn(".aide.local/trace.txt", files)
        data = aide_lite.build_repo_intelligence(root)
        paths = {record["path"] for record in data["file_inventory"]["records"]}
        self.assertIn("app/main.py", paths)
        self.assertNotIn(".git/HEAD", paths)
        self.assertNotIn(".aide.local/trace.txt", paths)

    def test_detect_python_imports_markdown_links_stale_doc_candidate_and_test_target(self) -> None:
        root = self.make_repo()
        data = aide_lite.build_repo_intelligence(root)
        dep = next(item for item in data["dependency_map"]["records"] if item["path"] == "app/main.py")
        self.assertIn("os", dep["imports"])
        self.assertIn("app", dep["imports"])
        doc = next(item for item in data["doc_link_map"]["records"] if item["doc_path"] == "docs/guide.md")
        self.assertTrue(any("missing.md" in item for item in doc["stale_candidates"]))
        test = next(item for item in data["test_map"]["records"] if item["test_path"] == "app/tests/test_main.py")
        self.assertIn("app/main.py", test["likely_targets"])
        self.assertEqual(test["confidence"], "high")

    def test_generate_repo_maps_and_validate_pass_on_fixture(self) -> None:
        root = self.make_repo()
        data = aide_lite.build_repo_intelligence(root)
        writes = aide_lite.write_repo_intelligence_outputs(root, data)
        self.assertTrue(all(result.action in {"written", "unchanged"} for result in writes.values()))
        for rel in [
            aide_lite.FILE_INVENTORY_JSON_PATH,
            aide_lite.OWNERSHIP_MAP_JSON_PATH,
            aide_lite.DEPENDENCY_MAP_JSON_PATH,
            aide_lite.REPO_TEST_MAP_JSON_PATH,
            aide_lite.DOC_LINK_MAP_JSON_PATH,
            aide_lite.GENERATED_MAP_JSON_PATH,
            aide_lite.ORPHAN_CANDIDATES_JSON_PATH,
        ]:
            self.assertTrue((root / rel).exists(), rel)
            json.loads((root / rel).read_text(encoding="utf-8"))
        checks = aide_lite.validate_repo_intelligence_files(root, require_latest=True)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")

    def test_repo_validate_warns_on_unknown_fixture(self) -> None:
        root = self.make_repo(include_unknown=True)
        aide_lite.write_repo_intelligence_outputs(root, aide_lite.build_repo_intelligence(root))
        checks = aide_lite.validate_repo_intelligence_files(root, require_latest=True)
        self.assertEqual(aide_lite.result_from_checks(checks), "WARN")
        self.assertTrue(any("unknown file classifications" in check.message for check in checks))

    def test_explain_file_command_output(self) -> None:
        root = self.make_repo()
        aide_lite.write_repo_intelligence_outputs(root, aide_lite.build_repo_intelligence(root))
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(root), "repo", "explain-file", "app/main.py"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("kind: source", result.stdout)
        self.assertIn("likely_tests: app/tests/test_main.py", result.stdout)

    def test_repo_commands_report_no_provider_model_network_behavior(self) -> None:
        root = self.make_repo()
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(root), "repo", "inventory"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("provider_or_model_calls: none", result.stdout)
        self.assertIn("network_calls: none", result.stdout)


if __name__ == "__main__":
    unittest.main()
