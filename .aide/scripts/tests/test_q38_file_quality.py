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
SPEC = importlib.util.spec_from_file_location("aide_lite_q38", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q38"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class Q38FileQualityTests(unittest.TestCase):
    def make_repo(self, include_secret_path: bool = False) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for rel in [
            *aide_lite.Q37_POLICY_FILES,
            *aide_lite.Q37_SCHEMA_FILES,
            aide_lite.REPO_INTELLIGENCE_README_PATH,
            *aide_lite.Q38_POLICY_FILES,
            *aide_lite.Q38_SCHEMA_FILES,
            aide_lite.QUALITY_README_PATH,
        ]:
            source = REPO_ROOT / rel
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
        self.write(root, "app/main.py", "from app import helper\n\ndef run():\n    return helper.VALUE\n")
        self.write(root, "app/helper.py", "VALUE = 1\n\ndef shared_helper():\n    return VALUE\n")
        self.write(root, "lib/other_helper.py", "def shared_helper():\n    return 2\n")
        self.write(root, "app/untested.py", "def lonely():\n    return 'needs review'\n")
        duplicate = "def duplicate_helper():\n    return 42\n"
        self.write(root, "app/duplicate_a.py", duplicate)
        self.write(root, "app/duplicate_b.py", duplicate)
        self.write(root, "app/tests/test_main.py", "from app import main\n\ndef test_run():\n    assert main.run() == 1\n")
        self.write(root, "docs/guide.md", "# Guide\n\nSee [main](app/main.py) and [missing](docs/missing.md).\n")
        self.write(root, ".aide/queue/Q/evidence/report.md", "# Evidence\n")
        self.write(root, ".aide/intake/latest-intent-packet.json", "{}\n")
        self.write(root, "docs/templates/card.md.template", "template\n")
        self.write(root, ".aide.local/trace.txt", "local state\n")
        self.write(root, ".git/HEAD", "ref: refs/heads/main\n")
        if include_secret_path:
            self.write(root, "secrets/token.txt", "fixture secret placeholder\n")
        repo_data = aide_lite.build_repo_intelligence(root)
        if include_secret_path:
            secret_record = aide_lite.classify_repo_file(root, "secrets/token.txt")
            repo_data["file_inventory"]["records"].append(secret_record)
        aide_lite.write_repo_intelligence_outputs(root, repo_data)
        return root

    def write(self, root: Path, rel: str, text: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def ledger(self, root: Path) -> dict[str, object]:
        ledger = aide_lite.build_quality_ledger(root)
        self.assertIsNotNone(ledger)
        assert ledger is not None
        aide_lite.write_quality_outputs(root, ledger)
        return ledger

    def record(self, ledger: dict[str, object], rel: str) -> dict[str, object]:
        records = ledger["records"]
        assert isinstance(records, list)
        return next(item for item in records if isinstance(item, dict) and item["path"] == rel)

    def test_quality_policy_anchor_validation(self) -> None:
        root = self.make_repo()
        checks = aide_lite.validate_quality_files(root, require_latest=False)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")

    def test_ledger_generation_from_fixture_repo_intelligence(self) -> None:
        root = self.make_repo()
        ledger = self.ledger(root)
        self.assertEqual(ledger["schema_version"], "aide.file-quality-ledger.v0")
        checks = aide_lite.validate_quality_files(root, require_latest=True)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")
        for rel in aide_lite.Q38_GENERATED_OUTPUT_FILES:
            self.assertTrue((root / rel).exists(), rel)
        first = ledger["records"][0]
        for field in json.loads((root / aide_lite.FILE_QUALITY_RECORD_SCHEMA_PATH).read_text(encoding="utf-8"))["required"]:
            self.assertIn(field, first)

    def test_active_source_without_docs_or_tests_warns(self) -> None:
        ledger = self.ledger(self.make_repo())
        record = self.record(ledger, "app/untested.py")
        self.assertEqual(record["quality_level"], "warn")
        self.assertIn("missing_doc_candidate", record["warnings"])
        self.assertIn("missing_test_or_validator_candidate", record["warnings"])

    def test_evidence_and_generated_files_are_exempt(self) -> None:
        ledger = self.ledger(self.make_repo())
        evidence = self.record(ledger, ".aide/queue/Q/evidence/report.md")
        generated = self.record(ledger, ".aide/intake/latest-intent-packet.json")
        self.assertEqual(evidence["quality_level"], "exempt")
        self.assertEqual(generated["quality_level"], "exempt")
        self.assertIn("tests_not_required_for_this_lifecycle", evidence["exemptions"])

    def test_stale_doc_and_orphan_candidates_warn(self) -> None:
        ledger = self.ledger(self.make_repo())
        doc_record = self.record(ledger, "docs/guide.md")
        source_record = self.record(ledger, "app/untested.py")
        self.assertIn("stale_doc_reference_candidate", doc_record["warnings"])
        self.assertIn("orphan_candidate", source_record["warnings"])

    def test_tracked_secret_like_path_fails_hard(self) -> None:
        ledger = self.ledger(self.make_repo(include_secret_path=True))
        record = self.record(ledger, "secrets/token.txt")
        self.assertEqual(record["quality_level"], "fail")
        self.assertIn("tracked_local_state_or_secret_path", record["warnings"])
        checks = aide_lite.validate_quality_ledger_data(ledger)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_duplicate_hash_and_repeated_helper_candidates(self) -> None:
        ledger = self.ledger(self.make_repo())
        reuse = ledger["reuse_report"]
        assert isinstance(reuse, dict)
        duplicate_paths = [set(item["paths"]) for item in reuse["duplicate_hash_candidates"]]
        self.assertIn({"app/duplicate_a.py", "app/duplicate_b.py"}, duplicate_paths)
        helper_names = {item["helper_name"] for item in reuse["repeated_helper_name_candidates"]}
        self.assertIn("shared_helper", helper_names)

    def test_quality_explain_file_command_output(self) -> None:
        root = self.make_repo()
        self.ledger(root)
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(root), "quality", "explain-file", "app/main.py"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("quality_level:", result.stdout)
        self.assertIn("warnings:", result.stdout)

    def test_quality_command_does_not_mutate_source_files(self) -> None:
        root = self.make_repo()
        source = root / "app/main.py"
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(root), "quality", "ledger"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        after = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertEqual(before, after)
        self.assertIn("file_deletes: false", result.stdout)
        self.assertIn("auto_fixes: false", result.stdout)


if __name__ == "__main__":
    unittest.main()
