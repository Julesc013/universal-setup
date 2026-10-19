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


    def explain(self, root, path, *options):
        return subprocess.run([sys.executable, "-B", str(MODULE_PATH), "--repo-root", str(root),
                               "quality", "explain-file", path, *options],
                              capture_output=True, text=True, check=False)

    def test_discovery_owner_docs_checks_and_unverified_freshness(self):
        root = self.make_repo()
        ledger = self.ledger(root)
        result = self.explain(root, "app/main.py", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["owner"], self.record(ledger, "app/main.py")["owner"])
        self.assertIn("docs/guide.md", data["relations"]["docs_refs"]["items"])
        self.assertIn("app/tests/test_main.py", data["relations"]["test_refs"]["items"])
        self.assertIn("not an executed check", data["relations"]["test_refs"]["reason"])
        self.assertEqual(data["coverage"], "heuristic_incomplete")
        self.assertEqual(data["freshness"], "unverified")
        human = self.explain(root, "app/main.py")
        self.assertEqual(human.returncode, 0)
        self.assertIn("app/tests/test_main.py", human.stdout)
        self.assertIn("freshness: unverified", human.stdout)
        self.write(root, "app/main.py", "raise RuntimeError('changed after inventory')\n")
        self.assertEqual(self.explain(root, "app/main.py", "--json").stdout, result.stdout)

    def test_reuse_links_distinct_helpers_without_claiming_equivalence(self):
        root = self.make_repo()
        self.ledger(root)
        data = json.loads(self.explain(root, "app/helper.py", "--json").stdout)
        helper = next(item for item in data["reuse"]["items"] if item["match"] == "shared_helper")
        self.assertIn("lib/other_helper.py", helper["peers"]["items"])
        self.assertEqual(helper["reason"], "repeated helper name")
        self.assertTrue(any("does not prove shared semantics" in item for item in data["caveats"]))
        duplicate = json.loads(self.explain(root, "app/duplicate_a.py", "--json").stdout)
        self.assertTrue(any(item["reason"] == "recorded identical content hash" and
                            "app/duplicate_b.py" in item["peers"]["items"]
                            for item in duplicate["reuse"]["items"]))

    def test_old_ledger_and_empty_results_are_not_negative_proof(self):
        root = self.make_repo()
        ledger = self.ledger(root)
        empty = json.loads(self.explain(root, "app/untested.py", "--json").stdout)
        self.assertEqual(empty["relations"]["test_refs"]["state"], "not_found")
        self.assertEqual(empty["reuse"]["state"], "not_found")
        ledger.pop("reuse_report")
        aide_lite.write_quality_outputs(root, ledger)
        self.assertEqual(aide_lite.result_from_checks(aide_lite.validate_quality_files(root, require_latest=True)), "PASS")
        old = json.loads(self.explain(root, "app/helper.py", "--json").stdout)
        self.assertEqual(old["reuse"]["state"], "unindexed")
        missing = self.explain(root, "not-indexed.py", "--json")
        self.assertEqual(missing.returncode, 1)
        self.assertEqual(json.loads(missing.stdout)["coverage"], "unindexed")

    def test_lookup_is_deterministic_and_does_not_require_target_source(self):
        root = self.make_repo()
        self.ledger(root)
        (root / "app/helper.py").unlink()
        def contents():
            return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in root.rglob("*") if p.is_file()}
        before = contents()
        first = self.explain(root, "app/helper.py", "--json")
        self.assertEqual(first.returncode, 0)
        self.assertEqual(first.stdout, self.explain(root, "app/helper.py", "--json").stdout)
        self.assertEqual(before, contents())
        (root / aide_lite.FILE_QUALITY_LEDGER_JSON_PATH).unlink()
        missing = self.explain(root, "app/helper.py", "--json")
        self.assertEqual(missing.returncode, 1)
        self.assertFalse((root / aide_lite.FILE_QUALITY_LEDGER_JSON_PATH).exists())

    def test_discovery_reports_omitted_relations_and_peers(self):
        root = self.make_repo()
        ledger = self.ledger(root)
        self.record(ledger, "app/helper.py")["test_refs"] = [f"tests/check_{i:02d}.py" for i in range(25)]
        ledger["reuse_report"]["repeated_helper_name_candidates"] = [
            {"helper_name": f"helper_{i:02d}", "paths": ["app/helper.py"] +
             [f"lib/peer_{j:02d}.py" for j in range(23)]} for i in range(22)]
        aide_lite.write_quality_outputs(root, ledger)
        data = json.loads(self.explain(root, "app/helper.py", "--json").stdout)
        self.assertEqual(len(data["relations"]["test_refs"]["items"]), 20)
        self.assertEqual(data["relations"]["test_refs"]["omitted"], 5)
        self.assertEqual(len(data["reuse"]["items"]), 20)
        self.assertEqual(data["reuse"]["omitted"], 2)
        self.assertEqual(data["reuse"]["items"][0]["peers"]["omitted"], 3)

    def test_discovery_refuses_malformed_and_oversized_reports_without_repair(self):
        root = self.make_repo()
        ledger = self.ledger(root)
        bad_record = json.loads(json.dumps(ledger))
        self.record(bad_record, "app/main.py")["test_refs"] = "invalid"
        bad_reuse = json.loads(json.dumps(ledger))
        bad_reuse["reuse_report"] = None
        bad_missing = json.loads(json.dumps(ledger))
        self.record(bad_missing, "app/main.py").pop("test_refs")
        bad_identity = json.loads(json.dumps(ledger))
        bad_identity["records"].append({"path": None})
        bad_revision = {**ledger, "source_commit": {"invalid": "revision"}}
        report = root / aide_lite.FILE_QUALITY_LEDGER_JSON_PATH
        for text in ("{", "[]", '{"schema_version":"unknown","records":[]}',
                     json.dumps(bad_record), json.dumps(bad_reuse), json.dumps(bad_missing),
                     json.dumps(bad_identity), json.dumps(bad_revision), " " * (16 * 1024 * 1024 + 1)):
            with self.subTest(size=len(text)):
                report.write_text(text, encoding="utf-8")
                digest = hashlib.sha256(report.read_bytes()).hexdigest()
                result = self.explain(root, "app/main.py", "--json")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(json.loads(result.stdout)["result"], "INVALID")
                self.assertEqual(hashlib.sha256(report.read_bytes()).hexdigest(), digest)

    def test_discovery_bounds_human_and_json_output_bytes(self):
        root = self.make_repo()
        ledger = self.ledger(root)
        # Item counts alone cannot bound a large scalar or reference string.
        self.record(ledger, "app/main.py")["owner"] = "x" * (65 * 1024)
        aide_lite.write_quality_outputs(root, ledger)
        report = root / aide_lite.FILE_QUALITY_LEDGER_JSON_PATH
        before = report.read_bytes()
        for options in ((), ("--json",)):
            result = self.explain(root, "app/main.py", *options)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("64 KiB", result.stdout)
            self.assertLessEqual(len(result.stdout.encode("utf-8")), 64 * 1024)
            self.assertEqual(before, report.read_bytes())


if __name__ == "__main__":
    unittest.main()
