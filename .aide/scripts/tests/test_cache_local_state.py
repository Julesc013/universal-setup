from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class CacheLocalStateTests(unittest.TestCase):
    def make_repo(self, prepared: bool = True) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        if prepared:
            aide_lite.run_context(root)
            aide_lite.write_task_packet(root, "Implement Q18 Cache + Local State Boundary")
            aide_lite.adapt_agents(root)
            verification = aide_lite.build_verification_report(root, task_packet_path=aide_lite.LATEST_PACKET_PATH)
            aide_lite.write_verification_report(root, aide_lite.LATEST_VERIFICATION_REPORT_PATH, verification)
            aide_lite.write_review_packet(root)
            aide_lite.write_golden_run_reports(root, aide_lite.run_golden_tasks(root, task_ids=aide_lite.SELFTEST_GOLDEN_TASK_IDS))
            records = aide_lite.build_ledger_scan_records(root)
            aide_lite.write_ledger_records(root, records)
            aide_lite.write_token_savings_summary(root, records, [])
            decision = aide_lite.build_route_decision(root)
            aide_lite.write_route_decision(root, decision)
        return root

    def test_cache_and_local_state_policy_anchors(self) -> None:
        root = self.make_repo(prepared=False)
        cache_policy = aide_lite.read_text(root / aide_lite.CACHE_POLICY_PATH)
        local_policy = aide_lite.read_text(root / aide_lite.LOCAL_STATE_POLICY_PATH)
        for anchor in aide_lite.CACHE_POLICY_ANCHORS:
            self.assertIn(anchor, cache_policy)
        for anchor in aide_lite.LOCAL_STATE_POLICY_ANCHORS:
            self.assertIn(anchor, local_policy)

    def test_gitignore_local_state_rule_detection(self) -> None:
        root = self.make_repo(prepared=False)
        self.assertTrue(aide_lite.gitignore_has_local_state_rules(root))
        aide_lite.write_text(root / ".gitignore", ".env\n")
        self.assertFalse(aide_lite.gitignore_has_local_state_rules(root))
        failures = [check for check in aide_lite.cache_status_checks(root) if check.severity == "FAIL"]
        self.assertTrue(any(".gitignore missing" in check.message for check in failures))

    def test_cache_key_refuses_ignored_local_and_secret_paths(self) -> None:
        root = self.make_repo(prepared=False)
        for rel in [".env", ".aide.local/state.json", "node_modules/pkg/index.js"]:
            with self.subTest(rel=rel):
                with self.assertRaisesRegex(ValueError, "refusing ignored/local/secret path"):
                    aide_lite.cache_record_for_file(root, rel, surface="baseline_surface")

    def test_content_hash_and_cache_key_are_deterministic_and_change_on_content(self) -> None:
        root = self.make_repo(prepared=False)
        first = aide_lite.cache_record_for_file(root, "README.md", surface="baseline_surface")
        second = aide_lite.cache_record_for_file(root, "README.md", surface="baseline_surface")
        self.assertEqual(first.content_sha256, second.content_sha256)
        self.assertEqual(first.key_id, second.key_id)
        self.assertEqual(aide_lite.stable_json_text({"b": 1, "a": 2}), aide_lite.stable_json_text({"a": 2, "b": 1}))
        aide_lite.write_text(root / "README.md", "# README\n\nchanged\n")
        changed = aide_lite.cache_record_for_file(root, "README.md", surface="baseline_surface")
        self.assertNotEqual(first.content_sha256, changed.content_sha256)
        self.assertNotEqual(first.key_id, changed.key_id)

    def test_task_packet_cache_key_includes_context_and_policy_signals(self) -> None:
        root = self.make_repo()
        record = aide_lite.cache_record_for_file(root, aide_lite.LATEST_PACKET_PATH, surface="task_packet", key_name="latest_task_packet")
        dependency_paths = {path for path, _digest in record.dependency_hashes}
        policy_paths = {path for path, _version in record.policy_versions}
        self.assertIn(aide_lite.LATEST_CONTEXT_PACKET_PATH, dependency_paths)
        self.assertIn(aide_lite.CACHE_POLICY_PATH, policy_paths)
        self.assertIn(aide_lite.LOCAL_STATE_POLICY_PATH, policy_paths)

    def test_cache_status_detects_missing_example_layout_and_tracking_risk(self) -> None:
        root = self.make_repo(prepared=False)
        (root / aide_lite.LOCAL_STATE_EXAMPLE_ROOT / "README.md").unlink()
        checks = aide_lite.cache_status_checks(root)
        self.assertTrue(any(check.severity == "FAIL" and "example" in check.message for check in checks))
        with mock.patch.object(aide_lite, "local_state_git_paths", return_value=[".aide.local/state.json"]):
            checks = aide_lite.cache_status_checks(root)
        self.assertTrue(any(check.severity == "FAIL" and "git status/index" in check.message for check in checks))

    def test_cache_report_writes_json_and_markdown_without_raw_contents(self) -> None:
        root = self.make_repo()
        json_result, md_result, data = aide_lite.write_cache_report(root)
        self.assertIn(json_result.action, {"written", "unchanged"})
        self.assertIn(md_result.action, {"written", "unchanged"})
        self.assertIn("latest_task_packet", data["keys"])
        report_json = aide_lite.read_text(root / aide_lite.CACHE_KEYS_JSON_PATH)
        report_md = aide_lite.read_text(root / aide_lite.CACHE_KEYS_MD_PATH)
        parsed = json.loads(report_json)
        self.assertFalse(parsed["contents_inline"])
        self.assertFalse(parsed["raw_prompt_storage"])
        self.assertFalse(parsed["raw_response_storage"])
        self.assertNotIn("print('hello')", report_json)
        self.assertNotIn("raw_prompt_body", report_json)
        self.assertIn("## CACHE_KEYS", report_md)
        self.assertFalse(any(check.severity == "FAIL" for check in aide_lite.cache_validation_checks(root)))

    def test_cache_commands_print_metadata_only(self) -> None:
        root = self.make_repo()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "cache", "key", "--file", aide_lite.LATEST_PACKET_PATH])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("AIDE Lite cache key", output)
        self.assertIn("raw_content_stored: false", output)
        self.assertNotIn("## PHASE", output)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "cache", "report"])
        self.assertEqual(code, 0)
        self.assertIn("contents_inline: false", buffer.getvalue())

    def test_selftest_includes_cache_checks(self) -> None:
        ok, messages = aide_lite.run_selftest()
        self.assertTrue(ok)
        self.assertTrue(any("cache" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
