from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class AideLiteReviewPackTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        aide_lite.run_context(root)
        aide_lite.write_task_packet(root, "Implement Q13 Evidence Review Workflow")
        aide_lite.adapt_agents(root)
        report = aide_lite.build_verification_report(root, task_packet_path=aide_lite.LATEST_PACKET_PATH)
        aide_lite.write_verification_report(root, aide_lite.LATEST_VERIFICATION_REPORT_PATH, report)
        return root

    def test_review_pack_creates_required_sections_and_refs(self) -> None:
        root = self.make_repo()
        result, packet = aide_lite.write_review_packet(root)
        text = aide_lite.read_text(result.path)
        for section in aide_lite.REVIEW_PACKET_REQUIRED_SECTIONS:
            self.assertIn(f"## {section}", text)
        self.assertIn(aide_lite.LATEST_PACKET_PATH, text)
        self.assertIn(aide_lite.LATEST_CONTEXT_PACKET_PATH, text)
        self.assertIn(aide_lite.LATEST_VERIFICATION_REPORT_PATH, text)
        self.assertIn(aide_lite.default_evidence_dir(root), text)
        self.assertIn(aide_lite.REVIEW_DECISION_POLICY_PATH, text)
        self.assertIn(aide_lite.REVIEW_PROMPT_PATH, text)
        self.assertEqual(packet.budget_status, "PASS")

    def test_review_packet_uses_refs_without_inline_source(self) -> None:
        root = self.make_repo()
        result, _packet = aide_lite.write_review_packet(root)
        text = aide_lite.read_text(result.path)
        self.assertNotIn("print('hello')", text)
        self.assertNotIn("SHOULD_NOT_APPEAR", text)
        self.assertNotIn("whole repo dump", text.lower())

    def test_fixture_without_source_ignore_or_baselines_remains_verifiable(self) -> None:
        source = aide_lite.repo_root_from_script()
        omitted = {source / ".gitignore", source / aide_lite.TOKEN_BASELINES_PATH,
                   source / aide_lite.TOKEN_LEDGER_PATH}
        exists = Path.exists
        with mock.patch.object(Path, "exists", lambda path: False if path in omitted else exists(path)):
            root = self.make_repo()
        self.assertTrue(aide_lite.gitignore_has_local_state_rules(root))
        report = aide_lite.build_verification_report(root, task_packet_path=aide_lite.LATEST_PACKET_PATH)
        self.assertIn(report.result, {"PASS", "WARN"}, report.findings)
        for name in ("root_history_baseline", "review_baseline", "repo_context_baseline"):
            baseline = aide_lite.baseline_by_name(root, name)
            self.assertGreater(aide_lite.calculate_baseline(root, baseline).approx_tokens, 0)
        aide_lite.write_review_packet(root)
        summary = aide_lite.write_token_savings_summary(root, [], [])
        self.assertTrue(summary.path.is_file())
        self.assertEqual(aide_lite.read_ledger_records(root), [])
        self.assertEqual(aide_lite.run_golden_token_ledger(root).result, "FAIL")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            exit_code = aide_lite.main(["--repo-root", str(root), "ledger", "scan"])
        self.assertEqual(exit_code, 0)
        measured = aide_lite.run_golden_token_ledger(root)
        self.assertEqual(measured.result, "PASS", measured.errors)

    def test_review_pack_is_deterministic_for_same_state(self) -> None:
        root = self.make_repo()
        first, _packet = aide_lite.write_review_packet(root)
        first_text = aide_lite.read_text(first.path)
        second, _packet = aide_lite.write_review_packet(root)
        second_text = aide_lite.read_text(second.path)
        self.assertEqual(second.action, "unchanged")
        self.assertEqual(first_text, second_text)

    def test_review_packet_validation_warns_when_refs_are_missing(self) -> None:
        root = self.make_repo()
        (root / aide_lite.LATEST_VERIFICATION_REPORT_PATH).unlink()
        result, _packet = aide_lite.write_review_packet(root)
        findings = aide_lite.verify_review_packet(root, aide_lite.normalize_rel(result.path.relative_to(root)))
        self.assertTrue(any(finding.severity == "WARN" and "referenced path does not exist" in finding.message for finding in findings))

        # Missing shared guidance must be reported by the real reference checker.
        (root / aide_lite.REVIEW_PROMPT_PATH).unlink()
        findings = aide_lite.verify_review_packet(root, aide_lite.normalize_rel(result.path.relative_to(root)))
        self.assertTrue(any(finding.severity == "WARN" and "referenced path does not exist" in finding.message
                            and finding.path == aide_lite.REVIEW_PROMPT_PATH for finding in findings))
        aide_lite.write_text(result.path, aide_lite.read_text(result.path).replace(aide_lite.REVIEW_PROMPT_PATH, "omitted-guidance"))
        findings = aide_lite.verify_review_packet(root, aide_lite.normalize_rel(result.path.relative_to(root)))
        self.assertTrue(any(finding.severity == "WARN" and finding.message == f"review ref missing: {aide_lite.REVIEW_PROMPT_PATH}"
                            for finding in findings))

    def test_malformed_review_packet_fails_validation_and_verify_command(self) -> None:
        root = self.make_repo()
        aide_lite.write_text(root / aide_lite.REVIEW_PACKET_PATH, "# Broken\n\n## Review Objective\n\nMissing required sections.\n")
        ok, messages = aide_lite.validate_repo(root)
        self.assertFalse(ok)
        self.assertTrue(any("review packet missing required section" in message for message in messages))

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            exit_code = aide_lite.main(["--repo-root", str(root), "verify", "--review-packet", aide_lite.REVIEW_PACKET_PATH])
        self.assertEqual(exit_code, 1)

    def test_forbidden_prompt_pattern_detection(self) -> None:
        root = self.make_repo()
        result, _packet = aide_lite.write_review_packet(root)
        aide_lite.write_text(result.path, aide_lite.read_text(result.path) + "\nfull prior transcript\n")
        findings = aide_lite.verify_review_packet(root, aide_lite.REVIEW_PACKET_PATH)
        self.assertTrue(any(finding.severity == "WARN" and "forbidden prompt pattern" in finding.message for finding in findings))

    def test_review_pack_command_and_selftest(self) -> None:
        root = self.make_repo()
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()):
            exit_code = aide_lite.main(["--repo-root", str(root), "review-pack"])
        self.assertEqual(exit_code, 0)
        self.assertIn("AIDE Lite review-pack", stdout.getvalue())
        self.assertTrue((root / aide_lite.REVIEW_PACKET_PATH).exists())

        ok, messages = aide_lite.run_selftest()
        self.assertTrue(ok)
        self.assertTrue(any("review-pack" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
