from __future__ import annotations

import importlib.util
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


VALID_EVIDENCE = """# Evidence Packet

## Task

Q12 Verifier v0

## Objective

Check mechanical verifier behavior.

## Scope

Allowed `.aide/verification/**`; forbidden `.env`.

## Changed Files

- `.aide/verification/latest-verification-report.md`
- `README.md`

## Validation Commands

- `py -3 .aide/scripts/aide_lite.py verify`

## Validation Results

PASS.

## Generated Artifacts

- `.aide/verification/latest-verification-report.md`

## Token Estimates

chars / 4 approximation.

## Risks

Structural only.

## Deferrals

No Gateway.

## Next Recommended Phase

Q13 Evidence Review Workflow.
"""


class AideLiteVerifierTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        aide_lite.run_context(root)
        aide_lite.write_task_packet(root, "Implement Q12 Verifier v0")
        aide_lite.adapt_agents(root)
        return root

    def test_evidence_packet_required_sections_pass_and_fail(self) -> None:
        root = self.make_repo()
        evidence = root / "evidence.md"
        aide_lite.write_text(evidence, VALID_EVIDENCE)
        findings = aide_lite.verify_evidence_packet(root, "evidence.md")
        self.assertFalse(any(finding.severity == "ERROR" for finding in findings))

        broken = root / "broken-evidence.md"
        aide_lite.write_text(broken, VALID_EVIDENCE.replace("## Risks\n", "## Missing Risks\n"))
        broken_findings = aide_lite.verify_evidence_packet(root, "broken-evidence.md")
        self.assertTrue(any("Risks" in finding.message for finding in broken_findings))
        self.assertEqual(aide_lite.verification_result(broken_findings), "FAIL")

    def test_task_packet_sections_and_forbidden_prompt_patterns(self) -> None:
        root = self.make_repo()
        packet_findings = aide_lite.verify_task_packet(root, aide_lite.LATEST_PACKET_PATH)
        self.assertFalse(any(finding.severity == "ERROR" for finding in packet_findings))

        packet = root / aide_lite.LATEST_PACKET_PATH
        aide_lite.write_text(packet, aide_lite.read_text(packet) + "\nfull prior transcript\n")
        findings = aide_lite.verify_task_packet(root, aide_lite.LATEST_PACKET_PATH)
        self.assertTrue(any(finding.check == "task_packet" and finding.severity == "WARN" for finding in findings))

    def test_file_reference_parser_and_line_ranges(self) -> None:
        root = self.make_repo()
        refs = aide_lite.extract_file_refs("See `.aide/context/latest-task-packet.md` and `README.md#L1-L1`.")
        self.assertIn(".aide/context/latest-task-packet.md", refs)
        self.assertIn("README.md#L1-L1", refs)

        existing = aide_lite.validate_file_reference(root, "README.md")
        self.assertEqual(existing.severity, "INFO")
        missing = aide_lite.validate_file_reference(root, "missing.md")
        self.assertEqual(missing.severity, "WARN")
        valid_line = aide_lite.validate_file_reference(root, "README.md#L1-L1")
        self.assertEqual(valid_line.severity, "INFO")
        invalid_line = aide_lite.validate_file_reference(root, "README.md#L99-L100")
        self.assertEqual(invalid_line.severity, "ERROR")

    def test_secret_scan_detects_values_but_not_policy_terms(self) -> None:
        fake_value = "abcdef0123456789" * 2
        findings = aide_lite.scan_secret_text("api_key = '" + fake_value + "'\n", ".aide/test.md")
        self.assertTrue(any(finding.severity == "ERROR" for finding in findings))

        policy_findings = aide_lite.scan_secret_text("The api_key term is policy text only.\n", ".aide/test.md")
        self.assertFalse(any(finding.severity == "ERROR" for finding in policy_findings))

    def test_diff_scope_classification(self) -> None:
        allowed = [".aide/verification/**", "README.md"]
        forbidden = [".env", ".aide.local/**"]
        self.assertEqual(aide_lite.classify_scope_path(".aide/verification/report.md", " M", allowed, forbidden).classification, "allowed")
        self.assertEqual(aide_lite.classify_scope_path(".env", "??", allowed, forbidden).classification, "forbidden")
        self.assertEqual(aide_lite.classify_scope_path("elsewhere/file.txt", " M", allowed, forbidden).classification, "unknown")
        self.assertEqual(aide_lite.classify_scope_path("README.md", " D", allowed, forbidden).classification, "warning")

    def test_adapter_drift_and_report_rendering(self) -> None:
        root = self.make_repo()
        agents = root / "AGENTS.md"
        aide_lite.write_text(agents, aide_lite.read_text(agents).replace("verify", "full-history-review"))
        self.assertEqual(aide_lite.adapter_status(root).status, "drift")

        report = aide_lite.build_verification_report(root, task_packet_path=aide_lite.LATEST_PACKET_PATH)
        rendered = aide_lite.render_verification_report(report)
        self.assertIn("## VERIFIER_RESULT", rendered)
        self.assertIn("## CHECK_COUNTS", rendered)
        self.assertNotIn("print('hello')", rendered)

    def test_verify_result_values_and_command_failure(self) -> None:
        self.assertEqual(aide_lite.verification_result([aide_lite.VerificationFinding("INFO", "x", "ok")]), "PASS")
        self.assertEqual(aide_lite.verification_result([aide_lite.VerificationFinding("WARN", "x", "watch")]), "WARN")
        self.assertEqual(aide_lite.verification_result([aide_lite.VerificationFinding("ERROR", "x", "bad")]), "FAIL")

        root = self.make_repo()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            exit_code = aide_lite.main(["--repo-root", str(root), "verify", "--evidence", "missing.md"])
        self.assertEqual(exit_code, 1)

    def test_write_report_path_is_bounded(self) -> None:
        root = self.make_repo()
        report = aide_lite.build_verification_report(root, task_packet_path=aide_lite.LATEST_PACKET_PATH)
        result = aide_lite.write_verification_report(root, ".aide/verification/test-report.md", report)
        self.assertIn(result.action, {"written", "unchanged"})
        with self.assertRaises(ValueError):
            aide_lite.write_verification_report(root, "../outside.md", report)

    def test_selftest_includes_verifier_checks(self) -> None:
        ok, messages = aide_lite.run_selftest()
        self.assertTrue(ok)
        self.assertTrue(any("verifier" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
