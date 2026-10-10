from __future__ import annotations

import contextlib
import importlib.util
import io
import json
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


class GatewayCommandTests(unittest.TestCase):
    def make_repo(self, prepared: bool = True) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        if prepared:
            aide_lite.run_context(root)
            aide_lite.write_task_packet(root, "Implement Q19 Gateway Architecture and Skeleton")
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
            aide_lite.write_cache_report(root)
        return root

    def test_gateway_policy_anchors(self) -> None:
        root = self.make_repo(prepared=False)
        policy = aide_lite.read_text(root / aide_lite.GATEWAY_POLICY_PATH)
        for anchor in aide_lite.GATEWAY_POLICY_ANCHORS:
            self.assertIn(anchor, policy)
        self.assertFalse(any(pattern.search(policy) for pattern in aide_lite.SECRET_PATTERNS))

    def test_gateway_status_command_writes_reports(self) -> None:
        root = self.make_repo()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "gateway", "status"])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("AIDE Lite gateway status", output)
        self.assertIn("provider_or_model_calls: none", output)
        self.assertIn("network_calls: none", output)
        data = json.loads(aide_lite.read_text(root / aide_lite.GATEWAY_STATUS_JSON_PATH))
        self.assertFalse(data["provider_calls_enabled"])
        self.assertFalse(data["model_calls_enabled"])
        self.assertFalse(data["outbound_network_enabled"])
        self.assertIn("readiness", data)

    def test_gateway_endpoints_and_smoke_commands(self) -> None:
        root = self.make_repo()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "gateway", "endpoints"])
        self.assertEqual(code, 0)
        endpoints = buffer.getvalue()
        self.assertIn("GET /health", endpoints)
        self.assertIn("/v1/chat/completions", endpoints)
        self.assertIn("provider_or_model_calls: none", endpoints)

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "gateway", "smoke"])
        self.assertEqual(code, 0)
        smoke = buffer.getvalue()
        self.assertIn("result: PASS", smoke)
        self.assertIn("/route/explain: 200 ok", smoke)
        self.assertNotIn("raw_prompt_body", smoke)

    def test_gateway_validation_checks_detect_missing_status(self) -> None:
        root = self.make_repo(prepared=False)
        (root / aide_lite.GATEWAY_STATUS_JSON_PATH).unlink()
        checks = aide_lite.gateway_validation_checks(root)
        self.assertTrue(any(check.severity == "FAIL" and aide_lite.GATEWAY_STATUS_JSON_PATH in check.message for check in checks))

    def test_gateway_validation_passes_after_status(self) -> None:
        root = self.make_repo()
        aide_lite.import_gateway_status_module(root).write_gateway_status_files(root)
        failures = [check for check in aide_lite.gateway_validation_checks(root) if check.severity == "FAIL"]
        self.assertEqual(failures, [])

    def test_selftest_includes_gateway_checks(self) -> None:
        ok, messages = aide_lite.run_selftest()
        self.assertTrue(ok)
        self.assertTrue(any("gateway" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
