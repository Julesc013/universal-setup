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


class ProviderAdapterCommandTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        aide_lite.import_provider_status_module(root).write_provider_status_files(root)
        return root

    def test_provider_policy_anchors(self) -> None:
        root = self.make_repo()
        policy = aide_lite.read_text(root / aide_lite.PROVIDER_ADAPTER_POLICY_PATH)
        for anchor in aide_lite.PROVIDER_ADAPTER_POLICY_ANCHORS:
            self.assertIn(anchor, policy)
        self.assertNotIn("live_calls_allowed_in_q20: true", policy)

    def test_provider_list_output_shape(self) -> None:
        root = self.make_repo()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "provider", "list"])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("AIDE Lite provider list", output)
        self.assertIn("deterministic_tools", output)
        self.assertIn("human", output)
        self.assertIn("provider_or_model_calls: none", output)

    def test_provider_status_writes_latest_artifacts(self) -> None:
        root = self.make_repo()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "provider", "status"])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("AIDE Lite provider status", output)
        self.assertIn("live_provider_calls: false", output)
        data = json.loads(aide_lite.read_text(root / aide_lite.PROVIDER_STATUS_JSON_PATH))
        self.assertFalse(data["live_provider_calls"])
        self.assertFalse(data["live_model_calls"])
        self.assertFalse(data["network_calls"])
        self.assertFalse(data["credentials_configured"])

    def test_provider_validate_passes_and_detects_invalid_fixture(self) -> None:
        root = self.make_repo()
        checks = aide_lite.provider_validation_checks(root)
        self.assertFalse([check for check in checks if check.severity == "FAIL"])
        text = aide_lite.read_text(root / aide_lite.PROVIDER_CATALOG_PATH)
        aide_lite.write_text(root / aide_lite.PROVIDER_CATALOG_PATH, text.replace("live_calls_allowed_in_q20: false", "live_calls_allowed_in_q20: true", 1))
        checks = aide_lite.provider_validation_checks(root)
        self.assertTrue(any(check.severity == "FAIL" and "live calls" in check.message.lower() for check in checks))

    def test_provider_contract_and_probe_offline(self) -> None:
        root = self.make_repo()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "provider", "contract"])
        self.assertEqual(code, 0)
        contract = buffer.getvalue()
        self.assertIn("required_fields:", contract)
        self.assertIn("provider_probe_calls_allowed_in_q20: false", contract)

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "provider", "probe", "--offline"])
        self.assertEqual(code, 0)
        probe = buffer.getvalue()
        self.assertIn("mode: offline", probe)
        self.assertIn("live_provider_calls: false", probe)
        self.assertIn("network_calls: none", probe)

    def test_provider_probe_requires_offline_flag(self) -> None:
        root = self.make_repo()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "provider", "probe"])
        self.assertEqual(code, 1)
        self.assertIn("offline_required: true", buffer.getvalue())

    def test_gateway_status_includes_provider_metadata_signal(self) -> None:
        root = self.make_repo()
        aide_lite.main(["--repo-root", str(root), "gateway", "status"])
        data = json.loads(aide_lite.read_text(root / aide_lite.GATEWAY_STATUS_JSON_PATH))
        self.assertIn("provider_adapters", data["signals"])
        self.assertTrue(data["signals"]["provider_adapters"]["present"])

    def test_route_decision_notes_provider_candidates_metadata_only(self) -> None:
        root = self.make_repo()
        aide_lite.write_task_packet(root, "Estimate tokens for README.md")
        decision = aide_lite.build_route_decision(root)
        self.assertTrue(any("provider_candidates_metadata_only" in note for note in decision.notes))
        data = aide_lite.route_decision_to_dict(decision)
        self.assertFalse(data["live_calls_allowed_in_q20"])
        self.assertTrue(data["provider_metadata_only"])

    def test_selftest_includes_provider_checks(self) -> None:
        ok, messages = aide_lite.run_selftest()
        self.assertTrue(ok)
        self.assertTrue(any("provider" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
