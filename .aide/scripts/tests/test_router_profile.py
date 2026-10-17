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


class RouterProfileTests(unittest.TestCase):
    def make_repo(self, prepared: bool = True) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        if prepared:
            aide_lite.run_context(root)
            aide_lite.write_task_packet(root, "Estimate tokens for README.md")
            aide_lite.adapt_agents(root)
            verification = aide_lite.build_verification_report(root, task_packet_path=aide_lite.LATEST_PACKET_PATH)
            aide_lite.write_verification_report(root, aide_lite.LATEST_VERIFICATION_REPORT_PATH, verification)
            aide_lite.write_review_packet(root)
            aide_lite.write_golden_run_reports(root, aide_lite.run_golden_tasks(root, task_ids=aide_lite.SELFTEST_GOLDEN_TASK_IDS))
            records = aide_lite.build_ledger_scan_records(root)
            aide_lite.write_ledger_records(root, records)
            aide_lite.write_token_savings_summary(root, records, [])
        return root

    def test_routing_policy_and_model_registry_anchors(self) -> None:
        root = self.make_repo()
        policy_text = aide_lite.read_text(root / aide_lite.ROUTING_POLICY_PATH)
        for anchor in aide_lite.ROUTING_POLICY_ANCHORS:
            self.assertIn(anchor, policy_text)
        provider_text = aide_lite.read_text(root / aide_lite.PROVIDERS_PATH)
        self.assertIn("live_calls_allowed_in_q17: false", provider_text)
        self.assertNotIn("live_calls_allowed_in_q17: true", provider_text)
        self.assertFalse(any(pattern.search(provider_text) for pattern in aide_lite.SECRET_PATTERNS))

    def test_route_classes_profiles_hard_floors_and_list_output(self) -> None:
        root = self.make_repo()
        profiles = aide_lite.parse_route_profiles(root)
        self.assertEqual({profile.task_class for profile in profiles}, set(aide_lite.TASK_CLASSES))
        self.assertEqual(aide_lite.route_profile_for_task(root, "deterministic_format_or_count").preferred_route_class, "no_model_tool")
        hard_floors = aide_lite.parse_hard_floor_minimums(root)
        self.assertIn("architecture_decision", hard_floors)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "route", "list"])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("route_classes:", output)
        self.assertIn("deterministic_format_or_count", output)
        self.assertIn("provider_or_model_calls: none", output)

    def test_deterministic_estimate_routes_to_no_model_tool(self) -> None:
        root = self.make_repo()
        aide_lite.write_task_packet(root, "Estimate tokens for README.md")
        decision = aide_lite.build_route_decision(root)
        self.assertEqual(decision.task_class, "deterministic_format_or_count")
        self.assertEqual(decision.route_class, "no_model_tool")
        self.assertEqual(decision.risk_class, "low")

    def test_hard_floor_tasks_route_to_frontier_or_human(self) -> None:
        root = self.make_repo()
        cases = [
            ("Decide architecture boundary for a new runtime service", "architecture_decision"),
            ("Perform security review for credential handling", "security_review"),
            ("Automatically rewrite routing policy from controller suggestions", "self_modification"),
        ]
        for text, expected_floor in cases:
            with self.subTest(text=text):
                aide_lite.write_task_packet(root, text)
                decision = aide_lite.build_route_decision(root)
                self.assertEqual(decision.hard_floor_applied, expected_floor)
                self.assertIn(decision.route_class, {"frontier", "human_review"})

    def test_unknown_task_routes_conservatively(self) -> None:
        root = self.make_repo()
        aide_lite.write_task_packet(root, "Triangulate a vague future capability with unclear acceptance")
        decision = aide_lite.build_route_decision(root)
        self.assertEqual(decision.task_class, "unknown")
        self.assertEqual(decision.route_class, "frontier")
        self.assertEqual(decision.fallback_route_class, "human_review")

    def test_failed_golden_tasks_block_token_optimization(self) -> None:
        root = self.make_repo()
        aide_lite.write_task_packet(root, "Optimize token packet size for a future phase")
        aide_lite.write_text(
            root / aide_lite.GOLDEN_RUN_JSON_PATH,
            json.dumps({"result": "FAIL", "task_count": 1, "pass_count": 0, "warn_count": 0, "fail_count": 1, "tasks": [{"task_id": "bad", "result": "FAIL"}]}),
        )
        decision = aide_lite.build_route_decision(root)
        self.assertTrue(decision.blocked)
        self.assertEqual(decision.route_class, "blocked")
        self.assertIn("golden tasks failed", decision.blocked_reason)

    def test_failed_verifier_blocks_non_repair_work(self) -> None:
        root = self.make_repo()
        aide_lite.write_task_packet(root, "Implement bounded code patch with compact evidence")
        aide_lite.write_text(
            root / aide_lite.LATEST_VERIFICATION_REPORT_PATH,
            "# Verification\n\n## VERIFIER_RESULT\n\n- result: FAIL\n- warnings: 0\n- errors: 1\n",
        )
        decision = aide_lite.build_route_decision(root)
        self.assertTrue(decision.blocked)
        self.assertEqual(decision.route_class, "blocked")
        self.assertIn("verifier failed", decision.blocked_reason)

    def test_missing_context_artifacts_warn_without_fabricating_pass(self) -> None:
        root = self.make_repo(prepared=False)
        aide_lite.write_task_packet(root, "Update README documentation for a bounded workflow")
        decision = aide_lite.build_route_decision(root)
        self.assertIn("snapshot_index_context", decision.required_checks)
        self.assertIn(decision.quality_gate_status, {"WARN", "FAIL"})

    def test_route_decision_artifacts_and_validate_shape(self) -> None:
        root = self.make_repo()
        decision = aide_lite.build_route_decision(root)
        json_result, md_result = aide_lite.write_route_decision(root, decision)
        self.assertIn(json_result.action, {"written", "unchanged"})
        self.assertIn(md_result.action, {"written", "unchanged"})
        data = json.loads(aide_lite.read_text(root / aide_lite.ROUTE_DECISION_JSON_PATH))
        for field in aide_lite.ROUTE_DECISION_REQUIRED_FIELDS:
            self.assertIn(field, data)
        self.assertFalse(data["live_calls_allowed_in_q17"])
        self.assertFalse(data["contents_inline"])
        markdown = aide_lite.read_text(root / aide_lite.ROUTE_DECISION_MD_PATH)
        for section in ["ROUTE_DECISION", "QUALITY_GATES", "RATIONALE", "SAFETY"]:
            self.assertIn(f"## {section}", markdown)
        self.assertNotIn("raw_prompt_body", markdown)
        self.assertFalse(any(check.severity == "FAIL" for check in aide_lite.routing_validation_checks(root)))

    def test_route_explain_command_makes_no_live_calls(self) -> None:
        root = self.make_repo()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "route", "explain"])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("advisory_only: true", output)
        self.assertIn("provider_or_model_calls: none", output)
        self.assertIn("network_calls: none", output)

    def test_selftest_includes_router_checks(self) -> None:
        ok, messages = aide_lite.run_selftest()
        self.assertTrue(ok)
        self.assertTrue(any("route" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
