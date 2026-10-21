from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
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


class OutcomeControllerTests(unittest.TestCase):
    def ledger_repo(self, rows: list[str]) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        path = root / aide_lite.OUTCOME_LEDGER_PATH
        path.parent.mkdir(parents=True)
        path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        return root

    def outcome_data(self, **changes: object) -> dict[str, object]:
        return {"run_id": "recorded-attempt", "phase": "repair", "source": "checks",
                "result": "FAIL", "notes": "retained diagnostic", **changes}

    def make_repo(self, prepared: bool = True) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        if prepared:
            aide_lite.run_context(root)
            aide_lite.write_task_packet(root, "Implement Q17 Router Profile v0")
            aide_lite.adapt_agents(root)
            verification = aide_lite.build_verification_report(root, task_packet_path=aide_lite.LATEST_PACKET_PATH)
            aide_lite.write_verification_report(root, aide_lite.LATEST_VERIFICATION_REPORT_PATH, verification)
            aide_lite.write_review_packet(root)
            aide_lite.write_golden_run_reports(root, aide_lite.run_golden_tasks(root, task_ids=aide_lite.SELFTEST_GOLDEN_TASK_IDS))
            records = aide_lite.build_ledger_scan_records(root)
            aide_lite.write_ledger_records(root, records)
            aide_lite.write_token_savings_summary(root, records, [])
        return root

    def test_controller_policy_and_failure_taxonomy_are_loadable(self) -> None:
        root = self.make_repo()
        policy_text = aide_lite.read_text(root / aide_lite.CONTROLLER_POLICY_PATH)
        for anchor in aide_lite.CONTROLLER_POLICY_ANCHORS:
            self.assertIn(anchor, policy_text)
        taxonomy = aide_lite.parse_failure_taxonomy(root)
        self.assertEqual(set(aide_lite.CONTROLLER_FAILURE_CLASSES), set(taxonomy))

    def test_outcome_record_write_read_and_raw_prompt_rejection(self) -> None:
        root = self.make_repo()
        record = aide_lite.make_outcome_record(
            root,
            "Q16",
            "validation",
            "PASS",
            failure_class="unknown",
            severity="info",
            related_paths=["README.md"],
            notes="metadata only",
            run_id="test.record",
        )
        aide_lite.write_outcome_records(root, [record])
        loaded = aide_lite.read_outcome_records(root)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].source, "validation")
        ledger_text = aide_lite.read_text(root / aide_lite.OUTCOME_LEDGER_PATH)
        self.assertNotIn("raw_prompt_body", ledger_text)
        with self.assertRaisesRegex(ValueError, "raw prompt"):
            aide_lite.make_outcome_record(
                root,
                "Q16",
                "bad",
                "WARN",
                failure_class="unknown",
                severity="warning",
                notes="raw prompt: do not store this",
            )

    def test_outcome_add_command_writes_metadata_record(self) -> None:
        root = self.make_repo()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(
                [
                    "--repo-root",
                    str(root),
                    "outcome",
                    "add",
                    "--phase",
                    "Q16",
                    "--source",
                    "validation",
                    "--result",
                    "PASS",
                    "--failure-class",
                    "unknown",
                    "--severity",
                    "info",
                    "--related-path",
                    "README.md",
                    "--notes",
                    "smoke metadata",
                ]
            )
        self.assertEqual(code, 0)
        self.assertIn("raw_content_stored: false", buffer.getvalue())
        self.assertTrue(aide_lite.read_outcome_records(root))

    def test_token_report_reader_detects_over_budget_sample(self) -> None:
        root = self.make_repo()
        record = aide_lite.LedgerRecord(
            "q14.scan.current",
            "Q16",
            "task_packet",
            aide_lite.LATEST_PACKET_PATH,
            40000,
            10,
            10000,
            "chars/4",
            "3200",
            "over_budget",
            "oversized fixture",
        )
        aide_lite.write_ledger_records(root, [record])
        signal = aide_lite.read_token_signal(root)
        self.assertEqual(signal["result"], "FAIL")
        self.assertEqual(signal["failure_class"], "token_budget_exceeded")

    def test_signal_readers_detect_bad_samples(self) -> None:
        root = self.make_repo()
        aide_lite.write_text(
            root / aide_lite.GOLDEN_RUN_JSON_PATH,
            json.dumps({"result": "FAIL", "task_count": 1, "pass_count": 0, "warn_count": 0, "fail_count": 1, "tasks": [{"task_id": "bad", "result": "FAIL"}]}),
        )
        self.assertEqual(aide_lite.read_golden_signal(root)["failure_class"], "golden_task_fail")
        aide_lite.write_text(
            root / aide_lite.LATEST_VERIFICATION_REPORT_PATH,
            "# Verification\n\n## VERIFIER_RESULT\n\n- result: FAIL\n- warnings: 1\n- errors: 1\n",
        )
        verifier = aide_lite.read_verifier_signal(root)
        self.assertEqual(verifier["result"], "FAIL")
        self.assertEqual(verifier["failure_class"], "verifier_fail")
        aide_lite.write_text(root / aide_lite.REVIEW_PACKET_PATH, "# Broken Review Packet\n")
        self.assertEqual(aide_lite.read_review_packet_signal(root)["failure_class"], "review_packet_incomplete")

    def test_context_artifact_reader_detects_missing_artifact(self) -> None:
        root = self.make_repo(prepared=False)
        signal = aide_lite.read_context_signal(root)
        self.assertEqual(signal["result"], "WARN")
        self.assertEqual(signal["failure_class"], "context_missing")

    def test_optimize_suggest_recommends_for_golden_fail_and_packet_size(self) -> None:
        root = self.make_repo()
        records = [
            aide_lite.make_outcome_record(root, "Q16", "golden", "FAIL", "golden_task_fail", "error", ["README.md"]),
            aide_lite.make_outcome_record(root, "Q16", "tokens", "WARN", "packet_too_large", "warning", ["README.md"]),
        ]
        recommendations = aide_lite.build_recommendations(root, records)
        ids = {item.recommendation_id for item in recommendations}
        self.assertIn("REC-GOLDEN-TASKS", ids)
        self.assertIn("REC-PACKET-BUDGET", ids)
        self.assertTrue(all(item.expected_benefit and item.rollback_condition for item in recommendations))
        self.assertTrue(all(not item.applies_automatically for item in recommendations))

    def test_optimize_suggest_proceeds_to_next_queue_phase_when_all_fixture_signals_pass(self) -> None:
        root = self.make_repo()
        records = [
            aide_lite.make_outcome_record(root, "Q16", "token", "PASS", "unknown", "info", ["README.md"]),
            aide_lite.make_outcome_record(root, "Q16", "golden", "PASS", "unknown", "info", ["README.md"]),
            aide_lite.make_outcome_record(root, "Q16", "verifier", "PASS", "unknown", "info", ["README.md"]),
        ]
        recommendations = aide_lite.build_recommendations(root, records)
        self.assertEqual([item.recommendation_id for item in recommendations], ["REC-PROCEED-Q18-WITH-GATES"])
        self.assertIn("Q18 Cache and Local State Boundary", recommendations[0].next_action)

    def test_optimize_command_writes_only_controller_outputs(self) -> None:
        root = self.make_repo()
        prompt_path = root / ".aide/prompts/compact-task.md"
        policy_path = root / aide_lite.CONTROLLER_POLICY_PATH
        before_prompt = aide_lite.read_text(prompt_path)
        before_policy = aide_lite.read_text(policy_path)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "optimize", "suggest"])
        self.assertEqual(code, 0)
        self.assertIn("applies_automatically: false", buffer.getvalue())
        self.assertEqual(before_prompt, aide_lite.read_text(prompt_path))
        self.assertEqual(before_policy, aide_lite.read_text(policy_path))
        self.assertTrue((root / aide_lite.RECOMMENDATIONS_PATH).exists())

    def test_outcome_report_command_and_selftest_include_controller(self) -> None:
        root = self.make_repo()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["--repo-root", str(root), "outcome", "report"])
        self.assertEqual(code, 0)
        self.assertIn("advisory_only: true", buffer.getvalue())
        self.assertTrue((root / aide_lite.OUTCOME_REPORT_PATH).exists())
        ok, messages = aide_lite.run_selftest()
        self.assertTrue(ok)
        self.assertTrue(any("outcome" in message and "optimize" in message for message in messages))

    def test_unfamiliar_metadata_roundtrips_with_legacy_defaults(self) -> None:
        metadata = {"subject": "revision-A", "lesson": {"ref": "local-test", "retired": False},
                    "values": [None, 2, 1.5, "explanation"]}
        root = self.ledger_repo([json.dumps(self.outcome_data(project_provenance=metadata))])
        records = aide_lite.read_outcome_records(root)
        self.assertEqual(records[0].severity, "warning")
        self.assertIsNone(records[0].approx_tokens)
        self.assertEqual(records[0].related_paths, ())
        aide_lite.write_outcome_records(root, records)
        path = root / aide_lite.OUTCOME_LEDGER_PATH
        actual = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(actual["project_provenance"], metadata)
        self.assertEqual(actual["result"], "FAIL")
        before = path.read_bytes()
        self.assertEqual(aide_lite.write_outcome_records(root, aide_lite.read_outcome_records(root)).action, "unchanged")
        self.assertEqual(path.read_bytes(), before)

    def test_unrelated_and_selected_metadata_survive_add(self) -> None:
        selected = self.outcome_data(project_provenance={"subject": "A"})
        unrelated = self.outcome_data(run_id="earlier-attempt", project_provenance={"subject": "B"})
        root = self.ledger_repo([json.dumps(selected), json.dumps(unrelated)])
        with contextlib.redirect_stdout(io.StringIO()):
            code = aide_lite.main(["--repo-root", str(root), "outcome", "add", "--run-id",
                                   "recorded-attempt", "--phase", "repair", "--source", "checks",
                                   "--result", "PASS", "--failure-class", "unknown", "--severity", "info",
                                   "--notes", "resolved same observation"])
        self.assertEqual(code, 0)
        rows = {x.run_id: aide_lite.outcome_record_to_dict(x) for x in aide_lite.read_outcome_records(root)}
        self.assertEqual(rows["recorded-attempt"]["result"], "PASS")
        self.assertEqual(rows["recorded-attempt"]["project_provenance"], {"subject": "A"})
        self.assertEqual(rows["earlier-attempt"]["result"], "FAIL")
        self.assertEqual(rows["earlier-attempt"]["project_provenance"], {"subject": "B"})

    def test_current_run_regeneration_preserves_matching_metadata(self) -> None:
        current = self.outcome_data(run_id="q16.current", project_note={"ref": "project-owned"})
        historical = self.outcome_data(run_id="original-failure", project_note={"ref": "history"})
        root = self.ledger_repo([json.dumps(current), json.dumps(historical)])
        replacement = aide_lite.outcome_record_from_dict(self.outcome_data(run_id="q16.current", result="PASS"))
        aide_lite.merge_outcome_records(root, [replacement])
        rows = {r.run_id: aide_lite.outcome_record_to_dict(r) for r in aide_lite.read_outcome_records(root)}
        self.assertEqual(rows["q16.current"]["project_note"], current["project_note"])
        self.assertEqual(rows["q16.current"]["result"], "PASS")
        self.assertEqual(rows["original-failure"]["project_note"], historical["project_note"])
        self.assertEqual(rows["original-failure"]["result"], "FAIL")

    def test_malformed_and_ambiguous_json_refuse_with_line_location(self) -> None:
        valid = json.dumps(self.outcome_data())
        bad_rows = ["{", "[]", "null", "{}", valid[:-1] + ',"result":"PASS"}',
                    valid[:-1] + ',"custom":{"x":1,"x":2}}',
                    valid[:-1] + ',"custom":NaN}', valid[:-1] + ',"custom":1e400}',
                    '[' * 2000 + '0' + ']' * 2000]
        for bad in bad_rows:
            with self.subTest(bad=bad):
                root = self.ledger_repo([valid, bad])
                path = root / aide_lite.OUTCOME_LEDGER_PATH
                before = path.read_bytes()
                with self.assertRaisesRegex(ValueError, r"outcome-ledger\.jsonl:2"):
                    aide_lite.read_outcome_records(root)
                self.assertEqual(path.read_bytes(), before)

    def test_invalid_known_types_are_not_coerced(self) -> None:
        invalid = [{"result": 1}, {"result": "SUCCESS"}, {"notes": []}, {"phase": None},
                   {"related_paths": "README.md"}, {"related_paths": [1]},
                   {"approx_tokens": True}, {"approx_tokens": -1}, {"approx_tokens": 2.5},
                   {"severity": "urgent"}, {"run_id": ""}]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                aide_lite.outcome_record_from_dict(self.outcome_data(**changes))

    def test_all_update_commands_preserve_corrupt_ledger_and_reports(self) -> None:
        root = self.make_repo()
        paths = [root / p for p in [aide_lite.OUTCOME_LEDGER_PATH,
                                   aide_lite.OUTCOME_REPORT_PATH, aide_lite.RECOMMENDATIONS_PATH]]
        paths[0].write_text(json.dumps(self.outcome_data()) + '\n{"private-marker":\n', encoding="utf-8")
        for path in paths[1:]:
            path.write_text("previous accepted report\n", encoding="utf-8")
        before = {path: path.read_bytes() for path in paths}
        commands = [["outcome", "add", "--phase", "repair", "--source", "checks", "--result", "PASS",
                     "--failure-class", "unknown", "--severity", "info"],
                    ["outcome", "report"], ["optimize", "suggest"]]
        for args in commands:
            with self.subTest(args=args):
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = aide_lite.main(["--repo-root", str(root), *args])
                self.assertEqual(code, 1, stdout.getvalue() + stderr.getvalue())
                self.assertIn("outcome-ledger.jsonl:2", stderr.getvalue())
                self.assertNotIn("private-marker", stdout.getvalue() + stderr.getvalue())
                self.assertEqual({path: path.read_bytes() for path in paths}, before)

    def test_orphaned_or_ambiguous_metadata_stops_regeneration(self) -> None:
        data = self.outcome_data(run_id="q16.current", project_note={"keep": True})
        for rows, replacements in [([data], []), ([data, data], [self.outcome_data(run_id="q16.current")]),
                                   ([data], [self.outcome_data(run_id="q16.current"), self.outcome_data(run_id="q16.current")])]:
            with self.subTest(rows=len(rows), replacements=len(replacements)):
                root = self.ledger_repo([json.dumps(row) for row in rows])
                path = root / aide_lite.OUTCOME_LEDGER_PATH
                before = path.read_bytes()
                with self.assertRaisesRegex(ValueError, "unfamiliar metadata"):
                    aide_lite.merge_outcome_records(root, [aide_lite.outcome_record_from_dict(x) for x in replacements])
                self.assertEqual(path.read_bytes(), before)

    def test_conflicting_metadata_refuses_without_boolean_number_conflation(self) -> None:
        old = aide_lite.outcome_record_from_dict(self.outcome_data(project_flag=True))
        new = aide_lite.outcome_record_from_dict(self.outcome_data(project_flag=1))
        with self.assertRaisesRegex(ValueError, "conflicts with unfamiliar metadata"):
            aide_lite.preserve_outcome_metadata([old], [new])

    def test_failed_atomic_replacement_preserves_original_and_cleans_temporary(self) -> None:
        root = self.ledger_repo([json.dumps(self.outcome_data(project_note="preserve"))])
        path = root / aide_lite.OUTCOME_LEDGER_PATH
        before = path.read_bytes()
        replacement = aide_lite.outcome_record_from_dict(self.outcome_data(result="PASS"))
        with mock.patch.object(aide_lite.os, "replace", side_effect=OSError("fixture replace failure")):
            with self.assertRaisesRegex(OSError, "fixture replace failure"):
                aide_lite.merge_outcome_records(root, [replacement], run_id="recorded-attempt")
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(list(path.parent.glob("*.tmp")), [])

    def test_actual_cli_preserves_metadata_and_refuses_corrupt_input(self) -> None:
        root = self.ledger_repo([json.dumps(self.outcome_data(project_note={"keep": "value"}))])
        command = [sys.executable, "-B", str(MODULE_PATH), "--repo-root", str(root), "outcome", "add",
                   "--run-id", "recorded-attempt", "--phase", "repair", "--source", "checks", "--result", "PASS",
                   "--failure-class", "unknown", "--severity", "info"]
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        path = root / aide_lite.OUTCOME_LEDGER_PATH
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["project_note"], {"keep": "value"})
        before = path.read_bytes()
        invalid_command = list(command)
        invalid_command[invalid_command.index("--phase") + 1] = ""
        invalid = subprocess.run(invalid_command, capture_output=True, text=True, encoding="utf-8", timeout=20)
        self.assertEqual(invalid.returncode, 1)
        self.assertEqual(path.read_bytes(), before)
        path.write_bytes(path.read_bytes() + b'{"private-marker":\n')
        before = path.read_bytes()
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=20)
        self.assertEqual(result.returncode, 1)
        self.assertIn("outcome-ledger.jsonl:2", result.stderr)
        self.assertNotIn("private-marker", result.stdout + result.stderr)
        self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
