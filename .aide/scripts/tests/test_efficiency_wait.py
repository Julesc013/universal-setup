"""Tiny portable observer tests; no model, process launch or bulk fixture."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock


REPO = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("aide_lite_efficiency_test", REPO / ".aide/scripts/aide_lite.py")
lite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lite
SPEC.loader.exec_module(lite)
JOB_ID = "a" * 32
SOURCE_COMMIT = "b" * 40
SOURCE_TREE = "c" * 40


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


class EfficiencyWaitTests(unittest.TestCase):
    def setUp(self):
        parent = Path(os.environ["AIDE_JOB_TMP"])
        self.temp = tempfile.TemporaryDirectory(prefix="efficiency-wait-", dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.control = self.root / "control"
        self.retained = self.root / "retained"
        self.control.mkdir()
        self.retained.mkdir()
        self.config = self.root / "execution.json"
        write(self.config, {"schema": "aide.managed-workspace.local.v1",
                            "roots": {"control": str(self.control), "retained": str(self.retained)}})
        self.job = {"source_commit": SOURCE_COMMIT, "source_tree": SOURCE_TREE}
        self.manifest = digest(self.job)

    def receipt(self, *, phase="retired", exit_code=0, reason="exited", owner=True):
        target = self.retained / JOB_ID
        target.mkdir(exist_ok=True)
        if owner:
            write(target / "owner.json", {"job_id": JOB_ID, "manifest_digest": self.manifest})
        write(target / "receipt.json", {"job_id": JOB_ID, "manifest_digest": self.manifest,
             "job": self.job, "phase": phase, "scratch_absent": True,
             "reservation_released": True, "result": {"job_id": JOB_ID, "reason": reason,
             "exit_code": exit_code, "quiescent": True},
             "collected_manifest": {"output": "d" * 64, "logs": "e" * 64},
             "peaks": {"scratch_bytes": 123, "memory_bytes": 456}, "raw_log": "x" * 3000})

    def wait(self, timeout=0, clock=lambda: 0, sleeper=lambda _: None):
        return lite.wait_for_managed_job(self.config, JOB_ID, self.manifest,
                                          timeout, 1, clock=clock, sleeper=sleeper)

    def test_terminal_is_bounded_repeatable_and_read_only(self):
        self.receipt()
        before = (self.retained / JOB_ID / "receipt.json").read_bytes()
        first, second = self.wait(), self.wait()
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "PASS")
        self.assertEqual(first["model_requests_started_by_observer"], 0)
        self.assertEqual(first["host_model_requests"], "unknown")
        self.assertEqual(first["invocation_control"], "observer_only")
        self.assertEqual(first["peak_scratch_bytes"], 123)
        self.assertEqual(first["evidence_status"], "receipt_present_outputs_unverified")
        self.assertLess(len(json.dumps(first)), 1400)
        self.assertEqual((self.retained / JOB_ID / "receipt.json").read_bytes(), before)

    def test_unchanged_wait_emits_only_terminal_view(self):
        write(self.control / "active.json", {"job_id": JOB_ID, "manifest_digest": self.manifest,
                                                  "job": self.job, "phase": "running"})
        tick = [0]
        def advance(seconds):
            tick[0] += seconds
            if tick[0] == 3:
                self.receipt()
                (self.control / "active.json").unlink()
        result = self.wait(timeout=5, clock=lambda: tick[0], sleeper=advance)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["observations"], 4)
        self.assertEqual(result["unchanged_observations"], 2)

    def test_timeout_is_pending_and_does_not_remove_active(self):
        write(self.control / "active.json", {"job_id": JOB_ID, "manifest_digest": self.manifest,
                                                  "job": self.job, "phase": "running"})
        result = self.wait()
        self.assertEqual(result["status"], "PENDING")
        self.assertFalse(result["terminal"])
        self.assertTrue((self.control / "active.json").exists())

    def test_missing_mismatch_and_nonterminal_receipt_cannot_pass(self):
        self.assertEqual(self.wait()["status"], "MISSING")
        write(self.control / "active.json", {"job_id": "d" * 32,
                                                  "manifest_digest": self.manifest, "phase": "running"})
        self.assertEqual(self.wait()["status"], "OTHER_ATTEMPT")
        (self.control / "active.json").unlink()
        self.receipt(phase="collected")
        self.assertEqual(self.wait()["status"], "ACTION_REQUIRED")
        self.receipt()
        write(self.retained / JOB_ID / "owner.json", {"job_id": JOB_ID, "manifest_digest": "0" * 64})
        self.assertEqual(self.wait()["status"], "EVIDENCE_UNAVAILABLE")

    def test_failure_oversize_and_redirected_root_cannot_pass(self):
        self.receipt(exit_code=1)
        self.assertEqual(self.wait()["status"], "FAIL")
        bad = json.loads((self.retained / JOB_ID / "receipt.json").read_text(encoding="utf-8"))
        bad.pop("collected_manifest")
        write(self.retained / JOB_ID / "receipt.json", bad)
        self.assertEqual(self.wait()["status"], "EVIDENCE_UNAVAILABLE")
        (self.retained / JOB_ID / "receipt.json").write_bytes(b"x" * (1024 * 1024 + 1))
        self.assertEqual(self.wait()["status"], "EVIDENCE_UNAVAILABLE")
        write(self.config, {"schema": "aide.managed-workspace.local.v1",
                            "roots": {"control": str(self.control),
                                      "retained": str(self.retained / ".." / "retained")}})
        with self.assertRaisesRegex(ValueError, "absolute child"):
            self.wait()

    def test_duplicate_receipt_key_cannot_hide_ambiguous_terminal(self):
        self.receipt()
        path = self.retained / JOB_ID / "receipt.json"
        path.write_text('{"phase":"collected",' + path.read_text(encoding="utf-8")[1:],
                        encoding="utf-8")
        self.assertEqual(self.wait()["status"], "EVIDENCE_UNAVAILABLE")

    def test_nonfinite_receipt_number_cannot_pass(self):
        self.receipt()
        path = self.retained / JOB_ID / "receipt.json"
        raw = path.read_text(encoding="utf-8")
        self.assertIn('"scratch_bytes": 123', raw)
        path.write_text(raw.replace('"scratch_bytes": 123', '"scratch_bytes": NaN'),
                        encoding="utf-8")
        self.assertEqual(self.wait()["status"], "EVIDENCE_UNAVAILABLE")

    def test_parser_recursion_is_bounded_evidence_failure(self):
        self.receipt()
        original = json.loads

        def deep_receipt(data, *args, **kwargs):
            if b'"phase"' in data:
                raise RecursionError("injected parser depth")
            return original(data, *args, **kwargs)

        with mock.patch.object(lite.json, "loads", side_effect=deep_receipt):
            self.assertEqual(self.wait()["status"], "EVIDENCE_UNAVAILABLE")

    def test_portable_cli_without_source_checkout(self):
        self.receipt()
        consumer = self.root / "consumer" / ".aide" / "scripts"
        consumer.mkdir(parents=True)
        script = consumer / "aide_lite.py"
        script.write_bytes((REPO / ".aide/scripts/aide_lite.py").read_bytes())
        command = [sys.executable, "-I", "-B", str(script), "--repo-root", str(self.root / "consumer"),
                   "job", "wait", "--config", str(self.config), "--job-id", JOB_ID,
                   "--manifest-digest", self.manifest, "--timeout-seconds", "0"]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stderr[-500:])
        self.assertEqual(json.loads(completed.stdout)["status"], "PASS")
        self.assertFalse((self.root / "consumer" / "core").exists())

    def codex_stream(self, name, *, session=None, usage=None, failed=False, repeat=False):
        session = session or str(uuid.UUID(int=1))
        events = [{"type": "thread.started", "thread_id": session}, {"type": "turn.started"}]
        if usage is not None:
            terminal = {"type": "turn.completed", "usage": usage}
            events.append(terminal)
            if repeat:
                events.append(terminal)
        if failed:
            events.append({"type": "turn.failed"})
        path = self.root / name
        path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
        return path

    def attempt_roster(self, name, attempts):
        path = self.root / name
        write(path, {"schema": "aide.codex-exec-attempt-roster.v1",
                     "work_id": "work-1", "attempts": attempts})
        return path

    def attributed_attempt(self, attempt_id, role, parent, stream):
        return {"attempt_id": attempt_id, "role": role,
                "parent_attempt_id": parent,
                "stream": stream.name if stream else None,
                "stream_sha256": hashlib.sha256(stream.read_bytes()).hexdigest() if stream else None}

    def test_codex_attempt_roster_attributes_parent_child_review_retry(self):
        usage = lambda count: {"input_tokens": count, "cached_input_tokens": 0,
                               "output_tokens": 2, "reasoning_output_tokens": 1}
        parent = self.codex_stream("parent.jsonl", session=str(uuid.UUID(int=1)), usage=usage(10))
        child = self.codex_stream("child.jsonl", session=str(uuid.UUID(int=2)), usage=usage(6))
        review = self.codex_stream("review.jsonl", session=str(uuid.UUID(int=3)), usage=usage(4))
        retry = self.codex_stream("retry.jsonl", session=str(uuid.UUID(int=4)), usage=usage(3))
        roster = self.attempt_roster("roster.json", [
            self.attributed_attempt("parent-1", "parent", None, parent),
            self.attributed_attempt("child-1", "child", "parent-1", child),
            self.attributed_attempt("review-1", "review", "parent-1", review),
            self.attributed_attempt("retry-1", "retry", "child-1", retry)])
        result = lite.summarize_codex_usage_attempts(roster)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["attempt_count"], 4)
        self.assertEqual(result["supplied_known_usage_totals"]["input_tokens"], 23)
        self.assertEqual({role: row["input_tokens"] for role, row in
                          result["role_known_usage_totals"].items()},
                         {"parent": 10, "child": 6, "review": 4, "retry": 3})
        self.assertIsNone(result["work_usage_totals"]["input_tokens"])
        self.assertIn("work_roster_completeness_unverified", result["coverage_gaps"])
        self.assertEqual(result["model_requests"], "unknown")
        self.assertFalse(result["raw_prompt_or_response_retained"])
        self.assertNotIn("parent.jsonl", json.dumps(result))
        command = [sys.executable, "-I", "-B", str(REPO / ".aide/scripts/aide_lite.py"),
                   "--repo-root", str(REPO), "job", "usage", "--attempt-set", str(roster)]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=15)
        self.assertEqual(completed.returncode, 2, completed.stderr[-500:])
        self.assertEqual(json.loads(completed.stdout)["attempt_count"], 4)

    def test_codex_attempt_roster_preserves_missing_parent_as_unknown(self):
        child = self.codex_stream("child.jsonl", session=str(uuid.UUID(int=2)),
                                  usage={"input_tokens": 6, "cached_input_tokens": 1,
                                         "output_tokens": 2, "reasoning_output_tokens": 0})
        roster = self.attempt_roster("missing.json", [
            self.attributed_attempt("parent-1", "parent", None, None),
            self.attributed_attempt("child-1", "child", "parent-1", child)])
        result = lite.summarize_codex_usage_attempts(roster)
        self.assertIn("attempt_stream_unavailable", result["coverage_gaps"])
        self.assertIsNone(result["role_known_usage_totals"]["parent"]["input_tokens"])
        self.assertEqual(result["role_known_usage_totals"]["child"]["input_tokens"], 6)
        self.assertEqual(result["supplied_known_usage_totals"]["input_tokens"], 6)
        self.assertIsNone(result["work_usage_totals"]["input_tokens"])

    def test_codex_attempt_roster_refuses_duplicate_and_escaping_streams(self):
        stream = self.codex_stream("one.jsonl", usage={"input_tokens": 2,
            "cached_input_tokens": 0, "output_tokens": 1, "reasoning_output_tokens": 0})
        parent = self.attributed_attempt("parent-1", "parent", None, stream)
        duplicate = self.attributed_attempt("child-1", "child", "parent-1", stream)
        roster = self.attempt_roster("duplicate.json", [parent, duplicate])
        with self.assertRaisesRegex(ValueError, "duplicate stream"):
            lite.summarize_codex_usage_attempts(roster)
        escaped = {**duplicate, "stream": "../one.jsonl"}
        roster = self.attempt_roster("escape.json", [parent, escaped])
        with self.assertRaisesRegex(ValueError, "stream path"):
            lite.summarize_codex_usage_attempts(roster)

    def test_codex_attempt_roster_does_not_attribute_same_session_overlap(self):
        usage = {"input_tokens": 5, "cached_input_tokens": 0,
                 "output_tokens": 1, "reasoning_output_tokens": 0}
        parent = self.codex_stream("parent.jsonl", usage=usage)
        child = self.codex_stream("child.jsonl", usage={**usage, "input_tokens": 7})
        roster = self.attempt_roster("overlap.json", [
            self.attributed_attempt("parent-1", "parent", None, parent),
            self.attributed_attempt("child-1", "child", "parent-1", child)])
        result = lite.summarize_codex_usage_attempts(roster)
        self.assertIn("same_session_multiple_streams_turn_identity_unknown", result["coverage_gaps"])
        self.assertIsNone(result["role_known_usage_totals"]["parent"]["input_tokens"])
        self.assertIsNone(result["role_known_usage_totals"]["child"]["input_tokens"])

    def test_codex_attempt_roster_refuses_non_string_parent_with_cli_result(self):
        roster = self.attempt_roster("invalid-parent.json", [
            self.attributed_attempt("parent-1", "parent", None, None),
            {**self.attributed_attempt("child-1", "child", "parent-1", None),
             "parent_attempt_id": ["parent-1"]}])
        with self.assertRaisesRegex(ValueError, "parent link"):
            lite.summarize_codex_usage_attempts(roster)
        command = [sys.executable, "-I", "-B", str(REPO / ".aide/scripts/aide_lite.py"),
                   "--repo-root", str(REPO), "job", "usage", "--attempt-set", str(roster)]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=15)
        self.assertEqual(completed.returncode, 1, completed.stderr[-500:])
        self.assertEqual(json.loads(completed.stdout)["status"], "REFUSED")

        roster = self.attempt_roster("invalid-grandparent.json", [
            self.attributed_attempt("parent-1", "parent", None, None),
            self.attributed_attempt("child-1", "child", "child-2", None),
            {**self.attributed_attempt("child-2", "child", "parent-1", None),
             "parent_attempt_id": {"bad": "parent-1"}}])
        with self.assertRaisesRegex(ValueError, "parent link"):
            lite.summarize_codex_usage_attempts(roster)

    def test_codex_attempt_roster_refuses_deep_json_with_cli_result(self):
        roster = self.root / "deep.json"
        roster.write_text("[" * 30000 + "0" + "]" * 30000, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "malformed JSON"):
            lite.summarize_codex_usage_attempts(roster)
        command = [sys.executable, "-I", "-B", str(REPO / ".aide/scripts/aide_lite.py"),
                   "--repo-root", str(REPO), "job", "usage", "--attempt-set", str(roster)]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=15)
        self.assertEqual(completed.returncode, 1, completed.stderr[-500:])
        self.assertEqual(json.loads(completed.stdout)["status"], "REFUSED")

    def test_codex_usage_import_deduplicates_exact_stream_and_terminal(self):
        path = self.codex_stream("one.jsonl", usage={"input_tokens": 20, "cached_input_tokens": 5,
            "output_tokens": 7, "reasoning_output_tokens": 2}, repeat=True)
        result = lite.summarize_codex_exec_usage([path, path])
        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(result["completed_turns"], 1)
        self.assertEqual(result["duplicate_streams_excluded"], 1)
        self.assertEqual(result["records"][0]["duplicate_terminal_events"], 1)
        self.assertEqual(result["usage_totals"]["input_tokens"], 20)
        self.assertEqual(result["usage_totals"]["reasoning_output_tokens"], 2)
        self.assertFalse(result["raw_prompt_or_response_retained"])

    def test_codex_usage_import_preserves_failed_and_missing_coverage(self):
        good = self.codex_stream("good.jsonl", usage={"input_tokens": 10, "output_tokens": 3},
                                 session=str(uuid.UUID(int=2)))
        failed = self.codex_stream("failed.jsonl", failed=True, session=str(uuid.UUID(int=3)))
        result = lite.summarize_codex_exec_usage([good, failed])
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIsNone(result["usage_totals"]["input_tokens"])
        self.assertEqual(result["known_usage_totals"]["input_tokens"], 10)
        self.assertIn("turn_failed_or_error", result["coverage_gaps"])
        self.assertIn("cached_input_tokens_unknown", result["coverage_gaps"])
        self.assertEqual(result["model_requests"], "unknown")

    def test_codex_usage_known_subtotal_does_not_turn_missing_into_zero(self):
        path = self.codex_stream("partial-categories.jsonl", usage={
            "input_tokens": 10, "output_tokens": 3})
        result = lite.summarize_codex_exec_usage([path])
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["known_usage_totals"]["input_tokens"], 10)
        self.assertEqual(result["known_usage_totals"]["output_tokens"], 3)
        self.assertIsNone(result["known_usage_totals"]["cached_input_tokens"])
        self.assertIsNone(result["known_usage_totals"]["reasoning_output_tokens"])

    def test_codex_usage_conflicting_terminal_cannot_contribute_known_subtotal(self):
        conflicted = self.codex_stream("conflicted.jsonl", usage={
            "input_tokens": 10, "cached_input_tokens": 2,
            "output_tokens": 4, "reasoning_output_tokens": 1})
        conflicted.write_text(conflicted.read_text(encoding="utf-8")
                              + json.dumps({"type": "turn.failed"}) + "\n", encoding="utf-8")
        good = self.codex_stream("good-independent.jsonl", session=str(uuid.UUID(int=2)),
                                 usage={"input_tokens": 6, "cached_input_tokens": 1,
                                        "output_tokens": 2, "reasoning_output_tokens": 0})
        result = lite.summarize_codex_exec_usage([conflicted, good])
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIn("terminal_conflict", result["coverage_gaps"])
        self.assertEqual(result["records"][0]["terminal_status"], "AMBIGUOUS")
        self.assertEqual(result["completed_turns"], 1)
        self.assertEqual(result["known_usage_totals"]["input_tokens"], 6)
        self.assertEqual(result["known_usage_totals"]["output_tokens"], 2)
        conflicted_only = lite.summarize_codex_exec_usage([conflicted])
        self.assertIsNone(conflicted_only["known_usage_totals"]["input_tokens"])

    def test_codex_usage_import_refuses_ambiguous_or_altered_usage(self):
        path = self.codex_stream("bad.jsonl", usage={"input_tokens": 1, "cached_input_tokens": 2,
            "output_tokens": 1, "reasoning_output_tokens": 0})
        with self.assertRaisesRegex(ValueError, "cached input"):
            lite.summarize_codex_exec_usage([path])
        path.write_text(path.read_text(encoding="utf-8") + json.dumps({"type": "turn.completed",
            "usage": {"input_tokens": 2, "output_tokens": 1}}) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            lite.summarize_codex_exec_usage([path])
        path.write_bytes(b"x" * 65)
        with mock.patch.object(lite, "CODEX_EXEC_MAX_STREAM_BYTES", 64):
            with self.assertRaisesRegex(ValueError, "bounded"):
                lite.summarize_codex_exec_usage([path])

    def test_codex_usage_import_refuses_duplicate_json_keys(self):
        path = self.codex_stream("duplicate.jsonl", usage={"input_tokens": 10,
            "cached_input_tokens": 0, "output_tokens": 2, "reasoning_output_tokens": 0})
        original = path.read_text(encoding="utf-8")
        path.write_text(original.replace('"input_tokens": 10',
                            '"input_tokens": 100, "input_tokens": 10', 1), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            lite.summarize_codex_exec_usage([path])
        path.write_text(original.replace('"type": "turn.completed"',
                            '"type": "error", "type": "turn.completed"', 1), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            lite.summarize_codex_exec_usage([path])

    def test_codex_usage_import_marks_resumed_session_ambiguity(self):
        usage = {"input_tokens": 10, "cached_input_tokens": 0,
                 "output_tokens": 2, "reasoning_output_tokens": 0}
        first = self.codex_stream("first.jsonl", usage=usage)
        second = self.codex_stream("second.jsonl", usage={**usage, "input_tokens": 11})
        result = lite.summarize_codex_exec_usage([first, second])
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIn("same_session_multiple_streams_turn_identity_unknown", result["coverage_gaps"])
        self.assertIsNone(result["usage_totals"]["input_tokens"])
        self.assertIsNone(result["known_usage_totals"]["input_tokens"])

    def test_codex_usage_import_requires_one_started_turn(self):
        usage = {"input_tokens": 10, "cached_input_tokens": 0,
                 "output_tokens": 2, "reasoning_output_tokens": 0}
        missing = self.codex_stream("missing-start.jsonl", usage=usage)
        events = [json.loads(line) for line in missing.read_text(encoding="utf-8").splitlines()]
        missing.write_text("\n".join(json.dumps(event) for event in events
                                     if event["type"] != "turn.started") + "\n", encoding="utf-8")
        result = lite.summarize_codex_exec_usage([missing])
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["completed_turns"], 0)
        self.assertIn("turn_boundary_ambiguous", result["coverage_gaps"])
        self.assertIsNone(result["known_usage_totals"]["input_tokens"])

        repeated = self.codex_stream("two-turns.jsonl", usage=usage, repeat=True)
        events = [json.loads(line) for line in repeated.read_text(encoding="utf-8").splitlines()]
        events.insert(3, {"type": "turn.started"})
        repeated.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
        result = lite.summarize_codex_exec_usage([repeated])
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["completed_turns"], 0)
        self.assertEqual(result["records"][0]["duplicate_terminal_events"], 1)
        self.assertIsNone(result["usage_totals"]["input_tokens"])

    def test_codex_usage_turn_ambiguity_preserves_independent_known_subtotal(self):
        ambiguous = self.codex_stream("ambiguous-turn.jsonl", usage={
            "input_tokens": 10, "cached_input_tokens": 2,
            "output_tokens": 4, "reasoning_output_tokens": 1})
        events = [json.loads(line) for line in ambiguous.read_text(encoding="utf-8").splitlines()]
        ambiguous.write_text("\n".join(json.dumps(event) for event in events
                                       if event["type"] != "turn.started") + "\n", encoding="utf-8")
        good = self.codex_stream("independent-turn.jsonl", session=str(uuid.UUID(int=2)),
                                 usage={"input_tokens": 6, "cached_input_tokens": 1,
                                        "output_tokens": 2, "reasoning_output_tokens": 0})
        result = lite.summarize_codex_exec_usage([ambiguous, good])
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIn("turn_boundary_ambiguous", result["coverage_gaps"])
        self.assertEqual(result["completed_turns"], 1)
        self.assertEqual(result["known_usage_totals"]["input_tokens"], 6)
        self.assertEqual(result["known_usage_totals"]["output_tokens"], 2)
        self.assertIsNone(result["usage_totals"]["input_tokens"])
        self.assertIsNone(lite.summarize_codex_exec_usage([ambiguous])
                          ["known_usage_totals"]["input_tokens"])

    def test_prompt_input_summary_counts_without_echoing_text(self):
        marker = "private-task-content-do-not-echo"
        raw = json.dumps([
            {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "α"}]},
            {"type": "message", "role": "user", "content": [{"type": "text", "text": marker}]},
        ]).encode("utf-8")
        result = lite.summarize_codex_prompt_input(raw)
        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(result["roles"]["developer"]["text_utf8_bytes"], 2)
        self.assertEqual(result["visible_text_utf8_bytes"], 2 + len(marker))
        self.assertEqual(result["effective_tokens"], None)
        self.assertNotIn(marker, json.dumps(result))
        cli = subprocess.run([sys.executable, "-I", "-B", str(REPO / ".aide/scripts/aide_lite.py"),
                              "--repo-root", str(REPO), "job", "context"], input=raw,
                             capture_output=True, timeout=15)
        self.assertEqual(cli.returncode, 0)
        self.assertEqual(json.loads(cli.stdout)["visible_text_utf8_bytes"], 2 + len(marker))
        self.assertNotIn(marker.encode(), cli.stdout + cli.stderr)

    def test_prompt_input_summary_bounds_and_marks_unknown_coverage(self):
        for raw in (b"", b"not-json", b"{}", b"[]", b"[{}]"):
            with self.assertRaises(ValueError):
                lite.summarize_codex_prompt_input(raw)
        with mock.patch.object(lite, "CODEX_PROMPT_INPUT_MAX_BYTES", 64):
            with self.assertRaisesRegex(ValueError, "bounded"):
                lite.summarize_codex_prompt_input(b"x" * 65)
        raw = json.dumps([{"type": "message", "role": "not-a-role", "content": [
            {"type": "image", "data": "do-not-echo"}]}]).encode()
        result = lite.summarize_codex_prompt_input(raw)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["coverage_gaps"], ["non_text_content", "unknown_role"])
        self.assertNotIn("do-not-echo", json.dumps(result))

    @unittest.skipUnless(os.name == "nt" and shutil.which("codex"), "installed Codex debug probe requires Windows Codex")
    def test_installed_codex_prompt_input_is_summarized_without_model_turn(self):
        host = shutil.which("codex")
        command = [host, "debug", "prompt-input", "-c", "features.apps=false",
                   "-c", "features.hooks=false", "-c", "features.multi_agent=false",
                   "-c", "features.remote_plugin=false", "AIDE context-size probe; do not run a model."]
        probe = subprocess.run(command, cwd=REPO, capture_output=True, timeout=20)
        self.assertEqual(probe.returncode, 0, f"Codex debugger exited {probe.returncode}")
        self.assertLessEqual(len(probe.stdout), lite.CODEX_PROMPT_INPUT_MAX_BYTES)
        result = lite.summarize_codex_prompt_input(probe.stdout)
        self.assertIn(result["status"], ("COMPLETE", "PARTIAL"))
        self.assertTrue(set(result["coverage_gaps"]).issubset({"unknown_role", "non_text_content"}))
        self.assertGreater(result["visible_text_utf8_bytes"], 44)
        self.assertEqual(result["model_requests_started_by_parser"], 0)
        self.assertFalse(result["raw_prompt_or_response_retained"])
        print("codex_context_coverage=" + json.dumps({
            "status": result["status"], "gaps": result["coverage_gaps"],
            "visible_text_utf8_bytes": result["visible_text_utf8_bytes"],
            "message_count": result["message_count"]}, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
