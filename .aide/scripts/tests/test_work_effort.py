"""Whole-work observation contracts; no provider, dispatch or acceptance effects."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

REPO = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("aide_effort_test", REPO / ".aide/scripts/aide_lite.py")
lite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lite
SPEC.loader.exec_module(lite)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class WorkEffortTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ["AIDE_JOB_TMP"])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = {"schema": "aide.work-effort-set.v1", "work_id": "work-1",
                         "receipts": [], "usage_roster": None}

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return {"path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def receipt(self, name="job.json", job_id="a" * 32, reason="exited", exit_code=0,
                phase="tests", memory=100, scratch=200, retired=True):
        job = {"schema": "aide.maintainer-job.v1", "workunit": "work-1",
               "source_commit": "b" * 40, "source_tree": "c" * 40}
        value = {"job_id": job_id, "manifest_digest": digest(job), "job": job,
                 "phase": "retired" if retired else "collected", "scratch_absent": retired,
                 "reservation_released": retired, "result": {"job_id": job_id,
                 "reason": reason, "exit_code": exit_code, "quiescent": True},
                 "peaks": {"memory_bytes": memory, "scratch_bytes": scratch},
                 "collected_manifest": {"output": "d" * 64},
                 "scratch": "DO_NOT_FOLLOW", "raw_log": "NEVER_PRINT_THIS"}
        self.manifest["receipts"].append({**self.write(name, value), "phase": phase})
        return value

    def view(self):
        self.write("work.json", self.manifest)
        return lite.summarize_work_effort(self.root, "work.json")

    def test_failures_cleanup_missing_phases_and_nonadditive_peaks(self):
        self.receipt()
        self.receipt("failed.json", "e" * 32, exit_code=1, memory=90, scratch=400, phase="repair")
        result = self.view()
        self.assertEqual(result["execution_outcomes"], {"SUCCEEDED": 1, "FAILED": 1, "CANCELLED": 0, "UNKNOWN": 0})
        self.assertEqual(result["retired_attempts_observed"], 2)
        self.assertEqual(result["max_observed_individual_job_peaks"], {"memory_peak_bytes": 100, "scratch_peak_bytes": 400})
        self.assertEqual(len(result["phases"]), 9)
        self.assertEqual(result["phases"]["review"], {"observed_attempts": 0, "accounting_coverage": "unknown"})
        self.assertIsNone(result["whole_work_cost"])
        self.assertIsNone(result["accepted_outcome_elapsed_seconds"])
        self.assertNotIn("NEVER_PRINT_THIS", json.dumps(result))
        self.assertNotIn("DO_NOT_FOLLOW", json.dumps(result))

    def test_cancel_incomplete_and_unknown_metrics(self):
        self.receipt(reason="cancelled", exit_code=1, memory=None, scratch=None, retired=False)
        self.receipt("incomplete.json", "e" * 32, reason="unrecognized", exit_code=0, retired=False)
        result = self.view()
        self.assertEqual(result["execution_outcomes"]["CANCELLED"], 1)
        self.assertEqual(result["execution_outcomes"]["UNKNOWN"], 1)
        self.assertEqual(result["retired_attempts_observed"], 0)
        self.assertIsNone(result["attempts"][0]["memory_peak_bytes"])

    def test_empty_work_is_unknown_not_zero_cost(self):
        result = self.view()
        self.assertEqual(result["attempt_count"], 0)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIsNone(result["max_observed_individual_job_peaks"]["memory_peak_bytes"])
        self.assertIsNone(result["model_usage"])

    def test_owner_exception_and_interrupted_recovery_keep_unknown_outcome(self):
        original = self.receipt()
        for reason in ("OSError", "controller_interrupted"):
            changed = copy.deepcopy(original)
            changed["result"] = {"reason": reason, "exit_code": None}
            changed["reconciliation"] = {"quiescent": True}
            self.manifest["receipts"][0] = {**self.write("job.json", changed), "phase": "recovery"}
            observed = self.view()
            self.assertEqual(observed["execution_outcomes"]["UNKNOWN"], 1)
            self.assertEqual(observed["retired_attempts_observed"], 1)
            self.assertIsNone(observed["attempts"][0]["reconciliation"]["result_quiescent"])
            self.assertTrue(observed["attempts"][0]["reconciliation"]["recovery_quiescent"])

    def test_limits_and_invalid_observation_types(self):
        original = self.receipt(reason="timeout", exit_code=124)
        self.assertEqual(self.view()["execution_outcomes"]["FAILED"], 1)
        for changed in ({**original, "scratch_absent": "true"},
                        {**original, "peaks": {"memory_bytes": -1}},
                        {**original, "peaks": {"scratch_bytes": True}},
                        {**original, "result": {"job_id": "a" * 32, "exit_code": True}}):
            self.manifest["receipts"][0] = {**self.write("job.json", changed), "phase": "tests"}
            with self.assertRaises(ValueError):
                self.view()

    def test_identical_duplicate_once_conflicting_phase_refused(self):
        self.receipt()
        self.manifest["receipts"].append(copy.deepcopy(self.manifest["receipts"][0]))
        result = self.view()
        self.assertEqual(result["attempt_count"], 1)
        self.assertEqual(result["duplicate_observations_excluded"], 1)
        self.manifest["receipts"][1]["phase"] = "repair"
        with self.assertRaisesRegex(ValueError, "conflicting"):
            self.view()

    def test_conflicting_snapshot_refused(self):
        self.receipt()
        self.receipt("other.json", exit_code=1)
        with self.assertRaisesRegex(ValueError, "conflicting"):
            self.view()

    def test_pins_work_manifest_source_and_result_identity(self):
        original = self.receipt()
        for field, value in (("job_id", "invalid"), ("manifest_digest", "0" * 64),
                             ("result", {"job_id": "e" * 32})):
            with self.subTest(field=field):
                changed = {**original, field: value}
                self.manifest["receipts"][0] = {**self.write("job.json", changed), "phase": "tests"}
                with self.assertRaises(ValueError):
                    self.view()
        for field, value in (("workunit", "another-work"), ("source_tree", "unknown"), ("schema", "future")):
            changed = copy.deepcopy(original)
            changed["job"][field] = value
            changed["manifest_digest"] = digest(changed["job"])
            self.manifest["receipts"][0] = {**self.write("job.json", changed), "phase": "tests"}
            with self.assertRaises(ValueError):
                self.view()
        self.manifest["receipts"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.view()

    def test_path_escape_absolute_and_redirected_ancestor_refused(self):
        self.receipt()
        for name in ("../job.json", str(self.root / "job.json"), "/job.json", "sub//job.json", "job.json:stream"):
            self.manifest["receipts"][0]["path"] = name
            with self.assertRaises(ValueError):
                self.view()
        original = Path.lstat
        def redirected(path, *args, **kwargs):
            if path == self.root / "sub":
                return SimpleNamespace(st_mode=0o40700, st_file_attributes=0x400)
            return original(path, *args, **kwargs)
        self.manifest["receipts"][0]["path"] = "sub/job.json"
        with mock.patch.object(Path, "lstat", redirected), self.assertRaisesRegex(ValueError, "redirected"):
            self.view()

    def test_hardlink_input_refused(self):
        self.receipt()
        os.link(self.root / "job.json", self.root / "alias.json")
        with self.assertRaisesRegex(ValueError, "ordinary"):
            self.view()

    def test_malformed_duplicate_nonfinite_and_size_bounds(self):
        self.receipt()
        for content in ('{}', '{"x":1,"x":2}', '{"x":NaN}', '{', ' ' * (256 * 1024 + 1)):
            (self.root / "job.json").write_text(content, encoding="utf-8")
            self.manifest["receipts"][0]["sha256"] = hashlib.sha256(content.encode()).hexdigest()
            with self.assertRaises(ValueError):
                self.view()
        self.manifest["receipts"] *= 17
        with self.assertRaisesRegex(ValueError, "sixteen"):
            self.view()
        (self.root / "work.json").write_bytes(b" " * (64 * 1024 + 1))
        with self.assertRaises(ValueError):
            lite.summarize_work_effort(self.root, "work.json")

    def test_usage_missing_streams_and_work_mismatch(self):
        roster = {"schema": "aide.codex-exec-attempt-roster.v1", "work_id": "work-1", "attempts": [
            {"attempt_id": "parent-1", "role": "parent", "parent_attempt_id": None,
             "stream": None, "stream_sha256": None}]}
        self.manifest["usage_roster"] = self.write("usage.json", roster)
        result = self.view()
        self.assertIn("attempt_stream_unavailable", result["model_usage"]["coverage_gaps"])
        self.assertTrue(all(value is None for value in result["model_usage"]["work_usage_totals"].values()))
        roster["work_id"] = "other"
        self.manifest["usage_roster"] = self.write("usage.json", roster)
        with self.assertRaisesRegex(ValueError, "work identity"):
            self.view()

    def test_usage_session_overlap_preserves_unknown_subtotals(self):
        entries = []
        for i in range(2):
            name = f"stream{i}.jsonl"
            events = [{"type": "thread.started", "thread_id": "00000000-0000-4000-8000-000000000001"},
                      {"type": "turn.started"}, {"type": "turn.completed", "usage": {
                       "input_tokens": 10 + i, "cached_input_tokens": 0, "output_tokens": 3}}]
            path = self.root / name
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
            entries.append({"attempt_id": f"a{i}", "role": "parent" if i == 0 else "review",
                            "parent_attempt_id": None if i == 0 else "a0", "stream": name,
                            "stream_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        self.manifest["usage_roster"] = self.write("usage.json", {
            "schema": "aide.codex-exec-attempt-roster.v1", "work_id": "work-1", "attempts": entries})
        usage = self.view()["model_usage"]
        self.assertIn("same_session_multiple_streams_turn_identity_unknown", usage["coverage_gaps"])
        self.assertTrue(all(value is None for value in usage["supplied_known_usage_totals"].values()))

    def test_actual_cli_human_json_refusal_and_read_only(self):
        self.receipt(exit_code=1)
        self.write("work.json", self.manifest)
        hostile = self.root / "core/execution/work_effort.py"
        hostile.parent.mkdir(parents=True)
        hostile.write_text("from pathlib import Path\nPath(__file__).with_name('EXECUTED').write_text('bad')\nraise RuntimeError('hostile target module')\n", encoding="utf-8")
        before = {path.relative_to(self.root).as_posix(): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        command = [sys.executable, str(REPO / ".aide/scripts/aide_lite.py"),
                   "--repo-root", str(self.root), "job", "effort", "--work-set", "work.json"]
        human = subprocess.run(command, capture_output=True, text=True, timeout=15)
        machine = subprocess.run(command + ["--json"], capture_output=True, text=True, timeout=15)
        self.assertEqual(human.returncode, 2, human.stderr)
        self.assertIn("1 failed", human.stdout)
        self.assertIn("accounting unknown", human.stdout)
        self.assertEqual(machine.returncode, 2, machine.stderr)
        self.assertEqual(json.loads(machine.stdout)["execution_outcomes"]["FAILED"], 1)
        self.assertEqual(before, {path.relative_to(self.root).as_posix(): path.read_bytes() for path in self.root.rglob("*") if path.is_file()})
        refused = subprocess.run(command[:-1] + ["../work.json", "--json"], capture_output=True, text=True, timeout=15)
        self.assertEqual(refused.returncode, 1)
        self.assertEqual(json.loads(refused.stdout)["status"], "REFUSED")

    def test_actual_cli_observes_evidence_only_root(self):
        self.write("work.json", self.manifest)
        result = subprocess.run([sys.executable, "-B", str(REPO / ".aide/scripts/aide_lite.py"),
            "--repo-root", str(self.root), "job", "effort", "--work-set", "work.json", "--json"],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)["attempt_count"], 0)
