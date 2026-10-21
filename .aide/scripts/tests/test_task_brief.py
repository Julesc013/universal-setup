"""Observable development brief contracts across existing independent readers."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("brief_test_cli", ROOT / ".aide/scripts/aide_lite.py")
aide = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = aide
spec.loader.exec_module(aide)


class TaskBriefTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.task = "PROJECT-BRIEF-01"
        self.base = ".aide/queue/" + self.task
        self.path = "src/repair.py"
        self.write(self.base + "/task.yaml", f"id: {self.task}\ntitle: Repair the consumer\nowner: project-owner\n")
        self.status()
        self.write("source.txt", "original evidence\n")
        self.quality = {"schema_version": "aide.file-quality-ledger.v0", "source_commit": "a" * 40,
                        "records": [{"path": self.path, "owner": "existing-module", "kind": "source",
                                     "status": "active", "quality_level": "documented",
                                     "recommended_next_action": "inspect existing tests",
                                     "docs_refs": ["docs/contract.md"], "test_refs": ["tests/test_consumer.py"],
                                     "dependency_refs": [], "warnings": [], "exemptions": []}]}
        self.write_quality()
        self.lesson = {"schema_version": "aide.outcome-lesson.v1", "id": "consumer-oracle", "revision": 1,
                       "state": "active", "summary": "Preserve the independent consumer check.",
                       "applies_to": [self.path], "supersedes": None,
                       "required_features": ["advisory_only", "revision_chain", "source_sha256"],
                       "evidence": [{"path": "source.txt", "sha256": hashlib.sha256(b"original evidence\n").hexdigest()}]}
        self.write_lessons([self.lesson])

    def write(self, relative, text):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
        return target

    def status(self, state="running", extra=""):
        self.write(self.base + "/status.yaml", f"task_id: {self.task}\nstatus: {state}\nnext_action: review_candidate\n" + extra)

    def write_quality(self):
        self.write(aide.FILE_QUALITY_LEDGER_JSON_PATH, json.dumps(self.quality))

    def write_lessons(self, lessons):
        self.write(aide.OUTCOME_LEDGER_PATH, "".join(json.dumps({"run_id": "attempt-" + str(item["revision"]),
                   "phase": "review", "source": "fixture", "result": "PASS", "lesson": item}) + "\n" for item in lessons))

    def view(self):
        return aide.build_task_development_brief(self.root, self.task, self.path)

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.root.rglob("*") if p.is_file()}

    def test_one_brief_preserves_distinct_owners_and_uncertainty(self):
        data = self.view()
        self.assertEqual(data["result"], "OBSERVED")
        self.assertEqual(data["continuation"]["task"]["owner"], "project-owner")
        self.assertEqual(data["quality"]["owner"], "existing-module")
        self.assertEqual(data["quality"]["relations"]["test_refs"]["items"], ["tests/test_consumer.py"])
        self.assertEqual(data["quality"]["relations"]["dependency_refs"]["state"], "not_found")
        self.assertEqual(data["quality"]["freshness"], "unverified")
        self.assertEqual(data["lessons"]["selected"][0]["lesson"], self.lesson)
        self.assertFalse(data["acceptance_verified"])
        self.assertFalse(data["execution_admitted"])
        self.assertEqual(data["usage_coverage"], "unknown")

    def test_completed_preparation_preserves_remaining_obligations(self):
        self.status("passed", "remaining_obligations:\n  - native_adoption\n")
        data = self.view()
        self.assertEqual(data["next_action"], "inspect_completed_evidence")
        self.assertEqual(data["continuation"]["task"]["remaining_obligations"], ["native_adoption"])
        self.assertIsNone(data["continuation"]["safe_to_resume"])

    def test_missing_auxiliary_records_are_partial_without_regeneration(self):
        (self.root / aide.FILE_QUALITY_LEDGER_JSON_PATH).unlink()
        (self.root / aide.OUTCOME_LEDGER_PATH).unlink()
        before = self.snapshot()
        data = self.view()
        self.assertEqual(data["result"], "PARTIAL")
        self.assertEqual(data["quality"]["coverage"], "unindexed")
        self.assertEqual(data["lesson_state"], "missing")
        self.assertEqual(before, self.snapshot())

    def test_malformed_quality_is_visible_and_does_not_hide_valid_lesson(self):
        self.write(aide.FILE_QUALITY_LEDGER_JSON_PATH, "{broken")
        data = self.view()
        self.assertEqual(data["result"], "PARTIAL")
        self.assertEqual(data["quality"]["result"], "INVALID")
        self.assertEqual(data["next_action"], "reconcile invalid auxiliary records")
        self.assertEqual(len(data["lessons"]["selected"]), 1)

    def test_invalid_lesson_chain_does_not_return_old_advice(self):
        second = {**self.lesson, "revision": 2, "supersedes": "0" * 64}
        self.write_lessons([self.lesson, second])
        data = self.view()
        self.assertEqual(data["result"], "PARTIAL")
        self.assertEqual(data["lesson_state"], "invalid")
        self.assertIsNone(data["lessons"])
        self.assertEqual(data["quality"]["owner"], "existing-module")

    def test_stale_and_retired_lessons_are_excluded(self):
        self.write("source.txt", "changed evidence\n")
        stale = self.view()["lessons"]
        self.assertEqual(stale["selected"], [])
        self.assertEqual(stale["excluded"][0]["reason"], "evidence_not_current")
        # Independently serialize the public predecessor contract.
        digest = hashlib.sha256(json.dumps(self.lesson, sort_keys=True, ensure_ascii=True,
                                           separators=(",", ":")).encode("ascii")).hexdigest()
        retired = {**self.lesson, "revision": 2, "state": "retired", "supersedes": digest}
        self.write_lessons([self.lesson, retired])
        data = self.view()["lessons"]
        self.assertEqual(data["selected"], [])
        self.assertEqual(data["excluded"][0]["reason"], "retired")

    def test_missing_task_does_not_read_auxiliary_records(self):
        with mock.patch.object(aide, "build_quality_file_explanation", side_effect=AssertionError("unexpected retrieval")):
            data = aide.build_task_development_brief(self.root, "MISSING-01", self.path)
        self.assertEqual(data["result"], "REFUSED")
        self.assertNotIn("quality", data)

    def test_explicit_task_ignores_another_latest_assignment(self):
        self.write(aide.LATEST_PACKET_PATH, "task_id: ANOTHER-01\n")
        self.assertEqual(self.view()["continuation"]["task"]["task_id"], self.task)

    def test_unsafe_or_noncanonical_paths_refuse_before_auxiliary_reads(self):
        with mock.patch.object(aide, "build_quality_file_explanation", side_effect=AssertionError("unexpected retrieval")):
            for path in ["../outside", "C:/outside", "src\\repair.py", ".env", ".git/config",
                         ".aide.local/private", "secrets/file", "src/../repair.py", "src/*", ""]:
                with self.subTest(path=path):
                    self.assertEqual(aide.build_task_development_brief(self.root, self.task, path)["result"], "REFUSED")

    def test_task_change_during_assembly_refuses_combined_advice(self):
        original = aide.build_quality_file_explanation
        def changed(*args):
            value = original(*args)
            self.status("blocked")
            return value
        with mock.patch.object(aide, "build_quality_file_explanation", side_effect=changed):
            data = self.view()
        self.assertEqual(data["result"], "REFUSED")
        self.assertIn("changed", data["reason"])
        self.assertNotIn("lessons", data)

    def test_task_record_hashes_describe_exact_observed_bytes(self):
        data = self.view()
        for ref, digest in data["task_record_sha256s"].items():
            target = self.root / ref
            self.assertEqual(digest, hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None)

    def test_shared_quality_reader_rejects_hardlinked_report(self):
        report = self.root / aide.FILE_QUALITY_LEDGER_JSON_PATH
        os.link(report, self.root / "shared-report.json")
        data = self.view()
        self.assertEqual(data["quality"]["result"], "INVALID")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = aide.main(["--repo-root", str(self.root), "quality", "explain-file", self.path, "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["result"], "INVALID")

    def test_combined_output_bound_refuses_without_partial_advice(self):
        self.quality["records"][0]["owner"] = "x" * 65536
        self.write_quality()
        data = self.view()
        self.assertEqual(data["result"], "REFUSED")
        self.assertIn("64 KiB", data["reason"])
        self.assertNotIn("quality", data)

    def test_human_output_quotes_controls_and_reports_omissions(self):
        self.quality["records"][0]["owner"] = "owner\x1b[31m\npretend-pass"
        self.quality["records"][0]["test_refs"] = [f"tests/test_{i}.py" for i in range(8)]
        self.write_quality()
        text = aide.render_task_development_brief(self.view())
        self.assertNotIn("\x1b", text)
        self.assertIn("\\u001b", text)
        self.assertIn("omitted: 5", text)
        self.assertIn("freshness unverified; coverage incomplete", text)
        self.assertIn("no execution or acceptance authority", text)

    def test_actual_cli_matches_independent_component_commands_without_writes(self):
        before = self.snapshot()
        def call(*args):
            result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / ".aide/scripts/aide_lite.py"),
                                     "--repo-root", str(self.root), *args], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        brief = call("task", "brief", "--task-id", self.task, "--path", self.path, "--json")
        self.assertEqual(brief["continuation"], call("task", "resume-plan", "--task-id", self.task, "--json"))
        self.assertEqual(brief["quality"], call("quality", "explain-file", self.path, "--json"))
        self.assertEqual(brief["lessons"], call("outcome", "lessons", "--path", self.path, "--json"))
        self.assertEqual(before, self.snapshot())

    def test_conflicting_index_status_refuses_before_auxiliary_reads(self):
        self.write(".aide/queue/index.yaml", f"tasks:\n  - id: {self.task}\n    status: passed\n")
        with mock.patch.object(aide, "build_quality_file_explanation", side_effect=AssertionError("unexpected retrieval")):
            self.assertEqual(self.view()["result"], "REFUSED")

    def test_missing_status_refuses_without_guessing_from_task(self):
        (self.root / self.base / "status.yaml").unlink()
        self.assertEqual(self.view()["result"], "REFUSED")

    def test_partial_cli_exit_preserves_actionable_uncertainty(self):
        self.write(aide.OUTCOME_LEDGER_PATH, "{broken\n")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = aide.main(["--repo-root", str(self.root), "task", "brief", "--task-id", self.task, "--path", self.path])
        self.assertEqual(code, 2)
        self.assertIn("lessons: invalid", output.getvalue())
        self.assertIn("next_action: reconcile invalid auxiliary records", output.getvalue())


if __name__ == "__main__":
    unittest.main()
