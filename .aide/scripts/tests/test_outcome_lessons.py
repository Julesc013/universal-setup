"""Independent observable selection, revision and delivered CLI contracts."""
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
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("lesson_test_cli", ROOT / ".aide/scripts/aide_lite.py")
aide = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = aide
spec.loader.exec_module(aide)
codec = aide.outcome_lessons_codec()


class OutcomeLessonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ledger = self.root / aide.OUTCOME_LEDGER_PATH
        self.ledger.parent.mkdir(parents=True)
        (self.root / "source.txt").write_bytes(b"observed source\n")

    def lesson(self, **changes):
        return {"schema_version": "aide.outcome-lesson.v1", "id": "fixture-lesson",
                "revision": 1, "state": "active", "summary": "Keep the consumer oracle independent.",
                "required_features": ["advisory_only", "revision_chain", "source_sha256"],
                "applies_to": ["tests/check.py"], "supersedes": None,
                "evidence": [{"path": "source.txt", "sha256": hashlib.sha256(b"observed source\n").hexdigest()}],
                **changes}

    def row(self, lesson, **changes):
        return {"run_id": "attempt-" + str(lesson["revision"]), "phase": "review",
                "source": "test", "result": "PASS", "lesson": lesson, **changes}

    def write(self, lessons):
        self.ledger.write_text("".join(json.dumps(self.row(x)) + "\n" for x in lessons), encoding="utf-8")

    def view(self, path="tests/check.py"):
        return aide.build_outcome_lessons(self.root, path)

    def test_correction_and_retirement_never_resurrect_old_advice(self):
        first = self.lesson()
        second = self.lesson(revision=2, supersedes=codec.canonical_digest(first), summary="Use a target-owned oracle.")
        retired = self.lesson(revision=3, supersedes=codec.canonical_digest(second), state="retired", summary="Replaced by an executable check.")
        self.write([first]); original = self.ledger.read_bytes()
        self.write([first, second]); corrected = self.view()
        self.assertEqual([x["lesson"]["summary"] for x in corrected["selected"]], [second["summary"]])
        self.assertTrue(self.ledger.read_bytes().startswith(original))
        self.write([first, second, retired]); before = self.ledger.read_bytes()
        result = self.view()
        self.assertEqual(result["selected"], [])
        self.assertEqual([(x["revision"], x["reason"]) for x in result["excluded"]], [(3, "retired")])
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_latest_stale_revision_does_not_fall_back(self):
        first = self.lesson()
        second = self.lesson(revision=2, supersedes=codec.canonical_digest(first),
                             evidence=[{"path": "source.txt", "sha256": "0" * 64}])
        self.write([first, second])
        result = self.view()
        self.assertEqual(result["selected"], [])
        self.assertEqual(result["excluded"][0]["evidence"][0]["state"], "stale")
        self.assertEqual(result["excluded"][0]["revision"], 2)

    def test_out_of_scope_and_retired_do_not_read_evidence(self):
        for lesson, reason in [(self.lesson(), "out_of_scope"), (self.lesson(state="retired"), "retired")]:
            with self.subTest(reason=reason):
                observed = mock.Mock(side_effect=AssertionError("unexpected evidence access"))
                result = codec.select([self.row(lesson)], "different.py", observed)
                self.assertEqual(result["selected"], [])
                self.assertEqual(result["excluded"][0]["reason"], reason)
                self.assertNotIn("summary", json.dumps(result))
                observed.assert_not_called()

    def test_missing_and_empty_ledger_are_distinct(self):
        self.assertEqual(self.view()["ledger_state"], "missing")
        self.write([])
        self.assertEqual(self.view()["ledger_state"], "observed")
        self.assertEqual(self.view()["selected"], [])

    def test_evidence_changes_and_missing_are_not_current(self):
        self.write([self.lesson()]); before = self.ledger.read_bytes()
        self.assertEqual(len(self.view()["selected"]), 1)
        (self.root / "source.txt").write_bytes(b"changed source\n")
        self.assertEqual(self.view()["excluded"][0]["evidence"][0]["state"], "stale")
        (self.root / "source.txt").unlink()
        self.assertEqual(self.view()["excluded"][0]["evidence"][0]["state"], "missing")
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_unknown_optional_metadata_is_preserved_and_bound(self):
        first = self.lesson(project_data={"why": ["caf\u00e9", {"flag": True}]})
        second = self.lesson(revision=2, supersedes=codec.canonical_digest(first))
        self.write([first]); before = self.ledger.read_bytes()
        self.assertEqual(self.view()["selected"][0]["lesson"], first)
        self.assertEqual(self.ledger.read_bytes(), before)
        first["project_data"]["why"].append("changed")
        self.write([first, second])
        with self.assertRaisesRegex(ValueError, "predecessor"):
            self.view()

    def test_bad_revision_chains_refuse_whole_selection(self):
        first = self.lesson()
        for lessons in ([first, first], [self.lesson(revision=2, supersedes="0" * 64)],
                        [first, self.lesson(revision=2, supersedes="0" * 64)],
                        [first, self.lesson(revision=3, supersedes=codec.canonical_digest(first))]):
            with self.subTest(lessons=lessons):
                self.write(lessons); before = self.ledger.read_bytes()
                with self.assertRaises(ValueError): self.view()
                self.assertEqual(self.ledger.read_bytes(), before)

    def test_unsupported_semantics_and_invalid_shapes_refuse(self):
        changes = [{"schema_version": "future"}, {"required_features": ["unknown"]},
                   {"required_features": ["revision_chain"] * 3}, {"revision": True},
                   {"summary": "\u001b[31munsafe"}, {"state": "accepted"},
                   {"supersedes": "0" * 64}, {"evidence": []}, {"applies_to": []},
                   {"evidence": [{"path": "source.txt", "sha256": "bad"}]}]
        for change in changes:
            with self.subTest(change=change):
                self.write([self.lesson(**change)])
                with self.assertRaises(ValueError): self.view()

    def test_invalid_ledger_rows_refuse_without_partial_output(self):
        good = json.dumps(self.row(self.lesson())) + "\n"
        for bad in ('{broken', '[]', '{"run_id":"x","run_id":"y"}',
                    '{"run_id":"x","phase":"p","source":"s","unknown":NaN}', '{}'):
            with self.subTest(bad=bad):
                self.ledger.write_text(good + bad, encoding="utf-8")
                before = self.ledger.read_bytes()
                with self.assertRaises(ValueError): self.view()
                self.assertEqual(self.ledger.read_bytes(), before)

    def test_exact_relative_paths_and_finite_bounds(self):
        for path in ("../source.txt", "/source.txt", "C:/file", "x//y", "x\\y", "x/*", "x/."):
            with self.subTest(path=path), self.assertRaises(ValueError):
                codec.relative_path(path)
        self.ledger.write_bytes(b" " * (codec.MAX_LEDGER + 1))
        with self.assertRaises(ValueError): self.view()
        self.ledger.write_bytes(b"\n" * 2049)
        with self.assertRaises(ValueError): self.view()
        self.write([self.lesson()]); (self.root / "source.txt").write_bytes(b"x" * (codec.MAX_EVIDENCE + 1))
        self.assertEqual(self.view()["excluded"][0]["evidence"][0]["state"], "unsafe_or_unreadable")

    def test_private_and_hardlinked_evidence_never_select(self):
        private = self.root / ".aide.local"; private.mkdir()
        (private / "source.txt").write_bytes(b"observed source\n")
        self.write([self.lesson(evidence=[{"path": ".aide.local/source.txt", "sha256": hashlib.sha256(b"observed source\n").hexdigest()}])])
        self.assertEqual(self.view()["excluded"][0]["evidence"][0]["state"], "unsafe_or_unreadable")
        os.link(self.root / "source.txt", self.root / "other.txt")
        self.write([self.lesson()])
        self.assertEqual(self.view()["excluded"][0]["evidence"][0]["state"], "unsafe_or_unreadable")
        os.link(self.ledger, self.root / "ledger-link")
        with self.assertRaises(ValueError): self.view()

    def test_ledger_and_evidence_change_during_selection_refuse(self):
        self.write([self.lesson()])
        original = aide.task_view_read
        for change_path in (aide.OUTCOME_LEDGER_PATH, "source.txt"):
            calls = {}
            def changing(root, path, **kwargs):
                raw = original(root, path, **kwargs)
                calls[path] = calls.get(path, 0) + 1
                return raw + b" " if path == change_path and calls[path] > 1 else raw
            with self.subTest(path=change_path), mock.patch.object(aide, "task_view_read", side_effect=changing):
                with self.assertRaisesRegex(ValueError, "changed"): self.view()

    def test_duplicate_identity_and_evidence_refuse(self):
        first = self.lesson()
        second = self.lesson(id="another")
        self.write([first, second])
        with self.assertRaisesRegex(ValueError, "identity"): self.view()
        self.write([self.lesson(evidence=first["evidence"] * 2)])
        with self.assertRaisesRegex(ValueError, "duplicate"): self.view()

    def test_revision_and_read_fanout_are_bounded(self):
        records = [self.row(self.lesson(id=f"lesson-{i}"), run_id=f"run-{i}") for i in range(257)]
        with self.assertRaisesRegex(ValueError, "limit"):
            codec.select(records, "tests/check.py", mock.Mock())
        records = [self.row(self.lesson(id=f"lesson-{i}", evidence=[{"path": f"file-{i}", "sha256": "0" * 64}]), run_id=f"run-{i}") for i in range(129)]
        self.ledger.write_text("\n".join(json.dumps(x) for x in records), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "read limit"): self.view()

    def test_plain_outcome_cannot_share_lesson_identity(self):
        row = self.row(self.lesson())
        plain = {key: value for key, value in row.items() if key != "lesson"}
        for rows in ([plain, row], [row, plain]):
            with self.subTest(rows=rows):
                self.ledger.write_text("\n".join(json.dumps(x) for x in rows), encoding="utf-8")
                before = self.ledger.read_bytes()
                with self.assertRaisesRegex(ValueError, "ambiguous lesson outcome identity"):
                    self.view()
                self.assertEqual(self.ledger.read_bytes(), before)

    def test_cli_is_read_only_and_helper_binds_to_distribution(self):
        self.write([self.lesson()])
        fake = self.root / ".aide/scripts/outcome_lessons.py"
        fake.parent.mkdir(parents=True)
        fake.write_text("raise RuntimeError('target module executed')\n", encoding="utf-8")
        inventory = lambda: {p.relative_to(self.root).as_posix(): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        before = inventory()
        prefix = [sys.executable, "-I", str(ROOT / ".aide/scripts/aide_lite.py"), "--repo-root", str(self.root), "outcome", "lessons", "--path", "tests/check.py"]
        result = subprocess.run(prefix + ["--json"], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["selected"][0]["lesson"]["summary"], self.lesson()["summary"])
        self.assertFalse(value["execution_admitted"])
        text = subprocess.run(prefix, capture_output=True, text=True, timeout=20)
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertIn("selected: 1; excluded: 0", text.stdout)
        self.assertEqual(inventory(), before)
        self.ledger.write_text("{broken", encoding="utf-8")
        failed = subprocess.run(prefix + ["--json"], capture_output=True, text=True, timeout=20)
        self.assertNotEqual(failed.returncode, 0)
        self.assertNotIn('"selected"', failed.stdout)


if __name__ == "__main__":
    unittest.main()
