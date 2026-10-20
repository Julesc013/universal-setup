"""Independent HTML and CLI oracles for the existing task brief projection."""
import base64
import contextlib
import copy
import hashlib
from html.parser import HTMLParser
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


aide = load("brief_view_cli", ROOT / ".aide/scripts/aide_lite.py")
renderer = load("brief_view_renderer", ROOT / ".aide/scripts/task_brief_view.py")


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.text = []
        self.observation = []
        self.style = []
        self.capture = None
        self.feed(text)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag == "pre" and dict(attrs).get("id") == "observation-json":
            self.capture = "observation"
        elif tag == "style":
            self.capture = "style"

    def handle_endtag(self, tag):
        if tag in {"pre", "style"}:
            self.capture = None

    def handle_data(self, data):
        self.text.append(data)
        if self.capture:
            getattr(self, self.capture).append(data)


def observation():
    return {
        "schema_version": "aide.task-brief.v1", "result": "OBSERVED",
        "read_only": True, "acceptance_verified": False, "execution_admitted": False,
        "path": "src/repair.py", "scope_ref": ".aide/queue/PROJECT-01/task.yaml",
        "usage_coverage": "unknown", "next_action": "inspect_completed_evidence",
        "continuation": {"recommendation": "inspect_completed_evidence",
            "reason": "Preserve completed work.", "safe_to_resume": None,
            "task": {"task_id": "PROJECT-01", "objective": "Repair the consumer",
                     "owner": "project-owner", "status": "passed", "result": "FIXTURE_PASS",
                     "next_action": "request_native_adoption",
                     "remaining_obligations": ["native_adoption", "cost_accounting"],
                     "evidence": [{"field": "report_ref", "availability": "missing",
                                   "applicability": "unverified"}]}},
        "quality": {"result": "PASS", "owner": "module-owner", "freshness": "unverified",
                    "coverage": "recorded", "relations": {"tests": {"state": "not_found",
                    "items": [], "reason": "No recorded relation.", "omitted": 0}}},
        "lessons": {"selected": [], "excluded": [{"id": "old-advice", "reason": "evidence_not_current"}]},
        "lesson_state": "observed", "task_record_sha256s": {"task.yaml": "a" * 64},
        "limitations": ["Missing information does not establish absence."]
    }


class BriefViewTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.task = "PROJECT-01"
        self.write(".aide/queue/PROJECT-01/task.yaml", "id: PROJECT-01\ntitle: Repair consumer\n")
        self.write(".aide/queue/PROJECT-01/status.yaml", "task_id: PROJECT-01\nstatus: running\nnext_action: inspect\n")
        self.write(aide.FILE_QUALITY_LEDGER_JSON_PATH, json.dumps({
            "schema_version": "aide.file-quality-ledger.v0", "source_commit": "a" * 40,
            "records": [{"path": "src/repair.py", "owner": "module-owner", "kind": "source",
                         "status": "active", "quality_level": "documented",
                         "recommended_next_action": "inspect", "docs_refs": [], "test_refs": [],
                         "dependency_refs": [], "warnings": [], "exemptions": []}]}))
        self.write(aide.OUTCOME_LEDGER_PATH, "")

    def write(self, name, value):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value, encoding="utf-8", newline="\n")
        return p

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.root.rglob("*") if p.is_file()}

    def call(self, *flags):
        return subprocess.run([sys.executable, "-I", "-B", str(ROOT / ".aide/scripts/aide_lite.py"),
                               "--repo-root", str(self.root), "task", "brief", "--task-id", self.task,
                               "--path", "src/repair.py", *flags], capture_output=True, timeout=30)

    def test_full_observation_roundtrip_and_independent_identity(self):
        data = observation()
        page = renderer.render(data)
        parsed = Document(page)
        canonical = json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
        self.assertEqual("".join(parsed.observation), canonical)
        self.assertEqual(json.loads("".join(parsed.observation)), data)
        self.assertIn(hashlib.sha256(canonical.encode("ascii")).hexdigest(), page)

    def test_document_has_no_active_elements_or_url_attributes(self):
        doc = Document(renderer.render(observation()))
        allowed = {"html", "head", "meta", "title", "style", "body", "header", "h1", "h2", "p",
                   "strong", "main", "section", "dl", "dt", "dd", "details", "summary", "pre",
                   "ul", "li", "footer", "code"}
        for tag, attrs in doc.tags:
            self.assertIn(tag, allowed)
            self.assertFalse(set(attrs) - {"lang", "charset", "http-equiv", "content", "name", "class", "id"})
        self.assertTrue(any(tag == "details" for tag, _ in doc.tags))
        self.assertFalse(any(attrs.get("http-equiv", "").lower() == "refresh" for _, attrs in doc.tags))

    def test_csp_allows_only_exact_fixed_style(self):
        doc = Document(renderer.render(observation()))
        csp = next(attrs["content"] for tag, attrs in doc.tags if attrs.get("http-equiv") == "Content-Security-Policy")
        css = "".join(doc.style).encode("ascii")
        digest = base64.b64encode(hashlib.sha256(css).digest()).decode("ascii")
        self.assertEqual(csp, "default-src 'none'; base-uri 'none'; form-action 'none'; style-src 'sha256-" + digest + "'")
        self.assertNotIn("url(", css.decode())
        self.assertNotIn("@import", css.decode())

    def test_hostile_project_values_are_text_in_every_projection(self):
        data = observation()
        attack = '"><script>alert(1)</script><img src="https://invalid.test/x" onerror="run()"> &'
        data["next_action"] = attack
        data["continuation"]["task"]["objective"] = attack
        data["quality"]["relations"] = {attack: {"items": [attack]}}
        data["lessons"]["selected"] = [{"summary": attack}]
        data["limitations"] = [attack]
        page = renderer.render(data)
        doc = Document(page)
        self.assertNotIn("<script>", page)
        self.assertFalse({"script", "img"} & {tag for tag, _ in doc.tags})
        self.assertEqual(json.loads("".join(doc.observation)), data)
        self.assertIn(attack, "".join(doc.text))

    def test_unicode_controls_and_direction_are_not_layout(self):
        data = observation()
        data["continuation"]["task"]["objective"] = "Jos\u00e9 \x1b[31m \u202e fake"
        page = renderer.render(data)
        page.encode("ascii")
        visible = "".join(Document(page).text)
        self.assertIn("Jos\u00e9", visible)
        self.assertIn("\\u001b", visible)
        self.assertIn("\\u202e", visible)
        self.assertNotIn("\x1b", visible)
        self.assertNotIn("\u202e", visible)

    def test_recorded_success_keeps_unfinished_obligations(self):
        text = "".join(Document(renderer.render(observation())).text)
        for item in ["Recorded status", "passed", "FIXTURE_PASS", "native_adoption",
                     "cost_accounting", "No execution or acceptance authority", "not live state"]:
            self.assertIn(item, text)

    def test_partial_unknown_and_stale_information_remains_visible(self):
        data = observation()
        data["result"] = "PARTIAL"
        data["quality"] = {"result": "MISSING", "coverage": "unindexed"}
        data["lesson_state"] = "invalid"
        data["lessons"] = None
        text = "".join(Document(renderer.render(data)).text)
        for item in ["PARTIAL", "MISSING", "unindexed", "invalid", "unknown", "unverified"]:
            self.assertIn(item, text)
        self.assertEqual(json.loads("".join(Document(renderer.render(observation())).observation))
                         ["lessons"]["excluded"][0]["reason"], "evidence_not_current")

    def test_refused_brief_needs_no_components(self):
        data = {"schema_version": "aide.task-brief.v1", "result": "REFUSED",
                "acceptance_verified": False, "execution_admitted": False,
                "reason": "Inputs changed.", "next_action": "Reconcile."}
        doc = Document(renderer.render(data))
        self.assertIn("Inputs changed.", "".join(doc.text))
        self.assertEqual(json.loads("".join(doc.observation)), data)
        self.assertNotIn("Recorded task", "".join(doc.text))

    def test_deterministic_and_nonmutating(self):
        data = observation()
        before = copy.deepcopy(data)
        self.assertEqual(renderer.render(data), renderer.render(copy.deepcopy(data)))
        self.assertEqual(data, before)

    def test_long_summary_reports_omission_but_preserves_complete_data(self):
        data = observation()
        data["continuation"]["task"]["objective"] = "x" * 2000
        doc = Document(renderer.render(data))
        self.assertIn("800 more characters", "".join(doc.text))
        self.assertEqual(json.loads("".join(doc.observation)), data)

    def test_input_and_actual_expanded_output_bounds_refuse(self):
        data = observation()
        data["extra"] = "x" * 65536
        with self.assertRaises(ValueError):
            renderer.render(data)
        data = observation()
        data["quality"]["owner"] = "&" * 58000
        self.assertLess(len(json.dumps(data).encode()), 65536)
        with self.assertRaises(ValueError):
            renderer.render(data)

    def test_malformed_or_authorizing_projection_refuses(self):
        for data in [None, {}, {**observation(), "result": "ACCEPTED"},
                     {**observation(), "schema_version": "future"},
                     {**observation(), "acceptance_verified": True},
                     {**observation(), "execution_admitted": True},
                     {**observation(), "continuation": []}]:
            with self.subTest(data=str(data)[:80]), self.assertRaises(ValueError):
                renderer.render(data)

    def test_fresh_html_cli_matches_json_and_writes_nothing(self):
        before = self.snapshot()
        page = self.call("--html")
        original = self.call("--json")
        self.assertEqual(page.returncode, 0, page.stderr)
        self.assertEqual(original.returncode, 0, original.stderr)
        self.assertEqual(json.loads("".join(Document(page.stdout.decode("ascii")).observation)), json.loads(original.stdout))
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(page.stderr)

    def test_actual_partial_exit_remains_two(self):
        (self.root / aide.OUTCOME_LEDGER_PATH).unlink()
        result = self.call("--html")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads("".join(Document(result.stdout.decode()).observation))["result"], "PARTIAL")

    def test_actual_refused_exit_remains_one(self):
        (self.root / ".aide/queue/PROJECT-01/status.yaml").unlink()
        result = self.call("--html")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads("".join(Document(result.stdout.decode()).observation))["result"], "REFUSED")

    def test_modes_are_mutually_exclusive(self):
        result = self.call("--json", "--html")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(result.stdout)
        self.assertIn(b"not allowed", result.stderr)

    def test_non_html_modes_do_not_load_optional_presentation(self):
        with mock.patch.object(aide, "task_brief_renderer", side_effect=AssertionError("unexpected renderer")):
            for flag in [[], ["--json"]]:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = aide.main(["--repo-root", str(self.root), "task", "brief",
                                      "--task-id", self.task, "--path", "src/repair.py", *flag])
                self.assertEqual(code, 0)

    def test_html_overflow_is_an_honest_refusal_with_no_partial_advice(self):
        data = observation()
        data["extra"] = "x" * 65536
        output = io.StringIO()
        with mock.patch.object(aide, "build_task_development_brief", return_value=data), contextlib.redirect_stdout(output):
            code = aide.main(["task", "brief", "--task-id", self.task, "--path", "src/repair.py", "--html"])
        parsed = json.loads("".join(Document(output.getvalue()).observation))
        self.assertEqual(code, 1)
        self.assertEqual(parsed["result"], "REFUSED")
        self.assertNotIn("continuation", parsed)

    def test_unavailable_renderer_does_not_emit_a_false_observation(self):
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(aide, "task_brief_renderer", side_effect=OSError("gone")), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = aide.main(["--repo-root", str(self.root), "task", "brief",
                              "--task-id", self.task, "--path", "src/repair.py", "--html"])
        self.assertEqual(code, 1)
        self.assertFalse(output.getvalue())
        self.assertIn("distribution-owned renderer", errors.getvalue())

    def test_target_cannot_shadow_distribution_renderer(self):
        self.write(".aide/scripts/task_brief_view.py", "raise AssertionError('target code executed')\n")
        before = self.snapshot()
        result = self.call("--html")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, self.snapshot())


if __name__ == "__main__":
    unittest.main()
