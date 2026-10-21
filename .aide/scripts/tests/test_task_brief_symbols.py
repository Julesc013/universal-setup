from __future__ import annotations
import hashlib
from html.parser import HTMLParser
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("brief_symbols_fixture", ROOT / ".aide/scripts/tests/test_task_brief.py")
_base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_base)
aide = _base.aide


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.selected = False
        self.parts = []
        self.tags = []
        self.feed(text)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag == "pre" and dict(attrs).get("id") == "observation-json":
            self.selected = True

    def handle_endtag(self, tag):
        if tag == "pre":
            self.selected = False

    def handle_data(self, text):
        if self.selected:
            self.parts.append(text)


class TaskBriefSymbolTests(unittest.TestCase):
    write = _base.TaskBriefTests.write
    status = _base.TaskBriefTests.status
    write_quality = _base.TaskBriefTests.write_quality
    write_lessons = _base.TaskBriefTests.write_lessons
    snapshot = _base.TaskBriefTests.snapshot

    def setUp(self):
        _base.TaskBriefTests.setUp(self)
        self.write(self.path, "def helper(value):\n    return value\n")
        self.related = "tests/test_consumer.py"
        self.write(self.related, "def test_contract():\n    module.helper(3)\n")

    def brief(self, **kwargs):
        return aide.build_task_development_brief(
            self.root, self.task, self.path, symbol="helper", **kwargs)

    def cli(self, *args, expected=0):
        env = os.environ.copy()
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        called = subprocess.run(
            [sys.executable, "-I", str(ROOT / ".aide/scripts/aide_lite.py"),
             "--repo-root", str(self.root), "task", "brief",
             "--task-id", self.task, "--path", self.path, *args],
            capture_output=True, env=env)
        self.assertEqual(called.returncode, expected, called.stdout + called.stderr)
        self.assertFalse(called.stderr)
        return called.stdout

    def test_default_never_queries_source_or_adds_optional_fields(self):
        with mock.patch.object(aide, "build_quality_symbol_inspection", side_effect=AssertionError("unexpected")):
            result = aide.build_task_development_brief(self.root, self.task, self.path)
        self.assertEqual(result["result"], "OBSERVED")
        self.assertNotIn("symbol_inspection", result)
        self.assertNotIn("symbol_selection", result)
        self.assertNotIn("fresh symbol:", aide.render_task_development_brief(result))
        self.assertNotIn("Fresh helper evidence", aide.task_brief_renderer().render(result))

    def test_explicit_primary_and_related_evidence_is_complete_and_distinct(self):
        result = self.brief(related_paths=[self.related])
        self.assertEqual(result["result"], "OBSERVED")
        self.assertEqual(result["symbol_selection"], [
            {"path": self.path, "reason": "task_target"},
            {"path": self.related, "reason": "explicit_related_source"}])
        primary, related = result["symbol_inspection"]["files"]
        definition = primary["syntax"]["definitions"]["items"][0]
        self.assertEqual((definition["qualified_name"], definition["line"], definition["end_line"]),
                         ("helper", 1, 2))
        call = related["syntax"]["calls"]["items"][0]
        self.assertEqual((call["scope"], call["line"], call["form"], call["resolution"]),
                         ("test_contract", 2, "attribute", "unresolved"))
        self.assertEqual(result["quality"]["owner"], "existing-module")
        self.assertEqual(result["quality"]["freshness"], "unverified")
        self.assertFalse(result["execution_admitted"])
        self.assertFalse(result["acceptance_verified"])
        self.assertEqual(primary["syntax"]["sha256"], hashlib.sha256((self.root / self.path).read_bytes()).hexdigest())

    def test_related_requires_symbol(self):
        data = aide.build_task_development_brief(self.root, self.task, self.path, related_paths=[self.related])
        self.assertEqual(data["result"], "REFUSED")
        self.assertIn("requires", data["reason"])

    def test_primary_only_does_not_follow_recorded_test_links(self):
        self.write(self.related, "bad syntax (\n")
        data = self.brief()
        self.assertEqual(data["result"], "OBSERVED")
        self.assertEqual([f["path"] for f in data["symbol_inspection"]["files"]], [self.path])
        self.assertEqual(data["symbol_inspection"]["coverage"], "explicit_selected_files_only")

    def test_missing_related_is_partial_not_absence_or_completed_work(self):
        self.status("passed", "remaining_obligations:\n  - downstream_adoption\n")
        data = self.brief(related_paths=["missing.py"])
        self.assertEqual(data["result"], "PARTIAL")
        self.assertEqual(data["symbol_inspection"]["files"][1]["syntax"], {"state": "missing", "match_state": "unknown"})
        self.assertEqual(data["continuation"]["task"]["remaining_obligations"], ["downstream_adoption"])
        self.assertEqual(data["next_action"], "inspect_completed_evidence")

    def test_unparsed_and_unsupported_sources_are_explicit(self):
        self.write("broken.py", "def helper(:\n")
        self.write("notes.txt", "helper()")
        data = self.brief(related_paths=["broken.py", "notes.txt"])
        self.assertEqual(data["result"], "PARTIAL")
        self.assertEqual([f["syntax"]["state"] for f in data["symbol_inspection"]["files"]],
                         ["parsed", "unindexed", "unsupported"])
        self.assertTrue(all(f["syntax"]["match_state"] == "unknown" for f in data["symbol_inspection"]["files"][1:]))

    def test_missing_and_malformed_advisory_ledger_preserve_fresh_syntax(self):
        (self.root / aide.FILE_QUALITY_LEDGER_JSON_PATH).unlink()
        for content, expected in [(None, "MISSING"), ("{bad", "INVALID")]:
            if content is not None:
                self.write(aide.FILE_QUALITY_LEDGER_JSON_PATH, content)
            with self.subTest(expected=expected):
                data = self.brief()
                self.assertEqual(data["result"], "PARTIAL")
                self.assertEqual(data["quality"]["result"], expected)
                self.assertEqual(data["symbol_inspection"]["files"][0]["syntax"]["match_state"], "found")

    def test_invalid_duplicate_and_excessive_paths_refuse(self):
        for paths in [[self.path], [self.path.upper()], ["../outside.py"], [".env.py"],
                      [self.related] * 8, [".aide.local/private.py"]]:
            with self.subTest(paths=paths):
                data = self.brief(related_paths=paths)
                self.assertEqual(data["result"], "REFUSED")
                self.assertNotIn("symbol_inspection", data)

    def test_invalid_identifiers_refuse(self):
        for symbol in ["", "a.b", "def", "\u212a"]:
            with self.subTest(symbol=symbol):
                data = aide.build_task_development_brief(self.root, self.task, self.path, symbol=symbol)
                self.assertEqual(data["result"], "REFUSED")

    def test_task_change_during_inspection_refuses_combined_observation(self):
        original = aide.build_quality_symbol_inspection
        def changed(*args):
            result = original(*args)
            self.status("blocked")
            return result
        with mock.patch.object(aide, "build_quality_symbol_inspection", side_effect=changed):
            data = self.brief()
        self.assertEqual(data["result"], "REFUSED")
        self.assertIn("changed", data["reason"])

    def test_quality_change_between_components_refuses(self):
        original = aide.build_quality_file_explanation
        def changed(*args):
            result = original(*args)
            self.quality["records"][0]["owner"] = "different-owner"
            self.write_quality()
            return result
        with mock.patch.object(aide, "build_quality_file_explanation", side_effect=changed):
            data = self.brief()
        self.assertEqual(data["result"], "REFUSED")
        self.assertIn("quality ledger changed", data["reason"])

    def test_source_change_inside_existing_inspector_refuses(self):
        original = aide.task_view_read
        reads = 0
        def changed(root, path, **kwargs):
            nonlocal reads
            raw = original(root, path, **kwargs)
            if path == self.path:
                reads += 1
                if reads == 1:
                    self.write(self.path, "def helper(): return 2\n")
            return raw
        with mock.patch.object(aide, "task_view_read", side_effect=changed):
            data = self.brief()
        self.assertEqual(data["result"], "REFUSED")
        self.assertNotIn("symbol_inspection", data)

    def test_combined_bound_refuses_without_dropping_fresh_component(self):
        original = aide.build_quality_symbol_inspection
        def large(*args):
            result = original(*args)
            result["caveats"].append("x" * 65536)
            return result
        with mock.patch.object(aide, "build_quality_symbol_inspection", side_effect=large):
            data = self.brief()
        self.assertEqual(data["result"], "REFUSED")
        self.assertIn("64 KiB", data["reason"])

    def test_alias_references_remain_unresolved_without_test_narrowing(self):
        self.write(self.related, "from package import helper as alias\nalias()\n")
        data = self.brief(related_paths=[self.related])
        syntax = data["symbol_inspection"]["files"][1]["syntax"]
        self.assertEqual(syntax["calls"]["items"], [])
        self.assertEqual(syntax["imports"]["items"][0]["resolution"], "declaration_only")
        self.assertIn("do not narrow required checks", " ".join(data["limitations"]))
        self.assertIn("runtime binding", " ".join(data["limitations"]))

    def test_text_locations_and_omissions_are_visible(self):
        self.write(self.path, "def helper(): pass\n" + "helper()\n" * 27)
        data = self.brief()
        text = aide.render_task_development_brief(data)
        self.assertIn("definitions line 1", text)
        self.assertIn("calls line 2", text)
        self.assertIn("omitted source matches: 25", text)
        self.assertEqual(data["symbol_inspection"]["files"][0]["syntax"]["calls"]["omitted"], 7)

    def test_html_preserves_full_observation_and_escapes_fresh_context(self):
        self.quality["records"][0]["owner"] = "<img src=x onerror=alert(1)>"
        self.write_quality()
        data = self.brief(related_paths=[self.related])
        html = aide.task_brief_renderer().render(data)
        page = Page(html)
        self.assertEqual(json.loads("".join(page.parts)), data)
        self.assertIn("Fresh helper evidence", html)
        self.assertIn("&lt;img", html)
        self.assertFalse({tag for tag, _ in page.tags} & {"script", "img", "form", "iframe"})
        self.assertFalse(any(k.startswith("on") or k in {"href", "src", "style", "action"}
                             for _, attrs in page.tags for k in attrs))

    def test_fresh_cli_is_read_only_and_uses_distribution_helpers(self):
        self.write(".aide/scripts/quality_symbols.py", "raise RuntimeError('project helper must not load')\n")
        self.write(self.path, "from pathlib import Path\nPath('executed').write_text('bad')\ndef helper(): pass\n")
        before = self.snapshot()
        args = ["--symbol", "helper", "--related-path", self.related]
        data = json.loads(self.cli(*args, "--json"))
        page = Page(self.cli(*args, "--html").decode("ascii"))
        self.assertEqual(json.loads("".join(page.parts)), data)
        self.assertIn("fresh symbol:", self.cli(*args).decode("ascii"))
        self.assertEqual(before, self.snapshot())

    def test_cli_partial_and_refusal_exit_semantics(self):
        partial = json.loads(self.cli("--symbol", "helper", "--related-path", "missing.py", "--json", expected=2))
        self.assertEqual(partial["result"], "PARTIAL")
        refused = json.loads(self.cli("--related-path", self.related, "--json", expected=1))
        self.assertEqual(refused["result"], "REFUSED")

