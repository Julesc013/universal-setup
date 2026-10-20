from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
CLI = ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_symbol_tests", CLI)
aide = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = aide
SPEC.loader.exec_module(aide)


class SymbolDiscoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, path, raw):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw.encode("utf-8") if isinstance(raw, str) else raw)

    def inspect(self, name="helper", paths=None):
        return aide.build_quality_symbol_inspection(self.root, name, paths or ["source.py"])

    def cli(self, *args, expected=0):
        env = os.environ.copy()
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        result = subprocess.run([sys.executable, "-I", str(CLI), "--repo-root", str(self.root),
            "quality", "inspect-symbol", *args], capture_output=True, env=env)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertFalse(result.stderr)
        return result.stdout

    def ledger(self, **fields):
        record = {"path": "source.py", "kind": "source", "status": "active", "owner": "project",
                  "quality_level": "warn", "recommended_next_action": "inspect",
                  "docs_refs": ["docs/guide.md"], "test_refs": ["tests/test_source.py"],
                  "dependency_refs": [], "warnings": [], "exemptions": [], **fields}
        value = {"schema_version": "aide.file-quality-ledger.v0", "source_commit": "old-recorded-revision",
                 "records": [record]}
        self.write(aide.FILE_QUALITY_LEDGER_JSON_PATH, json.dumps(value))
        return value

    def test_nested_async_decorated_definitions_and_parameters(self):
        self.write("source.py", "@decorate\nasync def helper(a, /, b=99, *args, c=123, **kwargs):\n"
                   "    class Container:\n        def helper(self):\n            return 99\n"
                   "    return a\n")
        result = self.inspect()["files"][0]["syntax"]
        definitions = result["definitions"]["items"]
        self.assertEqual([(d["qualified_name"], d["kind"], d["line"], d["end_line"])
                         for d in definitions],
                         [("helper", "async_function", 2, 6), ("helper.Container.helper", "function", 4, 5)])
        self.assertTrue(definitions[0]["decorated"])
        self.assertEqual([p["kind"] for p in definitions[0]["parameters"]["items"]],
                         ["positional_only", "positional_or_keyword", "variadic_positional",
                          "keyword_only", "variadic_keyword"])
        self.assertNotIn("99", json.dumps(definitions))
        self.assertNotIn("123", json.dumps(definitions))

    def test_syntax_calls_do_not_claim_runtime_resolution(self):
        self.write("source.py", "def outer():\n    helper()\n    object.helper()\n"
                   "    helper = other\n    helper()\n    return lambda: helper()\n")
        calls = self.inspect()["files"][0]["syntax"]["calls"]["items"]
        self.assertEqual([c["line"] for c in calls], [2, 3, 5, 6])
        self.assertEqual([c["form"] for c in calls], ["name", "attribute", "name", "name"])
        self.assertEqual(calls[-1]["scope"], "outer.<lambda>")
        self.assertTrue(all(c["resolution"] == "unresolved" for c in calls))

    def test_import_alias_declarations_not_alias_resolution(self):
        self.write("source.py", "from package import helper as alias\nalias()\n"
                   "from package import other as helper\nimport package.helper\nimport other as helper\n")
        syntax = self.inspect()["files"][0]["syntax"]
        self.assertEqual(len(syntax["imports"]["items"]), 4)
        self.assertEqual(syntax["imports"]["items"][0]["alias"], "alias")
        self.assertEqual(syntax["calls"]["items"], [])

    def test_comments_strings_and_bodies_are_not_disclosed(self):
        self.write("source.py", '# def helper(): helper()\ntext = "helper() def helper() private value"\n')
        syntax = self.inspect()["files"][0]["syntax"]
        self.assertEqual(syntax["match_state"], "not_found")
        self.assertNotIn("private value", json.dumps(syntax))

    def test_class_definition_and_header_call_scope(self):
        self.write("source.py", "@helper()\nclass helper(base=helper()):\n    def inner(self, x=helper()):\n"
                   "        helper()\n")
        syntax = self.inspect()["files"][0]["syntax"]
        self.assertEqual(syntax["definitions"]["items"][0]["kind"], "class")
        by_line = {c["line"]: c["scope"] for c in syntax["calls"]["items"]}
        self.assertEqual(by_line, {1: "<module>", 2: "<module>", 3: "helper", 4: "helper.inner"})

    def test_unicode_and_pyi(self):
        self.write("api.pyi", "def caf\u00e9(value: str) -> str: ...\n")
        observed = self.inspect("caf\u00e9", ["api.pyi"])["files"][0]["syntax"]
        self.assertEqual(observed["definitions"]["items"][0]["name"], "caf\u00e9")
        self.assertEqual(observed["sha256"], hashlib.sha256((self.root / "api.pyi").read_bytes()).hexdigest())
        self.assertIn("version", observed["parser"])
        cli_json = json.loads(self.cli("caf\u00e9", "--path", "api.pyi", "--json"))
        self.assertEqual(cli_json["symbol"], "caf\u00e9")
        human = self.cli("caf\u00e9", "--path", "api.pyi").decode("ascii")
        self.assertIn('caf\\u00e9', human)

    def test_invalid_identifier_and_normalization_refused(self):
        self.write("source.py", "pass\n")
        for name in ["", "a.b", "def", "has space", "x" * 257, "\u212a"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.inspect(name)

    def test_missing_unsupported_and_invalid_are_not_absence(self):
        self.write("broken.py", "def helper(:\n")
        self.write("bytes.py", b"\xff")
        self.write("other.txt", "def helper(): pass\n")
        result = self.inspect(paths=["absent.py", "broken.py", "bytes.py", "other.txt"])
        self.assertEqual(result["result"], "PARTIAL")
        self.assertEqual([f["syntax"]["state"] for f in result["files"]],
                         ["missing", "unindexed", "unindexed", "unsupported"])
        self.assertTrue(all(f["syntax"]["match_state"] == "unknown" for f in result["files"]))

    def test_missing_and_malformed_ledger_do_not_hide_syntax(self):
        self.write("source.py", "def helper(): pass\n")
        for raw, state in [(None, "missing"), ("{", "invalid"), ("[]", "invalid"),
                           ('{"schema_version":"future"}', "invalid")]:
            if raw is not None:
                self.write(aide.FILE_QUALITY_LEDGER_JSON_PATH, raw)
            result = self.inspect()
            self.assertEqual(result["result"], "PASS")
            self.assertEqual(result["files"][0]["recorded_context"]["state"], state)
            self.assertEqual(result["files"][0]["syntax"]["match_state"], "found")

    def test_recorded_owner_and_tests_remain_unverified(self):
        self.write("source.py", "def helper(): pass\n")
        self.ledger()
        context = self.inspect()["files"][0]["recorded_context"]
        self.assertEqual(context["state"], "recorded")
        self.assertEqual(context["freshness"], "unverified")
        self.assertEqual(context["evidence"]["owner"], "project")
        self.assertEqual(context["evidence"]["relations"]["test_refs"]["items"], ["tests/test_source.py"])

    def test_matches_and_parameters_have_omitted_counts(self):
        self.write("source.py", "def helper(" + ",".join("p" + str(i) for i in range(40))
                   + "): pass\n" + "helper()\n" * 27)
        syntax = self.inspect()["files"][0]["syntax"]
        self.assertEqual(len(syntax["calls"]["items"]), 20)
        self.assertEqual(syntax["calls"]["omitted"], 7)
        self.assertEqual(syntax["definitions"]["items"][0]["parameters"]["omitted"], 8)

    def test_paths_count_duplicates_private_and_traversal_refused(self):
        self.write("source.py", "pass\n")
        for paths in [[], ["source.py"] * 9, ["source.py", "SOURCE.py"], ["../source.py"],
                      [".env.py"], [".git/config"], ["a/../../source.py"], ["source.py:stream"],
                      ["source.py\n"], ["./source.py"]]:
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                aide.build_quality_symbol_inspection(self.root, "helper", paths)

    def test_per_file_and_total_read_bounds(self):
        self.write("large.py", b"#" * (4 * 1024 * 1024 + 1))
        with self.assertRaises(ValueError):
            self.inspect(paths=["large.py"])
        (self.root / "large.py").unlink()
        for name in ["a.py", "b.py", "c.py"]:
            self.write(name, b"#" * (3 * 1024 * 1024))
        with self.assertRaisesRegex(ValueError, "8 MiB"):
            self.inspect(paths=["a.py", "b.py", "c.py"])

    def test_hardlinked_source_refused(self):
        self.write("source.py", "pass\n")
        os.link(self.root / "source.py", self.root / "alias.py")
        with self.assertRaises(ValueError):
            self.inspect()

    def test_reparse_metadata_refused(self):
        self.write("source.py", "pass\n")
        original = Path.lstat
        class Linked:
            st_mode = 0o100644
            st_file_attributes = 0x400
        def inspect(path, *args, **kwargs):
            if path == self.root / "source.py":
                return Linked()
            return original(path, *args, **kwargs)
        with patch.object(Path, "lstat", inspect), self.assertRaises(ValueError):
            self.inspect()

    def test_source_change_during_read_refused(self):
        self.write("source.py", "def helper(): pass\n")
        original = aide.task_view_read
        calls = 0
        def changing(root, path, **kwargs):
            nonlocal calls
            data = original(root, path, **kwargs)
            if path == "source.py":
                calls += 1
                if calls == 1:
                    self.write("source.py", "def helper(): return 1\n")
            return data
        with patch.object(aide, "task_view_read", changing), self.assertRaisesRegex(ValueError, "changed"):
            self.inspect()

    def test_missing_source_appearing_during_read_refused(self):
        original = aide.task_view_read
        def appearing(root, path, **kwargs):
            try:
                return original(root, path, **kwargs)
            except FileNotFoundError:
                if path == "source.py":
                    self.write(path, "def helper(): pass\n")
                raise
        with patch.object(aide, "task_view_read", appearing), self.assertRaisesRegex(ValueError, "changed"):
            self.inspect()

    def test_ledger_change_during_read_refused(self):
        self.write("source.py", "pass\n")
        self.ledger()
        original = aide.task_view_read
        count = 0
        def changing(root, path, **kwargs):
            nonlocal count
            raw = original(root, path, **kwargs)
            if path == aide.FILE_QUALITY_LEDGER_JSON_PATH:
                count += 1
                if count == 1:
                    self.ledger(owner="changed")
            return raw
        with patch.object(aide, "task_view_read", changing), self.assertRaisesRegex(ValueError, "ledger changed"):
            self.inspect()

    def test_fresh_cli_json_and_text_are_read_only_and_do_not_execute_project(self):
        self.write("source.py", "from pathlib import Path\nPath('executed').write_text('bad')\n"
                   "def helper(): pass\n")
        self.write(".aide/scripts/quality_symbols.py", "raise RuntimeError('wrong helper')\n")
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        result = json.loads(self.cli("helper", "--path", "source.py", "--json"))
        self.assertEqual(result["files"][0]["syntax"]["definitions"]["items"][0]["line"], 3)
        text = self.cli("helper", "--path", "source.py").decode("ascii")
        self.assertIn("source_sha256:", text)
        self.assertIn("runtime binding", text)
        after = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(after, before)

    def test_cli_partial_and_refusal(self):
        self.assertEqual(json.loads(self.cli("helper", "--path", "absent.py", "--json", expected=1))["result"], "PARTIAL")
        self.assertEqual(json.loads(self.cli("helper", "--path", "../outside.py", "--json", expected=2))["result"], "REFUSED")

    def test_oversized_output_refuses_without_truncation(self):
        self.write("source.py", "def helper(): pass\n")
        self.ledger(owner="x" * (70 * 1024))
        for flag in [[], ["--json"]]:
            raw = self.cli("helper", "--path", "source.py", *flag, expected=2)
            self.assertLess(len(raw), 1024)
            self.assertIn(b"output exceeds 64 KiB", raw)


if __name__ == "__main__":
    unittest.main()
