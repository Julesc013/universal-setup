from __future__ import annotations

import importlib.util
import contextlib
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


class AideLiteWorkflowTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        return root

    def test_portable_pack_excludes_source_only_runtime_tests(self) -> None:
        root = self.make_repo()
        cases = {
            "test_aide_lite.py": True,
            "test_aide_apply_00_transaction_model.py": True,
            "test_aide_apply_01_managed_sections.py": True,
            "test_aide_local_process_execution_host.py": False,
            "test_aide_future_source_worker.py": False,
            "test_continuous_worker_state.py": False,
            "nested/test_aide_lite.py": False,
            "nested/test_aide_source_worker.py": False,
            "nested/test_continuous_worker_state.py": False,
        }
        for name, expected in cases.items():
            relative = ".aide/scripts/tests/" + name
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# harmless test module\n", encoding="utf-8")
            with self.subTest(name=name):
                self.assertEqual(
                    aide_lite.is_exportable_file(root, relative), expected
                )
                self.assertEqual(
                    relative in aide_lite.iter_portable_source_files(root), expected
                )

    def test_pack_boundary_refuses_injected_source_only_tests(self) -> None:
        root = self.make_repo()
        pack = root / "pack-fixture"
        for name in ("test_continuous_worker_state.py", "nested/test_aide_worker.py"):
            path = pack / "files/.aide/scripts/tests" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# harmless test module\n", encoding="utf-8")
        violations = aide_lite.validate_export_pack_boundary(pack)
        self.assertEqual(len(violations), 2)
        self.assertTrue(all("forbidden exported path" in v for v in violations))

    def test_portable_apply_descriptions_match_shipped_modules(self) -> None:
        root = self.make_repo()
        for relative in (
            ".aide/templates/portable-apply/README.md",
            ".aide/templates/portable-apply/__init__.py",
        ):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                (REPO_ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8"
            )
        source = root / "core/apply/README.md"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("Source-only executor is available here.\n", encoding="utf-8")
        pack, _ = aide_lite.build_export_pack(root)
        readme = (pack / "files/core/apply/README.md").read_text(encoding="utf-8")
        self.assertIn("managed_sections.py", readme)
        self.assertIn("not included", readme)
        self.assertNotIn("Source-only executor is available here", readme)
        self.assertFalse((pack / "files/core/apply/transaction_executor.py").exists())
        for relative in ("README.md", "__init__.py"):
            self.assertTrue(
                (pack / "files/.aide/templates/portable-apply" / relative).is_file()
            )

    def test_approximate_token_calculation(self) -> None:
        self.assertEqual(aide_lite.approx_tokens_for_chars(0), 0)
        self.assertEqual(aide_lite.approx_tokens_for_chars(1), 1)
        self.assertEqual(aide_lite.approx_tokens_for_chars(4), 1)
        self.assertEqual(aide_lite.approx_tokens_for_chars(5), 2)

    def test_missing_and_binary_estimate_failures_are_clear(self) -> None:
        root = self.make_repo()
        with self.assertRaisesRegex(ValueError, "file does not exist"):
            aide_lite.estimate_file(root, "missing.txt")
        (root / "blob.bin").write_bytes(b"\x00binary")
        with self.assertRaisesRegex(ValueError, "binary-like"):
            aide_lite.estimate_file(root, "blob.bin")

    def test_ignore_rules_cover_local_state_caches_and_build_outputs(self) -> None:
        patterns = aide_lite.load_ignore_patterns(self.make_repo())
        for rel in [
            ".git/config",
            ".env",
            ".aide.local/state.json",
            "node_modules/pkg/index.js",
            "dist/app.js",
            "build/output.txt",
            "core/harness/__pycache__/module.pyc",
        ]:
            self.assertTrue(aide_lite.is_ignored(rel, patterns), rel)
        self.assertFalse(aide_lite.is_ignored("README.md", patterns))

    def test_snapshot_is_sorted_and_contains_no_raw_file_contents(self) -> None:
        root = self.make_repo()
        result = aide_lite.write_snapshot(root)
        snapshot = json.loads(aide_lite.read_text(result.path))
        paths = [entry["path"] for entry in snapshot["files"]]
        self.assertEqual(paths, sorted(paths))
        self.assertFalse(any(path.startswith(".git/") for path in paths))
        self.assertFalse(any(path.startswith(".aide.local/") for path in paths))
        self.assertFalse(any(path.startswith("node_modules/") for path in paths))
        self.assertFalse(any(path.startswith("build/") for path in paths))
        self.assertTrue(snapshot["summary"]["file_count"] > 0)
        self.assertTrue(snapshot["summary"]["aggregate_approx_tokens"] > 0)
        self.assertTrue(all("contents" not in entry for entry in snapshot["files"]))

    def test_pack_uses_refs_and_reports_budget(self) -> None:
        root = self.make_repo()
        result, rendered = aide_lite.write_task_packet(root, "Implement Q11 Context Compiler v0")
        packet = aide_lite.read_text(result.path)
        for section in aide_lite.PACKET_REQUIRED_SECTIONS:
            self.assertIn(f"## {section}", packet)
        self.assertIn(aide_lite.SNAPSHOT_PATH, packet)
        self.assertNotIn("print('hello')", packet)
        self.assertEqual(rendered.budget_status, "PASS")

    def test_pack_warns_when_hard_budget_is_exceeded(self) -> None:
        root = self.make_repo()
        budget = root / ".aide/policies/token-budget.yaml"
        aide_lite.write_text(
            budget,
            aide_lite.read_text(budget).replace(
                "max_compact_task_packet_tokens: 3200",
                "max_compact_task_packet_tokens: 10",
            ),
        )
        _result, rendered = aide_lite.write_task_packet(root, "Implement Q11 Context Compiler v0")
        self.assertEqual(rendered.budget_status, "WARN")
        self.assertTrue(any("over hard limit" in warning for warning in rendered.warnings))

    def test_adapt_appends_preserves_manual_content_and_is_deterministic(self) -> None:
        root = self.make_repo()
        result, before, after = aide_lite.adapt_agents(root)
        once = aide_lite.read_text(root / "AGENTS.md")
        second, _before, _after = aide_lite.adapt_agents(root)
        twice = aide_lite.read_text(root / "AGENTS.md")
        self.assertEqual(result.action, "appended")
        self.assertEqual(second.action, "unchanged")
        self.assertEqual(before.status, "missing")
        self.assertEqual(after.status, "current")
        self.assertEqual(once, twice)
        self.assertIn("Manual intro.", twice)

    def test_adapt_detects_and_replaces_managed_drift(self) -> None:
        root = self.make_repo()
        aide_lite.adapt_agents(root)
        agents = root / "AGENTS.md"
        aide_lite.write_text(agents, aide_lite.read_text(agents).replace("review-pack", "full-history-review"))
        self.assertEqual(aide_lite.adapter_status(root).status, "drift")
        result, before, after = aide_lite.adapt_agents(root)
        self.assertEqual(result.action, "replaced")
        self.assertEqual(before.status, "drift")
        self.assertEqual(after.status, "current")

    def test_context_compiler_generates_maps_and_packet_refs(self) -> None:
        root = self.make_repo()
        result = aide_lite.run_context(root)
        repo_map = result["repo_map"]
        test_map = result["test_map_data"]
        paths = [entry["path"] for entry in repo_map["files"]]
        self.assertEqual(paths, sorted(paths, key=lambda path: (aide_lite.classify_role(path)[0], path)))
        self.assertIn(".aide/scripts/aide_lite.py", paths)
        self.assertNotIn(".env", paths)
        self.assertTrue(all("contents" not in entry for entry in repo_map["files"]))
        roles = {entry["role"] for entry in repo_map["files"]}
        self.assertIn("script", roles)
        self.assertIn("harness_code", roles)
        aide_mapping = next(item for item in test_map["mappings"] if item["source"] == ".aide/scripts/aide_lite.py")
        self.assertEqual(aide_mapping["confidence"], "high")
        self.assertTrue(aide_mapping["has_existing_candidate"])
        context_packet = aide_lite.read_text(result["context_packet"].path)
        for section in aide_lite.CONTEXT_PACKET_REQUIRED_SECTIONS:
            self.assertIn(f"## {section}", context_packet)
        self.assertIn(aide_lite.REPO_MAP_JSON_PATH, context_packet)
        self.assertNotIn("print('hello')", context_packet)

    def test_line_range_reference_validation(self) -> None:
        root = self.make_repo()
        ok, message = aide_lite.validate_line_ref(root, "README.md#L1-L1")
        self.assertTrue(ok, message)
        malformed, _ = aide_lite.validate_line_ref(root, "README.md")
        self.assertFalse(malformed)
        reversed_range, _ = aide_lite.validate_line_ref(root, "README.md#L2-L1")
        self.assertFalse(reversed_range)

    def test_validate_catches_missing_required_sections(self) -> None:
        root = self.make_repo()
        aide_lite.write_text(root / ".aide/prompts/compact-task.md", "# Broken\n\n## PHASE\n")
        ok, messages = aide_lite.validate_repo(root)
        self.assertFalse(ok)
        self.assertTrue(any("compact task missing section: GOAL" in message for message in messages))

    def test_selftest_passes(self) -> None:
        ok, messages = aide_lite.run_selftest()
        self.assertTrue(ok)
        self.assertTrue(any(message.startswith("PASS internal") for message in messages))

    def test_import_has_no_cli_side_effects(self) -> None:
        module_name = "aide_lite_import_probe"
        spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            assert spec.loader is not None
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                spec.loader.exec_module(module)
        finally:
            sys.modules.pop(module_name, None)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertTrue(callable(module.main))

    def test_test_alias_runs_internal_selftest(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = aide_lite.main(["test"])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("AIDE Lite test", output)
        self.assertIn("status: PASS", output)
        self.assertIn("PASS internal", output)

    def test_test_alias_returns_nonzero_on_internal_failure(self) -> None:
        original = aide_lite.run_selftest

        def failing_selftest() -> tuple[bool, list[str]]:
            raise AssertionError("controlled failure")

        aide_lite.run_selftest = failing_selftest
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                code = aide_lite.main(["test"])
        finally:
            aide_lite.run_selftest = original
        self.assertEqual(code, 1)
        output = buffer.getvalue()
        self.assertIn("AIDE Lite test", output)
        self.assertIn("status: FAIL", output)
        self.assertIn("controlled failure", output)

    def test_command_catalog_mentions_canonical_test_command(self) -> None:
        catalog = aide_lite.read_text(REPO_ROOT / ".aide/commands/catalog.yaml")
        self.assertIn("py -3 .aide/scripts/aide_lite.py test", catalog)
        self.assertIn("canonical AIDE Lite validation command", catalog)


if __name__ == "__main__":
    unittest.main()
