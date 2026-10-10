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


class AdapterCompilerTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        return root

    def test_adapter_policy_has_required_anchors(self) -> None:
        policy = aide_lite.read_text(REPO_ROOT / aide_lite.ADAPTER_POLICY_PATH)
        for anchor in [
            "template_compiler_only",
            "generated_or_preview_outputs",
            "no_tool_runtime_calls",
            "no_provider_calls",
            "managed_sections_required: true",
            "generated_outputs_not_canonical: true",
            "no_full_history_prompting",
            "adapter_guidance_must_reference_packets: true",
        ]:
            self.assertIn(anchor, policy)

    def test_targets_and_templates_load(self) -> None:
        targets = aide_lite.load_adapter_targets(REPO_ROOT)
        ids = {target.target_id for target in targets}
        for target_id in ["codex_agents_md", "claude_code", "aider", "cline", "continue", "cursor", "windsurf"]:
            self.assertIn(target_id, ids)
        for target in targets:
            if target.template_path:
                self.assertTrue((REPO_ROOT / target.template_path).exists(), target.template_path)
            if target.output_path:
                self.assertTrue(aide_lite.safe_adapter_output_path(target.output_path), target.output_path)

    def test_adapter_list_output_shape(self) -> None:
        root = self.make_repo()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = aide_lite.main(["--repo-root", str(root), "adapter", "list"])
        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertIn("AIDE Lite adapter list", output)
        self.assertIn("codex_agents_md", output)
        self.assertIn("provider_or_model_calls: none", output)

    def test_adapter_render_creates_outputs_and_manifest(self) -> None:
        root = self.make_repo()
        rendered, writes, drift = aide_lite.render_adapter_outputs(root, write=True)
        self.assertEqual(len(rendered), 7)
        self.assertTrue(any(write.path.name == "manifest.json" for write in writes))
        self.assertTrue((root / aide_lite.ADAPTER_GENERATED_MANIFEST_PATH).exists())
        self.assertTrue((root / aide_lite.ADAPTER_DRIFT_REPORT_PATH).exists())
        manifest = json.loads(aide_lite.read_text(root / aide_lite.ADAPTER_GENERATED_MANIFEST_PATH))
        self.assertTrue(manifest["generated_outputs_not_canonical"])
        self.assertFalse(manifest["provider_or_model_calls"])
        self.assertFalse(manifest["network_calls"])
        self.assertIn("codex_agents_md", {item["target_id"] for item in manifest["targets"]})
        self.assertTrue(any(record["target_id"] == "codex_agents_md" for record in drift))

    def test_generated_outputs_contain_compact_rules_and_no_secret_like_values(self) -> None:
        root = self.make_repo()
        aide_lite.render_adapter_outputs(root, write=True)
        for path in aide_lite.adapter_generated_output_paths(root):
            if path.name in {"manifest.json", "drift-report.md"}:
                continue
            text = aide_lite.read_text(path)
            self.assertIn(".aide/context/latest-task-packet.md", text, str(path))
            self.assertNotIn("paste the full history", text.lower())
            self.assertNotRegex(text, r"sk-[A-Za-z0-9]{16,}")
            self.assertFalse(any(f.severity == "ERROR" for f in aide_lite.scan_secret_text(text, str(path))))

    def test_drift_detects_missing_current_and_drifted_managed_target(self) -> None:
        root = self.make_repo()
        (root / "AGENTS.md").unlink()
        rendered, _writes, drift = aide_lite.render_adapter_outputs(root, write=False)
        missing = {record["target_id"]: record["status"] for record in drift}
        self.assertEqual(missing["codex_agents_md"], "missing")
        aide_lite.write_text(root / "AGENTS.md", "# AGENTS\n\nManual intro.\n")
        aide_lite.adapt_agents(root)
        rendered, _writes, drift = aide_lite.render_adapter_outputs(root, write=False)
        current = {record["target_id"]: record["status"] for record in drift}
        self.assertEqual(current["codex_agents_md"], "current")
        agents = root / "AGENTS.md"
        aide_lite.write_text(agents, aide_lite.read_text(agents).replace("review-pack", "full-history-review"))
        rendered, _writes, drift = aide_lite.render_adapter_outputs(root, write=False)
        drifted = {record["target_id"]: record["status"] for record in drift}
        self.assertEqual(drifted["codex_agents_md"], "drifted")

    def test_generate_preserves_manual_content_and_preview_only_targets(self) -> None:
        root = self.make_repo()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = aide_lite.main(["--repo-root", str(root), "adapter", "generate"])
        self.assertEqual(code, 0)
        agents = aide_lite.read_text(root / "AGENTS.md")
        self.assertIn("Manual intro.", agents)
        self.assertIn("section=aide-token-survival-adapter", agents)
        for rel in ["CLAUDE.md", ".aider.conf.yml", ".clinerules", ".continue/checks/aide-token-survival.md", ".cursor/rules/aide-token-survival.mdc", ".windsurf/rules/aide-token-survival.md"]:
            self.assertFalse((root / rel).exists(), rel)
        self.assertIn("preview_only_targets:", stdout.getvalue())

    def test_adapt_remains_deterministic(self) -> None:
        root = self.make_repo()
        first, _before, _after = aide_lite.adapt_agents(root)
        once = aide_lite.read_text(root / "AGENTS.md")
        second, _before_2, _after_2 = aide_lite.adapt_agents(root)
        twice = aide_lite.read_text(root / "AGENTS.md")
        self.assertEqual(first.action, "appended")
        self.assertEqual(second.action, "unchanged")
        self.assertEqual(once, twice)

    def test_export_pack_includes_adapter_templates_not_generated_previews(self) -> None:
        pack_root = REPO_ROOT / aide_lite.EXPORT_PACK_PATH
        for rel in [
            "files/.aide/policies/adapters.yaml",
            "files/.aide/adapters/targets.yaml",
            "files/.aide/adapters/templates/AGENTS.md.template",
            "files/.aide/adapters/templates/CLAUDE.md.template",
            "files/.aide/adapters/templates/windsurf-rule.template.md",
        ]:
            self.assertTrue((pack_root / rel).exists(), rel)
        self.assertFalse((pack_root / "files/.aide/generated/adapters/manifest.json").exists())
        self.assertFalse((pack_root / "files/.aide/generated/adapters/AGENTS.md").exists())

    def test_selftest_mentions_adapter_checks(self) -> None:
        ok, messages = aide_lite.run_selftest()
        self.assertTrue(ok)
        self.assertTrue(any("provider, adapter, and validate" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
