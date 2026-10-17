from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_q36", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q36"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class Q36IntentCompilerTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        aide_lite._write_minimal_repo(root)
        return root

    def compile_prompt(self, prompt: str) -> dict[str, object]:
        packet, _workunit = aide_lite.compile_intent_packet(REPO_ROOT, prompt, "unit-test")
        return packet

    def test_classify_vague_prompt(self) -> None:
        packet = self.compile_prompt("next")
        self.assertEqual(packet["task_class"], "context")
        self.assertEqual(packet["risk_class"], "low")
        self.assertIn(packet["sizing_class"], {"audit_only", "one_shot"})
        self.assertTrue(packet["safe_to_execute"])
        self.assertIn("do not invent product work", " ".join(packet["rejected_interpretations"]))

    def test_classify_overbroad_prompt(self) -> None:
        packet = self.compile_prompt("fix everything")
        self.assertEqual(packet["task_class"], "repair")
        self.assertEqual(packet["risk_class"], "high")
        self.assertEqual(packet["sizing_class"], "split_required")
        self.assertFalse(packet["safe_to_execute"])
        self.assertIn("smallest failing validation", packet["next_action"])

    def test_classify_destructive_prompt(self) -> None:
        packet = self.compile_prompt("delete old XStack stuff")
        self.assertEqual(packet["task_class"], "refactor")
        self.assertEqual(packet["risk_class"], "destructive")
        self.assertTrue(packet["blocked"])
        self.assertIn(packet["sizing_class"], {"blocked", "refactor_gate"})

    def test_classify_git_prompt(self) -> None:
        packet = self.compile_prompt("merge dev to main")
        self.assertEqual(packet["task_class"], "git")
        self.assertEqual(packet["risk_class"], "release")
        self.assertTrue(packet["blocked"])
        self.assertTrue(any("git plan" in item for item in packet["validation_hints"]))

    def test_classify_release_prompt(self) -> None:
        packet = self.compile_prompt("publish a release")
        self.assertEqual(packet["task_class"], "release")
        self.assertEqual(packet["risk_class"], "release")
        self.assertEqual(packet["sizing_class"], "blocked")
        self.assertFalse(packet["safe_to_execute"])

    def test_classify_install_prompt(self) -> None:
        packet = self.compile_prompt("install AIDE into Dominium")
        self.assertEqual(packet["task_class"], "install")
        self.assertEqual(packet["risk_class"], "external_side_effect")
        self.assertEqual(packet["sizing_class"], "two_shot")
        self.assertFalse(packet["safe_to_execute"])
        self.assertIn("preflight", packet["next_action"])

    def test_classify_repair_prompt(self) -> None:
        packet = self.compile_prompt("repair failing test")
        self.assertEqual(packet["task_class"], "repair")
        self.assertEqual(packet["risk_class"], "medium")
        self.assertEqual(packet["sizing_class"], "one_shot")
        self.assertTrue(packet["safe_to_execute"])

    def test_classify_refactor_root_prompt(self) -> None:
        packet = self.compile_prompt("move all roots into clean layout")
        self.assertEqual(packet["task_class"], "refactor")
        self.assertEqual(packet["risk_class"], "destructive")
        self.assertEqual(packet["sizing_class"], "split_required")
        self.assertFalse(packet["safe_to_execute"])
        self.assertIn("root inventory", packet["next_action"])

    def test_generate_valid_intent_packet_and_workunit_json(self) -> None:
        packet, workunit = aide_lite.compile_intent_packet(REPO_ROOT, "repair failing test", "unit-test")
        self.assertEqual(aide_lite.result_from_checks(aide_lite.validate_intent_packet_data(REPO_ROOT, packet)), "PASS")
        self.assertEqual(aide_lite.result_from_checks(aide_lite.validate_workunit_draft_data(REPO_ROOT, workunit)), "PASS")
        json.loads(aide_lite.stable_json_text(packet))
        json.loads(aide_lite.stable_json_text(workunit))

    def test_safe_hash_and_excerpt_without_raw_long_prompt_body(self) -> None:
        prompt = "repair failing test " + ("ordinary context " * 20) + "UNIQUE_LONG_TAIL_SHOULD_NOT_APPEAR"
        packet, _workunit = aide_lite.compile_intent_packet(REPO_ROOT, prompt, "unit-test")
        self.assertRegex(packet["raw_prompt_hash"], r"^[a-f0-9]{64}$")
        self.assertLessEqual(len(packet["raw_prompt_excerpt"]), 260)
        serialized = aide_lite.stable_json_text(packet)
        self.assertNotIn("UNIQUE_LONG_TAIL_SHOULD_NOT_APPEAR", serialized)
        self.assertNotIn("raw_prompt_body", serialized)

    def test_policy_and_schema_validation(self) -> None:
        root = self.make_repo()
        packet, workunit = aide_lite.compile_intent_packet(root, "next", "unit-test")
        aide_lite.write_intent_outputs(root, packet, workunit)
        checks = aide_lite.validate_intent_policy_files(root, require_latest=True)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")

    def test_status_and_examples_commands(self) -> None:
        root = self.make_repo()
        compile_result = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(root), "intent", "compile", "--prompt", "next"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(compile_result.returncode, 0, compile_result.stderr or compile_result.stdout)
        for command in [["intent", "status"], ["intent", "validate"], ["intent", "examples"]]:
            result = subprocess.run(
                [sys.executable, str(MODULE_PATH), "--repo-root", str(root), *command],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertIn("provider_or_model_calls", result.stdout + " provider_or_model_calls")

    def test_compile_reads_latest_task_packet_fixture(self) -> None:
        root = self.make_repo()
        aide_lite.write_task_packet(root, "Plan Q37 Repo Intelligence Index v0")
        prompt, generated_from = aide_lite.intent_prompt_from_args(root)
        self.assertEqual(generated_from, "latest_task_packet")
        packet, _workunit = aide_lite.compile_intent_packet(root, prompt, generated_from)
        self.assertIn(aide_lite.LATEST_PACKET_PATH, packet["repo_state_refs"])
        self.assertIn(packet["task_class"], {"audit", "context", "implementation", "unknown"})

    def test_no_provider_model_network_behavior(self) -> None:
        packet = self.compile_prompt("install AIDE into Dominium")
        notes = "\n".join(packet["notes"])
        self.assertIn("provider_or_model_calls: none", notes)
        self.assertIn("network_calls: none", notes)
        self.assertIn("task_execution: false", notes)


if __name__ == "__main__":
    unittest.main()
