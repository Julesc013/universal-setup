"""Public compact-message behavior and legacy compatibility."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CLI = ROOT / ".aide/scripts/aide_lite.py"
spec = importlib.util.spec_from_file_location("compact_message_subject", CLI)
aide = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = aide
spec.loader.exec_module(aide)

MESSAGE = """fix(pack): load the installed helper

Installed projects have no source core. Use their owned helper so the
same command works after import.

Validation: PASS - source checks; NOT RUN - native recovery
Changelog: Fixed: Load the helper owned by the installed project
AIDE-Task: EXAMPLE-01
AIDE-Format: compact-v1
"""

class CompactCommunicationTests(unittest.TestCase):
    def result(self, message):
        return aide.commit_message_result(aide.validate_commit_message_text(message))

    def parse(self, message=MESSAGE):
        return aide.parse_commit_for_changelog("a" * 40, message.splitlines()[0], message)

    def test_compact_message_checks_and_projects_without_old_sections(self):
        self.assertEqual(self.result(MESSAGE), "PASS")
        parsed = self.parse()
        self.assertFalse(parsed["malformed"])
        self.assertEqual(parsed["entries"][0]["category"], "Fixed")
        self.assertEqual(parsed["entries"][0]["summary"], "Load the helper owned by the installed project")
        self.assertEqual(parsed["entries"][0]["aide_result"], "")
        self.assertEqual(parsed["entries"][0]["aide_phase"], "")

    def test_optional_scope_and_style_type(self):
        for subject in ("fix: load the installed helper", "style(cli): align terminal output"):
            msg = subject + MESSAGE[MESSAGE.index("\n"):]
            self.assertEqual(self.result(msg), "PASS")

    def test_invalid_type_and_vague_subject_refuse(self):
        for subject in ("random(pack): load the installed helper", "fix(pack): update"):
            self.assertEqual(self.result(subject + MESSAGE[MESSAGE.index("\n"):]), "FAIL")

    def test_unknown_and_case_variant_format_refuse_without_entries(self):
        for value in ("compact-v2", "COMPACT-V1", ""):
            msg = MESSAGE.replace("compact-v1", value)
            self.assertEqual(self.result(msg), "FAIL")
            self.assertEqual(self.parse(msg)["entries"], [])

    def test_duplicate_format_refuses(self):
        for value in ("compact-v1", "compact-v2"):
            msg = MESSAGE + "AIDE-Format: " + value + "\n"
            self.assertEqual(self.result(msg), "FAIL")
            self.assertEqual(self.parse(msg)["entries"], [])

    def test_required_metadata_missing_or_empty_refuses(self):
        for key in ("Validation", "Changelog", "AIDE-Task", "AIDE-Format"):
            for replacement in ("", key + ":"):
                msg = "\n".join(replacement if line.startswith(key + ":") else line
                                for line in MESSAGE.splitlines())
                self.assertEqual(self.result(msg), "FAIL", key)

    def test_duplicate_singletons_refuse(self):
        for key, value in (("Validation", "FAIL - broken"), ("AIDE-Task", "OTHER"),
                           ("Risk", "one"), ("Follow-up", "one"), ("AIDE-Result", "PASS")):
            msg = MESSAGE + ("" if key in ("Validation", "AIDE-Task") else key + ": " + value + "\n")
            self.assertEqual(self.result(msg + key + ": " + value + "\n"), "FAIL", key)

    def test_multiple_changelog_entries_are_retained(self):
        msg = MESSAGE + "Changelog: Docs: Explain the installed route\nChangelog: Fixed: Retain the source route\n"
        parsed = self.parse(msg)
        self.assertEqual(self.result(msg), "PASS")
        self.assertEqual([e["category"] for e in parsed["entries"]], ["Fixed", "Fixed", "Docs"])
        self.assertEqual(sum(map(len, aide.extract_changelog_entries(msg).values())), 3)

    def test_unknown_or_empty_changelog_refuses_whole_compact_record(self):
        for value in ("Other: surprise", "Fixed:", "description without category"):
            msg = MESSAGE + "Changelog: " + value + "\n"
            self.assertEqual(self.result(msg), "FAIL")
            self.assertEqual(self.parse(msg)["entries"], [])

    def test_prose_cannot_be_replaced_with_only_metadata_or_placeholder(self):
        start = MESSAGE.index("Validation:")
        for prose in ("", "TODO", "none"):
            msg = MESSAGE.splitlines()[0] + "\n\n" + prose + "\n\n" + MESSAGE[start:]
            self.assertEqual(self.result(msg), "FAIL")

    def test_subject_blank_separator_required(self):
        self.assertEqual(self.result(MESSAGE.replace("\n\n", "\n", 1)), "FAIL")

    def test_validation_mixed_outcomes_preserved_and_not_promoted(self):
        parsed = self.parse()
        self.assertEqual(parsed["validation"], "PASS - source checks; NOT RUN - native recovery")
        for value in ("PASS", "PASSABLE - tests", "TODO", "UNKNOWN - tests"):
            msg = MESSAGE.replace("PASS - source checks; NOT RUN - native recovery", value)
            self.assertEqual(self.result(msg), "FAIL")
        self.assertEqual(self.result(MESSAGE.replace("PASS - source", "FAIL - source")), "PASS")

    def test_misplaced_metadata_cannot_override_a_failure(self):
        msg = MESSAGE.replace("Installed projects", "Validation: FAIL - observed\n\nInstalled projects")
        self.assertEqual(self.result(msg), "FAIL")
        self.assertEqual(self.parse(msg)["entries"], [])

    def test_breaking_alias_and_continuation_preserve_migration(self):
        msg = MESSAGE.replace("fix(pack):", "fix(pack)!:")
        self.assertEqual(self.result(msg), "FAIL")
        for label in ("BREAKING CHANGE", "BREAKING-CHANGE"):
            updated = msg + label + ": Rename the helper interface\n Migrate callers to the owned helper.\n"
            self.assertEqual(self.result(updated), "PASS")
            entry = self.parse(updated)["entries"][0]
            self.assertTrue(entry["breaking"])
            self.assertIn("Migrate callers", entry["breaking_change"])
        both = msg + "BREAKING CHANGE: one\nBREAKING-CHANGE: two\n"
        self.assertEqual(self.result(both), "FAIL")

    def test_fenced_examples_are_not_format_metadata_or_style_findings(self):
        example = "```text\nAIDE-Format: unknown\n# example\nValidation: FAIL - example\n```\n\n"
        msg = MESSAGE.replace("Installed projects", example + "Installed projects")
        self.assertEqual(self.result(msg), "PASS")
        old = aide.COMMIT_GOOD_EXAMPLE.replace("## Why", example + "## Why")
        self.assertFalse(aide.has_compact_commit_marker(old))
        self.assertEqual(self.result(old), "PASS")

    def test_style_guidance_warns_instead_of_becoming_a_blocker(self):
        for msg in (MESSAGE.replace("Installed projects", "# Background\nInstalled projects"),
                    MESSAGE.replace("Installed projects", "## Background\nInstalled projects"),
                    MESSAGE.replace("load the installed helper", "x" * 80),
                    MESSAGE.replace("load the installed helper", "load the installed helper.")):
            self.assertEqual(self.result(msg), "WARN")
            self.assertFalse(self.parse(msg)["malformed"])
            self.assertTrue(self.parse(msg)["entries"])
        self.assertEqual(self.result(MESSAGE.replace("Installed projects", "### Context\nInstalled projects")), "PASS")

    def test_control_characters_and_known_sensitive_markers_fail(self):
        for value in ("\x00", "\x1b", "OPENAI_API_KEY"):
            self.assertEqual(self.result(MESSAGE.replace("source core", value)), "FAIL")

    def test_no_historical_reinterpretation(self):
        good = aide.COMMIT_GOOD_EXAMPLE
        for msg in (good, good.replace("- Added:", "- Unknown:"), good.replace("## Risks", "## Other")):
            observed = [(c.severity, c.message) for c in aide.validate_commit_message_text(msg)]
            legacy = [(c.severity, c.message) for c in aide.validate_legacy_commit_message_text(msg)]
            self.assertEqual(observed, legacy)
        self.assertEqual(self.result(good), "PASS")
        self.assertEqual(self.result(good.replace("- Added:", "- Unknown:")), "FAIL")

    def test_normalization_changes_only_line_endings(self):
        msg = MESSAGE.replace("\n", "\r\n")
        self.assertEqual(aide.normalize_commit_draft(msg), MESSAGE)
        self.assertEqual(aide.normalize_commit_draft(MESSAGE), MESSAGE)

    def test_git_subject_identity_mismatch_refuses_changelog_entry(self):
        parsed = aide.parse_commit_for_changelog("a" * 40, "fix(pack): different behavior", MESSAGE)
        self.assertTrue(parsed["malformed"])
        self.assertEqual(parsed["entries"], [])

    def test_actual_cli_checks_message_without_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "message.txt"
            path.write_text(MESSAGE, encoding="utf-8")
            before = path.read_bytes()
            result = subprocess.run([sys.executable, "-I", "-B", str(CLI), "--repo-root", str(root),
                "commit", "check", "--message-file", "message.txt"], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("result: PASS", result.stdout)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual([p.name for p in root.iterdir()], ["message.txt"])

    def test_actual_git_mixed_history_preview_retains_old_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, text=True, encoding="utf-8").strip()
            git("init", "-q")
            git("config", "user.name", "AIDE fixture")
            git("config", "user.email", "fixture@example.invalid")
            messages = [aide.COMMIT_GOOD_EXAMPLE, MESSAGE,
                        aide.COMMIT_GOOD_EXAMPLE.replace("- Added:", "- Unknown:")]
            oids = []
            for index, msg in enumerate(messages):
                (root / "file.txt").write_text(str(index), encoding="utf-8")
                (root / "message.txt").write_text(msg, encoding="utf-8")
                git("add", "file.txt")
                git("commit", "-q", "-F", "message.txt")
                oids.append(git("rev-parse", "HEAD"))
            preview = aide.make_changelog_preview(root, limit=10)
            self.assertEqual(preview["commit_count"], 3)
            self.assertEqual(preview["malformed_count"], 1)
            self.assertEqual(preview["malformed_commits"][0]["commit_sha"], oids[2])
            fixed = preview["categories"]["Fixed"]
            self.assertEqual(len(fixed), 1)
            self.assertEqual(fixed[0]["commit_sha"], oids[1])
            self.assertIn("NOT RUN", fixed[0]["validation"])
            self.assertFalse(preview["release_publishing"])
            self.assertEqual(git("rev-parse", "HEAD"), oids[-1])

    def test_metadata_extensions_preserved_without_fabricated_defaults(self):
        parsed = self.parse(MESSAGE + "Refs: project-123\nCo-authored-by: Example <example@example.invalid>\n")
        self.assertEqual(parsed["trailers"]["Refs"], "project-123")
        self.assertEqual(parsed["risks"], "")
        self.assertEqual(parsed["follow_up"], "")


    def test_complete_compact_facts_survive_json_and_markdown_previews(self):
        msg = MESSAGE.replace("fix(pack):", "fix(pack)!:").replace(
            "PASS - source checks; NOT RUN - native recovery",
            "PASS - source checks\n NOT RUN - native recovery")
        msg += ("Risk: project migration pending\n Existing consumers need recovery checks.\n"
                "Follow-up: qualify installed upgrade\n Preserve direct project edits.\n"
                "BREAKING CHANGE: Rename the helper API\n Migrate callers before rollout.\n")
        parsed = self.parse(msg)
        self.assertFalse(parsed["malformed"])
        data = {"entries": parsed["entries"], "categories": {"Fixed": parsed["entries"]},
                "source_range": "fixture", "source_head": "a" * 40}
        release = aide.make_release_notes_preview_data(data)
        outputs = [json.dumps(release), aide.render_release_notes_preview(data, release),
                   aide.render_changelog_preview(data)]
        for output in outputs:
            for detail in ("NOT RUN - native recovery", "Existing consumers need recovery checks.",
                           "Preserve direct project edits.", "Migrate callers before rollout."):
                self.assertIn(detail, output)
        old = aide.parse_commit_for_changelog("b" * 40, aide.COMMIT_GOOD_EXAMPLE.splitlines()[0],
                                             aide.COMMIT_GOOD_EXAMPLE)
        self.assertNotIn("breaking_changes", aide.make_release_notes_preview_data({"entries": old["entries"]}))

    def test_default_git_comment_suffix_retained_with_heading_warnings(self):
        suffix = "\n# Please enter the commit message\n#\n\n# Changes to be committed:\n"
        parsed, checks = aide.parse_compact_commit(MESSAGE + suffix)
        self.assertEqual(aide.result_from_checks(checks), "WARN")
        self.assertIn("# Changes to be committed:", parsed["trailing_comments"])
        self.assertEqual(self.parse(MESSAGE + suffix)["validation"], self.parse()["validation"])
        self.assertEqual(self.result(MESSAGE + suffix + "Validation: FAIL - late value\n"), "FAIL")
        self.assertEqual(self.result(MESSAGE.replace("Changelog: Fixed:", "Changelog: Invalid:") + suffix), "FAIL")
        self.assertEqual(self.result("# only comments\nAIDE-Format: compact-v1\n"), "FAIL")

    def test_actual_default_hook_and_editor_comment_draft(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, text=True,
                                               encoding="utf-8", stderr=subprocess.STDOUT).strip()
            git("init", "-q")
            git("config", "user.name", "AIDE fixture")
            git("config", "user.email", "fixture@example.invalid")
            cli = root / ".aide/scripts/aide_lite.py"
            hook = root / ".aide/hooks/commit-msg"
            cli.parent.mkdir(parents=True)
            hook.parent.mkdir(parents=True)
            cli.write_bytes(CLI.read_bytes())
            hook.write_bytes((ROOT / ".aide/hooks/commit-msg").read_bytes())
            hook.chmod(0o755)
            git("config", "core.hooksPath", ".aide/hooks")
            draft = root / "message.txt"
            draft.write_text(MESSAGE + "\n# Please enter the commit message\n#\n\n# Changes to be committed:\n",
                             encoding="utf-8")
            original = draft.read_bytes()
            result = subprocess.run([sys.executable, "-I", "-B", str(cli), "--repo-root", str(root),
                "commit", "check", "--message-file", "message.txt"], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("result: WARN", result.stdout)
            self.assertEqual(draft.read_bytes(), original)
            (root / "source.txt").write_text("fixture", encoding="utf-8")
            git("add", "source.txt")
            git("commit", "-q", "--cleanup=strip", "-F", "message.txt")
            actual = git("log", "-1", "--format=%B") + "\n"
            self.assertEqual(actual, MESSAGE)
            self.assertEqual(self.result(actual), "PASS")


if __name__ == "__main__":
    unittest.main()
