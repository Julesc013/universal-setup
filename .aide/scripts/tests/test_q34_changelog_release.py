from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import importlib.util


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_q34", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q34"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


def run_git(root: Path, *args: str) -> None:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)


def init_fixture_repo(root: Path) -> None:
    run_git(root, "init")
    run_git(root, "config", "user.name", "AIDE Test")
    run_git(root, "config", "user.email", "aide-test@example.invalid")


def commit_fixture(root: Path, filename: str, content: str, message: str) -> None:
    aide_lite.write_text(root / filename, content)
    message_path = root / "COMMIT_MSG"
    aide_lite.write_text(message_path, message)
    run_git(root, "add", filename)
    run_git(root, "commit", "-F", str(message_path))


class Q34ChangelogReleaseTests(unittest.TestCase):
    def test_preview_source_head_follows_selected_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_fixture_repo(root)
            message = aide_lite.COMMIT_GOOD_EXAMPLE
            commit_fixture(root, "first.txt", "first\n", message)
            selected = aide_lite.git_head_commit(root)
            commit_fixture(root, "second.txt", "second\n", message)
            self.assertNotEqual(selected, aide_lite.git_head_commit(root))
            self.assertEqual(aide_lite.make_changelog_preview(root, to_ref=selected, limit=10)["source_head"], selected)
            self.assertEqual(aide_lite.make_changelog_preview(root, revision_range=selected, limit=10)["source_head"], selected)
            self.assertEqual(aide_lite.make_changelog_preview(root, revision_range=selected, to_ref="HEAD", limit=10)["source_head"], selected)
            current = aide_lite.git_head_commit(root)
            self.assertEqual(aide_lite.make_changelog_preview(root, revision_range=f"{selected}..", to_ref=selected, limit=10)["source_head"], current)
            self.assertEqual(aide_lite.make_changelog_preview(root, revision_range=f"{selected}..HEAD", to_ref=selected, limit=10)["source_head"], current)

    def test_parse_valid_conventional_subject(self) -> None:
        parsed = aide_lite.parse_conventional_subject("feat(changelog): add release draft previews")
        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["type"], "feat")
        self.assertEqual(parsed["scope"], "changelog")
        self.assertEqual(parsed["summary"], "add release draft previews")

    def test_parse_breaking_marker(self) -> None:
        parsed = aide_lite.parse_conventional_subject("feat(changelog)!: change release draft schema")
        self.assertTrue(parsed["valid"])
        self.assertTrue(parsed["breaking"])

    def test_parse_structured_body_sections_trailers_and_categories(self) -> None:
        message = aide_lite.COMMIT_GOOD_EXAMPLE.replace(
            "policy(aide): define structured commit recovery",
            "feat(changelog): add release draft previews",
        )
        parsed = aide_lite.parse_commit_for_changelog("abc123456789", "feat(changelog): add release draft previews", message)
        self.assertFalse(parsed["malformed"])
        self.assertIn("## Summary", parsed["sections_present"])
        self.assertEqual(parsed["trailers"]["AIDE-Phase"], "Q27")
        self.assertEqual(parsed["entries"][0]["category"], "Added")
        self.assertIn("commit-message enforcement", parsed["entries"][0]["summary"])

    def test_parse_aide_trailers(self) -> None:
        trailers = aide_lite.parse_commit_trailers(aide_lite.COMMIT_GOOD_EXAMPLE)
        self.assertEqual(trailers["AIDE-Task"], "Q27-commit-discipline-workunit-recovery-v0")
        self.assertEqual(trailers["AIDE-Quality-Gate"], "commit-check-pass")

    def test_detect_malformed_commit_body(self) -> None:
        parsed = aide_lite.parse_commit_for_changelog("bad123", "feat(changelog): missing body", "feat(changelog): missing body\n")
        self.assertTrue(parsed["malformed"])
        self.assertIn("missing_commit_body", parsed["malformed_reasons"])
        self.assertIn("missing_changelog_category", parsed["malformed_reasons"])

    def test_detect_legacy_semi_structured_commit_as_warning(self) -> None:
        message = "docs: old format\n\nWhy: historical note\nWhat changed: prose\nValidation: not structured\n"
        parsed = aide_lite.parse_commit_for_changelog("legacy123", "docs: old format", message)
        self.assertTrue(parsed["malformed"])
        self.assertTrue(parsed["legacy"])
        self.assertIn("legacy_semi_structured_body", parsed["malformed_reasons"])

    def test_handle_merge_commit_as_ignored(self) -> None:
        parsed = aide_lite.parse_commit_for_changelog("merge123", "Merge branch 'task/example'", "Merge branch 'task/example'\n")
        self.assertTrue(parsed["ignored"])
        self.assertFalse(parsed["malformed"])
        self.assertIn("merge_commit_ignored", parsed["warnings"])

    def test_generate_markdown_and_json_previews_from_fixture_repo(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init_fixture_repo(root)
            valid_message = aide_lite.COMMIT_GOOD_EXAMPLE.replace(
                "policy(aide): define structured commit recovery",
                "feat(changelog): add release draft previews",
            )
            commit_fixture(root, "one.txt", "one\n", valid_message)
            commit_fixture(root, "two.txt", "two\n", "update\n\nWhy: legacy note\nValidation: WARN\n")
            data = aide_lite.write_changelog_preview(root, revision_range="HEAD", limit=10)
            self.assertEqual(data["schema_version"], "aide.changelog-preview.v0")
            self.assertGreaterEqual(data["malformed_count"], 1)
            self.assertTrue((root / aide_lite.CHANGELOG_PREVIEW_MD_PATH).exists())
            self.assertTrue((root / aide_lite.RELEASE_NOTES_PREVIEW_MD_PATH).exists())
            self.assertTrue((root / aide_lite.CHANGELOG_PREVIEW_JSON_PATH).exists())
            self.assertTrue((root / aide_lite.RELEASE_NOTES_PREVIEW_JSON_PATH).exists())
            changelog = json.loads(aide_lite.read_text(root / aide_lite.CHANGELOG_PREVIEW_JSON_PATH))
            release = json.loads(aide_lite.read_text(root / aide_lite.RELEASE_NOTES_PREVIEW_JSON_PATH))
            self.assertIn("entries", changelog)
            self.assertIn("highlights", release)
            self.assertTrue(changelog["preview_only"])
            self.assertTrue(release["preview_only"])

    def test_changelog_validate_passes_for_current_repo_outputs(self) -> None:
        # Managed jobs provide an explicit D scratch parent; raw discovery
        # retains its pre-existing standard temporary-directory behavior.
        with tempfile.TemporaryDirectory(prefix="q34-preview-", dir=os.environ.get("AIDE_JOB_TMP")) as temp:
            aide_lite.write_changelog_preview(REPO_ROOT, revision_range="HEAD~1..HEAD",
                                              limit=1, output_dir=temp)
            checks = aide_lite.validate_changelog_outputs(REPO_ROOT, output_dir=temp)
            self.assertNotEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_malformed_report_contains_malformed_fixture(self) -> None:
        malformed = {
            "source_range": "fixture",
            "malformed_count": 1,
            "malformed_commits": [{"commit": "bad123", "subject": "update", "reason": "subject_not_conventional"}],
        }
        rendered = aide_lite.render_malformed_commits_report(malformed)
        self.assertIn("subject_not_conventional", rendered)
        self.assertIn("history_rewritten: false", rendered)

    def test_preview_text_does_not_publish_or_tag(self) -> None:
        data = {
            "source_range": "fixture",
            "source_head": "abc123",
            "commit_count": 0,
            "malformed_count": 0,
            "category_counts": {},
            "categories": {},
            "entries": [],
            "malformed_commits": [],
            "preview_only": True,
        }
        text = aide_lite.render_changelog_preview(data) + aide_lite.render_release_notes_preview(data)
        self.assertIn("Preview only", text)
        self.assertIn("does not create tags", text)
        self.assertIn("GitHub Releases", text)


if __name__ == "__main__":
    unittest.main()
