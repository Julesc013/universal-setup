from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from contextlib import ExitStack
from argparse import Namespace
from io import StringIO
import tempfile
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_q48", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q48"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class Q48GitHubReleaseDraftTests(unittest.TestCase):
    def make_repo(self) -> Path:
        stack = ExitStack()
        self.addCleanup(stack.close)
        root = Path(stack.enter_context(aide_lite.public_archive_fixture("aide-public-release-test-")))
        for rel in [*aide_lite.Q47_POLICY_FILES, *aide_lite.Q47_SCHEMA_FILES, *aide_lite.Q48_POLICY_FILES, *aide_lite.Q48_SCHEMA_FILES, aide_lite.RELEASE_README_PATH]:
            source = REPO_ROOT / rel
            self.write(root, rel, source.read_text(encoding="utf-8"))
        self.write(root, ".gitignore", ".aide.local/\n.aide.local/**\n.env\nsecrets/\n")
        self.write(root, aide_lite.CHANGELOG_PREVIEW_MD_PATH, "# AIDE Changelog Preview\n\nsource_head: fixture-commit\n- Added: fixture changelog entry.\n")
        self.write(root, aide_lite.RELEASE_NOTES_PREVIEW_MD_PATH, "# AIDE Release Notes Preview\n\nsource_head: fixture-commit\n- Fixture release note.\n")
        self.write(root, aide_lite.CHANGELOG_PREVIEW_JSON_PATH, aide_lite.stable_json_text({"source_head": "fixture-commit"}))
        self.write(root, aide_lite.RELEASE_NOTES_PREVIEW_JSON_PATH, aide_lite.stable_json_text({"source_head": "fixture-commit"}))
        self.write_pack(root)
        aide_lite.build_release_bundle_outputs(root)
        return root

    def write(self, root: Path, rel: str, text: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def write_pack(self, root: Path) -> None:
        pack_root = aide_lite.export_pack_root(root, aide_lite.EXPORT_PACK_ID)
        self.write(root, f"{aide_lite.EXPORT_PACK_PATH}/README.md", "# Pack\n")
        self.write(root, f"{aide_lite.EXPORT_PACK_PATH}/install.md", "# Install\n")
        self.write(root, f"{aide_lite.EXPORT_PACK_PATH}/import-policy.yaml", "schema_version: fixture.import.v0\n")
        self.write(root, f"{aide_lite.EXPORT_PACK_PATH}/export-report.md", "# Export Report\n")
        self.write(root, f"{aide_lite.EXPORT_PACK_FILES_ROOT}/.aide/scripts/aide_lite.py", "# portable script\n")
        self.write(root, f"{aide_lite.EXPORT_PACK_FILES_ROOT}/docs/reference/aide-lite.md", "# AIDE Lite\n")
        self.write(
            root,
            f"{aide_lite.EXPORT_PACK_PATH}/manifest.yaml",
            "\n".join([
                "schema_version: q25.aide-lite-pack-manifest.v1",
                "pack_id: aide-lite-pack-v0",
                "source_repo: fixture/aide",
                "source_commit: fixture-commit",
                "source_dirty_state: true",
                "files:",
                "  - files/.aide/scripts/aide_lite.py",
                "  - files/docs/reference/aide-lite.md",
            ]) + "\n",
        )
        checksums = aide_lite.build_pack_checksums(pack_root)
        self.write(root, f"{aide_lite.EXPORT_PACK_PATH}/checksums.json", aide_lite.stable_json_text(checksums))

    def run_cmd(self, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(root), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_policy_and_schema_validation(self) -> None:
        root = self.make_repo()
        checks = aide_lite.validate_github_release_draft_files(root, require_outputs=False)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")

    def test_fixture_bundle_produces_draft_markdown_and_json(self) -> None:
        root = self.make_repo()
        draft = aide_lite.build_github_release_draft_outputs(root)
        self.assertTrue((root / aide_lite.GITHUB_RELEASE_DRAFT_MD_PATH).exists())
        self.assertTrue((root / aide_lite.GITHUB_RELEASE_DRAFT_JSON_PATH).exists())
        self.assertTrue(draft["no_publish"])
        self.assertIn("not published", draft["release_body_markdown"].lower())
        self.assertIn("aide-lite-pack-v0-draft-", draft["suggested_tag"])

    def test_draft_distinguishes_legacy_planners_from_exact_plan_apply(self) -> None:
        root = self.make_repo()
        draft = aide_lite.build_github_release_draft_outputs(root)
        body = draft["release_body_markdown"]
        self.assertNotIn("remain plan/dry-run models", body)
        self.assertNotIn("remain preservation-first planning surfaces", body)
        self.assertIn("Q43-Q46", body)
        self.assertIn("exact-plan", body)
        self.assertIn("final profile qualification", body)
        self.assertIn("Local draft only", body)
        self.assertTrue(draft["no_publish"])

    def test_assets_include_hashes_and_upload_plan_is_no_upload(self) -> None:
        root = self.make_repo()
        aide_lite.build_github_release_draft_outputs(root)
        assets = json.loads((root / aide_lite.GITHUB_RELEASE_ASSETS_JSON_PATH).read_text(encoding="utf-8"))
        self.assertGreaterEqual(assets["asset_count"], 8)
        for asset in assets["assets"]:
            if asset["validation_status"] == "present":
                self.assertTrue(asset["sha256"])
                self.assertGreater(asset["size_bytes"], 0)
        plan = json.loads((root / aide_lite.GITHUB_RELEASE_UPLOAD_PLAN_JSON_PATH).read_text(encoding="utf-8"))
        self.assertTrue(plan["no_upload"])
        self.assertIn("upload_release_asset", plan["blocked_actions"])

    def test_missing_required_asset_creates_blocker(self) -> None:
        root = self.make_repo()
        (root / aide_lite.RELEASE_ZIP_PATH).unlink()
        aide_lite.build_github_release_draft_outputs(root)
        validation = json.loads((root / aide_lite.GITHUB_RELEASE_DRAFT_VALIDATION_JSON_PATH).read_text(encoding="utf-8"))
        self.assertEqual(validation["result"], "FAIL")
        self.assertTrue(any("required release asset is not publishable" in blocker or "required asset missing" in blocker for blocker in validation["blockers"]))

    def test_stale_previews_are_not_publish_candidates(self) -> None:
        root = self.make_repo()
        self.write(root, aide_lite.CHANGELOG_PREVIEW_MD_PATH, "# AIDE Changelog Preview\n\nsource_head: stale-commit\n")
        self.write(root, aide_lite.RELEASE_NOTES_PREVIEW_MD_PATH, "# AIDE Release Notes Preview\n\nsource_head: stale-commit\n")
        aide_lite.build_release_bundle_outputs(root)
        aide_lite.build_github_release_draft_outputs(root)
        assets = json.loads((root / aide_lite.GITHUB_RELEASE_ASSETS_JSON_PATH).read_text(encoding="utf-8"))["assets"]
        preview_assets = [asset for asset in assets if asset["kind"] in {"changelog_preview_copy", "release_notes_preview_copy"}]
        self.assertEqual(len(preview_assets), 2)
        self.assertTrue(all(asset["validation_status"] == "blocked_stale" for asset in preview_assets))
        self.assertTrue(all(asset["publish_candidate"] is False for asset in preview_assets))
        checks = aide_lite.validate_github_release_draft_files(root, require_outputs=True)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_missing_preview_json_blocks_draft_and_draft_validate(self) -> None:
        preview_pairs = [
            (aide_lite.CHANGELOG_PREVIEW_JSON_PATH, aide_lite.RELEASE_CHANGELOG_PREVIEW_PATH),
            (aide_lite.RELEASE_NOTES_PREVIEW_JSON_PATH, aide_lite.RELEASE_RELEASE_NOTES_PREVIEW_PATH),
        ]
        for source_json, destination in preview_pairs:
            with self.subTest(source_json=source_json):
                root = self.make_repo()
                (root / source_json).unlink()
                bundle = self.run_cmd(root, "release", "bundle")
                self.assertEqual(bundle.returncode, 1, bundle.stdout + bundle.stderr)
                copied = (root / destination).read_text(encoding="utf-8")
                self.assertIn("status: blocked_stale_source_preview", copied)
                self.assertIn(f"source preview JSON missing at {source_json}", copied)
                self.assertIn("publish_candidate: false", copied)
                draft = self.run_cmd(root, "release", "draft")
                self.assertEqual(draft.returncode, 1, draft.stdout + draft.stderr)
                assets = json.loads((root / aide_lite.GITHUB_RELEASE_ASSETS_JSON_PATH).read_text(encoding="utf-8"))["assets"]
                preview_assets = [asset for asset in assets if asset["path"] == destination]
                self.assertEqual(len(preview_assets), 1)
                self.assertEqual(preview_assets[0]["validation_status"], "blocked_stale")
                self.assertFalse(preview_assets[0]["publish_candidate"])
                draft_validate = self.run_cmd(root, "release", "draft-validate")
                self.assertEqual(draft_validate.returncode, 1, draft_validate.stdout + draft_validate.stderr)
                self.assertIn("result: FAIL", draft_validate.stdout)

    def test_draft_provenance_uses_pack_identity_not_checkout_path(self) -> None:
        root = self.make_repo()
        draft = aide_lite.build_github_release_draft_outputs(root)
        provenance = json.loads((root / aide_lite.RELEASE_PROVENANCE_JSON_PATH).read_text(encoding="utf-8"))
        self.assertEqual(draft["source_repo"], "fixture/aide")
        self.assertEqual(provenance["source_repo"], "fixture/aide")
        self.assertNotIn(str(root), json.dumps(draft, sort_keys=True))
        self.assertNotIn(str(root), json.dumps(provenance, sort_keys=True))

    def test_publication_boundary_is_false_and_advisory_only(self) -> None:
        root = self.make_repo()
        aide_lite.build_github_release_draft_outputs(root)
        boundary = aide_lite.github_release_boundary_data()
        for key in ["tag_created", "github_release_created", "upload_performed", "network_api_call", "branch_mutation", "active_ci_installed"]:
            self.assertFalse(boundary[key])
        result = self.run_cmd(root, "release", "publication-boundary")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no_publish: true", result.stdout)

    def test_draft_validate_rejects_implied_published_state(self) -> None:
        root = self.make_repo()
        aide_lite.build_github_release_draft_outputs(root)
        draft_path = root / aide_lite.GITHUB_RELEASE_DRAFT_JSON_PATH
        draft = json.loads(draft_path.read_text(encoding="utf-8"))
        draft["no_publish"] = False
        draft_path.write_text(json.dumps(draft), encoding="utf-8")
        checks = aide_lite.validate_github_release_draft_files(root, require_outputs=True)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_draft_validate_rejects_checksum_mismatch(self) -> None:
        root = self.make_repo()
        aide_lite.build_github_release_draft_outputs(root)
        self.write(root, aide_lite.RELEASE_INSTALL_NOTES_PATH, "# tampered\n")
        checks = aide_lite.validate_github_release_draft_files(root, require_outputs=True)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")
        self.assertTrue(any("checksum mismatch" in check.message for check in checks))

    def test_commands_generate_local_only_outputs(self) -> None:
        root = self.make_repo()
        for args in [
            ("release", "draft"),
            ("release", "draft-validate"),
            ("release", "draft-status"),
            ("release", "upload-plan"),
            ("release", "checklist"),
            ("release", "publication-boundary"),
        ]:
            result = self.run_cmd(root, *args)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("no_publish: true", result.stdout)
        self.assertTrue((root / aide_lite.GITHUB_RELEASE_DRAFT_MD_PATH).exists())
        self.assertTrue((root / aide_lite.GITHUB_RELEASE_DRAFT_VALIDATION_JSON_PATH).exists())


class Q48ChecklistProjectionTests(unittest.TestCase):
    def make_repo(self) -> Path:
        stack = ExitStack()
        self.addCleanup(stack.close)
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="aide-checklist-")))
        for rel in [*aide_lite.Q48_POLICY_FILES, *aide_lite.Q48_SCHEMA_FILES]:
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((REPO_ROOT / rel).read_bytes())
        for name, value in [("source_commit", "fixture-commit"), ("source_branch", "fixture"), ("dirty_state", False)]:
            stack.enter_context(patch.object(aide_lite, "github_release_" + name, return_value=value))
        return root

    def set_policy(self, root: Path, text: str) -> None:
        (root / aide_lite.RELEASE_CHECKLIST_POLICY_PATH).write_text(text, encoding="utf-8")

    def save_checklist(self, root: Path, data: dict) -> None:
        path = root / aide_lite.GITHUB_RELEASE_CHECKLIST_JSON_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")

    def test_current_policy_exposes_documentation_and_download_obligations(self) -> None:
        root = self.make_repo()
        data = aide_lite.github_release_checklist_data(root, [], [])
        for item in [
            "reconcile README, relevant docs, TODO, PLANS, ROADMAP and CHANGELOG for the exact tag",
            "distinguish released, qualified-unpublished, development and remaining work",
            "review release body without duplicated title or manual prose wrapping",
            "review human download labels and stable filenames",
        ]:
            self.assertIn(item, data["manual_review_required"])
        self.assertEqual(data["schema_version"], "aide.github-release-checklist.v0")
        self.assertTrue(data["no_publish"])

    def test_project_items_keep_their_order_and_replace_defaults(self) -> None:
        root = self.make_repo()
        self.set_policy(root, "manual_review_items:\n  # Project-owned checks\n  - 'Inspect native ABI'\n  - \"Review caf\u00e9 encoding\"\nnext_section:\n  - not a review item\n")
        data = aide_lite.github_release_checklist_data(root, [], [])
        self.assertEqual(data["manual_review_required"], ["Inspect native ABI", "Review caf\u00e9 encoding"])

    def test_missing_empty_and_blank_items_block_without_mutating_inputs(self) -> None:
        root = self.make_repo()
        policy = root / aide_lite.RELEASE_CHECKLIST_POLICY_PATH
        for text in [None, "manual_review_items: []\n", "manual_review_items:\n", 'manual_review_items:\n  - ""\n']:
            with self.subTest(text=text):
                if text is None:
                    policy.unlink()
                else:
                    self.set_policy(root, text)
                blockers, warnings = ["retained blocker"], ["retained warning"]
                data = aide_lite.github_release_checklist_data(root, blockers, warnings)
                self.assertEqual(data["manual_review_required"], [])
                self.assertTrue(any("no manual review items" in item for item in data["blockers"]))
                self.assertEqual(blockers, ["retained blocker"])
                self.assertEqual(warnings, ["retained warning"])
                checks = aide_lite.validate_github_release_draft_files(root, require_outputs=False)
                self.assertTrue(any(check.severity == "FAIL" and "nonempty manual review" in check.message for check in checks))

    def test_valid_older_policy_retains_its_original_seven_items(self) -> None:
        root = self.make_repo()
        items = ["review release body", "review suggested tag", "review asset list", "review known risks", "review target install caveats", "decide whether this is pre-release/draft/stable", "decide whether to publish"]
        self.set_policy(root, "manual_review_items:\n" + "".join("  - " + item + "\n" for item in items))
        self.assertEqual(aide_lite.github_release_checklist_data(root, [], [])["manual_review_required"], items)

    def test_markdown_uses_small_headings_and_one_logical_line_per_item(self) -> None:
        root = self.make_repo()
        data = aide_lite.github_release_checklist_data(root, [], [])
        text = aide_lite.render_github_release_checklist_md(data)
        self.assertTrue(text.startswith("### GitHub Release Publication Checklist\n"))
        self.assertTrue(all(line.startswith(("### ", "#### ")) for line in text.splitlines() if line.startswith("#")))
        for item in data["manual_review_required"]:
            self.assertEqual(text.splitlines().count("- " + item), 1)

    def test_validator_and_golden_reject_omitted_or_reordered_policy_items(self) -> None:
        root = self.make_repo()
        data = aide_lite.github_release_checklist_data(root, [], [])
        expected = data["manual_review_required"]
        for items in [expected, expected[:-1], list(reversed(expected))]:
            with self.subTest(items=items):
                self.save_checklist(root, {**data, "manual_review_required": items})
                checks = aide_lite.validate_github_release_draft_files(root)
                projection = [check for check in checks if check.message == "publication checklist matches current manual review policy"]
                self.assertEqual([check.severity for check in projection], ["PASS" if items == expected else "FAIL"])
                golden = aide_lite.run_golden_github_release_checklist(root)
                self.assertEqual(golden.result, "PASS" if items == expected else "FAIL")
        for raw in ["{}", "[]"]:
            with self.subTest(raw=raw):
                (root / aide_lite.GITHUB_RELEASE_CHECKLIST_JSON_PATH).write_text(raw, encoding="utf-8")
                checks = aide_lite.validate_github_release_draft_files(root)
                projection = [check for check in checks if check.message == "publication checklist matches current manual review policy"]
                self.assertEqual([check.severity for check in projection], ["FAIL"])
        (root / aide_lite.GITHUB_RELEASE_CHECKLIST_JSON_PATH).write_text("{malformed", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            aide_lite.validate_github_release_draft_files(root)

    def test_cached_cli_refuses_stale_policy_without_rewriting_or_dispatching(self) -> None:
        root = self.make_repo()
        data = aide_lite.github_release_checklist_data(root, [], [])
        self.save_checklist(root, data)
        self.set_policy(root, "manual_review_items:\n  - new project obligation\n")
        before = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
        with patch.object(aide_lite, "build_github_release_draft_outputs", side_effect=AssertionError("unexpected regeneration")), patch.object(aide_lite.subprocess, "run", side_effect=AssertionError("unexpected process")), patch("sys.stdout", new_callable=StringIO) as output:
            self.assertEqual(aide_lite.command_release_checklist(Namespace(repo_root=root)), 1)
        self.assertIn("manual_review_current: false", output.getvalue())
        self.assertIn("no_publish: true", output.getvalue())
        self.assertEqual(before, {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()})

    def test_cached_cli_accepts_current_projection_without_claiming_publication(self) -> None:
        root = self.make_repo()
        self.save_checklist(root, aide_lite.github_release_checklist_data(root, [], []))
        with patch("sys.stdout", new_callable=StringIO) as output:
            self.assertEqual(aide_lite.command_release_checklist(Namespace(repo_root=root)), 0)
        self.assertIn("manual_review_current: true", output.getvalue())
        self.assertIn("no_publish: true", output.getvalue())

    def test_cli_reports_missing_checklist_without_generating_files(self) -> None:
        root = self.make_repo()
        before = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
        with patch.object(aide_lite, "build_github_release_draft_outputs", side_effect=AssertionError("unexpected regeneration")), patch.object(aide_lite.subprocess, "run", side_effect=AssertionError("unexpected process")), patch("sys.stdout", new_callable=StringIO) as output:
            self.assertEqual(aide_lite.command_release_checklist(Namespace(repo_root=root)), 1)
        self.assertIn("manual_review_current: false", output.getvalue())
        self.assertIn("no_publish: true", output.getvalue())
        self.assertEqual(before, {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()})


if __name__ == "__main__":
    unittest.main()
