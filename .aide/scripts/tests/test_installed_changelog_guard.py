"""Installed identity must not turn a project queue into source authority."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    "installed_guard_export_fixtures", ROOT / ".aide/scripts/tests/test_export_import.py")
fixtures = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fixtures
spec.loader.exec_module(fixtures)
aide = fixtures.aide_lite


class InstalledChangelogGuardTests(unittest.TestCase):
    def setUp(self):
        helper = fixtures.ExportImportTests()
        self.addCleanup(helper.doCleanups)
        source = helper.make_source_repo(minimal_recovery=True)
        pack = helper.build_pack(source)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.target = Path(temporary.name)
        result = aide.apply_import_pack(pack, self.target, mode="safe")
        self.assertFalse(result["conflicts"])
        aide.write_text(self.target / ".aide/queue/index.yaml", "items: []\n")
        self.receipt_path = self.target / aide.PORTABLE_IMPORT_RECEIPT_PATH

    def guard(self, **overrides):
        options = {"canonical_paths": (".aide/changelog",), "installed_changelog": True}
        options.update(overrides)
        return aide.source_maintainer_job_guard(self.target, **options)

    def rewrite_receipt(self, mutate):
        receipt = json.loads(self.receipt_path.read_bytes())
        mutate(receipt)
        receipt["receipt_digest"] = aide.portable_import_record_digest(receipt, "receipt_digest")
        self.receipt_path.write_text(json.dumps(receipt), encoding="utf8")

    def test_installed_queue_and_project_profile_allow_changelog_only(self):
        self.assertTrue(self.guard())
        aide.write_text(self.target / ".aide/profile.yaml",
                        'profile_id: "target-project" # custom\nprofile_mode: project\n')
        self.assertTrue(self.guard())
        self.assertFalse(self.guard(installed_changelog=False))
        self.assertFalse(self.guard(packaging=True))
        self.assertFalse(self.guard(canonical_paths=(".aide/release",)))
        self.assertFalse(self.guard(canonical_paths=()))

    def test_absent_malformed_or_invalid_receipt_refuses(self):
        valid = self.receipt_path.read_bytes()
        for contents in (None, b"{broken", b"{}", valid.replace(b'"receipt_digest": "', b'"receipt_digest": "0', 1)):
            with self.subTest(contents="absent" if contents is None else len(contents)):
                if contents is None:
                    self.receipt_path.unlink()
                else:
                    self.receipt_path.write_bytes(contents)
                self.assertFalse(self.guard())

    def test_receipt_must_own_exact_cli(self):
        valid = self.receipt_path.read_bytes()
        for mutation in (
            lambda r: r["managed"].pop(".aide/scripts/aide_lite.py"),
            lambda r: r["managed"][".aide/scripts/aide_lite.py"].update(source="files/unrelated.py"),
            lambda r: r["managed"][".aide/scripts/aide_lite.py"].update(
                installed_digest="0" * 64, source_digest="0" * 64),
        ):
            self.receipt_path.write_bytes(valid)
            self.rewrite_receipt(mutation)
            self.assertFalse(self.guard())

    def test_modified_or_missing_cli_refuses(self):
        cli = self.target / ".aide/scripts/aide_lite.py"
        cli.write_bytes(cli.read_bytes() + b"\n# direct edit\n")
        self.assertFalse(self.guard())
        cli.unlink()
        self.assertFalse(self.guard())

    def test_recorded_cli_overlay_refuses(self):
        cli = self.target / ".aide/scripts/aide_lite.py"
        cli.write_bytes(cli.read_bytes() + b"\n# project overlay\n")
        self.rewrite_receipt(lambda r: r["managed"][".aide/scripts/aide_lite.py"].update(
            installed_digest=aide.target_file_digest(cli), local_overlay=True,
            ownership="project_overlay_on_aide_managed"))
        self.assertFalse(self.guard())

    def test_pending_lifecycle_operations_refuse(self):
        for relative in (aide.PORTABLE_IMPORT_INTENT_PATH, aide.PORTABLE_REPAIR_INTENT_PATH,
                         aide.PORTABLE_REMOVAL_INTENT_PATH):
            with self.subTest(relative=relative):
                path = self.target / relative
                path.write_bytes(b"{}")
                self.assertFalse(self.guard())
                path.unlink()

    def test_source_identity_cannot_use_installed_receipt(self):
        for profile in (
            "profile_id: aide-self-hosting\nprofile_mode: self-hosting\n",
            "profile_id: aide-self-hosting # source\nprofile_mode: self-hosting\n",
            "profile_id: 'aide-self-hosting' # source\nprofile_mode: \"self-hosting\"\n",
            "profile_id: target\nprofile_mode: self-hosting # source\n",
            "profile_id: aide-self-hosting\nprofile_mode: project\n",
            "profile_id: target\nprofile_id: aide-self-hosting\n",
            "profile_id: target\nprofile_mode: [self-hosting]\n",
            'profile_id: "aide-self\\u002dhosting"\nprofile_mode: project\n',
            "profile_id: target\n<<: *inherited\n",
            '{profile_id: aide-self-hosting, profile_mode: self-hosting}\n',
        ):
            with self.subTest(profile=profile):
                aide.write_text(self.target / ".aide/profile.yaml", profile)
                self.assertFalse(self.guard())

    def test_source_runner_still_requires_source_admission(self):
        aide.write_text(self.target / "core/execution/managed_workspace.py", "# source marker\n")
        self.assertFalse(self.guard())


if __name__ == "__main__":
    unittest.main()
