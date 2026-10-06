"""Stable commands consume export as input; only release needs write admission."""
import argparse
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from core.execution import managed_workspace

spec = importlib.util.spec_from_file_location("stable_admission_lite", ROOT / ".aide/scripts/aide_lite.py")
lite = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lite
spec.loader.exec_module(lite)


class StableReleaseAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = contextlib.ExitStack()
        self.addCleanup(self.temp.close)
        self.root = Path(self.temp.enter_context(lite.public_archive_fixture("aide-public-release-test-")))
        for relative in ("core/execution/managed_workspace.py", ".aide/queue/index.yaml"):
            p = self.root / relative
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("fixture", encoding="utf-8")
        self.args = argparse.Namespace(repo_root=self.root, version="1.0.0")

    def command(self, kind, declarations):
        record = {"job": {"canonical_outputs": declarations}}
        with patch.object(managed_workspace, "current_context", return_value=record), \
                patch.object(lite, "build_stable_release_candidate", return_value={"identity": {"source_commit": "f" * 40}}) as build, \
                patch.object(lite, "validate_stable_release_candidate", return_value={"result": "PASS", "problems": []}) as validate, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            code = getattr(lite, "command_release_stable_" + kind)(self.args)
        return code, output.getvalue(), build.call_count + validate.call_count

    def test_build_accepts_release_only_reservation(self):
        self.assertEqual(self.command("build", {".aide/release": {"bytes": 8388608}})[::2], (0, 1))

    def test_validate_accepts_release_only_reservation(self):
        self.assertEqual(self.command("validate", {".aide/release": {"bytes": 8388608}})[::2], (0, 1))

    def test_build_refuses_missing_release_before_asset_effect(self):
        code, output, effects = self.command("build", {".aide/export/aide-lite-pack-v0": {"bytes": 8388608}})
        self.assertEqual((code, effects), (1, 0))
        self.assertIn("requires declared canonical output reservations", output)

    def test_validate_refuses_missing_release_before_asset_effect(self):
        code, output, effects = self.command("validate", {})
        self.assertEqual((code, effects), (1, 0))
        self.assertIn("requires declared canonical output reservations", output)

    def test_shared_packaging_guard_still_requires_export_and_release(self):
        record = {"job": {"canonical_outputs": {".aide/release": {"bytes": 8388608}}}}
        with patch.object(managed_workspace, "current_context", return_value=record), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(lite.source_maintainer_job_guard(self.root, packaging=True))


if __name__ == "__main__":
    unittest.main()
