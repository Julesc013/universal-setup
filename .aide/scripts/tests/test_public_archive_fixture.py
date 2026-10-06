"""Only admitted public fixtures inherit observable job-temp permissions."""
from contextlib import ExitStack, contextmanager
import importlib.util
import os
from pathlib import Path
import stat
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from core.execution import managed_workspace as owner

spec = importlib.util.spec_from_file_location("public_fixture_lite", ROOT / ".aide/scripts/aide_lite.py")
lite = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lite
spec.loader.exec_module(lite)
PREFIX = "aide-public-release-test-"


@unittest.skipUnless(os.name == "nt", "Windows cross-account temp compatibility")
class PublicArchiveFixtureTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.base = Path(stack.enter_context(lite.public_archive_fixture(PREFIX)))
        self.control = self.base / "control"
        self.control.mkdir()
        self.scratch = self.base / "admitted"
        self.temp = self.scratch / "tmp"
        self.temp.mkdir(parents=True)
        self.record = {"scratch": str(self.scratch), "job": {"cwd": str(ROOT)}}

    @contextmanager
    def mocked_job(self, temp=None):
        with patch.dict(os.environ, {"AIDE_JOB_ID": "a" * 32,
                                     "AIDE_JOB_CONTROL": str(self.control),
                                     "AIDE_JOB_TMP": str(temp or self.temp)}), \
                patch.object(owner, "read_json", return_value=self.record), \
                patch.object(owner, "current_context", return_value=self.record):
            yield

    def test_unmanaged_keeps_standard_private_temp(self):
        with patch.dict(os.environ):
            os.environ.pop("AIDE_JOB_ID", None)
            # Do not create the deliberately incompatible private directory
            # inside the native monitor qualification. Check factory selection.
            with patch.object(lite.tempfile, "TemporaryDirectory") as private:
                private.return_value.__enter__.return_value = str(self.base)
                with lite.public_archive_fixture(PREFIX) as directory:
                    self.assertTrue(Path(directory).is_dir())
                private.assert_called_once_with(prefix=PREFIX)

    def test_unknown_namespace_refuses_before_allocation(self):
        before = set(self.temp.iterdir())
        with self.mocked_job(), self.assertRaisesRegex(ValueError, "namespace"):
            with lite.public_archive_fixture("../escape-"):
                self.fail("must refuse")
        self.assertEqual(set(self.temp.iterdir()), before)

    def test_forged_context_refuses_before_allocation(self):
        with self.mocked_job(), patch.object(owner, "current_context", side_effect=owner.WorkspaceRefused("admitted Windows Job")):
            with self.assertRaisesRegex(owner.WorkspaceRefused, "Windows Job"):
                with lite.public_archive_fixture(PREFIX):
                    self.fail("must refuse")
        self.assertEqual(list(self.temp.iterdir()), [])

    def test_outside_temp_refuses_before_allocation(self):
        outside = self.base / "outside"
        outside.mkdir()
        with self.mocked_job(outside), self.assertRaisesRegex(owner.WorkspaceRefused, "this admitted job"):
            with lite.public_archive_fixture(PREFIX):
                self.fail("must refuse")
        self.assertEqual(list(outside.iterdir()), [])

    def test_shared_file_preserved_on_cleanup_refusal(self):
        with self.mocked_job(), self.assertRaisesRegex(owner.WorkspaceRefused, "single-link"):
            with lite.public_archive_fixture(PREFIX) as directory:
                fixture = Path(directory)
                (fixture / "public").write_text("public fixture")
                os.link(fixture / "public", fixture / "shared")
        self.assertTrue((fixture / "public").exists())
        self.assertTrue((fixture / "shared").exists())
        # Retire exactly the two test-owned links after checking preservation.
        (fixture / "shared").unlink()
        (fixture / "public").unlink()
        fixture.rmdir()

    def test_readonly_public_file_retires_without_acl_change(self):
        with self.mocked_job():
            with lite.public_archive_fixture(PREFIX) as directory:
                fixture = Path(directory)
                public = fixture / "public"
                public.write_text("public fixture")
                public.chmod(stat.S_IREAD)
        self.assertFalse(fixture.exists())

    def test_changed_root_preserved_on_cleanup_refusal(self):
        with self.mocked_job(), self.assertRaisesRegex(owner.WorkspaceRefused, "identity changed"):
            with lite.public_archive_fixture(PREFIX) as directory:
                fixture = Path(directory)
                old = fixture.with_name("test-owned-original")
                fixture.rename(old)
                fixture.mkdir()
                (fixture / "replacement").write_text("test-owned replacement")
        self.assertTrue((fixture / "replacement").exists())
        self.assertTrue(old.is_dir())

    def test_real_admitted_public_fixture_is_held_then_retired(self):
        # The native qualification runs this under the actual worker account.
        # Holding public bytes across monitor samples proves the Jules owner
        # can measure them; receipt/retirement are checked by the controller.
        with lite.public_archive_fixture(PREFIX) as directory:
            fixture = Path(directory)
            (fixture / "public").write_bytes(b"public fixture\n" * 80000)
            time.sleep(2)
        self.assertFalse(fixture.exists())


if __name__ == "__main__":
    unittest.main()
