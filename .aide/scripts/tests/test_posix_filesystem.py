"""Real-filesystem checks for the cooperative Linux/Darwin binding."""
import ctypes
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


MODULE = Path(__file__).resolve().parents[1] / "posix_filesystem.py"
SPEC = importlib.util.spec_from_file_location("tested_posix_filesystem", MODULE)
fs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fs)


def digest(data):
    return hashlib.sha256(data).hexdigest()


@unittest.skipUnless(os.name == "posix" and sys.platform in {"linux", "darwin"}, "native Linux/Darwin binding")
class PosixFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.path = self.root / "owned.txt"

    def tearDown(self):
        self.temporary.cleanup()

    def test_complete_create_refuses_existing_without_changing_bytes(self):
        fs.create_bytes(self.path, b"complete\0payload")
        self.assertEqual(self.path.read_bytes(), b"complete\0payload")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            fs.create_bytes(self.path, b"replacement")
        self.assertEqual(self.path.read_bytes(), b"complete\0payload")
        self.assertEqual(list(self.root.glob(".*aide-stage-*")), [])

    def test_update_preserves_mode_owner_and_cleans_exact_backup(self):
        self.path.write_bytes(b"old")
        self.path.chmod(0o640)
        before = self.path.stat()
        fs.write_exact(self.root, self.path.name, b"new", digest(b"old"), ".owned.txt.aide-import-backup-test")
        after = self.path.stat()
        self.assertEqual(self.path.read_bytes(), b"new")
        self.assertEqual((after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
                         (before.st_uid, before.st_gid, 0o640))
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_stale_preimage_never_mutates_target(self):
        self.path.write_bytes(b"project edit")
        with self.assertRaises(RuntimeError):
            fs.write_exact(self.root, self.path.name, b"incoming", digest(b"old"))
        self.assertEqual(self.path.read_bytes(), b"project edit")
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_symlink_leaf_and_ancestor_refused(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "file").write_bytes(b"preserve")
        self.path.symlink_to(outside / "file")
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            fs.unlink_exact(self.path, digest(b"preserve"))
        alias = self.root / "alias"
        alias.symlink_to(outside, target_is_directory=True)
        with self.assertRaises((OSError, RuntimeError, ValueError)):
            fs.write_exact(self.root, "alias/file", b"replace", digest(b"preserve"))
        self.assertEqual((outside / "file").read_bytes(), b"preserve")

    def test_hardlink_and_fifo_refused_without_blocking(self):
        self.path.write_bytes(b"preserve")
        alias = self.root / "hardlink"
        os.link(self.path, alias)
        with self.assertRaises(RuntimeError):
            fs.unlink_exact(self.path, digest(b"preserve"))
        self.assertEqual(alias.read_bytes(), b"preserve")
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(RuntimeError):
            with fs.verified_file(fifo):
                self.fail("FIFO accepted")

    def test_bounded_read_and_changed_open_leaf_are_detected(self):
        self.path.write_bytes(b"original")
        with self.assertRaises(ValueError):
            with fs.verified_file(self.path, max_bytes=3):
                self.fail("oversized file accepted")
        with fs.verified_file(self.path, digest(b"original")) as leaf:
            self.assertEqual(leaf.check(capture=True), b"original")
            self.path.write_bytes(b"changed")
            with self.assertRaises(RuntimeError):
                leaf.check()
        self.assertEqual(self.path.read_bytes(), b"changed")
        with fs.verified_file(self.path) as snapshot:
            self.path.write_bytes(b"changed again")
            with self.assertRaises(RuntimeError):
                snapshot.check()

    def test_changed_ancestor_detected_and_replacement_preserved(self):
        parent = self.root / "parent"
        parent.mkdir()
        leaf = parent / "file"
        leaf.write_bytes(b"old")
        with fs.verified_file(leaf, digest(b"old")) as guard:
            parent.rename(self.root / "original-parent")
            parent.mkdir()
            (parent / "file").write_bytes(b"rival")
            with self.assertRaises(RuntimeError):
                guard.check()
        self.assertEqual((parent / "file").read_bytes(), b"rival")
        self.assertEqual((self.root / "original-parent/file").read_bytes(), b"old")

    def test_replacement_before_unlink_is_preserved(self):
        self.path.write_bytes(b"old")
        identity = fs.identity(self.path, digest(b"old"))
        def replace():
            self.path.rename(self.root / "saved")
            self.path.write_bytes(b"rival")
        with self.assertRaises(RuntimeError):
            fs.unlink_exact(self.path, digest(b"old"), replace, expected_identity=identity)
        self.assertEqual(self.path.read_bytes(), b"rival")
        self.assertEqual((self.root / "saved").read_bytes(), b"old")

    def test_exact_identity_required_for_disposition(self):
        self.path.write_bytes(b"same")
        with self.assertRaises(RuntimeError):
            fs.unlink_exact(self.path, digest(b"same"), expected_identity="0" * 24)
        self.assertEqual(self.path.read_bytes(), b"same")
        fs.unlink_exact(self.path, digest(b"same"), expected_identity=fs.identity(self.path, digest(b"same")))
        self.assertFalse(self.path.exists())

    def test_rival_publication_preserves_rival_and_intent_backup(self):
        self.path.write_bytes(b"old")
        original_identity = fs.identity(self.path, digest(b"old"))
        backup = self.root / ".owned.txt.aide-import-backup-test"
        publish = fs._publish
        def rival(directory, name, descriptor, destination, expected):
            self.path.write_bytes(b"rival")
            publish(directory, name, descriptor, destination, expected)
        with patch.object(fs, "_publish", side_effect=rival):
            with self.assertRaises(FileExistsError):
                fs.write_exact(self.root, self.path.name, b"incoming", digest(b"old"), backup.name)
        self.assertEqual(self.path.read_bytes(), b"rival")
        self.assertEqual(backup.read_bytes(), b"old")
        self.assertEqual(fs.identity(backup, digest(b"old")), original_identity)
        self.assertEqual(list(self.root.glob(".*aide-stage-*")), [])

    def test_failed_publication_restores_original_and_backup_restore_refuses_rival(self):
        self.path.write_bytes(b"old")
        with patch.object(fs, "_publish", side_effect=OSError("injected failure")):
            with self.assertRaises(OSError):
                fs.write_exact(self.root, self.path.name, b"incoming", digest(b"old"))
        self.assertEqual(self.path.read_bytes(), b"old")
        backup = self.root / ".owned.txt.aide-import-backup-test"
        identity = fs.identity(self.path, digest(b"old"))
        self.path.rename(backup)
        self.path.write_bytes(b"rival")
        with self.assertRaises(FileExistsError):
            fs.restore_backup(self.root, self.path.name, backup.name, digest(b"old"), identity)
        self.assertEqual(backup.read_bytes(), b"old")
        self.path.unlink()  # fixture-owned rival, explicitly removed by the test
        fs.restore_backup(self.root, self.path.name, backup.name, digest(b"old"), identity)
        self.assertEqual(self.path.read_bytes(), b"old")
        self.assertEqual(fs.identity(self.path, digest(b"old")), identity)

    def test_unavailable_native_binding_refuses_before_target_effect(self):
        with patch.object(fs, "_native_rename", side_effect=ValueError("unavailable")):
            with self.assertRaises(ValueError):
                fs.write_exact(self.root, "nested/file", b"incoming", "missing")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_special_permissions_refused_before_replacement(self):
        self.path.write_bytes(b"old")
        self.path.chmod(0o2640)
        with self.assertRaises(ValueError):
            fs.write_exact(self.root, self.path.name, b"incoming", digest(b"old"))
        self.assertEqual(self.path.read_bytes(), b"old")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o2640)

    def test_native_extended_metadata_survives_update(self):
        self.path.write_bytes(b"old")
        if sys.platform.startswith("linux"):
            os.setxattr(self.path, "user.aide-fixture", b"project metadata")
            read = lambda: os.getxattr(self.path, "user.aide-fixture")
        else:
            library = ctypes.CDLL(None, use_errno=True)
            set_attribute = library.setxattr
            set_attribute.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
            set_attribute.restype = ctypes.c_int
            payload = b"project metadata"
            self.assertEqual(set_attribute(os.fsencode(self.path), b"org.aide.fixture", payload, len(payload), 0, 0), 0)
            get_attribute = library.getxattr
            get_attribute.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
            get_attribute.restype = ctypes.c_ssize_t
            def read():
                value = ctypes.create_string_buffer(1024)
                size = get_attribute(os.fsencode(self.path), b"org.aide.fixture", value, len(value), 0, 0)
                self.assertGreaterEqual(size, 0)
                return value.raw[:size]
        fs.write_exact(self.root, self.path.name, b"new", digest(b"old"))
        self.assertEqual(read(), b"project metadata")
        self.assertEqual(self.path.read_bytes(), b"new")

    def test_native_acl_survives_update(self):
        self.path.write_bytes(b"old")
        if sys.platform.startswith("linux"):
            # Linux UAPI format, independently constructed named-user ACL.
            entries = ((1, 7, 0xffffffff), (2, 4, 65534), (4, 4, 0xffffffff),
                       (16, 4, 0xffffffff), (32, 0, 0xffffffff))
            acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)
            os.setxattr(self.path, "system.posix_acl_access", acl)
            read = lambda: os.getxattr(self.path, "system.posix_acl_access")
        else:
            result = subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(self.path)],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            def read():
                result = subprocess.run(["/bin/ls", "-le", str(self.path)],
                    stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                entries = [line.strip() for line in result.stdout.splitlines()[1:] if b"everyone" in line]
                self.assertTrue(entries, result.stdout)
                return b"\n".join(entries)
        before = read()
        fs.write_exact(self.root, self.path.name, b"new", digest(b"old"))
        self.assertEqual(read(), before)
        self.assertEqual(self.path.read_bytes(), b"new")


if __name__ == "__main__":
    unittest.main()
