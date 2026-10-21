"""Descriptor-based filesystem binding for Lite's cooperative POSIX profile.

This module owns filesystem operations, not import/removal plans or receipts.
It verifies ancestry, entry identity and bytes, and never replaces a rival name.
Advisory ownership does not prevent unrelated processes from changing a name
between a check and unlink; hostile-writer containment is not provided here.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import hashlib
import os
from pathlib import Path
import stat
import sys


def _same(first, second):
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def file_identity(info):
    """Retain the existing persisted 32-bit device / 64-bit inode representation."""
    if not 0 <= info.st_dev < 2**32 or not 0 < info.st_ino < 2**64:
        raise ValueError("filesystem identity does not fit the current lifecycle record")
    return f"{info.st_dev:08x}{info.st_ino:016x}"


def _leaf(name):
    if not name or name in {".", ".."} or any(char in name for char in "/\\\0"):
        raise ValueError("filesystem operation requires one literal leaf name")
    return name


def require_descriptors():
    if os.name != "posix":
        raise ValueError("POSIX descriptor filesystem is unavailable")
    for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK"):
        if not hasattr(os, flag):
            raise ValueError(f"required POSIX flag unavailable: {flag}")
    for operation in (os.open, os.stat, os.mkdir, os.unlink):
        if operation not in os.supports_dir_fd:
            raise ValueError(f"required directory-relative operation unavailable: {operation.__name__}")
    if os.stat not in os.supports_follow_symlinks:
        raise ValueError("no-follow entry inspection unavailable")


def _native_rename():
    """Named OS bindings: Linux RENAME_NOREPLACE or Darwin RENAME_EXCL."""
    require_descriptors()
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        function, flag = getattr(library, "renameat2", None), 1
    elif sys.platform == "darwin":
        function, flag = getattr(library, "renameatx_np", None), 4
    else:
        raise ValueError("this profile requires a qualified native no-replace rename binding")
    if function is None:
        raise ValueError("native no-replace rename binding is unavailable")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    return function, flag


def _rename(directory, source, destination):
    function, flag = _native_rename()
    directory.check()
    if function(directory.fd, os.fsencode(_leaf(source)), directory.fd, os.fsencode(_leaf(destination)), flag):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)
    directory.sync()
    directory.check()


class Directory:
    """Keep no-follow descriptors to every ancestor and verify their live names."""
    def __init__(self, path, *, for_write=False):
        self.path = Path(path)
        self.for_write = for_write
        self.chain = []

    @property
    def fd(self):
        return self.chain[-1][2]

    def __enter__(self):
        require_descriptors()
        if not self.path.is_absolute() or self.path.anchor != "/" or ".." in self.path.parts:
            raise ValueError("POSIX filesystem requires an absolute non-traversing path")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            self.chain.append((None, "/", os.open("/", flags)))
            for part in self.path.parts[1:]:
                self.check()
                parent = self.fd
                child = os.open(_leaf(part), flags, dir_fd=parent)
                self.chain.append((parent, part, child))
            self.check()
            if self.for_write:
                self.sync()  # refuse unavailable directory durability before file effects
            return self
        except BaseException:
            self.close()
            raise

    def check(self):
        for parent, name, descriptor in self.chain:
            opened = os.fstat(descriptor)
            current = os.stat("/", follow_symlinks=False) if parent is None else os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or not stat.S_ISDIR(current.st_mode) or not _same(opened, current) or not opened.st_nlink:
                raise RuntimeError("filesystem ancestor identity changed")

    def sync(self):
        os.fsync(self.fd)

    def close(self):
        while self.chain:
            os.close(self.chain.pop()[2])

    def __exit__(self, *_):
        self.close()


class VerifiedFile:
    def __init__(self, directory, name, expected_digest=None, *, max_bytes=None):
        self.directory = directory
        self.name = _leaf(name)
        self.expected_digest = expected_digest
        self.max_bytes = max_bytes
        self.fd = None

    def __enter__(self):
        self.directory.check()
        self.fd = os.open(self.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                          dir_fd=self.directory.fd)
        try:
            self.initial = os.fstat(self.fd)
            self.identity = file_identity(self.initial)
            observed_digest = self.check()
            if self.expected_digest is None:
                self.expected_digest = observed_digest
            return self
        except BaseException:
            self.close()
            raise

    def check(self, *, capture=False):
        self.directory.check()
        before = os.fstat(self.fd)
        entry = os.stat(self.name, dir_fd=self.directory.fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(entry.st_mode)
                or before.st_nlink != 1 or entry.st_nlink != 1
                or not _same(before, self.initial) or not _same(before, entry)):
            raise RuntimeError("filesystem leaf is not the exact single-link regular file")
        if self.max_bytes is not None and before.st_size > self.max_bytes:
            raise ValueError("filesystem leaf exceeds the declared read limit")
        os.lseek(self.fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(self.fd, min(65536, remaining))
            if not chunk:
                raise RuntimeError("filesystem preimage shortened while reading")
            remaining -= len(chunk)
            digest.update(chunk)
            if capture:
                chunks.append(chunk)
        after = os.fstat(self.fd)
        fields = lambda value: (value.st_dev, value.st_ino, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if fields(before) != fields(after):
            raise RuntimeError("filesystem preimage changed while reading")
        if self.expected_digest is not None and digest.hexdigest() != self.expected_digest:
            raise RuntimeError("stale filesystem preimage bytes")
        current = os.stat(self.name, dir_fd=self.directory.fd, follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) or not _same(after, current) or current.st_nlink != 1:
            raise RuntimeError("filesystem entry changed while reading")
        self.directory.check()
        return b"".join(chunks) if capture else digest.hexdigest()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __exit__(self, *_):
        self.close()


@contextmanager
def verified_file(path, expected_digest=None, *, max_bytes=None):
    path = Path(path)
    with Directory(path.parent) as directory, VerifiedFile(directory, path.name, expected_digest, max_bytes=max_bytes) as leaf:
        yield leaf


def identity(path, expected_digest):
    with verified_file(path, expected_digest) as leaf:
        return leaf.identity


def _metadata(source, destination):
    """Preserve ownership, mode and supported native ACL/xattr metadata before publication."""
    info = os.fstat(source)
    if info.st_mode & 0o6000 or getattr(info, "st_flags", 0):
        raise ValueError("special permission bits or file flags require explicit metadata handling")
    target = os.fstat(destination)
    if (info.st_uid, info.st_gid) != (target.st_uid, target.st_gid):
        os.fchown(destination, info.st_uid, info.st_gid)
    os.fchmod(destination, stat.S_IMODE(info.st_mode))
    if sys.platform == "darwin":
        function = getattr(ctypes.CDLL(None, use_errno=True), "fcopyfile", None)
        if function is None:
            raise ValueError("native ACL/xattr metadata copy unavailable")
        function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        function.restype = ctypes.c_int
        if function(source, destination, None, 5):  # COPYFILE_ACL | COPYFILE_XATTR
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    elif sys.platform.startswith("linux"):
        attributes = {name: os.getxattr(source, name) for name in os.listxattr(source)}
        for name in os.listxattr(destination):
            if name not in attributes:
                os.removexattr(destination, name)
        for name, value in attributes.items():
            os.setxattr(destination, name, value)
        if {name: os.getxattr(destination, name) for name in os.listxattr(destination)} != attributes:
            raise RuntimeError("filesystem extended metadata changed during copy")
    else:
        raise ValueError("native metadata preservation is not qualified for this profile")
    result = os.fstat(destination)
    if (result.st_uid, result.st_gid, stat.S_IMODE(result.st_mode)) != (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)):
        raise RuntimeError("filesystem ownership or permissions changed during copy")


@contextmanager
def _stage(directory, target_name, data, metadata_source=None):
    _native_rename()  # no path-based replace fallback
    directory.check()
    name = f".{_leaf(target_name)}.aide-stage-{os.urandom(16).hex()}"
    descriptor = os.open(name, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory.fd)
    initial = None
    try:
        initial = os.fstat(descriptor)
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view[:65536])
            if not count:
                raise OSError("filesystem staged write made no progress")
            view = view[count:]
        if metadata_source is not None:
            _metadata(metadata_source, descriptor)
        os.fsync(descriptor)
        directory.sync()
        yield name, descriptor
    finally:
        try:
            # A published stage name is absent. An unknown replacement is preserved.
            try:
                current = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                directory.check()
                if initial is None or not stat.S_ISREG(current.st_mode) or not _same(initial, current) or current.st_nlink != 1:
                    raise RuntimeError("staged name changed; replacement preserved")
                os.unlink(name, dir_fd=directory.fd)
                directory.sync()
        finally:
            os.close(descriptor)


def _publish(directory, stage_name, descriptor, target_name, expected_digest):
    directory.check()
    with VerifiedFile(directory, stage_name, expected_digest) as staged:
        if not _same(os.fstat(descriptor), os.fstat(staged.fd)):
            raise RuntimeError("staged inode changed before publication")
        _rename(directory, stage_name, target_name)
        staged.name = target_name
        staged.check()


def create_bytes(path, data):
    path = Path(path)
    with Directory(path.parent, for_write=True) as directory:
        with _stage(directory, path.name, data) as (name, descriptor):
            _publish(directory, name, descriptor, path.name, hashlib.sha256(data).hexdigest())


def unlink_exact(path, expected_digest, before_disposition=None, *, expected_identity=None):
    path = Path(path)
    with Directory(path.parent, for_write=True) as directory, VerifiedFile(directory, path.name, expected_digest) as leaf:
        if expected_identity is not None and leaf.identity != expected_identity:
            raise RuntimeError("filesystem removal inode changed")
        if before_disposition is not None:
            before_disposition()
        leaf.check()
        os.unlink(leaf.name, dir_fd=directory.fd)
        directory.sync()
        if os.fstat(leaf.fd).st_nlink != 0:
            raise RuntimeError("filesystem removal effect is uncertain")
        directory.check()


def ensure_parent(root, relative):
    root = Path(root)
    parts = relative.replace("\\", "/").split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise ValueError("filesystem target is not a bounded relative path")
    for part in parts:
        _leaf(part)
    current = root
    with Directory(root, for_write=True):
        for part in parts[:-1]:
            with Directory(current, for_write=True) as directory:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=directory.fd)
                    directory.sync()
                except FileExistsError:
                    pass
            current = current / part
            with Directory(current, for_write=True):
                pass
    return current / parts[-1]


def write_exact(root, relative, data, expected_digest, backup_relative=None):
    _native_rename()
    target = ensure_parent(root, relative)
    if expected_digest == "missing":
        create_bytes(target, data)
        return
    backup = target.with_name(f".{target.name}.aide-import-backup-{os.urandom(12).hex()}") if backup_relative is None else Path(root) / backup_relative
    if backup.parent != target.parent or not backup.name.startswith(f".{target.name}.aide-import-backup-"):
        raise ValueError("filesystem backup is outside the target parent")
    with Directory(target.parent, for_write=True) as directory, VerifiedFile(directory, target.name, expected_digest) as original:
        with _stage(directory, target.name, data, original.fd) as (name, descriptor):
            original.check()
            _rename(directory, original.name, backup.name)
            original.name = backup.name
            original.check()
            try:
                _publish(directory, name, descriptor, target.name, hashlib.sha256(data).hexdigest())
            except BaseException:
                try:
                    original.check()
                    _rename(directory, original.name, target.name)
                    original.name = target.name
                except (OSError, ValueError, RuntimeError):
                    pass  # a rival target or uncertainty retains the intent-bound backup
                raise
            original.check()
            os.unlink(original.name, dir_fd=directory.fd)
            directory.sync()
            if os.fstat(original.fd).st_nlink != 0:
                raise RuntimeError("filesystem backup disposition is uncertain")


def restore_backup(root, relative, backup_relative, expected_digest, expected_identity):
    target, backup = Path(root) / relative, Path(root) / backup_relative
    if backup.parent != target.parent or not backup.name.startswith(f".{target.name}.aide-import-backup-"):
        raise ValueError("filesystem restore backup is outside the target parent")
    with Directory(target.parent, for_write=True) as directory, VerifiedFile(directory, backup.name, expected_digest) as original:
        if original.identity != expected_identity:
            raise RuntimeError("filesystem restore backup identity changed")
        original.check()
        _rename(directory, original.name, target.name)
        original.name = target.name
        original.check()
