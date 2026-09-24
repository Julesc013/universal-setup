# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Compose and verify an unsigned, inspect-only Windows bundle envelope.

The supplied machine host is copied byte for byte. It does not yet consume the
product bundle or perform an installation. The ZIP carrier is one physical
file that requires extraction; it is not a single-file executable setup.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import zipfile
from pathlib import Path
from typing import Any

from usk_bundle_author import AuthoringError, inspect_bundle

BUFFER = 65536
MAX_RUNTIME_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
RUNTIME_NAME = "usk_machine.exe"
INPUT_NAMES = ("payload.zip", "product.bundle.json")
PROFILE_NAMES = ("sidecar", "one_file_carrier")


class EnvelopeError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def _read_plain_file(path: Path) -> tuple[Path, os.stat_result]:
    if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
        raise EnvelopeError(f"input is a link or reparse point: {path.name}")
    facts = path.stat()
    if not stat.S_ISREG(facts.st_mode):
        raise EnvelopeError(f"input is not a regular file: {path.name}")
    return path, facts


def _copy_observed(source: Path, destination: Any, limit: int | None = None) -> dict[str, Any]:
    _, before = _read_plain_file(source)
    if limit is not None and before.st_size > limit:
        raise EnvelopeError("input exceeds its byte budget")
    digest = hashlib.sha256()
    count = 0
    with source.open("rb") as reader:
        opened = os.fstat(reader.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
                before.st_dev, before.st_ino, before.st_size):
            raise EnvelopeError("input changed while opening")
        while block := reader.read(BUFFER):
            count += len(block)
            if limit is not None and count > limit:
                raise EnvelopeError("input exceeds its byte budget")
            destination.write(block)
            digest.update(block)
        after = os.fstat(reader.fileno())
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) or count != before.st_size:
            raise EnvelopeError("input changed while copying")
    return {"sha256": digest.hexdigest(), "size_bytes": count}


def _digest_bytes(data: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}


def _digest_stream(stream: Any, limit: int | None = None) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    for block in iter(lambda: stream.read(BUFFER), b""):
        size += len(block)
        if limit is not None and size > limit:
            raise EnvelopeError("envelope member exceeds its byte budget")
        digest.update(block)
    return {"sha256": digest.hexdigest(), "size_bytes": size}


def _read_bounded(stream: Any, limit: int) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise EnvelopeError("envelope metadata exceeds its byte budget")
    return data


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    info.compress_type = zipfile.ZIP_STORED
    return info


def _manifest(bundle: dict[str, Any], profile: str, entries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "usk.prefab_envelope.v1",
        "profile": profile,
        "product_id": bundle["product_id"],
        "product_version": bundle["product_version"],
        "target": bundle["target"],
        "entries": entries,
        "properties": {
            "entrypoint_count": 1 if profile == "sidecar" else 0,
            "physical_file_count": 4 if profile == "sidecar" else 1,
            "extraction_required": profile != "sidecar",
            "installation_mode": "inspect_only",
            "runtime_dependency_closure": "unqualified",
        },
    }


def _validate_runtime(runtime: Path) -> None:
    _read_plain_file(runtime)
    if runtime.suffix.lower() != ".exe" or runtime.stat().st_size > MAX_RUNTIME_BYTES:
        raise EnvelopeError("Windows machine host input is invalid")
    with runtime.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise EnvelopeError("Windows machine host lacks PE signature")


def build_envelope(bundle_path: Path, runtime: Path, profile: str, output_dir: Path) -> dict[str, Any]:
    if profile not in PROFILE_NAMES:
        raise EnvelopeError("unknown envelope profile")
    bundle_path = bundle_path.resolve(strict=True)
    runtime = runtime.absolute()
    output_dir = output_dir.resolve(strict=True)
    if not output_dir.is_dir() or any(output_dir.iterdir()):
        raise EnvelopeError("output directory must exist and be empty")
    if output_dir == bundle_path.parent or output_dir.is_relative_to(bundle_path.parent):
        raise EnvelopeError("output directory must be outside the compiled bundle")
    _validate_runtime(runtime)
    bundle = inspect_bundle(bundle_path)
    if bundle["target"] != "windows-x64":
        raise EnvelopeError("only the Windows x64 source-level envelope is admitted")
    source_files = {RUNTIME_NAME: runtime,
                    "payload.zip": bundle_path.parent / "payload.zip",
                    "product.bundle.json": bundle_path}
    entries: dict[str, dict[str, Any]] = {}
    for name, source in source_files.items():
        _, facts = _read_plain_file(source)
        if name == RUNTIME_NAME and facts.st_size > MAX_RUNTIME_BYTES:
            raise EnvelopeError("runtime exceeds its byte budget")
        # The builder streams bytes below, but identities are known before the
        # manifest is written. A second source observation follows composition.
        with source.open("rb") as stream:
            digest = hashlib.sha256()
            size = 0
            for block in iter(lambda: stream.read(BUFFER), b""):
                digest.update(block)
                size += len(block)
            if size != facts.st_size or os.fstat(stream.fileno()).st_mtime_ns != facts.st_mtime_ns:
                raise EnvelopeError("input changed while inventorying")
        entries[name] = {"sha256": digest.hexdigest(), "size_bytes": size}
    manifest = _manifest(bundle, profile, entries)
    manifest_bytes = _canonical(manifest)
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise EnvelopeError("envelope manifest exceeds its byte budget")
    if profile == "sidecar":
        for name, source in source_files.items():
            with (output_dir / name).open("xb") as output:
                observed = _copy_observed(source, output,
                                          MAX_RUNTIME_BYTES if name == RUNTIME_NAME else None)
            if observed != entries[name]:
                raise EnvelopeError("source identity changed after inventory")
        with (output_dir / "prefab.manifest.json").open("xb") as output:
            output.write(manifest_bytes)
        inspect_envelope(output_dir)
    else:
        carrier = output_dir / "setup.carrier.zip"
        with zipfile.ZipFile(carrier, "x", allowZip64=True) as archive:
            for name in sorted((*source_files, "prefab.manifest.json")):
                if name == "prefab.manifest.json":
                    archive.writestr(_zip_info(name), manifest_bytes)
                else:
                    with archive.open(_zip_info(name), "w") as output:
                        observed = _copy_observed(source_files[name], output,
                                                  MAX_RUNTIME_BYTES if name == RUNTIME_NAME else None)
                    if observed != entries[name]:
                        raise EnvelopeError("source identity changed after inventory")
        inspect_envelope(carrier)
    # Revalidate the original graph after composition, including the ZIP bytes.
    if inspect_bundle(bundle_path) != bundle:
        raise EnvelopeError("compiled bundle changed during envelope composition")
    return manifest


def inspect_envelope(path: Path) -> dict[str, Any]:
    if path.is_dir():
        if {item.name for item in path.iterdir()} != {
                RUNTIME_NAME, *INPUT_NAMES, "prefab.manifest.json"}:
            raise EnvelopeError("sidecar closure is not exact")
        manifest_path, _ = _read_plain_file(path / "prefab.manifest.json")
        with manifest_path.open("rb") as stream:
            data = _read_bounded(stream, MAX_MANIFEST_BYTES)
        profile = "sidecar"
        observed = {}
        for name in (RUNTIME_NAME, *INPUT_NAMES):
            source, _ = _read_plain_file(path / name)
            with source.open("rb") as stream:
                observed[name] = _digest_stream(stream,
                    MAX_RUNTIME_BYTES if name == RUNTIME_NAME else None)
        with (path / "product.bundle.json").open("rb") as stream:
            bundle_bytes = _read_bounded(stream, MAX_BUNDLE_BYTES)
        with (path / RUNTIME_NAME).open("rb") as stream:
            runtime_prefix = stream.read(2)
    else:
        if path.name != "setup.carrier.zip":
            raise EnvelopeError("one-file carrier name is invalid")
        _read_plain_file(path)
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if names != sorted((RUNTIME_NAME, *INPUT_NAMES, "prefab.manifest.json")):
                raise EnvelopeError("one-file carrier closure is not exact")
            if archive.comment or any(
                    item.compress_type != zipfile.ZIP_STORED or
                    item.date_time != (1980, 1, 1, 0, 0, 0) or
                    item.create_system != 3 or (item.external_attr >> 16) != 0o100644
                    for item in archive.infolist()):
                raise EnvelopeError("carrier metadata profile changed")
            with archive.open("prefab.manifest.json") as stream:
                data = _read_bounded(stream, MAX_MANIFEST_BYTES)
            observed = {}
            for name in (RUNTIME_NAME, *INPUT_NAMES):
                with archive.open(name) as stream:
                    observed[name] = _digest_stream(stream,
                        MAX_RUNTIME_BYTES if name == RUNTIME_NAME else None)
            with archive.open("product.bundle.json") as stream:
                bundle_bytes = _read_bounded(stream, MAX_BUNDLE_BYTES)
            with archive.open(RUNTIME_NAME) as stream:
                runtime_prefix = stream.read(2)
        profile = "one_file_carrier"
    if not data.endswith(b"\n"):
        raise EnvelopeError("envelope manifest is oversized or not canonical")
    try:
        manifest = json.loads(data, parse_constant=lambda value: (_ for _ in ()).throw(
            EnvelopeError(f"invalid manifest JSON constant: {value}")))
    except (ValueError, UnicodeDecodeError) as error:
        raise EnvelopeError("envelope manifest is invalid") from error
    if not isinstance(manifest, dict) or _canonical(manifest) != data or \
            manifest.get("schema") != "usk.prefab_envelope.v1" or \
            manifest.get("profile") != profile:
        raise EnvelopeError("envelope manifest schema or profile changed")
    entries = manifest.get("entries")
    if not isinstance(entries, dict) or set(entries) != set(observed) or any(
            entries[name] != observed[name] for name in observed):
        raise EnvelopeError("envelope member identity mismatch")
    if runtime_prefix != b"MZ":
        raise EnvelopeError("runtime member lacks PE signature")
    try:
        bundle = json.loads(bundle_bytes)
    except (ValueError, UnicodeDecodeError) as error:
        raise EnvelopeError("product bundle member is invalid") from error
    if not isinstance(bundle, dict) or not isinstance(bundle.get("payload"), dict):
        raise EnvelopeError("product bundle member has invalid shape")
    if (manifest.get("target"), manifest.get("product_id"), manifest.get("product_version")) != (
            bundle.get("target"), bundle.get("product_id"), bundle.get("product_version")) or \
            bundle["payload"].get("sha256") != observed["payload.zip"]["sha256"] or \
            bundle["payload"].get("size_bytes") != observed["payload.zip"]["size_bytes"]:
        raise EnvelopeError("envelope and product bundle identities diverged")
    if manifest != _manifest(bundle, profile, manifest["entries"]):
        raise EnvelopeError("envelope properties changed")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--bundle", required=True, type=Path)
    build.add_argument("--runtime", required=True, type=Path)
    build.add_argument("--profile", choices=PROFILE_NAMES, required=True)
    build.add_argument("--output-dir", required=True, type=Path)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("--path", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = (build_envelope(args.bundle, args.runtime, args.profile, args.output_dir)
                  if args.command == "build" else inspect_envelope(args.path))
        print(_canonical(result).decode("ascii"), end="")
        return 0
    except (AuthoringError, EnvelopeError, OSError, zipfile.BadZipFile) as error:
        print(f"prefab envelope: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
