# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Build and inspect the selected Windows NTFS publisher candidate package.

This package carries actual native host, service, control and client binaries
with a finalized authored bundle. It remains unsigned and requires separately
qualified service, volume and rights provisioning before any installation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

from usk_prefab_envelope import (EnvelopeError, MAX_MANIFEST_BYTES,
    MAX_RUNTIME_BYTES, _canonical, _copy_observed, _read_bounded,
    _read_plain_file, build_envelope, inspect_envelope)


SCHEMA = "usk.selected_ntfs_candidate_package.v1"
PROFILE = "windows_nt_x64_local_ntfs_service_sid_noreplace_v1"
BINARIES = {
    "service": "usk_publisher_service.exe",
    "control": "usk_publisher_service_control.exe",
    "client": "usk_publisher_client.exe",
}
MAX_PUBLISHER_BINARIES = 256 * 1024 * 1024


class CandidatePackageError(ValueError):
    pass


def _file_identity(path: Path, limit: int | None = None) -> dict[str, Any]:
    source, facts = _read_plain_file(path)
    if limit is not None and facts.st_size > limit:
        raise CandidatePackageError("package member exceeds its byte budget")
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
                facts.st_dev, facts.st_ino, facts.st_size):
            raise CandidatePackageError("package member changed while opening")
        while block := stream.read(65536):
            size += len(block)
            if limit is not None and size > limit:
                raise CandidatePackageError("package member exceeds its byte budget")
            digest.update(block)
        after = os.fstat(stream.fileno())
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                facts.st_dev, facts.st_ino, facts.st_size, facts.st_mtime_ns):
            raise CandidatePackageError("package member changed during inspection")
    return {"sha256": digest.hexdigest(), "size_bytes": size}


def _plain_directory(path: Path) -> None:
    if not path.is_dir() or path.is_symlink() or \
            getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
        raise CandidatePackageError("package directory is absent or redirected")


def _require_pe(path: Path) -> None:
    _read_plain_file(path)
    with path.open("rb") as source:
        if source.read(2) != b"MZ":
            raise CandidatePackageError("publisher executable lacks PE signature")


def _manifest(prefab: dict[str, Any], entries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {"schema": SCHEMA, "profile": PROFILE,
            "product_id": prefab["product_id"],
            "product_version": prefab["product_version"],
            "target": "windows-x64", "entries": entries,
            "installation_mode": "selected_ntfs_candidate",
            "signing_status": "unsigned",
            "provisioning": "dedicated_ntfs_volume_and_restricted_service_required"}


def inspect_candidate_package(path: Path) -> dict[str, Any]:
    root = path.absolute()
    _plain_directory(root)
    if {item.name for item in root.iterdir()} != {
            "inspect", "publisher", "setup-package.manifest.json"}:
        raise CandidatePackageError("candidate package root closure differs")
    inspect_root, publisher_root = root / "inspect", root / "publisher"
    _plain_directory(inspect_root)
    _plain_directory(publisher_root)
    if {item.name for item in publisher_root.iterdir()} != set(BINARIES.values()):
        raise CandidatePackageError("candidate publisher binary closure differs")
    prefab = inspect_envelope(inspect_root)
    if prefab["profile"] != "sidecar" or prefab["target"] != "windows-x64":
        raise CandidatePackageError("candidate package requires a Windows sidecar")
    manifest_file, _ = _read_plain_file(root / "setup-package.manifest.json")
    with manifest_file.open("rb") as source:
        manifest_bytes = _read_bounded(source, MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, ValueError) as error:
        raise CandidatePackageError("candidate package manifest is invalid") from error
    if not isinstance(manifest, dict) or _canonical(manifest) != manifest_bytes:
        raise CandidatePackageError("candidate package manifest is not canonical")
    expected_paths = {f"inspect/{name}" for name in
                      ("usk_machine.exe", "payload.zip", "product.bundle.json",
                       "prefab.manifest.json")}
    expected_paths.update(f"publisher/{name}" for name in BINARIES.values())
    if not isinstance(manifest.get("entries"), dict) or \
            set(manifest["entries"]) != expected_paths:
        raise CandidatePackageError("candidate package manifest closure differs")
    entries = {}
    total_publisher = 0
    for relative in sorted(expected_paths):
        member = root / relative
        limit = MAX_RUNTIME_BYTES if relative.endswith(".exe") else None
        entries[relative] = _file_identity(member, limit)
        if relative.startswith("publisher/"):
            total_publisher += entries[relative]["size_bytes"]
            _require_pe(member)
    if total_publisher > MAX_PUBLISHER_BINARIES:
        raise CandidatePackageError("publisher binary closure exceeds byte budget")
    if manifest != _manifest(prefab, entries):
        raise CandidatePackageError("candidate package identity or profile differs")
    return manifest


def build_candidate_package(bundle: Path, machine: Path, service: Path,
                            control: Path, client: Path, output: Path) -> dict[str, Any]:
    root = output.absolute()
    _plain_directory(root)
    if any(root.iterdir()):
        raise CandidatePackageError("candidate package output must be empty")
    source_bundle = bundle.resolve(strict=True)
    if root == source_bundle.parent or root.is_relative_to(source_bundle.parent):
        raise CandidatePackageError("candidate output overlaps the authored bundle")
    native = {"service": service.absolute(), "control": control.absolute(),
              "client": client.absolute()}
    if any(native[role].name.lower() != BINARIES[role] for role in BINARIES):
        raise CandidatePackageError("candidate requires ordinary, gate-free publisher binaries")
    sizes = []
    for source in native.values():
        _require_pe(source)
        _, facts = _read_plain_file(source)
        sizes.append(facts.st_size)
    if sum(sizes) > MAX_PUBLISHER_BINARIES:
        raise CandidatePackageError("publisher binary closure exceeds byte budget")
    inspect_root, publisher_root = root / "inspect", root / "publisher"
    inspect_root.mkdir()
    publisher_root.mkdir()
    prefab = build_envelope(source_bundle, machine, "sidecar", inspect_root)
    entries = {}
    for role, name in BINARIES.items():
        with (publisher_root / name).open("xb") as target:
            entries[f"publisher/{name}"] = _copy_observed(native[role], target,
                                                            MAX_RUNTIME_BYTES)
    for name in ("usk_machine.exe", "payload.zip", "product.bundle.json",
                 "prefab.manifest.json"):
        entries[f"inspect/{name}"] = _file_identity(inspect_root / name)
    manifest = _manifest(prefab, entries)
    with (root / "setup-package.manifest.json").open("xb") as target:
        target.write(_canonical(manifest))
    if inspect_candidate_package(root) != manifest:
        raise CandidatePackageError("emitted candidate package changed")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    for option in ("bundle", "machine", "service", "control", "client", "output-dir"):
        build.add_argument("--" + option, required=True, type=Path)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("--path", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = (build_candidate_package(args.bundle, args.machine, args.service,
                  args.control, args.client, args.output_dir) if args.command == "build"
                  else inspect_candidate_package(args.path))
        sys.stdout.buffer.write(_canonical(result))
        return 0
    except (CandidatePackageError, EnvelopeError, OSError, ValueError) as error:
        parser.exit(2, f"selected candidate package: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
