# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Compile a minimal declarative product into an exact, unsigned local bundle.

The compiler reads finalized files; it never builds, signs, executes hooks, or
chooses an installation target. The output is a payload ZIP and a sidecar that
retains component choices for a later machine planner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

if __package__:
    from .usk_component_resolver import (ResolutionError, resolve_component_ids,
                                         resolve_transition_component_ids)
else:
    from usk_component_resolver import (ResolutionError, resolve_component_ids,
                                        resolve_transition_component_ids)


MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_FILES = 65536
MAX_PATH_BYTES = 4096
MAX_DEPTH = 64
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
RESERVED = {"con", "prn", "aux", "nul", "clock$"}
RESERVED.update(f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10))


class AuthoringError(ValueError):
    pass


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthoringError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> Any:
    with path.open("rb") as source:
        raw = source.read(MAX_SOURCE_BYTES + 1)
    if len(raw) > MAX_SOURCE_BYTES:
        raise AuthoringError("JSON exceeds the input budget")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_object_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          AuthoringError(f"invalid JSON constant: {value}")))


def _fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise AuthoringError(f"invalid fields in {label}")
    return value


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise AuthoringError(f"invalid {label}")
    return value


def _path(value: Any, label: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= MAX_PATH_BYTES or
            not value.isascii() or any(ord(ch) < 32 or ord(ch) >= 127 for ch in value) or
            any(ch in value for ch in '\\:*?"<>|') or value.startswith("/")):
        raise AuthoringError(f"invalid {label}")
    parts = value.split("/")
    if len(parts) > MAX_DEPTH or any(
            not part or len(part) > 255 or part in (".", "..") or part[-1] in (".", " ") or
            part.split(".", 1)[0].lower() in RESERVED for part in parts):
        raise AuthoringError(f"unsafe {label}: {value}")
    return value


def _refs(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_FILES:
        raise AuthoringError(f"invalid {label}")
    refs = [_id(item, label) for item in value]
    if len(refs) != len(set(refs)):
        raise AuthoringError(f"duplicate {label}")
    return sorted(refs)


def _check_file_paths(paths: list[str]) -> None:
    folded = [path.lower() for path in paths]
    members = set(folded)
    if len(members) != len(folded):
        raise AuthoringError("duplicate bundle path")
    for path in folded:
        parts = path.split("/")
        if any("/".join(parts[:index]) in members for index in range(1, len(parts))):
            raise AuthoringError(f"file is the parent of another bundle path: {path}")


def validate_project(project: Any, target: str) -> list[dict[str, Any]]:
    """Validate the closed authoring subset and return target-specific file data."""
    _fields(project, {"schema", "product_id", "publisher_id", "product_version",
                      "allowed_scopes", "components"}, "project")
    if project["schema"] != "usk.authoring_project.v1":
        raise AuthoringError("unsupported project schema")
    _id(project["product_id"], "product_id")
    _id(project["publisher_id"], "publisher_id")
    version = project["product_version"]
    if not isinstance(version, str) or not 1 <= len(version) <= 128:
        raise AuthoringError("invalid product_version")
    _id(target, "target")
    scopes = project["allowed_scopes"]
    if (not isinstance(scopes, list) or not scopes or
            any(not isinstance(scope, str) or scope not in
                ("portable", "per_user", "machine") for scope in scopes) or
            len(scopes) != len(set(scopes))):
        raise AuthoringError("invalid allowed_scopes")
    components = project["components"]
    if not isinstance(components, list) or not 1 <= len(components) <= 4096:
        raise AuthoringError("invalid component count")
    output: list[dict[str, Any]] = []
    names: set[str] = set()
    occupied: list[str] = []
    file_count = 0
    for component in components:
        _fields(component, {"id", "required", "default_selected", "requires",
                            "conflicts", "variants"}, "component")
        name = _id(component["id"], "component_id")
        if name in names:
            raise AuthoringError(f"duplicate component: {name}")
        names.add(name)
        if type(component["required"]) is not bool or type(component["default_selected"]) is not bool:
            raise AuthoringError(f"invalid selection flags: {name}")
        requires = _refs(component["requires"], "requires")
        conflicts = _refs(component["conflicts"], "conflicts")
        variants = component["variants"]
        if not isinstance(variants, list) or not variants or len(variants) > 256:
            raise AuthoringError(f"invalid variants: {name}")
        found: dict[str, list[dict[str, str]]] = {}
        for variant in variants:
            _fields(variant, {"target", "files"}, "variant")
            variant_target = _id(variant["target"], "variant target")
            if variant_target in found:
                raise AuthoringError(f"duplicate target: {name}/{variant_target}")
            files = variant["files"]
            if not isinstance(files, list) or not files or len(files) > MAX_FILES:
                raise AuthoringError(f"invalid files: {name}/{variant_target}")
            mapped: list[dict[str, str]] = []
            local_paths: set[str] = set()
            for item in files:
                _fields(item, {"source", "path"}, "file")
                source = _path(item["source"], "source path")
                path = _path(item["path"], "bundle path")
                folded = path.lower()
                if folded in local_paths:
                    raise AuthoringError(f"duplicate bundle path: {path}")
                local_paths.add(folded)
                mapped.append({"source": source, "path": path})
            found[variant_target] = mapped
        if target not in found:
            raise AuthoringError(f"missing target variant: {name}/{target}")
        mapped = found[target]
        file_count += len(mapped)
        if file_count > MAX_FILES:
            raise AuthoringError("file count exceeds the budget")
        for item in mapped:
            folded = item["path"].lower()
            occupied.append(folded)
        output.append({"id": name, "required": component["required"],
                       "default_selected": component["default_selected"],
                       "requires": requires, "conflicts": conflicts, "files": mapped})
    try:
        resolve_component_ids(output)
    except ResolutionError as error:
        raise AuthoringError(str(error)) from error
    _check_file_paths(occupied)
    return sorted(output, key=lambda item: item["id"])


@contextmanager
def _source_handle(root: Path, relative: str):
    path = root / relative
    current = root
    for part in relative.split("/"):
        current = current / part
        facts = current.lstat()
        if stat.S_ISLNK(facts.st_mode) or getattr(facts, "st_file_attributes", 0) & 0x400:
            raise AuthoringError(f"source uses a reparse point: {relative}")
    if not path.resolve(strict=True).is_relative_to(root):
        raise AuthoringError(f"source escapes project: {relative}")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise AuthoringError(f"source is not a regular file: {relative}")
    handle = path.open("rb")
    opened = os.fstat(handle.fileno())
    if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
        handle.close()
        raise AuthoringError(f"source changed while opening: {relative}")
    try:
        yield handle, opened
    finally:
        handle.close()


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def compile_bundle(source: Path, target: str, output_dir: Path) -> dict[str, Any]:
    """Build into an explicitly supplied, existing empty directory."""
    source = source.resolve(strict=True)
    root = source.parent.resolve(strict=True)
    output_dir = output_dir.resolve(strict=True)
    if not output_dir.is_dir() or any(output_dir.iterdir()):
        raise AuthoringError("output directory must exist and be empty")
    if output_dir == root or output_dir.is_relative_to(root):
        raise AuthoringError("output directory must be outside the project")
    project = _read_json(source)
    components = validate_project(project, target)
    archive_path = output_dir / "payload.zip"
    bundle_path = output_dir / "product.bundle.json"
    inventory: dict[str, dict[str, Any]] = {}
    jobs = sorted(((file["path"], file["source"]) for component in components
                   for file in component["files"]), key=lambda item: item[0])
    created_archive = False
    created_sidecar = False
    try:
        with zipfile.ZipFile(archive_path, "x", allowZip64=True) as archive:
            created_archive = True
            for destination, relative in jobs:
                with _source_handle(root, relative) as opened:
                    stream, facts = opened
                    info = zipfile.ZipInfo(destination, (1980, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    info.external_attr = 0o100644 << 16
                    info.compress_type = zipfile.ZIP_STORED
                    info.file_size = facts.st_size
                    digest = hashlib.sha256()
                    count = 0
                    with archive.open(info, "w") as target_stream:
                        for block in iter(lambda: stream.read(65536), b""):
                            target_stream.write(block)
                            digest.update(block)
                            count += len(block)
                    after = os.fstat(stream.fileno())
                    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                            facts.st_dev, facts.st_ino, facts.st_size, facts.st_mtime_ns) or count != facts.st_size:
                        raise AuthoringError(f"source changed while reading: {relative}")
                    inventory[destination] = {"path": destination, "size_bytes": count,
                                              "sha256": digest.hexdigest()}
        # Reopen and independently read the carrier before emitting its sidecar.
        with zipfile.ZipFile(archive_path) as archive:
            if archive.namelist() != [destination for destination, _ in jobs]:
                raise AuthoringError("archive entry set changed")
            for destination, _ in jobs:
                digest = hashlib.sha256()
                size = 0
                with archive.open(destination) as stream:
                    for block in iter(lambda: stream.read(65536), b""):
                        digest.update(block)
                        size += len(block)
                expected = inventory[destination]
                if size != expected["size_bytes"] or digest.hexdigest() != expected["sha256"]:
                    raise AuthoringError(f"archive entry mismatch: {destination}")
        for component in components:
            component["files"] = [inventory[item["path"]] for item in
                                  sorted(component["files"], key=lambda item: item["path"])]
        bundle = {"schema": "usk.product_bundle.v1", "product_id": project["product_id"],
                  "publisher_id": project["publisher_id"], "product_version": project["product_version"],
                  "target": target, "allowed_scopes": sorted(project["allowed_scopes"]),
                  "components": components,
                  "payload": {"file": "payload.zip", "size_bytes": archive_path.stat().st_size,
                              "sha256": _digest_file(archive_path)}}
        serialized = _canonical_json(bundle)
        if len(serialized) > MAX_SOURCE_BYTES:
            raise AuthoringError("compiled bundle exceeds the metadata budget")
        with bundle_path.open("xb") as sidecar:
            created_sidecar = True
            sidecar.write(serialized)
        return bundle
    except BaseException:
        if created_sidecar:
            bundle_path.unlink(missing_ok=True)
        if created_archive:
            archive_path.unlink(missing_ok=True)
        raise


def inspect_bundle(path: Path) -> dict[str, Any]:
    """Reopen a local compiled bundle and compare every declared payload byte."""
    bundle = _read_json(path)
    _fields(bundle, {"schema", "product_id", "publisher_id", "product_version",
                     "target", "allowed_scopes", "components", "payload"}, "bundle")
    if bundle["schema"] != "usk.product_bundle.v1":
        raise AuthoringError("unsupported bundle schema")
    for field in ("product_id", "publisher_id", "target"):
        _id(bundle[field], field)
    if (not isinstance(bundle["product_version"], str) or
            not 1 <= len(bundle["product_version"]) <= 128):
        raise AuthoringError("invalid product_version")
    scopes = bundle["allowed_scopes"]
    if (not isinstance(scopes, list) or not scopes or
            any(not isinstance(scope, str) or scope not in
                ("portable", "per_user", "machine") for scope in scopes) or
            scopes != sorted(set(scopes))):
        raise AuthoringError("invalid allowed_scopes")
    components = bundle["components"]
    if not isinstance(components, list) or not 1 <= len(components) <= 4096:
        raise AuthoringError("invalid component count")
    paths: dict[str, dict[str, Any]] = {}
    names: list[str] = []
    for component in components:
        _fields(component, {"id", "required", "default_selected", "requires",
                            "conflicts", "files"}, "compiled component")
        names.append(_id(component["id"], "component_id"))
        if type(component["required"]) is not bool or type(component["default_selected"]) is not bool:
            raise AuthoringError("invalid selection flags")
        _refs(component["requires"], "requires")
        _refs(component["conflicts"], "conflicts")
        files = component["files"]
        if not isinstance(files, list) or not files or len(files) > MAX_FILES:
            raise AuthoringError("invalid compiled files")
        for item in files:
            _fields(item, {"path", "size_bytes", "sha256"}, "compiled file")
            name = _path(item["path"], "bundle path")
            if (type(item["size_bytes"]) is not int or item["size_bytes"] < 0 or
                    not isinstance(item["sha256"], str) or
                    not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
                raise AuthoringError(f"invalid inventory: {name}")
            if name.lower() in paths:
                raise AuthoringError(f"duplicate inventory path: {name}")
            paths[name.lower()] = item
    if names != sorted(set(names)):
        raise AuthoringError("components must be unique and sorted")
    if len(paths) > MAX_FILES:
        raise AuthoringError("inventory exceeds file budget")
    _check_file_paths([item["path"] for item in paths.values()])
    try:
        resolve_component_ids(components)
    except ResolutionError as error:
        raise AuthoringError(str(error)) from error
    payload = _fields(bundle["payload"], {"file", "size_bytes", "sha256"}, "payload")
    if (payload["file"] != "payload.zip" or type(payload["size_bytes"]) is not int or
            payload["size_bytes"] < 1 or not isinstance(payload["sha256"], str) or
            not re.fullmatch(r"[0-9a-f]{64}", payload["sha256"])):
        raise AuthoringError("invalid payload identity")
    archive_path = path.parent / "payload.zip"
    if (archive_path.stat().st_size != payload["size_bytes"] or
            _digest_file(archive_path) != payload["sha256"]):
        raise AuthoringError("payload archive digest mismatch")
    with zipfile.ZipFile(archive_path) as archive:
        if archive.namelist() != sorted(item["path"] for item in paths.values()):
            raise AuthoringError("archive entry set differs from inventory")
        for info in archive.infolist():
            expected = paths[info.filename.lower()]
            if info.compress_type != zipfile.ZIP_STORED or info.file_size != expected["size_bytes"]:
                raise AuthoringError(f"archive entry metadata mismatch: {info.filename}")
            digest = hashlib.sha256()
            size = 0
            with archive.open(info) as stream:
                for block in iter(lambda: stream.read(65536), b""):
                    digest.update(block)
                    size += len(block)
            if size != expected["size_bytes"] or digest.hexdigest() != expected["sha256"]:
                raise AuthoringError(f"archive entry content mismatch: {info.filename}")
    return bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="compile finalized files into an unsigned bundle")
    build.add_argument("--source", required=True, type=Path)
    build.add_argument("--target", required=True)
    build.add_argument("--output-dir", required=True, type=Path)
    resolve = sub.add_parser("resolve", help="show component closure; no machine plan is emitted")
    resolve.add_argument("--bundle", required=True, type=Path)
    resolve.add_argument("--select", action="append", default=[])
    transition = sub.add_parser("resolve-transition",
                                help="preserve an accepted selection across verified bundles")
    transition.add_argument("--previous-bundle", required=True, type=Path)
    transition.add_argument("--candidate-bundle", required=True, type=Path)
    transition.add_argument("--selected", action="append", default=[])
    transition.add_argument("--scope", required=True,
                            choices=("portable", "per_user", "machine"))
    inspect = sub.add_parser("inspect", help="verify the compiled bundle and exact payload")
    inspect.add_argument("--bundle", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            bundle = compile_bundle(args.source, args.target, args.output_dir)
            print(bundle["payload"]["sha256"])
        elif args.command == "resolve":
            bundle = inspect_bundle(args.bundle)
            print(json.dumps(resolve_component_ids(bundle["components"], args.select)))
        elif args.command == "resolve-transition":
            previous = inspect_bundle(args.previous_bundle)
            candidate = inspect_bundle(args.candidate_bundle)
            if any(previous[field] != candidate[field] for field in
                   ("product_id", "publisher_id", "target")):
                raise AuthoringError("incompatible product or target identity")
            if (args.scope not in previous["allowed_scopes"] or
                    args.scope not in candidate["allowed_scopes"]):
                raise AuthoringError("installation scope is not supported by both bundles")
            print(json.dumps(resolve_transition_component_ids(
                previous["components"], args.selected, candidate["components"])))
        else:
            bundle = inspect_bundle(args.bundle)
            print(bundle["payload"]["sha256"])
    except (AuthoringError, ResolutionError, OSError, json.JSONDecodeError,
            UnicodeError, zipfile.BadZipFile) as error:
        print(f"bundle-author: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
