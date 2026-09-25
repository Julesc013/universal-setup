# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Finalize an exact component selection from a verified compiled bundle.

This creates a self-contained selected payload and product bundle. The receipt
binds the derived bytes to the full authoring bundle; it is not a signature or
an install authorization.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from usk_bundle_author import AuthoringError, inspect_bundle
from usk_component_resolver import ResolutionError, resolve_component_ids

BUFFER = 65536
RECEIPT_NAME = "selection.receipt.json"


class SelectionError(ValueError):
    pass


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(BUFFER), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def _selected_bundle(source: dict[str, Any], selected: tuple[str, ...]) -> dict[str, Any]:
    included = set(selected)
    result = copy.deepcopy(source)
    result["components"] = [entry for entry in result["components"]
                            if entry["id"] in included]
    return result


def _emit_archive(source_archive: Path, files: dict[str, dict[str, Any]],
                  destination: Any) -> None:
    with zipfile.ZipFile(source_archive) as original, \
            zipfile.ZipFile(destination, "w", allowZip64=True) as output:
        for name in sorted(files):
            item = files[name]
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            info.file_size = item["size_bytes"]
            digest = hashlib.sha256()
            size = 0
            with original.open(name) as reader, output.open(info, "w") as writer:
                for block in iter(lambda: reader.read(BUFFER), b""):
                    size += len(block)
                    digest.update(block)
                    writer.write(block)
            if size != item["size_bytes"] or digest.hexdigest() != item["sha256"]:
                raise SelectionError("source member changed during finalization")


def _receipt(source: dict[str, Any], source_path: Path, selected: tuple[str, ...],
             requested: list[str], final: dict[str, Any], final_path: Path) -> dict[str, Any]:
    return {
        "schema": "usk.bundle_selection_receipt.v1",
        "source_bundle_sha256": _hash(source_path),
        "source_payload_sha256": source["payload"]["sha256"],
        "requested_components": sorted(requested),
        "selected_components": list(selected),
        "final_bundle_sha256": _hash(final_path),
        "final_payload_sha256": final["payload"]["sha256"],
    }


def inspect_selection(source_path: Path, output_dir: Path) -> dict[str, Any]:
    """Verify source and derived bytes, exact selection, and receipt closure."""
    if {item.name for item in output_dir.iterdir()} != {
            "product.bundle.json", "payload.zip", RECEIPT_NAME}:
        raise SelectionError("finalized output closure is not exact")
    source = inspect_bundle(source_path)
    final_path = output_dir / "product.bundle.json"
    final = inspect_bundle(final_path)
    if final_path.read_bytes() != _canonical(final):
        raise SelectionError("finalized bundle is not canonical")
    raw = (output_dir / RECEIPT_NAME).read_bytes()
    if len(raw) > 1024 * 1024:
        raise SelectionError("selection receipt exceeds its bound")
    try:
        receipt = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(
            SelectionError(f"invalid receipt constant: {value}")))
    except (ValueError, UnicodeDecodeError) as error:
        raise SelectionError("selection receipt is invalid") from error
    if not isinstance(receipt, dict) or _canonical(receipt) != raw or \
            receipt.get("schema") != "usk.bundle_selection_receipt.v1":
        raise SelectionError("selection receipt is not canonical")
    requested = receipt.get("requested_components")
    if (not isinstance(requested, list) or
            any(not isinstance(item, str) for item in requested) or
            requested != sorted(set(requested))):
        raise SelectionError("selection request is invalid")
    try:
        selected = resolve_component_ids(source["components"], requested)
    except ResolutionError as error:
        raise SelectionError("selection no longer resolves") from error
    if not selected:
        raise SelectionError("empty component selection")
    expected = _selected_bundle(source, selected)
    expected["payload"] = final["payload"]
    if final != expected or receipt != _receipt(
            source, source_path, selected, requested, final, final_path):
        raise SelectionError("finalized bundle or receipt differs from source selection")
    files = {item["path"]: item for component in expected["components"]
             for item in component["files"]}
    with tempfile.TemporaryFile(mode="w+b") as rebuilt, \
            (output_dir / "payload.zip").open("rb") as actual:
        _emit_archive(source_path.parent / "payload.zip", files, rebuilt)
        rebuilt.seek(0)
        while True:
            observed = actual.read(BUFFER)
            if observed != rebuilt.read(BUFFER):
                raise SelectionError("finalized archive contains noncanonical bytes")
            if not observed:
                break
    return receipt


def finalize_selection(source_path: Path, requested: list[str],
                       output_dir: Path) -> dict[str, Any]:
    source_path = source_path.resolve(strict=True)
    output_dir = output_dir.resolve(strict=True)
    if (not output_dir.is_dir() or any(output_dir.iterdir()) or
            output_dir == source_path.parent or
            output_dir.is_relative_to(source_path.parent)):
        raise SelectionError("output must be an empty directory outside source bundle")
    if len(requested) != len(set(requested)):
        raise SelectionError("duplicate requested component")
    source = inspect_bundle(source_path)
    source_bundle_hash = _hash(source_path)
    try:
        selected = resolve_component_ids(source["components"], requested)
    except ResolutionError as error:
        raise SelectionError(str(error)) from error
    if not selected:
        raise SelectionError("empty component selection")
    final = _selected_bundle(source, selected)
    files = {item["path"]: item for component in final["components"]
             for item in component["files"]}
    if not files:
        raise SelectionError("selected components contain no files")
    source_archive = source_path.parent / "payload.zip"
    final_archive = output_dir / "payload.zip"
    with final_archive.open("xb") as output:
        _emit_archive(source_archive, files, output)
    final["payload"] = {"file": "payload.zip", "size_bytes": final_archive.stat().st_size,
                        "sha256": _hash(final_archive)}
    final_path = output_dir / "product.bundle.json"
    with final_path.open("xb") as stream:
        stream.write(_canonical(final))
    if _hash(source_path) != source_bundle_hash or \
            inspect_bundle(source_path) != source:
        raise SelectionError("source bundle changed during finalization")
    receipt = _receipt(source, source_path, selected, requested, final, final_path)
    with (output_dir / RECEIPT_NAME).open("xb") as stream:
        stream.write(_canonical(receipt))
    if inspect_selection(source_path, output_dir) != receipt:
        raise SelectionError("finalized selection failed reopening")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    finalize = sub.add_parser("finalize")
    finalize.add_argument("--bundle", required=True, type=Path)
    finalize.add_argument("--select", action="append", default=[])
    finalize.add_argument("--output-dir", required=True, type=Path)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("--source-bundle", required=True, type=Path)
    inspect.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = (finalize_selection(args.bundle, args.select, args.output_dir)
                  if args.command == "finalize" else
                  inspect_selection(args.source_bundle, args.output_dir))
        print(_canonical(result).decode("ascii"), end="")
        return 0
    except (AuthoringError, ResolutionError, SelectionError, OSError,
            zipfile.BadZipFile, KeyError, TypeError) as error:
        print(f"bundle selection: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
