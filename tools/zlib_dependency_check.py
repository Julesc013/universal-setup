# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROVENANCE = ROOT / "external" / "zlib" / "provenance.v1.toml"
UPSTREAM = ROOT / "external" / "zlib" / "upstream"
WORKUNIT = ROOT / "release" / "index" / "deflate_zip64_streaming_workunit.v1.toml"
CMAKE = ROOT / "CMakeLists.txt"

EXPECTED = {
    "schema": "universal_setup.third_party_source.v1",
    "dependency_id": "zlib",
    "version": "1.3.2",
    "spdx_license_expression": "Zlib",
    "upstream_repository": "https://github.com/madler/zlib",
    "upstream_tag": "v1.3.2",
    "tag_object": "216c70c020aa53f0c40920d155f808b6b59c9acb",
    "source_commit": "da607da739fa6047df13e66a2af6b8bec7c2a498",
    "source_archive_url": "https://zlib.net/zlib-1.3.2.tar.gz",
    "source_archive_sha256": "bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16",
    "selection": "private inflate and checksum subset",
    "modified": False,
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate() -> list[str]:
    if not PROVENANCE.is_file():
        return ["zlib provenance record is missing"]
    try:
        with PROVENANCE.open("rb") as handle:
            record = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return [f"zlib provenance record cannot be read: {exc}"]

    problems: list[str] = []
    for key, expected in EXPECTED.items():
        if record.get(key) != expected:
            problems.append(f"zlib provenance {key} must be {expected!r}")

    declared: dict[str, str] = {}
    for item in record.get("file", []):
        if not isinstance(item, dict):
            problems.append("zlib provenance file entry must be a table")
            continue
        name = item.get("path")
        digest = item.get("sha256")
        if not isinstance(name, str) or Path(name).name != name:
            problems.append("zlib provenance path must be one safe file name")
            continue
        if name in declared:
            problems.append(f"zlib provenance duplicates {name}")
            continue
        if not isinstance(digest, str) or len(digest) != 64 or any(
            ch not in "0123456789abcdef" for ch in digest
        ):
            problems.append(f"zlib provenance has invalid SHA-256 for {name}")
            continue
        declared[name] = digest

    actual = {
        path.name for path in UPSTREAM.iterdir() if path.is_file()
    } if UPSTREAM.is_dir() else set()
    if set(declared) != actual:
        missing = sorted(set(declared) - actual)
        extra = sorted(actual - set(declared))
        if missing:
            problems.append(f"zlib subset is missing declared files: {', '.join(missing)}")
        if extra:
            problems.append(f"zlib subset contains undeclared files: {', '.join(extra)}")
    for name, expected in declared.items():
        path = UPSTREAM / name
        if path.is_file() and sha256(path) != expected:
            problems.append(f"zlib upstream file changed: {name}")
    if "LICENSE" not in declared:
        problems.append("zlib subset must retain the upstream LICENSE")

    cmake = CMAKE.read_text(encoding="utf-8")
    for target in (
        "usk_zlib_inflate_objects PRIVATE Z_PREFIX",
        "usk_archive_static PRIVATE Z_PREFIX",
        "usk_static PRIVATE Z_PREFIX",
        "usk_shared PRIVATE USK_BUILD_SHARED Z_PREFIX",
    ):
        if f"target_compile_definitions({target}" not in cmake:
            problems.append(f"private zlib symbol namespace is missing for {target.split()[0]}")

    if not WORKUNIT.is_file():
        problems.append("Deflate/ZIP64 WorkUnit record is missing")
    else:
        with WORKUNIT.open("rb") as handle:
            workunit = tomllib.load(handle)
        expected_workunit = {
            "schema": "universal_setup.deflate_zip64_streaming_workunit.v1",
            "workunit": "USK-DEFLATE-ZIP64-STREAMING-01",
            "status": "implementation_complete_review_pending",
            "public_c_abi": "1.0",
            "archive_methods": ["stored", "deflate"],
            "archive_containers": ["classic_zip", "single_disk_zip64"],
            "deflate_wrapper": "raw_rfc1951",
            "dependency_symbol_namespace": "Z_PREFIX",
            "stream_buffer_bytes": 65536,
            "peak_configured_stream_buffers_bytes": 131072,
            "complete_payload_retained": False,
            "package_license_expression": "MIT AND Zlib",
            "support_claim": "unclaimed_pending_protected_integration",
        }
        for key, expected in expected_workunit.items():
            if workunit.get(key) != expected:
                problems.append(f"Deflate/ZIP64 WorkUnit {key} must be {expected!r}")
        dependency = workunit.get("dependency", {})
        for key in ("tag_object", "source_commit", "archive_sha256"):
            provenance_key = {
                "archive_sha256": "source_archive_sha256"
            }.get(key, key)
            if dependency.get(key) != record.get(provenance_key):
                problems.append(f"Deflate/ZIP64 dependency {key} drifted")
        authority = workunit.get("authority", {})
        if not authority or any(value is not False for value in authority.values()):
            problems.append("Deflate/ZIP64 WorkUnit authority must remain entirely false")
    return problems


def main() -> int:
    problems = validate()
    if problems:
        for problem in problems:
            print(f"zlib-dependency-check: {problem}")
        return 1
    print(f"zlib-dependency-check: ok ({len(list(UPSTREAM.iterdir()))} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
