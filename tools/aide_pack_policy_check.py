# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Verify the pinned Apache-2.0 development pack before granting license exceptions."""
from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ".aide/install/aide-lite-pack-v0.receipt.json"
RECEIPT_SHA256 = "acfb447755fd49d059d3275a2cc66c65f0fed00821d50996ae3b006ec57523a2"
SOURCE_MAIN = "1402003782ee9e23d3892065f3b4e4dc329ccbfe"
EXPORT_SOURCE = "27338811d14b3314a98434a68be4a7d7d56b6667"
LICENSES = {
    "LICENSE": "4dc06d89797867a708e238be9df8c67f9c6395a29f783b00b009cdf80a0bf9c5",
    "NOTICE": "2246ed3f6738e9a9175648ecb6fdc6fc0423b96e4a2db7e6a8c70727c4ca9950",
}
DEVELOPMENT_DEPENDENCY = {
    "id": "aide-lite",
    "version": SOURCE_MAIN,
    "spdx_license_expression": "Apache-2.0",
    "license_file": "external/aide/LICENSE",
    "notice_file": "external/aide/NOTICE",
    "provenance_file": "external/aide/provenance.v1.json",
}


def read_regular(root: Path, relative: str, limit: int = 8 * 1024 * 1024) -> bytes:
    parts = PurePosixPath(relative).parts
    if not parts or relative != "/".join(parts) or any(p in {"", ".", ".."} for p in parts):
        raise ValueError(f"invalid relative tooling path: {relative}")
    current = root
    for part in parts:
        current = current / part
        facts = current.lstat()
        if stat.S_ISLNK(facts.st_mode) or getattr(facts, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"reparse/link tooling path: {relative}")
    if not stat.S_ISREG(facts.st_mode) or facts.st_size > limit:
        raise ValueError(f"nonregular or oversized tooling file: {relative}")
    return current.read_bytes()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate(root: Path = ROOT) -> tuple[list[str], set[Path]]:
    problems: list[str] = []
    licensed: set[Path] = set()
    try:
        provenance = json.loads(read_regular(root, "external/aide/provenance.v1.json", 8192))
        expected = {
            "schema": "universal_setup.aide_development_tooling.v1",
            "source_repository": "Julesc013/aide",
            "source_main": SOURCE_MAIN,
            "export_source": EXPORT_SOURCE,
            "spdx_license_expression": "Apache-2.0",
            "runtime_dependency": False,
            "receipt": RECEIPT,
            "receipt_sha256": RECEIPT_SHA256,
            "managed_records": 819,
            "managed_files": 818,
            "licenses": LICENSES,
        }
        if provenance != expected:
            raise ValueError("AIDE development provenance drifted")
        for name, digest in LICENSES.items():
            if sha256(read_regular(root, f"external/aide/{name}", 32768)) != digest:
                raise ValueError(f"AIDE upstream {name} drifted")
        raw = read_regular(root, RECEIPT, 512 * 1024)
        if sha256(raw) != RECEIPT_SHA256:
            raise ValueError("AIDE import receipt drifted")
        receipt = json.loads(raw)
        if (receipt.get("schema_version") != "aide.portable-import-receipt.v2"
                or receipt.get("mode") != "safe"
                or receipt.get("network_calls") is not False
                or receipt.get("provider_or_model_calls") is not False
                or receipt.get("pack") != {
                    "checksums_digest": "dd564384415f06165d53f4de492840131dfd74f230485c2326fba8e44df10a2d",
                    "manifest_digest": "81c215bdf9f21ccda65f06a848cca0c1d1101d8f54e1b5b06aff8544b1398ec9",
                    "pack_id": "aide-lite-pack-v0",
                    "source_commit": EXPORT_SOURCE,
                }):
            raise ValueError("AIDE safe-import identity drifted")
        managed = receipt.get("managed")
        if not isinstance(managed, dict) or len(managed) != 819:
            raise ValueError("AIDE managed inventory drifted")
        file_count = 0
        for relative, entry in managed.items():
            if (not isinstance(entry, dict)
                    or entry.get("ownership") != "aide_portable_managed"
                    or entry.get("local_overlay") is not False
                    or entry.get("source_digest") != entry.get("installed_digest")):
                raise ValueError(f"AIDE managed ownership drifted: {relative}")
            digest = entry["installed_digest"]
            if relative == "AGENTS.md":
                if entry.get("kind") != "portable_managed_section" or entry.get("source") != "AGENTS.md.template":
                    raise ValueError("AIDE AGENTS section ownership drifted")
                # Importer section digests use UTF-8 text with normalized newlines.
                text = read_regular(root, relative, 65536).decode("utf-8").replace("\r\n", "\n")
                begin = "<!-- AIDE-PORTABLE:BEGIN section=aide-lite-pack-v0"
                end = "<!-- AIDE-PORTABLE:END section=aide-lite-pack-v0 -->"
                if text.count(begin) != 1 or text.count(end) != 1:
                    raise ValueError("AIDE AGENTS section missing or ambiguous")
                start = text.index(begin)
                finish = text.index(end, start) + len(end)
                if sha256(text[start:finish].encode("utf-8")) != digest:
                    raise ValueError("AIDE managed AGENTS section drifted")
                continue
            if (entry.get("kind") != "managed_file" or entry.get("source") != relative
                    or not relative.startswith((".aide/", ".aide.local.example/", "docs/reference/"))):
                raise ValueError(f"AIDE managed file outside optional tooling: {relative}")
            if sha256(read_regular(root, relative)) != digest:
                raise ValueError(f"AIDE managed file drifted: {relative}")
            licensed.add(Path(relative))
            file_count += 1
        if file_count != 818:
            raise ValueError("AIDE managed file count drifted")
        profile = ".aide/profile.yaml"
        header = read_regular(root, profile, 16384).decode("utf-8").splitlines()[:8]
        if "SPDX-License-Identifier: Apache-2.0" not in "\n".join(header):
            raise ValueError("AIDE target-owned profile must retain its Apache-2.0 attribution")
        licensed.add(Path(profile))
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        problems.append(str(error))
    # A failed proof never grants any source a license-policy exception.
    return problems, set() if problems else licensed


def main() -> int:
    problems, licensed = validate()
    for problem in problems:
        print(f"aide-pack-policy-check: {problem}")
    if not problems:
        print(f"aide-pack-policy-check: ok (818 upstream files, target profile, preserved AGENTS section; development only)")
    return int(bool(problems))


if __name__ == "__main__":
    raise SystemExit(main())
