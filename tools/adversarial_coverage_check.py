# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/fixtures/setup/m2-adversarial-coverage.v1.json"

REQUIRED_CASES = {
    "unicode_and_long_paths",
    "case_collisions",
    "unicode_normalization_collisions",
    "links_and_reparse_points",
    "source_replacement",
    "target_ancestor_replacement",
    "concurrent_applies",
    "read_only_sources",
    "partial_writes",
    "insufficient_space_simulation",
    "cross_device_move",
    "changed_ownership_manifests",
    "audit_chain_tampering",
    "stale_and_replayed_plans",
    "foreign_files_during_repair_or_uninstall",
    "frontend_cancellation_and_process_termination",
}
REQUIRED_PLATFORMS = {
    "linux": "ubuntu-24.04",
    "macos": "macos-15-intel",
    "windows": "windows-2022",
}


def main() -> int:
    document = json.loads(MANIFEST.read_text(encoding="utf-8"))
    problems: list[str] = []
    if document.get("schema") != "usk.m2_adversarial_coverage.v1":
        problems.append("unexpected coverage schema")

    authority = document.get("authority", {})
    expected_authority = {
        "automation_can_record_operator_verdict": False,
        "execution_authority": False,
        "operator_verdict": "pending",
        "ordinary_live_apply": "unavailable_pending_operator_acceptance",
    }
    for key, expected in expected_authority.items():
        if authority.get(key) != expected:
            problems.append(f"authority field {key} must remain {expected!r}")

    platforms = {item.get("id"): item.get("runner") for item in document.get("required_platforms", [])}
    if platforms != REQUIRED_PLATFORMS:
        problems.append(f"required platform runners differ: {platforms!r}")

    cases = document.get("cases", [])
    by_id = {case.get("id"): case for case in cases}
    if len(by_id) != len(cases):
        problems.append("adversarial case identifiers must be unique")
    missing = sorted(REQUIRED_CASES - set(by_id))
    extra = sorted(set(by_id) - REQUIRED_CASES)
    if missing:
        problems.append(f"missing required cases: {', '.join(missing)}")
    if extra:
        problems.append(f"unexpected cases: {', '.join(extra)}")

    for case_id in sorted(REQUIRED_CASES - {"frontend_cancellation_and_process_termination"}):
        case = by_id.get(case_id, {})
        if case.get("owner") != "universal_setup":
            problems.append(f"{case_id}: owner must be universal_setup")
        evidence = case.get("evidence", [])
        if not evidence:
            problems.append(f"{case_id}: evidence is required")
        for proof in evidence:
            relative = proof.get("path", "")
            path = ROOT / relative
            if not path.is_file():
                problems.append(f"{case_id}: evidence file is missing: {relative}")
                continue
            text = path.read_text(encoding="utf-8")
            for marker in proof.get("markers", []):
                if marker not in text:
                    problems.append(f"{case_id}: marker {marker!r} is missing from {relative}")

    frontend = by_id.get("frontend_cancellation_and_process_termination", {})
    if frontend.get("owner") != "factorio_launcher" or frontend.get("status") != "consumer_proof_required":
        problems.append("frontend cancellation/termination must remain an explicit consumer proof")
    if len(frontend.get("external_evidence", [])) < 2:
        problems.append("frontend consumer proof must identify cancellation and process evidence")

    if problems:
        for problem in problems:
            print(f"adversarial-coverage: {problem}", file=sys.stderr)
        return 1
    print(
        "adversarial-coverage: ok "
        f"({len(REQUIRED_CASES) - 1} setup cases; 1 explicit consumer case; "
        f"{len(REQUIRED_PLATFORMS)} hosted platforms)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
