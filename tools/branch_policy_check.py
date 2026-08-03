# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import datetime
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "release/index/branch_policy.v1.toml"
REPOSITORY = "universal-setup"


def check_data(data: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if data.get("schema") != "universal.repository_branch_policy.v1":
        problems.append("branch policy has the wrong schema")
    if data.get("repository") != REPOSITORY:
        problems.append("branch policy has the wrong repository identity")
    try:
        reviewed = datetime.date.fromisoformat(str(data.get("reviewed_on")))
    except ValueError:
        problems.append("branch policy reviewed_on must use YYYY-MM-DD")
    else:
        if reviewed.isoformat() != data.get("reviewed_on"):
            problems.append("branch policy reviewed_on must use YYYY-MM-DD")
    expected = {
        "branches": {"canonical": "main", "integration": "dev", "task_prefix": "task/", "hotfix_prefix": "hotfix/", "release_tags_from": "main"},
        "invariants": {"main_must_be_ancestor_of_dev": True, "task_must_start_from_exact_dev": True, "normal_task_pull_request_target": "dev", "normal_main_pull_request_source": "dev", "direct_protected_push": False, "force_push": False, "protected_branch_deletion": False, "maximum_completed_unpromoted_work_units": 1, "consumer_pins_may_reference_dev": False},
        "synchronization": {"after_dev_promotion": "fast_forward_dev_to_canonical_main_closeout", "after_main_hotfix": "open_main_to_dev_pull_request", "unrelated_divergence": "fail_for_human_review", "force_reset_dev": False},
        "dependency_tracks": {"stable": "exact_provider_sha_reachable_from_provider_main", "canary": "exact_provider_dev_sha_input_without_tracked_lock_change", "adoption": "separate_exact_pin_pull_request_after_provider_main_promotion", "atomic_cross_repository_merge": False},
        "automation_authority": {"task_branch_write": True, "pull_request_write": True, "protected_branch_write": False, "self_approval": False, "self_merge": False, "signing": False, "publication": False, "product_credentials": False},
    }
    for section, values in expected.items():
        actual = data.get(section)
        if not isinstance(actual, dict):
            problems.append(f"branch policy is missing [{section}]")
            continue
        for key, value in values.items():
            if actual.get(key) != value:
                problems.append(f"branch policy {section}.{key} must be {value!r}")
    return problems


def check() -> list[str]:
    if not POLICY.is_file():
        return [f"branch policy is missing: {POLICY}"]
    with POLICY.open("rb") as handle:
        return check_data(tomllib.load(handle))


def main() -> int:
    problems = check()
    if problems:
        for problem in problems:
            print(f"branch-policy-check: {problem}", file=sys.stderr)
        return 1
    print("branch-policy-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
