# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import datetime
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "release/index/branch_policy.v2.toml"
HISTORICAL_POLICY = ROOT / "release/index/branch_policy.v1.toml"
CAMPAIGN_AUTHORITY = ROOT / "release/index/campaign_authority.v1.toml"
REPOSITORY = "universal-setup"
CAMPAIGN = "USK-SPEC-TO-RELEASE-01"
OID_RE = re.compile(r"^[0-9a-f]{40}$")


EXPECTED_POLICY = {
    "branches": {
        "canonical": "main",
        "integration": "dev",
        "task_prefix": "task/",
        "hotfix_prefix": "hotfix/",
        "release_tags_from": "main",
    },
    "invariants": {
        "main_must_be_ancestor_of_dev": True,
        "task_must_start_from_exact_dev": True,
        "normal_task_pull_request_target": "dev",
        "normal_main_pull_request_source": "dev",
        "direct_protected_push": False,
        "force_push": False,
        "protected_branch_deletion": False,
        "merge_bypass": False,
        "immutable_release_tags": True,
        "maximum_completed_unpromoted_work_units": 1,
        "consumer_pins_may_reference_dev": False,
    },
    "synchronization": {
        "after_dev_promotion": "fast_forward_dev_to_canonical_main_closeout",
        "after_main_hotfix": "open_main_to_dev_pull_request",
        "unrelated_divergence": "fail_for_technical_review",
        "force_reset_dev": False,
    },
    "dependency_tracks": {
        "stable": "exact_provider_sha_reachable_from_provider_main",
        "canary": "exact_provider_dev_sha_input_without_tracked_lock_change",
        "adoption": "separate_exact_pin_pull_request_after_provider_main_promotion",
        "atomic_cross_repository_merge": False,
    },
    "automation_authority": {
        "task_branch_write": True,
        "pull_request_write": True,
        "protected_branch_write": False,
        "normal_pull_request_merge": True,
        "merge_executor_may_equal_pr_author": True,
        "github_self_approval": False,
        "technical_review_required": True,
        "different_review_context_required": True,
        "human_review_claim_requires_human_principal": True,
        "configured_release_signing": True,
        "qualified_release_publication": True,
        "configured_release_credentials": True,
        "credential_creation_or_export": False,
        "unrelated_product_credentials": False,
    },
    "merge_gate": {
        "expected_head_required": True,
        "expected_base_required": True,
        "required_checks_must_succeed": True,
        "unresolved_threads_allowed": False,
        "draft_allowed": False,
        "mergeable_required": True,
        "technical_review_exact_head_required": True,
        "normal_pull_request_path_required": True,
    },
    "release_gate": {
        "exact_main_source_required": True,
        "machine_qualification_required": True,
        "remote_readback_required": True,
        "tag_movement_allowed": False,
        "configured_signer_required_when_signing": True,
        "qualified_candidate_required": True,
    },
}


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _date_errors(data: dict[str, Any], prefix: str) -> list[str]:
    try:
        reviewed = datetime.date.fromisoformat(str(data.get("reviewed_on")))
    except ValueError:
        return [prefix + " reviewed_on must use YYYY-MM-DD"]
    if reviewed.isoformat() != data.get("reviewed_on"):
        return [prefix + " reviewed_on must use YYYY-MM-DD"]
    return []


def check_data(data: dict[str, Any]) -> list[str]:
    """Validate the active repository policy as a closed, reviewable contract."""
    problems: list[str] = []
    expected_top = {
        "schema", "repository", "reviewed_on", "status", "campaign_authority",
        *EXPECTED_POLICY,
    }
    if set(data) != expected_top:
        problems.append("branch policy top-level fields are incomplete or unknown")
    if data.get("schema") != "universal.repository_branch_policy.v2":
        problems.append("branch policy has the wrong schema")
    if data.get("repository") != REPOSITORY:
        problems.append("branch policy has the wrong repository identity")
    if data.get("status") != "active":
        problems.append("branch policy must be active")
    if data.get("campaign_authority") != "release/index/campaign_authority.v1.toml":
        problems.append("branch policy must bind the canonical campaign authority")
    problems.extend(_date_errors(data, "branch policy"))
    for section, values in EXPECTED_POLICY.items():
        actual = data.get(section)
        if not isinstance(actual, dict):
            problems.append(f"branch policy is missing [{section}]")
            continue
        if set(actual) != set(values):
            problems.append(f"branch policy [{section}] fields are incomplete or unknown")
        for key, value in values.items():
            if actual.get(key) != value:
                problems.append(f"branch policy {section}.{key} must be {value!r}")
    return problems


def check_campaign_data(data: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    expected_top = {
        "schema", "campaign", "repository", "status", "recorded_at",
        "authority_source", "r2_zip_sha256", "r2_goal_sha256",
        "initial_dev_commit", "initial_dev_tree", "scope", "binding", "review",
        "constraints", "release",
    }
    if set(data) != expected_top:
        problems.append("campaign authority top-level fields are incomplete or unknown")
    if data.get("schema") != "universal.spec_to_release_campaign_authority.v1":
        problems.append("campaign authority has the wrong schema")
    if data.get("campaign") != CAMPAIGN or data.get("status") != "active":
        problems.append("campaign authority must identify the active campaign")
    if data.get("repository") != "Julesc013/universal-setup":
        problems.append("campaign authority has the wrong repository")
    try:
        stamp = datetime.datetime.fromisoformat(str(data.get("recorded_at")))
        if stamp.tzinfo is None:
            raise ValueError
    except ValueError:
        problems.append("campaign authority recorded_at must be timezone-aware")
    for field in ("r2_zip_sha256", "r2_goal_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(data.get(field, ""))):
            problems.append(f"campaign authority {field} must be SHA-256")
    for field in ("initial_dev_commit", "initial_dev_tree"):
        if not OID_RE.fullmatch(str(data.get(field, ""))):
            problems.append(f"campaign authority {field} must be a Git object ID")
    expected_sections = {
        "scope": {
            "implementation", "testing", "documentation", "task_branches_and_worktrees",
            "pull_requests", "qualified_dev_merge", "qualified_main_promotion",
            "automatic_exact_task_binding", "build_and_package", "immutable_release_tagging",
            "configured_release_signing", "qualified_release_publication",
        },
        "binding": {
            "fresh_owner_approval_per_workunit", "exact_source_commit_and_tree",
            "exact_task_definition_digest", "exact_specification_aggregate",
            "scope_may_widen_template", "accepted_predecessor_receipts_required",
            "effect_target_receipt_required_for_endpoint_or_user_state",
            "ordinary_source_change_requires_rebind_not_reauthorization",
        },
        "review": {
            "technical_review_required", "different_review_context_required",
            "agent_review_allowed", "human_approval_required_by_campaign",
            "truthful_provenance_required", "agent_review_must_not_claim_human_approval",
        },
        "constraints": {
            "direct_protected_push", "force_push", "merge_bypass", "red_or_pending_merge",
            "stale_head_or_base_merge", "fabricated_acceptance",
            "credential_creation_export_or_disclosure", "unrelated_data_mutation",
            "customer_machine_effects_without_runtime_consent_and_policy", "tag_movement",
        },
        "release": {
            "exact_main_source", "qualified_candidate_bytes",
            "configured_purpose_authorized_signer_only", "remote_tag_asset_and_digest_readback",
            "missing_signer_blocks_only_signing_and_claims_that_require_it",
        },
    }
    false_fields = {
        "fresh_owner_approval_per_workunit", "scope_may_widen_template",
        "human_approval_required_by_campaign", "direct_protected_push", "force_push",
        "merge_bypass", "red_or_pending_merge", "stale_head_or_base_merge",
        "fabricated_acceptance", "credential_creation_export_or_disclosure",
        "unrelated_data_mutation",
        "customer_machine_effects_without_runtime_consent_and_policy", "tag_movement",
    }
    for section, fields in expected_sections.items():
        value = data.get(section)
        if not isinstance(value, dict) or set(value) != fields:
            problems.append(f"campaign authority [{section}] fields are incomplete or unknown")
            continue
        for key, enabled in value.items():
            expected = key not in false_fields
            if enabled is not expected:
                problems.append(f"campaign authority {section}.{key} must be {expected!r}")
    return problems


def merge_admission_errors(observation: dict[str, Any]) -> list[str]:
    """Pure exact-green PR merge oracle; it performs no GitHub operation."""
    errors: list[str] = []
    for field in ("expected_head_oid", "observed_head_oid", "expected_base_oid", "observed_base_oid"):
        if not OID_RE.fullmatch(str(observation.get(field, ""))):
            errors.append(field + " must be a Git object ID")
    if observation.get("observed_head_oid") != observation.get("expected_head_oid"):
        errors.append("pull request head is stale")
    if observation.get("observed_base_oid") != observation.get("expected_base_oid"):
        errors.append("pull request base is stale")
    if observation.get("state") != "OPEN" or observation.get("draft") is not False:
        errors.append("pull request must be open and non-draft")
    if observation.get("mergeable") is not True:
        errors.append("pull request must be mergeable")
    if observation.get("merge_method") != "normal_pull_request":
        errors.append("normal pull-request merge path is required")
    for field, message in (
        ("direct_protected_push", "direct protected push is forbidden"),
        ("force_update", "force update is forbidden"),
        ("bypass", "ruleset bypass is forbidden"),
    ):
        if observation.get(field) is not False:
            errors.append(message)
    if observation.get("unresolved_threads") != 0:
        errors.append("all review threads must be resolved")
    checks = observation.get("required_checks")
    if not isinstance(checks, list) or not checks:
        errors.append("required checks are missing")
    else:
        for check in checks:
            if not isinstance(check, dict) or not check.get("name"):
                errors.append("required check observation is malformed")
                continue
            if check.get("conclusion") != "SUCCESS":
                errors.append("required check is not successful: " + str(check.get("name")))
            if check.get("head_oid") != observation.get("expected_head_oid"):
                errors.append("required check is bound to a stale head: " + str(check.get("name")))
            if check.get("base_oid") != observation.get("expected_base_oid"):
                errors.append("required check is bound to a stale base: " + str(check.get("name")))
    review = observation.get("technical_review")
    if not isinstance(review, dict):
        errors.append("technical review is missing")
    else:
        if review.get("kind") not in {"agent", "human"}:
            errors.append("technical review kind must be agent or human")
        if not review.get("reviewer_context") or review.get("reviewer_context") == review.get("author_context"):
            errors.append("technical review must use a different review context")
        if review.get("head_oid") != observation.get("expected_head_oid"):
            errors.append("technical review is bound to a stale head")
        if review.get("kind") == "agent":
            if review.get("claims_human") is not False:
                errors.append("agent review must not claim human provenance")
            if review.get("github_state") == "APPROVED":
                errors.append("agent review must not fabricate GitHub approval")
    return errors


def check() -> list[str]:
    problems: list[str] = []
    if not POLICY.is_file():
        problems.append(f"branch policy is missing: {POLICY}")
    else:
        problems.extend(check_data(_load_toml(POLICY)))
    if not CAMPAIGN_AUTHORITY.is_file():
        problems.append(f"campaign authority is missing: {CAMPAIGN_AUTHORITY}")
    else:
        problems.extend(check_campaign_data(_load_toml(CAMPAIGN_AUTHORITY)))
    if not HISTORICAL_POLICY.is_file():
        problems.append(f"historical branch policy is missing: {HISTORICAL_POLICY}")
    else:
        historical = _load_toml(HISTORICAL_POLICY)
        expected = POLICY.relative_to(ROOT).as_posix()
        if historical.get("status") != "superseded" or historical.get("superseded_by") != expected:
            problems.append("historical branch policy must point to the active v2 policy")
    return problems


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
