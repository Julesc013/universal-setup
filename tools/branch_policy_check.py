# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import subprocess
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
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_STATUS_CHECKS = [
    "native-windows", "native-windows-win32", "native-linux", "native-macos",
    "sanitizer", "fuzz-smoke",
]
GITHUB_RULESET_ID = 20445004
GITHUB_ACTIONS_INTEGRATION_ID = 15368
ASSOCIATED_PROMOTION_PR_PAGE_SIZE = 100
MAX_ASSOCIATED_PROMOTION_PR_PAGES = 3
CLOSEOUT_PROOF_FIELDS = {
    "live_main_tip_oid", "live_dev_tip_oid", "promotion_merge",
    "dev_base_tree_oid", "prior_main_ancestry", "promotion_pull_request",
}


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
        "after_dev_promotion": "zero_content_normal_pull_request_main_to_dev_closeout",
        "after_main_hotfix": "require_separate_hotfix_reconciliation_review",
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
        "strict_required_status_checks": True,
        "github_ruleset_id": GITHUB_RULESET_ID,
        "github_actions_integration_id": GITHUB_ACTIONS_INTEGRATION_ID,
        "required_status_checks": REQUIRED_STATUS_CHECKS,
        "unresolved_threads_allowed": False,
        "draft_allowed": False,
        "mergeable_required": True,
        "technical_review_exact_head_required": True,
        "normal_pull_request_path_required": True,
        "post_promotion_closeout_main_to_dev_route_only": True,
        "post_promotion_closeout_exact_live_tips_required": True,
        "post_promotion_closeout_two_parent_promotion_merge_required": True,
        "post_promotion_closeout_zero_content_tree_required": True,
        "post_promotion_closeout_exact_merged_pr_provenance_required": True,
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


def _closeout_proof_errors(observation: dict[str, Any]) -> list[str]:
    """Validate the closed live facts required for a main-to-dev closeout."""
    errors: list[str] = []
    proof = observation.get("closeout_proof")
    if not isinstance(proof, dict) or set(proof) != CLOSEOUT_PROOF_FIELDS:
        return ["main-to-dev closeout proof is missing or malformed"]
    expected_head = observation.get("expected_head_oid")
    expected_base = observation.get("expected_base_oid")
    if proof.get("live_main_tip_oid") != expected_head:
        errors.append("closeout proof is not bound to the live main tip")
    if proof.get("live_dev_tip_oid") != expected_base:
        errors.append("closeout proof is not bound to the live dev tip")

    merge = proof.get("promotion_merge")
    if not isinstance(merge, dict) or set(merge) != {"oid", "tree_oid", "parent_oids"}:
        errors.append("closeout promotion merge proof is malformed")
        parents: list[Any] = []
    else:
        parents = merge.get("parent_oids") if isinstance(merge.get("parent_oids"), list) else []
        if merge.get("oid") != expected_head:
            errors.append("closeout promotion merge is not the exact main head")
        if not OID_RE.fullmatch(str(merge.get("tree_oid", ""))):
            errors.append("closeout promotion merge tree is invalid")
        if (len(parents) != 2 or any(not OID_RE.fullmatch(str(parent)) for parent in parents) or
                (len(parents) == 2 and parents[0] == parents[1])):
            errors.append("closeout promotion merge must have exactly two Git parents")
        elif parents[1] != expected_base:
            errors.append("closeout promotion merge second parent is not the exact dev base")
        if merge.get("tree_oid") != proof.get("dev_base_tree_oid"):
            errors.append("closeout promotion merge tree differs from the exact dev base tree")
    if not OID_RE.fullmatch(str(proof.get("dev_base_tree_oid", ""))):
        errors.append("closeout dev base tree is invalid")

    ancestry = proof.get("prior_main_ancestry")
    expected_prior = parents[0] if len(parents) == 2 else None
    if not isinstance(ancestry, dict) or set(ancestry) != {
        "ancestor_oid", "descendant_oid", "merge_base_oid", "status",
    }:
        errors.append("closeout prior-main ancestry proof is malformed")
    else:
        if ancestry.get("ancestor_oid") != expected_prior or ancestry.get("descendant_oid") != expected_base:
            errors.append("closeout prior-main ancestry is not bound to the promotion parents")
        if ancestry.get("merge_base_oid") != expected_prior or ancestry.get("status") != "AHEAD":
            errors.append("closeout prior-main is not an ancestor of the exact dev base")

    promotion_pr = proof.get("promotion_pull_request")
    if not isinstance(promotion_pr, dict) or set(promotion_pr) != {
        "number", "merged", "base_ref", "head_ref", "base_repository", "head_repository",
        "merge_commit_oid", "head_oid",
    }:
        errors.append("closeout promotion pull-request proof is malformed")
    else:
        if type(promotion_pr.get("number")) is not int or promotion_pr["number"] <= 0:
            errors.append("closeout promotion pull-request number is invalid")
        if promotion_pr.get("merged") is not True:
            errors.append("closeout promotion pull request is not merged")
        if promotion_pr.get("base_ref") != "main" or promotion_pr.get("head_ref") != "dev":
            errors.append("closeout promotion pull request is not dev-to-main")
        if (promotion_pr.get("base_repository") != "Julesc013/universal-setup" or
                promotion_pr.get("head_repository") != "Julesc013/universal-setup"):
            errors.append("closeout promotion pull request must use canonical same-repository refs")
        if promotion_pr.get("merge_commit_oid") != expected_head or promotion_pr.get("head_oid") != expected_base:
            errors.append("closeout promotion pull request is not bound to the exact merge and dev base")
    return errors


def merge_admission_errors(observation: dict[str, Any]) -> list[str]:
    """Validate a closed observation produced by the live GitHub collector below."""
    errors: list[str] = []
    expected_top = {
        "schema", "collector", "collected_from_github", "repository", "pull_request",
        "base_ref", "head_ref", "base_repository", "head_repository", "expected_head_oid", "observed_head_oid",
        "expected_base_oid", "observed_base_oid", "state", "draft", "mergeable",
        "merge_state_status", "merge_method", "direct_protected_push", "force_update",
        "bypass", "unresolved_threads", "author_context", "executor_context",
        "author_login", "required_check_policy", "required_checks", "technical_review",
        "closeout_proof",
    }
    if set(observation) != expected_top:
        errors.append("merge observation fields are incomplete or unknown")
    if observation.get("schema") != "universal.github_merge_observation.v2":
        errors.append("merge observation schema is invalid")
    if observation.get("collector") != "tools/branch_policy_check.py/live-v2" or observation.get("collected_from_github") is not True:
        errors.append("merge observation must come from the live GitHub collector")
    if observation.get("repository") != "Julesc013/universal-setup":
        errors.append("merge observation repository is invalid")
    if (observation.get("head_repository") != "Julesc013/universal-setup" or
            observation.get("base_repository") != "Julesc013/universal-setup"):
        errors.append("pull request must use canonical same-repository refs")
    if type(observation.get("pull_request")) is not int or observation["pull_request"] <= 0:
        errors.append("pull request number is invalid")
    head_ref = observation.get("head_ref")
    base_ref = observation.get("base_ref")
    main_to_dev_closeout = False
    if not isinstance(head_ref, str) or not head_ref:
        errors.append("pull request refs are invalid")
    elif head_ref.startswith("task/"):
        if base_ref != "dev":
            errors.append("task pull request must target dev")
    elif head_ref == "dev":
        if base_ref != "main":
            errors.append("dev promotion pull request must target main")
    elif head_ref == "main":
        if base_ref != "dev":
            errors.append("main closeout pull request must target dev")
        else:
            main_to_dev_closeout = True
    else:
        errors.append("pull request route is not declared by branch policy")
    if main_to_dev_closeout:
        errors.extend(_closeout_proof_errors(observation))
    elif observation.get("closeout_proof") is not None:
        errors.append("closeout proof must be null outside main-to-dev closeout")
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
    if observation.get("merge_state_status") != "CLEAN":
        errors.append("GitHub merge state must be CLEAN")
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
    check_policy = observation.get("required_check_policy")
    expected_check_policy = {
        "ruleset_id": GITHUB_RULESET_ID,
        "strict": True,
        "integration_id": GITHUB_ACTIONS_INTEGRATION_ID,
        "names": REQUIRED_STATUS_CHECKS,
    }
    if check_policy != expected_check_policy:
        errors.append("required-check policy differs from the live pinned GitHub ruleset")
    checks = observation.get("required_checks")
    if not isinstance(checks, list):
        errors.append("required checks are missing")
    else:
        names = [check.get("name") for check in checks if isinstance(check, dict)]
        if set(names) != set(REQUIRED_STATUS_CHECKS):
            errors.append("required check observations do not exactly cover the pinned set")
        for check in checks:
            if not isinstance(check, dict) or set(check) != {
                "name", "status", "conclusion", "head_oid",
                "integration_id", "details_url",
            }:
                errors.append("required check observation is malformed")
                continue
            if check.get("status") != "COMPLETED" or check.get("conclusion") != "SUCCESS":
                errors.append("required check is not successful: " + str(check.get("name")))
            if check.get("integration_id") != GITHUB_ACTIONS_INTEGRATION_ID:
                errors.append("required check has the wrong GitHub integration: " + str(check.get("name")))
            if not re.fullmatch(r"https://github\.com/Julesc013/universal-setup/actions/runs/\d+/job/\d+", str(check.get("details_url", ""))):
                errors.append("required check details URL is invalid: " + str(check.get("name")))
            if check.get("head_oid") != observation.get("expected_head_oid"):
                errors.append("required check is bound to a stale head: " + str(check.get("name")))
    review = observation.get("technical_review")
    if not isinstance(review, dict):
        errors.append("technical review is missing")
    else:
        expected_review_fields = {
            "kind", "reviewer_context", "author_context", "head_oid", "claims_human",
            "github_state", "reviewer_principal", "provenance",
        }
        if set(review) != expected_review_fields:
            errors.append("technical review fields are incomplete or unknown")
        if review.get("kind") not in {"agent", "human"}:
            errors.append("technical review kind must be agent or human")
        if review.get("author_context") != observation.get("author_context"):
            errors.append("technical review author context is not bound to the live PR author")
        if not review.get("reviewer_context") or review.get("reviewer_context") == observation.get("author_context"):
            errors.append("technical review must use a different review context")
        if review.get("head_oid") != observation.get("expected_head_oid"):
            errors.append("technical review is bound to a stale head")
        if review.get("kind") == "agent":
            if review.get("claims_human") is not False or not str(review.get("reviewer_principal", "")).startswith("agent:"):
                errors.append("agent review must not claim human provenance")
            if review.get("github_state") != "COMMENTED":
                errors.append("agent review must not fabricate GitHub approval")
            expected_provider = "github_issue_comment"
        else:
            if review.get("claims_human") is not True or str(review.get("reviewer_principal", "")).startswith("agent:"):
                errors.append("human review needs an actual human principal")
            if review.get("github_state") != "APPROVED":
                errors.append("human technical review must be an actual GitHub approval")
            expected_provider = "github_pull_request_review"
        provenance = review.get("provenance")
        if not isinstance(provenance, dict) or set(provenance) != {"provider", "id", "url", "body_sha256"}:
            errors.append("technical review provenance is malformed")
        else:
            if provenance.get("provider") != expected_provider or type(provenance.get("id")) is not int or provenance["id"] <= 0:
                errors.append("technical review provenance provider or ID is invalid")
            if not str(provenance.get("url", "")).startswith("https://github.com/Julesc013/universal-setup/"):
                errors.append("technical review provenance URL is invalid")
            if not SHA256_RE.fullmatch(str(provenance.get("body_sha256", ""))):
                errors.append("technical review body digest is invalid")
    return errors


def _gh_json(arguments: list[str]) -> Any:
    result = subprocess.run(
        ["gh", "api", *arguments], cwd=ROOT, check=False,
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError("GitHub API read failed: " + result.stderr.strip())
    return json.loads(result.stdout)


def _review_from_github(
    repository: str, pull_request: int, head_oid: str, author_context: str,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    kind = receipt.get("kind")
    reviewer_context = receipt.get("reviewer_context")
    record_id = receipt.get("github_record_id")
    if kind not in {"agent", "human"} or not isinstance(reviewer_context, str) or not reviewer_context:
        raise RuntimeError("technical review receipt kind/context is invalid")
    if type(record_id) is not int or record_id <= 0:
        raise RuntimeError("technical review receipt GitHub record ID is invalid")
    if kind == "agent":
        record = _gh_json([f"repos/{repository}/issues/comments/{record_id}"])
        body = str(record.get("body", ""))
        if head_oid not in body or reviewer_context not in body or "RESULT: APPROVE" not in body:
            raise RuntimeError("agent review comment does not bind the exact head/context/approval result")
        if record.get("issue_url", "").rsplit("/", 1)[-1] != str(pull_request):
            raise RuntimeError("agent review comment belongs to a different pull request")
        principal = "agent:" + reviewer_context
        state = "COMMENTED"
        claims_human = False
        provider = "github_issue_comment"
        url = record.get("html_url")
    else:
        record = _gh_json([f"repos/{repository}/pulls/{pull_request}/reviews/{record_id}"])
        body = str(record.get("body", ""))
        if record.get("commit_id") != head_oid or record.get("state") != "APPROVED":
            raise RuntimeError("human GitHub review is not an exact-head approval")
        principal = str(record.get("user", {}).get("login", ""))
        if not principal:
            raise RuntimeError("human GitHub review has no principal")
        state = "APPROVED"
        claims_human = True
        provider = "github_pull_request_review"
        url = record.get("html_url")
    return {
        "kind": kind,
        "reviewer_context": reviewer_context,
        "author_context": author_context,
        "head_oid": head_oid,
        "claims_human": claims_human,
        "github_state": state,
        "reviewer_principal": principal,
        "provenance": {
            "provider": provider,
            "id": record_id,
            "url": url,
            "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        },
    }


def _live_branch_tip(repository: str, branch: str) -> str:
    ref = _gh_json([f"repos/{repository}/git/ref/heads/{branch}"])
    tip = ref.get("object", {})
    if tip.get("type") != "commit" or not OID_RE.fullmatch(str(tip.get("sha", ""))):
        raise RuntimeError("live branch tip is not a commit: " + branch)
    return tip["sha"]


def _collect_closeout_proof(repository: str, head_oid: str, base_oid: str) -> dict[str, Any]:
    """Read and bind the one zero-content promotion closeout shape from GitHub."""
    main_tip = _live_branch_tip(repository, "main")
    dev_tip = _live_branch_tip(repository, "dev")
    if main_tip != head_oid or dev_tip != base_oid:
        raise RuntimeError("main-to-dev closeout is not bound to the live main and dev tips")

    promotion = _gh_json([f"repos/{repository}/git/commits/{head_oid}"])
    dev_base = _gh_json([f"repos/{repository}/git/commits/{base_oid}"])
    parents = [parent.get("sha") for parent in promotion.get("parents", []) if isinstance(parent, dict)]
    promotion_tree = promotion.get("tree", {}).get("sha")
    dev_tree = dev_base.get("tree", {}).get("sha")
    if (len(parents) != 2 or any(not OID_RE.fullmatch(str(parent)) for parent in parents) or
            (len(parents) == 2 and parents[0] == parents[1]) or
            parents[1] != base_oid or not OID_RE.fullmatch(str(promotion_tree)) or
            promotion_tree != dev_tree):
        raise RuntimeError("main-to-dev closeout lacks an exact zero-content promotion merge")

    comparison = _gh_json([f"repos/{repository}/compare/{parents[0]}...{base_oid}"])
    comparison_status = str(comparison.get("status", "")).upper()
    merge_base_oid = comparison.get("merge_base_commit", {}).get("sha")
    if comparison_status != "AHEAD" or merge_base_oid != parents[0]:
        raise RuntimeError("promotion prior-main is not an ancestor of the exact dev base")

    associated: list[Any] = []
    for page in range(1, MAX_ASSOCIATED_PROMOTION_PR_PAGES + 1):
        page_items = _gh_json([
            f"repos/{repository}/commits/{head_oid}/pulls", "--method", "GET", "-f",
            f"per_page={ASSOCIATED_PROMOTION_PR_PAGE_SIZE}", "-f", f"page={page}",
        ])
        if not isinstance(page_items, list):
            raise RuntimeError("associated promotion pull-request response is malformed")
        associated.extend(page_items)
        if len(page_items) < ASSOCIATED_PROMOTION_PR_PAGE_SIZE:
            break
    else:
        raise RuntimeError("associated promotion pull-request set exceeds bounded collector")
    candidates = [item for item in associated if isinstance(item, dict) and
                  item.get("merged_at") is not None and
                  item.get("base", {}).get("ref") == "main" and
                  item.get("head", {}).get("ref") == "dev" and
                  item.get("base", {}).get("repo", {}).get("full_name") == repository and
                  item.get("head", {}).get("repo", {}).get("full_name") == repository and
                  item.get("merge_commit_sha") == head_oid and
                  item.get("head", {}).get("sha") == base_oid]
    if len(candidates) != 1 or type(candidates[0].get("number")) is not int:
        raise RuntimeError("exact merged dev-to-main promotion provenance is unavailable")
    promotion_pr = candidates[0]
    return {
        "live_main_tip_oid": head_oid,
        "live_dev_tip_oid": base_oid,
        "promotion_merge": {
            "oid": head_oid,
            "tree_oid": promotion_tree,
            "parent_oids": parents,
        },
        "dev_base_tree_oid": dev_tree,
        "prior_main_ancestry": {
            "ancestor_oid": parents[0],
            "descendant_oid": base_oid,
            "merge_base_oid": merge_base_oid,
            "status": comparison_status,
        },
        "promotion_pull_request": {
            "number": promotion_pr["number"],
            "merged": True,
            "base_ref": "main",
            "head_ref": "dev",
            "base_repository": repository,
            "head_repository": repository,
            "merge_commit_oid": head_oid,
            "head_oid": base_oid,
        },
    }


def collect_github_merge_observation(
    repository: str, pull_request: int, expected_head: str, expected_base: str,
    review_receipt: dict[str, Any],
) -> dict[str, Any]:
    if repository != "Julesc013/universal-setup":
        raise RuntimeError("repository is outside the canonical policy")
    pr = _gh_json([f"repos/{repository}/pulls/{pull_request}"])
    rules = _gh_json([f"repos/{repository}/rules/branches/{pr['base']['ref']}"])
    check_rule = next((item for item in rules if item.get("type") == "required_status_checks"), None)
    pull_rule = next((item for item in rules if item.get("type") == "pull_request"), None)
    if check_rule is None or pull_rule is None:
        raise RuntimeError("live branch rules do not contain required checks and pull-request gates")
    parameters = check_rule.get("parameters", {})
    live_checks = parameters.get("required_status_checks", [])
    live_names = [item.get("context") for item in live_checks]
    live_integrations = {item.get("integration_id") for item in live_checks}
    if (check_rule.get("ruleset_id") != GITHUB_RULESET_ID or
            parameters.get("strict_required_status_checks_policy") is not True or
            live_names != REQUIRED_STATUS_CHECKS or
            live_integrations != {GITHUB_ACTIONS_INTEGRATION_ID}):
        raise RuntimeError("live required-check rules differ from the pinned policy")
    pull_parameters = pull_rule.get("parameters", {})
    if (pull_parameters.get("required_approving_review_count") != 0 or
            pull_parameters.get("required_review_thread_resolution") is not True):
        raise RuntimeError("live pull-request rules differ from the pinned policy")

    head_oid = str(pr.get("head", {}).get("sha", ""))
    base_oid = str(pr.get("base", {}).get("sha", ""))
    author_login = str(pr.get("user", {}).get("login", ""))
    author_context = "github:" + author_login
    review = _review_from_github(
        repository, pull_request, head_oid, author_context, review_receipt,
    )
    closeout_proof = None
    if pr.get("head", {}).get("ref") == "main" and pr.get("base", {}).get("ref") == "dev":
        closeout_proof = _collect_closeout_proof(repository, head_oid, base_oid)
    check_data = _gh_json([
        f"repos/{repository}/commits/{head_oid}/check-runs", "--method", "GET",
        "-f", "filter=latest", "-f", "per_page=100",
    ])
    runs = check_data.get("check_runs", [])
    bound_checks = []
    for name in REQUIRED_STATUS_CHECKS:
        # A context name is only trustworthy when every exact-head producer of
        # that name is acceptable.  In particular, do not hide a competing
        # producer by filtering it out before merge_admission_errors can check
        # the pinned GitHub Actions integration.
        candidates = [item for item in runs if item.get("name") == name and
                      item.get("head_sha") == head_oid]
        if not candidates:
            raise RuntimeError("live check set is missing for exact head: " + name)
        for item in candidates:
            bound_checks.append({
                "name": name,
                "status": str(item.get("status", "")).upper(),
                "conclusion": str(item.get("conclusion", "")).upper(),
                "head_oid": item.get("head_sha"),
                "integration_id": item.get("app", {}).get("id"),
                "details_url": item.get("details_url"),
            })
    owner, name = repository.split("/", 1)
    query = """query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewThreads(first:100){nodes{isResolved}pageInfo{hasNextPage}}}}}"""
    thread_data = _gh_json([
        "graphql", "-f", "query=" + query, "-F", "owner=" + owner,
        "-F", "name=" + name, "-F", "number=" + str(pull_request),
    ])
    threads = thread_data["data"]["repository"]["pullRequest"]["reviewThreads"]
    if threads["pageInfo"]["hasNextPage"]:
        raise RuntimeError("review thread set exceeds bounded live collector")
    unresolved = sum(not item["isResolved"] for item in threads["nodes"])
    executor = _gh_json(["user"])
    if (_live_branch_tip(repository, str(pr.get("head", {}).get("ref", ""))) != head_oid or
            _live_branch_tip(repository, str(pr.get("base", {}).get("ref", ""))) != base_oid):
        raise RuntimeError("pull request refs changed during live collection")
    observation = {
        "schema": "universal.github_merge_observation.v2",
        "collector": "tools/branch_policy_check.py/live-v2",
        "collected_from_github": True,
        "repository": repository,
        "pull_request": pull_request,
        "base_ref": pr.get("base", {}).get("ref"),
        "head_ref": pr.get("head", {}).get("ref"),
        "base_repository": pr.get("base", {}).get("repo", {}).get("full_name"),
        "head_repository": pr.get("head", {}).get("repo", {}).get("full_name"),
        "expected_head_oid": expected_head,
        "observed_head_oid": head_oid,
        "expected_base_oid": expected_base,
        "observed_base_oid": base_oid,
        "state": str(pr.get("state", "")).upper(),
        "draft": pr.get("draft"),
        "mergeable": pr.get("mergeable"),
        "merge_state_status": str(pr.get("mergeable_state", "")).upper(),
        "merge_method": "normal_pull_request",
        "direct_protected_push": False,
        "force_update": False,
        "bypass": False,
        "unresolved_threads": unresolved,
        "author_context": author_context,
        "executor_context": "github:" + str(executor.get("login", "")),
        "author_login": author_login,
        "required_check_policy": {
            "ruleset_id": GITHUB_RULESET_ID,
            "strict": True,
            "integration_id": GITHUB_ACTIONS_INTEGRATION_ID,
            "names": REQUIRED_STATUS_CHECKS,
        },
        "required_checks": bound_checks,
        "technical_review": review,
        "closeout_proof": closeout_proof,
    }
    return observation


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command")
    merge = subcommands.add_parser("merge-check")
    merge.add_argument("--repository", default="Julesc013/universal-setup")
    merge.add_argument("--pull-request", type=int, required=True)
    merge.add_argument("--expected-head", required=True)
    merge.add_argument("--expected-base", required=True)
    merge.add_argument("--review-receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    problems = check()
    if problems:
        for problem in problems:
            print(f"branch-policy-check: {problem}", file=sys.stderr)
        return 1
    if args.command == "merge-check":
        try:
            receipt = json.loads(args.review_receipt.read_text(encoding="utf-8"))
            observation = collect_github_merge_observation(
                args.repository, args.pull_request, args.expected_head,
                args.expected_base, receipt,
            )
            problems = merge_admission_errors(observation)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
            print("branch-policy-check: " + str(exc), file=sys.stderr)
            return 1
        if problems:
            for problem in problems:
                print(f"branch-policy-check: {problem}", file=sys.stderr)
            return 1
        print(json.dumps({"status": "PASS", "observation": observation}, indent=2))
        return 0
    print("branch-policy-check: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
