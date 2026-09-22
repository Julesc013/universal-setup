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
        "strict_required_status_checks": True,
        "github_ruleset_id": GITHUB_RULESET_ID,
        "github_actions_integration_id": GITHUB_ACTIONS_INTEGRATION_ID,
        "required_status_checks": REQUIRED_STATUS_CHECKS,
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
    """Validate a closed observation produced by the live GitHub collector below."""
    errors: list[str] = []
    expected_top = {
        "schema", "collector", "collected_from_github", "repository", "pull_request",
        "base_ref", "head_ref", "expected_head_oid", "observed_head_oid",
        "expected_base_oid", "observed_base_oid", "state", "draft", "mergeable",
        "merge_state_status", "merge_method", "direct_protected_push", "force_update",
        "bypass", "unresolved_threads", "author_context", "executor_context",
        "author_login", "required_check_policy", "required_checks", "technical_review",
    }
    if set(observation) != expected_top:
        errors.append("merge observation fields are incomplete or unknown")
    if observation.get("schema") != "universal.github_merge_observation.v1":
        errors.append("merge observation schema is invalid")
    if observation.get("collector") != "tools/branch_policy_check.py/live-v1" or observation.get("collected_from_github") is not True:
        errors.append("merge observation must come from the live GitHub collector")
    if observation.get("repository") != "Julesc013/universal-setup":
        errors.append("merge observation repository is invalid")
    if type(observation.get("pull_request")) is not int or observation["pull_request"] <= 0:
        errors.append("pull request number is invalid")
    head_ref = observation.get("head_ref")
    base_ref = observation.get("base_ref")
    if not isinstance(head_ref, str) or not head_ref:
        errors.append("pull request refs are invalid")
    elif head_ref.startswith("task/"):
        if base_ref != "dev":
            errors.append("task pull request must target dev")
    elif head_ref == "dev":
        if base_ref != "main":
            errors.append("dev promotion pull request must target main")
    else:
        errors.append("pull request route is not declared by branch policy")
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
                "name", "status", "conclusion", "head_oid", "base_oid",
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
            if check.get("base_oid") != observation.get("expected_base_oid"):
                errors.append("required check is bound to a stale base: " + str(check.get("name")))
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
                "base_oid": base_oid,
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
    observation = {
        "schema": "universal.github_merge_observation.v1",
        "collector": "tools/branch_policy_check.py/live-v1",
        "collected_from_github": True,
        "repository": repository,
        "pull_request": pull_request,
        "base_ref": pr.get("base", {}).get("ref"),
        "head_ref": pr.get("head", {}).get("ref"),
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
