# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import copy
import tomllib
import unittest
from unittest.mock import patch

from tools import branch_policy_check


HEAD = "1" * 40
BASE = "2" * 40
PRIOR_MAIN = "3" * 40
TREE = "4" * 40


def valid_merge() -> dict:
    return {
        "schema": "universal.github_merge_observation.v2",
        "collector": "tools/branch_policy_check.py/live-v2",
        "collected_from_github": True,
        "repository": "Julesc013/universal-setup",
        "pull_request": 62,
        "base_ref": "dev",
        "head_ref": "task/campaign",
        "base_repository": "Julesc013/universal-setup",
        "head_repository": "Julesc013/universal-setup",
        "expected_head_oid": HEAD,
        "observed_head_oid": HEAD,
        "expected_base_oid": BASE,
        "observed_base_oid": BASE,
        "state": "OPEN",
        "draft": False,
        "mergeable": True,
        "merge_state_status": "CLEAN",
        "merge_method": "normal_pull_request",
        "direct_protected_push": False,
        "force_update": False,
        "bypass": False,
        "unresolved_threads": 0,
        "author_context": "github:Julesc013",
        "executor_context": "github:Julesc013",
        "author_login": "Julesc013",
        "required_check_policy": {
            "ruleset_id": branch_policy_check.GITHUB_RULESET_ID,
            "strict": True,
            "integration_id": branch_policy_check.GITHUB_ACTIONS_INTEGRATION_ID,
            "names": branch_policy_check.REQUIRED_STATUS_CHECKS,
        },
        "required_checks": [{
            "name": name,
            "status": "COMPLETED",
            "conclusion": "SUCCESS",
            "head_oid": HEAD,
            "integration_id": branch_policy_check.GITHUB_ACTIONS_INTEGRATION_ID,
            "details_url": "https://github.com/Julesc013/universal-setup/actions/runs/1/job/2",
        } for name in branch_policy_check.REQUIRED_STATUS_CHECKS],
        "technical_review": {
            "kind": "agent",
            "reviewer_context": "reviewer-context",
            "author_context": "github:Julesc013",
            "head_oid": HEAD,
            "claims_human": False,
            "github_state": "COMMENTED",
            "reviewer_principal": "agent:reviewer-context",
            "provenance": {
                "provider": "github_issue_comment",
                "id": 1,
                "url": "https://github.com/Julesc013/universal-setup/issues/62#issuecomment-1",
                "body_sha256": "a" * 64,
            },
        },
        "closeout_proof": None,
    }


def valid_closeout() -> dict:
    observation = valid_merge()
    observation.update({
        "base_ref": "dev",
        "head_ref": "main",
        "expected_head_oid": HEAD,
        "observed_head_oid": HEAD,
        "expected_base_oid": BASE,
        "observed_base_oid": BASE,
    })
    for check in observation["required_checks"]:
        check["head_oid"] = HEAD
    observation["technical_review"]["head_oid"] = HEAD
    observation["closeout_proof"] = {
        "live_main_tip_oid": HEAD,
        "live_dev_tip_oid": BASE,
        "promotion_merge": {
            "oid": HEAD,
            "tree_oid": TREE,
            "parent_oids": [PRIOR_MAIN, BASE],
        },
        "dev_base_tree_oid": TREE,
        "prior_main_ancestry": {
            "ancestor_oid": PRIOR_MAIN,
            "descendant_oid": BASE,
            "merge_base_oid": PRIOR_MAIN,
            "status": "AHEAD",
        },
        "promotion_pull_request": {
            "number": 61,
            "merged": True,
            "base_ref": "main",
            "head_ref": "dev",
            "base_repository": "Julesc013/universal-setup",
            "head_repository": "Julesc013/universal-setup",
            "merge_commit_oid": HEAD,
            "head_oid": BASE,
        },
    }
    return observation


class BranchPolicyTests(unittest.TestCase):
    def test_canonical_policy_and_campaign_are_valid(self) -> None:
        self.assertEqual(branch_policy_check.check(), [])

    def test_provider_dev_cannot_become_a_consumer_pin(self) -> None:
        with branch_policy_check.POLICY.open("rb") as handle:
            policy = tomllib.load(handle)
        invalid = copy.deepcopy(policy)
        invalid["invariants"]["consumer_pins_may_reference_dev"] = True
        self.assertIn(
            "branch policy invariants.consumer_pins_may_reference_dev must be False",
            branch_policy_check.check_data(invalid),
        )

    def test_exact_green_pr_merge_allows_author_to_execute_merge(self) -> None:
        observation = valid_merge()
        self.assertEqual(observation["author_context"], observation["executor_context"])
        self.assertEqual(branch_policy_check.merge_admission_errors(observation), [])

    def test_declared_dev_to_main_promotion_is_admitted(self) -> None:
        observation = valid_merge()
        observation["head_ref"] = "dev"
        observation["base_ref"] = "main"
        self.assertEqual(branch_policy_check.merge_admission_errors(observation), [])

    def test_normal_routes_require_a_null_closeout_proof(self) -> None:
        observation = valid_merge()
        observation["closeout_proof"] = {}
        self.assertIn(
            "closeout proof must be null outside main-to-dev closeout",
            branch_policy_check.merge_admission_errors(observation),
        )

    def test_zero_content_main_to_dev_closeout_is_admitted(self) -> None:
        self.assertEqual(branch_policy_check.merge_admission_errors(valid_closeout()), [])

    def test_closeout_proof_rejects_each_required_promotion_fact(self) -> None:
        cases = {
            "wrong main tip": (
                lambda proof: proof.__setitem__("live_main_tip_oid", PRIOR_MAIN),
                "closeout proof is not bound to the live main tip",
            ),
            "wrong dev tip": (
                lambda proof: proof.__setitem__("live_dev_tip_oid", PRIOR_MAIN),
                "closeout proof is not bound to the live dev tip",
            ),
            "one parent": (
                lambda proof: proof["promotion_merge"].__setitem__("parent_oids", [PRIOR_MAIN]),
                "closeout promotion merge must have exactly two Git parents",
            ),
            "wrong parent order": (
                lambda proof: proof["promotion_merge"].__setitem__("parent_oids", [BASE, PRIOR_MAIN]),
                "closeout promotion merge second parent is not the exact dev base",
            ),
            "duplicate parents": (
                lambda proof: proof["promotion_merge"].__setitem__("parent_oids", [BASE, BASE]),
                "closeout promotion merge must have exactly two Git parents",
            ),
            "unequal trees": (
                lambda proof: proof.__setitem__("dev_base_tree_oid", PRIOR_MAIN),
                "closeout promotion merge tree differs from the exact dev base tree",
            ),
            "nonancestor": (
                lambda proof: proof["prior_main_ancestry"].__setitem__("status", "DIVERGED"),
                "closeout prior-main is not an ancestor of the exact dev base",
            ),
            "unmerged promotion": (
                lambda proof: proof["promotion_pull_request"].__setitem__("merged", False),
                "closeout promotion pull request is not merged",
            ),
            "wrong promotion route": (
                lambda proof: proof["promotion_pull_request"].__setitem__("head_ref", "task/not-dev"),
                "closeout promotion pull request is not dev-to-main",
            ),
            "forked promotion": (
                lambda proof: proof["promotion_pull_request"].__setitem__("head_repository", "fork/universal-setup"),
                "closeout promotion pull request must use canonical same-repository refs",
            ),
            "wrong promotion binding": (
                lambda proof: proof["promotion_pull_request"].__setitem__("merge_commit_oid", PRIOR_MAIN),
                "closeout promotion pull request is not bound to the exact merge and dev base",
            ),
        }
        for name, (mutate, expected) in cases.items():
            with self.subTest(name=name):
                observation = valid_closeout()
                mutate(observation["closeout_proof"])
                self.assertIn(expected, branch_policy_check.merge_admission_errors(observation))
        observation = valid_closeout()
        observation["closeout_proof"] = None
        self.assertIn(
            "main-to-dev closeout proof is missing or malformed",
            branch_policy_check.merge_admission_errors(observation),
        )

    def test_closeout_rejects_fork_and_content_bearing_or_arbitrary_main_history(self) -> None:
        observation = valid_closeout()
        observation["head_repository"] = "fork/universal-setup"
        self.assertIn(
            "pull request must use canonical same-repository refs",
            branch_policy_check.merge_admission_errors(observation),
        )
        observation = valid_closeout()
        observation["closeout_proof"]["promotion_merge"]["parent_oids"] = [PRIOR_MAIN]
        self.assertIn(
            "closeout promotion merge must have exactly two Git parents",
            branch_policy_check.merge_admission_errors(observation),
        )
        observation = valid_closeout()
        observation["closeout_proof"]["dev_base_tree_oid"] = PRIOR_MAIN
        self.assertIn(
            "closeout promotion merge tree differs from the exact dev base tree",
            branch_policy_check.merge_admission_errors(observation),
        )

    def test_undeclared_routes_are_denied(self) -> None:
        observation = valid_merge()
        observation["head_ref"] = "feature/unreviewed"
        self.assertIn(
            "pull request route is not declared by branch policy",
            branch_policy_check.merge_admission_errors(observation),
        )
        observation = valid_merge()
        observation["base_ref"] = "main"
        self.assertIn("task pull request must target dev", branch_policy_check.merge_admission_errors(observation))
        observation = valid_closeout()
        observation["base_ref"] = "main"
        self.assertIn("main closeout pull request must target dev", branch_policy_check.merge_admission_errors(observation))
        observation = valid_merge()
        observation["head_ref"] = "hotfix/content-bearing"
        self.assertIn("pull request route is not declared by branch policy", branch_policy_check.merge_admission_errors(observation))

    def test_stale_head_and_base_are_denied_even_with_green_checks(self) -> None:
        observation = valid_merge()
        observation["observed_head_oid"] = "3" * 40
        observation["observed_base_oid"] = "4" * 40
        errors = branch_policy_check.merge_admission_errors(observation)
        self.assertIn("pull request head is stale", errors)
        self.assertIn("pull request base is stale", errors)

    def test_red_pending_or_stale_check_is_denied(self) -> None:
        for conclusion in ("FAILURE", "PENDING", "CANCELLED"):
            with self.subTest(conclusion=conclusion):
                observation = valid_merge()
                observation["required_checks"][0]["conclusion"] = conclusion
                self.assertTrue(any(
                    "required check is not successful" in error
                    for error in branch_policy_check.merge_admission_errors(observation)
                ))
        observation = valid_merge()
        observation["required_checks"][0]["head_oid"] = "5" * 40
        self.assertTrue(any(
            "stale head" in error for error in branch_policy_check.merge_admission_errors(observation)
        ))
        observation = valid_merge()
        observation["technical_review"]["head_oid"] = "5" * 40
        self.assertIn("technical review is bound to a stale head", branch_policy_check.merge_admission_errors(observation))

    def test_duplicate_exact_head_success_suites_are_admitted_but_any_red_duplicate_is_denied(self) -> None:
        observation = valid_merge()
        observation["required_checks"].append(copy.deepcopy(observation["required_checks"][0]))
        self.assertEqual(branch_policy_check.merge_admission_errors(observation), [])
        for conclusion in ("PENDING", "FAILURE"):
            with self.subTest(conclusion=conclusion):
                invalid = valid_merge()
                duplicate = copy.deepcopy(invalid["required_checks"][0])
                duplicate["conclusion"] = conclusion
                invalid["required_checks"].append(duplicate)
                self.assertTrue(any(
                    "required check is not successful" in error
                    for error in branch_policy_check.merge_admission_errors(invalid)
                ))

    def test_required_check_cannot_be_missing_or_from_the_wrong_app(self) -> None:
        observation = valid_merge()
        observation["required_checks"] = observation["required_checks"][1:]
        self.assertIn(
            "required check observations do not exactly cover the pinned set",
            branch_policy_check.merge_admission_errors(observation),
        )
        observation = valid_merge()
        observation["required_checks"][0]["integration_id"] = 1
        self.assertTrue(any(
            "wrong GitHub integration" in error
            for error in branch_policy_check.merge_admission_errors(observation)
        ))

    def test_collector_retains_wrong_app_duplicate_for_admission(self) -> None:
        def check_run(name: str, *, app_id: int, conclusion: str) -> dict:
            return {
                "name": name,
                "status": "completed",
                "conclusion": conclusion.lower(),
                "head_sha": HEAD,
                "app": {"id": app_id},
                "details_url": "https://github.com/Julesc013/universal-setup/actions/runs/1/job/2",
            }

        required = [
            {"context": name, "integration_id": branch_policy_check.GITHUB_ACTIONS_INTEGRATION_ID}
            for name in branch_policy_check.REQUIRED_STATUS_CHECKS
        ]
        runs = [
            check_run(name, app_id=branch_policy_check.GITHUB_ACTIONS_INTEGRATION_ID,
                      conclusion="SUCCESS")
            for name in branch_policy_check.REQUIRED_STATUS_CHECKS
        ]
        runs.append(check_run("native-windows", app_id=1, conclusion="FAILURE"))

        def github(arguments: list[str]) -> dict:
            endpoint = arguments[0]
            if endpoint.endswith("/pulls/62"):
                return {
                    "base": {"ref": "dev", "sha": BASE, "repo": {"full_name": "Julesc013/universal-setup"}},
                    "head": {"ref": "task/campaign", "sha": HEAD, "repo": {"full_name": "Julesc013/universal-setup"}},
                    "user": {"login": "Julesc013"},
                    "state": "open", "draft": False, "mergeable": True,
                    "mergeable_state": "clean",
                }
            if "/rules/branches/" in endpoint:
                return [
                    {"type": "required_status_checks", "ruleset_id": branch_policy_check.GITHUB_RULESET_ID,
                     "parameters": {"strict_required_status_checks_policy": True,
                                    "required_status_checks": required}},
                    {"type": "pull_request", "parameters": {
                        "required_approving_review_count": 0,
                        "required_review_thread_resolution": True,
                    }},
                ]
            if endpoint.endswith("/check-runs"):
                return {"check_runs": runs}
            if endpoint == "graphql":
                return {"data": {"repository": {"pullRequest": {"reviewThreads": {
                    "nodes": [], "pageInfo": {"hasNextPage": False},
                }}}}}
            if endpoint == "user":
                return {"login": "Julesc013"}
            if "/git/ref/heads/" in endpoint:
                return {"object": {"type": "commit", "sha": HEAD if endpoint.endswith("task/campaign") else BASE}}
            self.fail("unexpected GitHub API request: " + endpoint)

        with patch.object(branch_policy_check, "_gh_json", side_effect=github), patch.object(
            branch_policy_check, "_review_from_github", return_value=valid_merge()["technical_review"],
        ):
            observation = branch_policy_check.collect_github_merge_observation(
                "Julesc013/universal-setup", 62, HEAD, BASE,
                {"kind": "agent", "reviewer_context": "reviewer-context", "github_record_id": 1},
            )
        errors = branch_policy_check.merge_admission_errors(observation)
        self.assertTrue(any("not successful: native-windows" in error for error in errors))
        self.assertTrue(any("wrong GitHub integration: native-windows" in error for error in errors))

    def test_closeout_collector_binds_live_promotion_facts_and_detects_races(self) -> None:
        def collect(case: str | None = None) -> dict:
            required = [
                {"context": name, "integration_id": branch_policy_check.GITHUB_ACTIONS_INTEGRATION_ID}
                for name in branch_policy_check.REQUIRED_STATUS_CHECKS
            ]
            runs = [{
                "name": name, "status": "completed", "conclusion": "success", "head_sha": HEAD,
                "app": {"id": branch_policy_check.GITHUB_ACTIONS_INTEGRATION_ID},
                "details_url": "https://github.com/Julesc013/universal-setup/actions/runs/1/job/2",
            } for name in branch_policy_check.REQUIRED_STATUS_CHECKS]
            tips = {"main": 0, "dev": 0}

            def github(arguments: list[str]) -> dict | list:
                endpoint = arguments[0]
                if endpoint.endswith("/pulls/62"):
                    return {
                        "base": {"ref": "dev", "sha": BASE, "repo": {"full_name": "Julesc013/universal-setup"}},
                        "head": {"ref": "main", "sha": HEAD, "repo": {"full_name": "Julesc013/universal-setup"}},
                        "user": {"login": "Julesc013"}, "state": "open", "draft": False,
                        "mergeable": True, "mergeable_state": "clean",
                    }
                if "/rules/branches/" in endpoint:
                    return [
                        {"type": "required_status_checks", "ruleset_id": branch_policy_check.GITHUB_RULESET_ID,
                         "parameters": {"strict_required_status_checks_policy": True,
                                        "required_status_checks": required}},
                        {"type": "pull_request", "parameters": {
                            "required_approving_review_count": 0,
                            "required_review_thread_resolution": True,
                        }},
                    ]
                if "/git/ref/heads/" in endpoint:
                    branch = endpoint.rsplit("/", 1)[-1]
                    tips[branch] += 1
                    sha = HEAD if branch == "main" else BASE
                    if case == "raced refs" and tips[branch] == 2:
                        sha = PRIOR_MAIN
                    return {"object": {"type": "commit", "sha": sha}}
                if endpoint.endswith("/git/commits/" + HEAD):
                    parents = [PRIOR_MAIN, BASE]
                    if case == "one parent":
                        parents = [PRIOR_MAIN]
                    elif case == "wrong parent order":
                        parents = [BASE, PRIOR_MAIN]
                    elif case == "duplicate parents":
                        parents = [BASE, BASE]
                    return {"tree": {"sha": TREE}, "parents": [{"sha": parent} for parent in parents]}
                if endpoint.endswith("/git/commits/" + BASE):
                    return {"tree": {"sha": PRIOR_MAIN if case == "unequal trees" else TREE}}
                if "/compare/" in endpoint:
                    return {"status": "diverged" if case == "nonancestor" else "ahead",
                            "merge_base_commit": {"sha": PRIOR_MAIN}}
                if endpoint.endswith("/commits/" + HEAD + "/pulls"):
                    promotion = {
                        "number": 61, "merged_at": "2026-09-23T00:00:00Z",
                        "base": {"ref": "main", "repo": {"full_name": "Julesc013/universal-setup"}},
                        "head": {"ref": "dev", "sha": BASE, "repo": {"full_name": "Julesc013/universal-setup"}},
                        "merge_commit_sha": HEAD,
                    }
                    if case == "missing promotion":
                        return []
                    if case == "ambiguous promotion":
                        return [promotion, copy.deepcopy(promotion)]
                    if case == "unmerged promotion":
                        promotion["merged_at"] = None
                    if case == "mismatched promotion":
                        promotion["head"]["sha"] = PRIOR_MAIN
                    return [promotion]
                if endpoint.endswith("/check-runs"):
                    return {"check_runs": runs}
                if endpoint == "graphql":
                    return {"data": {"repository": {"pullRequest": {"reviewThreads": {
                        "nodes": [], "pageInfo": {"hasNextPage": False},
                    }}}}}
                if endpoint == "user":
                    return {"login": "Julesc013"}
                self.fail("unexpected GitHub API request: " + endpoint)

            with patch.object(branch_policy_check, "_gh_json", side_effect=github), patch.object(
                branch_policy_check, "_review_from_github", return_value=valid_closeout()["technical_review"],
            ):
                return branch_policy_check.collect_github_merge_observation(
                    "Julesc013/universal-setup", 62, HEAD, BASE,
                    {"kind": "agent", "reviewer_context": "reviewer-context", "github_record_id": 1},
                )

        observation = collect()
        self.assertEqual(observation["closeout_proof"], valid_closeout()["closeout_proof"])
        self.assertEqual(branch_policy_check.merge_admission_errors(observation), [])
        failures = {
            "one parent": "zero-content promotion merge",
            "wrong parent order": "zero-content promotion merge",
            "duplicate parents": "zero-content promotion merge",
            "unequal trees": "zero-content promotion merge",
            "nonancestor": "not an ancestor",
            "missing promotion": "promotion provenance is unavailable",
            "ambiguous promotion": "promotion provenance is unavailable",
            "unmerged promotion": "promotion provenance is unavailable",
            "mismatched promotion": "promotion provenance is unavailable",
            "raced refs": "refs changed during live collection",
        }
        for case, expected in failures.items():
            with self.subTest(case=case):
                with self.assertRaisesRegex(RuntimeError, expected):
                    collect(case)

    def test_direct_force_bypass_and_unresolved_threads_are_denied(self) -> None:
        observation = valid_merge()
        observation["direct_protected_push"] = True
        observation["force_update"] = True
        observation["bypass"] = True
        observation["unresolved_threads"] = 1
        errors = branch_policy_check.merge_admission_errors(observation)
        self.assertIn("direct protected push is forbidden", errors)
        self.assertIn("force update is forbidden", errors)
        self.assertIn("ruleset bypass is forbidden", errors)
        self.assertIn("all review threads must be resolved", errors)

    def test_review_must_be_independent_and_truthfully_agent_authored(self) -> None:
        observation = valid_merge()
        observation["technical_review"]["reviewer_context"] = observation["author_context"]
        observation["technical_review"]["claims_human"] = True
        observation["technical_review"]["github_state"] = "APPROVED"
        errors = branch_policy_check.merge_admission_errors(observation)
        self.assertIn("technical review must use a different review context", errors)
        self.assertIn("agent review must not claim human provenance", errors)
        self.assertIn("agent review must not fabricate GitHub approval", errors)

    def test_observation_requires_live_collector_and_exact_required_check_set(self) -> None:
        observation = valid_merge()
        observation["collected_from_github"] = False
        observation["required_checks"].pop()
        errors = branch_policy_check.merge_admission_errors(observation)
        self.assertIn("merge observation must come from the live GitHub collector", errors)
        self.assertIn("required check observations do not exactly cover the pinned set", errors)

    def test_human_claim_requires_github_review_provenance(self) -> None:
        observation = valid_merge()
        review = observation["technical_review"]
        review["kind"] = "human"
        review["claims_human"] = True
        review["github_state"] = "APPROVED"
        review["reviewer_principal"] = "human-reviewer"
        errors = branch_policy_check.merge_admission_errors(observation)
        self.assertIn("technical review provenance provider or ID is invalid", errors)


if __name__ == "__main__":
    unittest.main()
