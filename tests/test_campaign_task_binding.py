# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import copy
import datetime as dt
import unittest

from tools import campaign_task_binding


class CampaignTaskBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority, cls.bundle, cls.integrity = campaign_task_binding.load_inputs()

    def binding(self) -> dict:
        source_commit = campaign_task_binding.git_oid("HEAD")
        source_tree = campaign_task_binding.git_oid("HEAD^{tree}")
        return campaign_task_binding.create_binding(
            "USK-WU-004",
            source_commit,
            source_tree,
            ["USK-WU-002=release/index/specification_baseline.v1.toml"],
            "repository-development",
            None,
        )

    def test_campaign_authority_derives_non_effectful_binding_without_fresh_owner_grant(self) -> None:
        binding = self.binding()
        self.assertEqual(
            campaign_task_binding.binding_errors(
                binding, self.authority, self.bundle, self.integrity
            ),
            [],
        )
        self.assertFalse(binding["authorization"]["fresh_owner_approval_required"])
        self.assertFalse(binding["authorization"]["template_itself_authorizes_execution"])

    def test_binding_cannot_widen_task_scope(self) -> None:
        binding = self.binding()
        binding["scope"]["allowed_paths"].append("runtime/**")
        self.assertIn(
            "task scope differs from the immutable template",
            campaign_task_binding.binding_errors(
                binding, self.authority, self.bundle, self.integrity
            ),
        )

    def test_binding_requires_every_predecessor_receipt(self) -> None:
        binding = self.binding()
        binding["predecessors"] = {}
        self.assertIn(
            "accepted predecessor receipts do not match dependencies",
            campaign_task_binding.binding_errors(
                binding, self.authority, self.bundle, self.integrity
            ),
        )

    def test_arbitrary_file_cannot_be_effect_target_receipt(self) -> None:
        with self.assertRaisesRegex(
            campaign_task_binding.BindingError,
            "effect target receipt must be under release/evidence",
        ):
            campaign_task_binding.create_binding(
                "USK-WU-004",
                campaign_task_binding.git_oid("HEAD"),
                campaign_task_binding.git_oid("HEAD^{tree}"),
                ["USK-WU-002=release/index/specification_baseline.v1.toml"],
                "disposable-windows-lab",
                "spec/manifest.json",
            )

    def test_arbitrary_file_cannot_be_predecessor_receipt(self) -> None:
        with self.assertRaisesRegex(
            campaign_task_binding.BindingError,
            "predecessor receipt must be repository-governed release evidence",
        ):
            campaign_task_binding.create_binding(
                "USK-WU-004",
                campaign_task_binding.git_oid("HEAD"),
                campaign_task_binding.git_oid("HEAD^{tree}"),
                ["USK-WU-002=spec/manifest.json"],
                "repository-development",
                None,
            )

    def test_source_tree_must_belong_to_source_commit(self) -> None:
        with self.assertRaisesRegex(
            campaign_task_binding.BindingError,
            "source tree does not belong to source commit",
        ):
            campaign_task_binding.create_binding(
                "USK-WU-004",
                campaign_task_binding.git_oid("HEAD"),
                campaign_task_binding.git_oid("HEAD"),
                ["USK-WU-002=release/index/specification_baseline.v1.toml"],
                "repository-development",
                None,
            )

    def test_changed_task_definition_stales_binding(self) -> None:
        binding = self.binding()
        invalid = copy.deepcopy(binding)
        invalid["task_definition"]["sha256"] = "0" * 64
        self.assertIn(
            "task definition binding is stale",
            campaign_task_binding.binding_errors(
                invalid, self.authority, self.bundle, self.integrity
            ),
        )

    def test_baseline_requires_successful_ci_and_typed_review_provenance(self) -> None:
        path = campaign_task_binding.ROOT / "release/index/specification_baseline.v1.toml"
        document = campaign_task_binding.receipt_document(path)
        document["post_merge_ci_conclusion"] = "failure"
        document.pop("technical_review_id")
        errors = campaign_task_binding.predecessor_receipt_errors(
            "USK-WU-002", path, document, campaign_task_binding.git_oid("HEAD")
        )
        self.assertTrue(any("successful post-merge CI" in error for error in errors))
        self.assertTrue(any("technical review provenance" in error for error in errors))

    def test_workunit_receipt_rejects_generic_evidence(self) -> None:
        path = campaign_task_binding.ROOT / "release/evidence/example.json"
        document = {
            "schema": "universal.workunit_receipt.v1", "status": "accepted",
            "workunit": "USK-WU-002", "source_commit": campaign_task_binding.git_oid("HEAD"),
            "source_tree": campaign_task_binding.git_oid("HEAD^{tree}"),
            "evidence": [{"path": "README.md"}],
        }
        errors = campaign_task_binding.predecessor_receipt_errors(
            "USK-WU-002", path, document, campaign_task_binding.git_oid("HEAD")
        )
        self.assertTrue(any("not a typed governed receipt" in error for error in errors))

    def test_workunit_receipt_dereferences_bounded_evidence_receipts(self) -> None:
        source_commit = campaign_task_binding.git_oid("HEAD")
        source_tree = campaign_task_binding.git_oid("HEAD^{tree}")
        document = {
            "schema": "universal.workunit_receipt.v1", "status": "accepted",
            "workunit": "USK-WU-002", "source_commit": source_commit, "source_tree": source_tree,
            "evidence": [{
                "path": "release/evidence/no-such-workunit-evidence.json", "sha256": "0" * 64, "kind": "review",
            }],
        }
        errors = campaign_task_binding.predecessor_receipt_errors(
            "USK-WU-002", campaign_task_binding.ROOT / "release/evidence/example.json", document, source_commit
        )
        self.assertTrue(any("is missing or unsafe" in error for error in errors))
        actual = campaign_task_binding.ROOT / "release/evidence/od-005-campaign-authority.json"
        document["evidence"] = [{
            "path": "release/evidence/od-005-campaign-authority.json", "sha256": campaign_task_binding.sha256(actual), "kind": "review",
        }]
        errors = campaign_task_binding.predecessor_receipt_errors(
            "USK-WU-002", campaign_task_binding.ROOT / "release/evidence/example.json", document, source_commit
        )
        self.assertTrue(any("fields are incomplete or unknown" in error for error in errors))

    def test_effect_receipt_rejects_future_issuance_and_arbitrary_authority(self) -> None:
        path = campaign_task_binding.ROOT / "release/evidence/example.json"
        now = dt.datetime.now(dt.timezone.utc)
        document = {
            "schema": "universal.effect_target_receipt.v1", "status": "admitted",
            "campaign": "USK-SPEC-TO-RELEASE-01", "workunits": ["USK-WU-004"],
            "environment_kind": "disposable-windows-lab", "effect_class": "disposable_lab",
            "target_identity": "lab:one", "authorized_effects": ["anything"],
            "issued_at": (now + dt.timedelta(minutes=5)).isoformat(),
            "expires_at": (now + dt.timedelta(hours=1)).isoformat(),
        }
        errors = campaign_task_binding.target_receipt_errors(
            "USK-WU-004", path, document, "disposable-windows-lab", ["install.package"]
        )
        self.assertTrue(any("exact authorized effects" in error for error in errors))
        self.assertTrue(any("exactly bind requested effects" in error for error in errors))
        self.assertTrue(any("timestamps are invalid" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
