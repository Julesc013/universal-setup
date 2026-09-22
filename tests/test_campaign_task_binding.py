# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import copy
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


if __name__ == "__main__":
    unittest.main()
