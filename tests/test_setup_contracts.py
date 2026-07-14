# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "contracts" / "schema" / "setup"

M1_CONTRACT_SPINE = {
    "recipe": "usk.recipe.v1",
    "source": "usk.source.v1",
    "install_plan": "usk.install_plan.v1",
    "operation_plan": "usk.operation_plan.v1",
    "installed_state": "usk.installed_state.v1",
    "ownership_manifest": "usk.ownership_manifest.v1",
    "transaction_journal": "usk.transaction_journal.v1",
    "audit_event": "usk.audit_event.v1",
    "verification_report": "usk.verification_report.v1",
    "repair_report": "usk.repair_report.v1",
    "move_report": "usk.move_report.v1",
    "uninstall_report": "usk.uninstall_report.v1",
    "recovery_report": "usk.recovery_report.v1",
    "refusal": "usk.refusal.v1",
}

RETAINED_CONTRACTS = {
    "archive_inspect_request": "usk.archive_inspect_request.v1",
    "archive_inspection": "usk.archive_inspection.v1",
    "package_verify_request": "usk.package_verify_request.v1",
    "package_verify_report": "usk.package_verify_report.v1",
    "repair_plan": "usk.repair_plan.v1",
    "recovery_plan": "usk.recovery_plan.v1",
    "verify_report": "usk.verify_report.v1",
    "audit_log": "usk.audit_log.v1",
    "transaction": "usk.transaction.v1",
    "rollback": "usk.rollback.v1",
    "ownership": "usk.ownership.v1",
    "policy": "usk.policy.v1",
    "setup_manifest": "usk.setup_manifest.v1",
}

M2_TARGET_CONTRACTS = {
    "target_policy": "usk.target_policy.v1",
    "target_evidence": "usk.target_evidence.v1",
    "target_policy_decision": "usk.target_policy_decision.v1",
}

M2_PUBLIC_REQUEST_CONTRACTS = {
    "install_local_plan_request": "usk.install_local_plan_request.v1",
    "install_local_apply_request": "usk.install_local_apply_request.v1",
    "installed_inspect_request": "usk.installed_inspect_request.v1",
    "installed_verify_request": "usk.installed_verify_request.v1",
    "repair_plan_request": "usk.repair_plan_request.v1",
    "repair_apply_request": "usk.repair_apply_request.v1",
    "move_plan_request": "usk.move_plan_request.v1",
    "move_apply_request": "usk.move_apply_request.v1",
    "uninstall_plan_request": "usk.uninstall_plan_request.v1",
    "uninstall_apply_request": "usk.uninstall_apply_request.v1",
    "recovery_inspect_request": "usk.recovery_inspect_request.v1",
    "recovery_plan_request": "usk.recovery_plan_request.v1",
    "recovery_apply_request": "usk.recovery_apply_request.v1",
}

M2_EVIDENCE_CONTRACTS = {
    "live_target_evidence_capture_request": "usk.live_target_evidence_capture_request.v1",
    "live_target_evidence_packet": "usk.live_target_evidence_packet.v1",
    "operator_verdict_record_request": "usk.operator_verdict_record_request.v1",
    "m2_live_acceptance_summary": "usk.m2_live_acceptance_summary.v1",
}


def load_schema(name: str) -> dict:
    path = SCHEMA_ROOT / f"{name}.v1.schema.json"
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


class SetupContractTests(unittest.TestCase):
    def test_m1_contract_spine_is_versioned_strict_and_complete(self) -> None:
        for name, schema_const in M1_CONTRACT_SPINE.items():
            with self.subTest(name=name):
                schema = load_schema(name)
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertEqual(schema["type"], "object")
                self.assertIn("schema", schema["required"])
                self.assertEqual(schema["properties"]["schema"]["const"], schema_const)
                self.assertIs(schema["additionalProperties"], False)

    def test_retained_contracts_remain_parseable_and_versioned(self) -> None:
        for name, schema_const in RETAINED_CONTRACTS.items():
            with self.subTest(name=name):
                schema = load_schema(name)
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertEqual(schema["properties"]["schema"]["const"], schema_const)

    def test_m2_target_contracts_are_versioned_strict_and_complete(self) -> None:
        for name, schema_const in M2_TARGET_CONTRACTS.items():
            with self.subTest(name=name):
                schema = load_schema(name)
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertEqual(schema["type"], "object")
                self.assertIn("schema", schema["required"])
                self.assertEqual(schema["properties"]["schema"]["const"], schema_const)
                self.assertIs(schema["additionalProperties"], False)

    def test_m2_public_request_contracts_are_explicit_strict_and_versioned(self) -> None:
        for name, schema_const in M2_PUBLIC_REQUEST_CONTRACTS.items():
            with self.subTest(name=name):
                schema = load_schema(name)
                self.assertEqual(schema["properties"]["schema"]["const"], schema_const)
                self.assertIn("schema", schema["required"])
                self.assertIs(schema["additionalProperties"], False)

        for operation in ("install_local", "repair", "move", "uninstall", "recovery"):
            plan = load_schema(f"{operation}_plan_request")
            apply = load_schema(f"{operation}_apply_request")
            self.assertNotEqual(
                plan["properties"]["schema"]["const"],
                apply["properties"]["schema"]["const"],
            )
            self.assertIn("reviewed_plan_id", apply["required"])
            self.assertIn("reviewed_plan_digest", apply["required"])
            self.assertEqual(apply["properties"]["confirmation"]["const"], "APPLY")

        install_plan = load_schema("install_local_plan_request")
        target_class = install_plan["$defs"]["target"]["properties"]["class"]["enum"]
        self.assertEqual(set(target_class), {"operator_acceptance", "managed_portable"})
        serialized = json.dumps(install_plan).lower()
        for forbidden in ("shell_command", "powershell", "network_url", "credential_reference"):
            self.assertNotIn(forbidden, serialized)

    def test_m2_live_target_evidence_is_strict_and_keeps_human_authority_separate(self) -> None:
        for name, schema_const in M2_EVIDENCE_CONTRACTS.items():
            schema = load_schema(name)
            self.assertEqual(schema["properties"]["schema"]["const"], schema_const)
            self.assertIs(schema["additionalProperties"], False)

        schema = load_schema("live_target_evidence_packet")
        self.assertTrue(
            {
                "source_revisions", "setup_abi", "contract_versions", "archive", "recipe",
                "target", "filesystem", "plan", "committed_closure", "state", "snapshots",
                "recovery", "automated_findings", "operator_verdict",
            }.issubset(schema["required"])
        )
        pending, recorded = schema["properties"]["operator_verdict"]["oneOf"]
        self.assertEqual(pending["properties"]["status"]["const"], "pending")
        self.assertEqual(pending["properties"]["verdict"]["type"], "null")
        self.assertEqual(recorded["properties"]["status"]["const"], "recorded")
        self.assertEqual(set(recorded["properties"]["verdict"]["enum"]), {"Pass", "Fail", "Inconclusive"})
        serialized = json.dumps(schema).lower()
        for forbidden in ("run.execute", "network_url", "credential", "registry_write", "elevation"):
            self.assertNotIn(forbidden, serialized)

        verdict_request = load_schema("operator_verdict_record_request")
        self.assertEqual(verdict_request["properties"]["confirmation"]["const"], "RECORD VERDICT")
        self.assertEqual(
            set(verdict_request["properties"]["verdict"]["enum"]),
            {"Pass", "Fail", "Inconclusive"},
        )

    def test_m2_target_policy_is_fail_closed_and_product_neutral(self) -> None:
        policy = load_schema("target_policy")["properties"]
        self.assertEqual(
            set(policy["mutable_target_classes"]["items"]["enum"]),
            {"operator_acceptance", "managed_portable"},
        )
        self.assertEqual(
            set(policy["activation"]["enum"]),
            {"unavailable", "operator_acceptance_candidate", "accepted_live_portable"},
        )
        for field in policy["conditions"]["required"]:
            self.assertIs(policy["conditions"]["properties"][field]["const"], True)
        for field in policy["forbidden_authorities"]["required"]:
            self.assertIs(policy["forbidden_authorities"]["properties"][field]["const"], False)

        evidence = load_schema("target_evidence")["properties"]
        self.assertEqual(
            set(evidence["target_state"]["enum"]),
            {"nonexistent", "empty", "nonempty", "unproven"},
        )
        self.assertIn("identity_digest", evidence["filesystem"]["required"])
        self.assertIn("persistent_effects_complete", load_schema("target_evidence")["required"])

        decision = load_schema("target_policy_decision")
        self.assertIn("target_binding_digest", decision["required"])
        self.assertIn("mutation_authorized", decision["required"])

    def test_recipe_is_data_only_local_archive_portable_policy(self) -> None:
        schema = load_schema("recipe")
        properties = schema["properties"]
        source = properties["source"]["properties"]
        self.assertEqual(source["kind"]["const"], "local_archive")
        self.assertEqual(properties["target_scope"]["const"], "portable")
        serialized = json.dumps(schema).lower()
        for forbidden in (
            "shell_command",
            "powershell",
            "batch_script",
            "network_url",
            "credential_reference",
            "registry_script",
            "post_install_hook",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_archive_inspection_is_local_bounded_and_normalized(self) -> None:
        request = load_schema("archive_inspect_request")
        self.assertEqual(request["properties"]["archive_format"]["const"], "zip")
        self.assertEqual(
            set(request["properties"]["budgets"]["required"]),
            {
                "max_entries",
                "max_uncompressed_bytes",
                "max_entry_bytes",
                "max_depth",
                "max_ratio",
                "max_elapsed_ms",
            },
        )
        inspection = load_schema("archive_inspection")
        self.assertEqual(
            inspection["properties"]["normalization_policy"]["const"],
            "ascii_case_insensitive_v1",
        )
        self.assertIn("entry_set_digest", inspection["required"])
        self.assertIs(
            inspection["properties"]["source"]["properties"]["stable_read"]["const"],
            True,
        )

    def test_plans_bind_inputs_and_require_immediate_revalidation(self) -> None:
        install = load_schema("install_plan")
        identity = install["$defs"]["input_identity"]["required"]
        self.assertEqual(
            set(identity),
            {"recipe_digest", "source_digest", "policy_digest", "provider_revision"},
        )
        revalidation = install["properties"]["revalidation"]["properties"]
        self.assertIs(revalidation["immediately_before_apply"]["const"], True)
        self.assertEqual(
            set(revalidation["invalidate_on"]["items"]["enum"]),
            {"source", "recipe", "target", "policy", "provider_revision"},
        )
        refusal = install["$defs"]["refusal_policy"]["properties"]
        self.assertIn("pre_snapshot_digest", install["properties"]["target"]["required"])
        for field in (
            "refuse_network",
            "refuse_registry",
            "refuse_elevation",
            "refuse_package_manager",
            "refuse_installer_execution",
            "refuse_existing_target",
        ):
            self.assertIs(refusal[field]["const"], True)

        operation = load_schema("operation_plan")
        self.assertIn("target_snapshots", operation["required"])
        self.assertIn("pre_target_snapshot_digest", load_schema("repair_plan")["required"])
        self.assertEqual(operation["properties"]["unknown_file_policy"]["const"], "retain_and_report")
        self.assertNotIn("adopt", operation["properties"]["operation"]["enum"])

    def test_installed_state_and_manifest_bind_exact_ownership(self) -> None:
        state = load_schema("installed_state")
        self.assertTrue(
            {
                "recipe_digest",
                "source_archive_digest",
                "target_root",
                "target_scope",
                "component_selection",
                "ownership_manifest_ref",
                "ownership_manifest_digest",
                "entrypoints",
                "setup_abi",
                "transaction_id",
                "last_verification",
                "audit_chain_id",
            }.issubset(state["required"])
        )
        ownership = load_schema("ownership_manifest")
        file_required = ownership["properties"]["files"]["items"]["required"]
        self.assertEqual(set(file_required), {"relative_path", "sha256", "size_bytes"})
        self.assertIn("directories", ownership["required"])

    def test_transaction_journal_exposes_full_durable_state_machine(self) -> None:
        journal = load_schema("transaction_journal")
        states = set(journal["$defs"]["state"]["enum"])
        self.assertEqual(
            states,
            {
                "created",
                "validated",
                "planned",
                "staging",
                "staged",
                "verified",
                "committing",
                "committed",
                "completed",
                "refused",
                "failed",
                "recovery_required",
                "rolled_back",
                "abandoned_by_operator",
            },
        )
        transition = journal["properties"]["transitions"]["items"]
        self.assertIs(
            transition["properties"]["durable_before_external_visibility"]["const"],
            True,
        )

    def test_audit_and_lifecycle_reports_preserve_foreign_content(self) -> None:
        audit = load_schema("audit_event")
        self.assertIn("previous_event_digest", audit["required"])
        self.assertIn("event_digest", audit["required"])

        verification = load_schema("verification_report")
        self.assertIn("unknown_paths", verification["required"])

        repair = load_schema("repair_report")
        self.assertIn("retained_unknown_paths", repair["required"])

        move = load_schema("move_report")
        self.assertIn(
            "retired_retained",
            move["properties"]["old_root_status"]["enum"],
        )

        uninstall = load_schema("uninstall_report")
        self.assertIn("retained_changed_owned_files", uninstall["required"])
        self.assertIn("retained_unknown_paths", uninstall["required"])
        self.assertIn("retained_directories", uninstall["required"])
        self.assertIs(uninstall["properties"]["source_archive_deleted"]["const"], False)

        recovery = load_schema("recovery_report")
        self.assertIn("available_actions", recovery["required"])
        self.assertIn("selected_action", recovery["required"])

    def test_refusal_contract_covers_plan_drift_and_forbidden_authority(self) -> None:
        refusal_codes = set(load_schema("refusal")["properties"]["code"]["enum"])
        for code in (
            "source_changed",
            "recipe_changed",
            "target_changed",
            "policy_changed",
            "provider_revision_changed",
            "plan_digest_mismatch",
            "network_forbidden",
            "registry_forbidden",
            "elevation_forbidden",
            "package_manager_forbidden",
            "installer_execution_forbidden",
            "recovery_required",
            "live_target_acceptance_required",
            "target_class_forbidden",
            "target_not_explicit",
            "target_outside_acceptance_root",
            "target_not_empty",
            "target_filesystem_not_local",
            "target_path_redirected",
            "target_mount_redirected",
            "target_root_excluded",
            "target_space_insufficient",
            "source_target_same_object",
            "target_effects_incomplete",
            "target_identity_unproven",
        ):
            self.assertIn(code, refusal_codes)

    def test_policy_contract_forbids_setup_side_effect_classes(self) -> None:
        properties = load_schema("policy")["properties"]
        self.assertEqual(properties["network_allowed"]["const"], False)
        self.assertEqual(properties["registry_allowed"]["const"], False)
        self.assertEqual(properties["elevation_allowed"]["const"], False)
        self.assertEqual(properties["package_manager_allowed"]["const"], False)
        self.assertEqual(properties["product_specific_installer_allowed"]["const"], False)
        self.assertEqual(properties["installer_execution_allowed"]["const"], False)
        self.assertEqual(properties["credential_access_allowed"]["const"], False)

    def test_ownership_contract_has_mutation_gates(self) -> None:
        properties = load_schema("ownership")["properties"]
        self.assertIn("foreign_owned", properties["kind"]["enum"])
        self.assertEqual(properties["may_verify"]["type"], "boolean")
        self.assertEqual(properties["may_repair"]["type"], "boolean")
        self.assertEqual(properties["may_uninstall"]["type"], "boolean")

    def test_all_setup_schemas_parse_and_stay_product_neutral(self) -> None:
        forbidden = ("factorio", "dominium", "eureka", "modset", "mod_portal")
        for path in SCHEMA_ROOT.glob("*.schema.json"):
            with self.subTest(path=path.name):
                schema = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                text = json.dumps(schema).lower()
                for token in forbidden:
                    self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
