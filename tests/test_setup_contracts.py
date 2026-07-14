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
    "verify_report": "usk.verify_report.v1",
    "audit_log": "usk.audit_log.v1",
    "transaction": "usk.transaction.v1",
    "rollback": "usk.rollback.v1",
    "ownership": "usk.ownership.v1",
    "policy": "usk.policy.v1",
    "setup_manifest": "usk.setup_manifest.v1",
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
