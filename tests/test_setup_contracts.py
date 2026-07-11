from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_SETUP_SCHEMAS = {
    "install_plan": "usk.install_plan.v1",
    "installed_state": "usk.installed_state.v1",
    "verify_report": "usk.verify_report.v1",
    "package_verify_request": "usk.package_verify_request.v1",
    "package_verify_report": "usk.package_verify_report.v1",
    "audit_log": "usk.audit_log.v1",
    "transaction": "usk.transaction.v1",
    "rollback": "usk.rollback.v1",
    "ownership": "usk.ownership.v1",
    "refusal": "usk.refusal.v1",
    "policy": "usk.policy.v1",
}


def load_schema(name: str) -> dict:
    path = ROOT / "contracts" / "schema" / "setup" / f"{name}.v1.schema.json"
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


class SetupContractTests(unittest.TestCase):
    def test_usetup_contract_schema_spine_exists(self) -> None:
        for name, schema_const in EXPECTED_SETUP_SCHEMAS.items():
            with self.subTest(name=name):
                schema = load_schema(name)
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertEqual(schema["type"], "object")
                self.assertIn("schema", schema["required"])
                self.assertEqual(schema["properties"]["schema"]["const"], schema_const)

    def test_install_plan_is_local_and_refusal_first(self) -> None:
        schema = load_schema("install_plan")
        refusal_policy = schema["properties"]["refusal_policy"]["properties"]
        self.assertEqual(refusal_policy["refuse_network"]["const"], True)
        self.assertEqual(refusal_policy["refuse_registry"]["const"], True)
        self.assertEqual(refusal_policy["refuse_package_manager"]["const"], True)
        self.assertEqual(refusal_policy["refuse_product_specific_installer"]["const"], True)

    def test_policy_contract_forbids_setup_side_effect_classes(self) -> None:
        schema = load_schema("policy")
        properties = schema["properties"]
        self.assertEqual(properties["network_allowed"]["const"], False)
        self.assertEqual(properties["registry_allowed"]["const"], False)
        self.assertEqual(properties["package_manager_allowed"]["const"], False)
        self.assertEqual(properties["product_specific_installer_allowed"]["const"], False)

    def test_ownership_contract_has_mutation_gates(self) -> None:
        schema = load_schema("ownership")
        properties = schema["properties"]
        self.assertIn("foreign_owned", properties["kind"]["enum"])
        self.assertEqual(properties["may_verify"]["type"], "boolean")
        self.assertEqual(properties["may_repair"]["type"], "boolean")
        self.assertEqual(properties["may_uninstall"]["type"], "boolean")

    def test_contract_schemas_stay_product_neutral(self) -> None:
        forbidden = ("factorio", "dominium", "eureka", "modset", "mod_portal")
        for path in (ROOT / "contracts" / "schema" / "setup").glob("*.schema.json"):
            text = path.read_text(encoding="utf-8").lower()
            with self.subTest(path=path.name):
                for token in forbidden:
                    self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
