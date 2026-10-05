# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Validate transaction fixtures and a built command graph against schemas."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_lifecycle_contract_schemas.py <usk_command_graph_smoke>", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "tests"))
    from transaction_compat_reference import convert

    fixtures = root / "tests/fixtures/setup/transaction-compat"
    for directory, schema_name, fixture_name, kind in (
        ("transaction", "transaction_plan.v1", "v1-plan.json", "transaction_plan"),
        ("setup", "transaction.v1", "v1-transaction.json", "transaction"),
        ("transaction", "transaction_plan.v2", "v2-move-plan.json", "transaction_plan"),
        ("setup", "transaction.v2", "v2-update-transaction.json", "transaction"),
    ):
        contract = json.loads((root / "contracts/schema" / directory /
                               f"{schema_name}.schema.json").read_text(encoding="utf-8"))
        document = json.loads((fixtures / fixture_name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(contract)
        Draft202012Validator(contract).validate(document)
        version = int(schema_name.rsplit("v", 1)[1])
        converted = convert(document, kind, version)
        Draft202012Validator(contract).validate(converted)
        if version == 1:
            newer = convert(document, kind, 2)
            newer_contract = json.loads((root / "contracts/schema" / directory /
                                         f"{kind}.v2.schema.json").read_text(encoding="utf-8"))
            Draft202012Validator(newer_contract).validate(newer)
            assert convert(newer, kind, 1) == document

    schema_path = root / "contracts/schema/setup/command_graph.v2.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    completed = subprocess.run(
        [sys.argv[1], "--dump-v2"], capture_output=True, check=True, timeout=30,
    )
    response = json.loads(completed.stdout)
    assert response["schema"] == "usk.command_response.v1"
    assert response["status"] == "ok" and response["error"] is None
    graph = response["payload"]
    Draft202012Validator(schema).validate(graph)
    names = [entry["command"] for entry in graph["commands"]]
    assert len(names) == len(set(names))
    print(f"lifecycle-contract-schemas: PASS (4 fixtures, {len(names)} descriptors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
