"""Lossless version tagging for the retained transaction contracts.

This adapter does not authorize execution. Modern lifecycle mutation uses the
reviewed operation plans and durable transaction journal instead.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any


LEGACY_OPERATIONS = frozenset({
    "install_local", "verify", "repair", "uninstall", "adopt", "audit",
})
VERSION_TWO_OPERATIONS = LEGACY_OPERATIONS | {"update", "move", "recovery"}
CONTRACTS = {
    "transaction_plan": frozenset({
        "schema", "transaction_id", "plan_id", "operation", "dry_run",
        "steps", "rollback_required",
    }),
    "transaction": frozenset({
        "schema", "transaction_id", "plan_id", "operation", "status",
        "dry_run", "stage_root", "steps", "audit_log_ref", "rollback_ref",
    }),
}


def convert(document: dict[str, Any], kind: str, version: int) -> dict[str, Any]:
    """Convert v1/v2 identity fields; refuse operations v1 cannot express.

    Only the schema tag changes. All other fields, including legacy extension
    fields on transaction plans, are preserved exactly.
    """
    if kind not in CONTRACTS or version not in (1, 2):
        raise ValueError("unknown transaction contract or version")
    if not isinstance(document, dict) or not CONTRACTS[kind] <= document.keys():
        raise ValueError("transaction document lacks required fields")
    source_schema = document.get("schema")
    valid_schemas = {f"usk.{kind}.v1", f"usk.{kind}.v2"}
    if source_schema not in valid_schemas:
        raise ValueError("unknown source transaction schema")
    operation = document.get("operation")
    if operation not in VERSION_TWO_OPERATIONS:
        raise ValueError("unknown transaction operation")
    if source_schema.endswith(".v1") and operation not in LEGACY_OPERATIONS:
        raise ValueError("v1 transaction contains an operation outside its contract")
    if version == 1 and operation not in LEGACY_OPERATIONS:
        raise ValueError("operation has no v1 representation")
    converted = deepcopy(document)
    converted["schema"] = f"usk.{kind}.v{version}"
    return converted
