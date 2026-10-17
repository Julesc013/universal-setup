# Blocker And Repair Model

The blocker policy is defined in `.aide/policies/blockers.yaml`. The repair loop policy is defined in `.aide/policies/repair-loop.yaml`.

Blocker classes:

- `missing_prerequisite`
- `test_failure`
- `merge_conflict`
- `missing_implementation`
- `docs_overclaim`
- `schema_mismatch`
- `tool_unavailable`
- `dependency_unavailable`
- `security_destructive_risk`
- `ambiguous_product_decision`
- `validation_runtime_exceeded`
- `source_state_conflict`
- `target_pack_drift`
- `promotion_gate_failed`
- `capability_reality_mismatch`
- `unknown`

Severity values are `low`, `medium`, `high`, `critical`, `unsafe`, and `unknown`.

RepairTask records are future work plans. They map a blocker to a bounded repair class, scope, allowed paths, forbidden paths, retry limits, validation requirements, evidence requirements, expected outcome, and unsafe boundary.

X-OS-00 does not execute repairs. It defines conservative retry controls so later phases can decide when to retry, split, quarantine, supersede, or request a human decision.

## Repair Loop Defaults

- `max_attempts_per_task`: 3
- `max_repair_depth`: 2
- `max_checkpoint_repair_passes`: 2

Unsafe blockers quarantine. Repeated identical blockers should not loop forever. Missing decisions must be surfaced rather than guessed.
