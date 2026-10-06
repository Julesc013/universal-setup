# Move, Salvage, And Path Alias Planning

Q42 adds AIDE's first deterministic candidate map layer for future structural
change. It builds candidate move maps, salvage maps, path alias plans,
reference rewrite plans, and migration ledger draft events from existing
repo-intelligence, quality, refactor, root, and tool evidence.

Q42 is no-apply infrastructure. It does not move files, delete files, rewrite
references, create aliases, create shims, execute wrappers, mutate target
repositories, mutate branches, call providers/models/network services, or treat
candidate maps as approved migration truth.

## Why It Exists

Root recycling, tool absorption, install, upgrade, repair, and rollback work all
need a shared way to describe possible structural changes before applying them.
Q42 provides that shared description:

- move maps say which file path might move to which future target path;
- salvage maps say which material may need keeping, wrapping, adapting,
  extracting, converting, archiving, aliasing, shimming, or further review;
- path alias plans say which old paths may need compatibility aliases or shims
  during a future transition;
- reference rewrite plans list references that would need review before any
  future rewrite;
- migration ledger drafts define the event shape future apply and rollback
  phases must record.

## Commands

```text
py -3 .aide/scripts/aide_lite.py refactor map
py -3 .aide/scripts/aide_lite.py refactor move-map
py -3 .aide/scripts/aide_lite.py refactor salvage-map
py -3 .aide/scripts/aide_lite.py refactor aliases
py -3 .aide/scripts/aide_lite.py refactor rewrite-plan
py -3 .aide/scripts/aide_lite.py refactor validate-map
py -3 .aide/scripts/aide_lite.py refactor map-status
```

`refactor map` writes the current candidate bundle under `.aide/refactors/`.
The read commands print the current map family, and `validate-map` checks that
the bundle remains candidate-only.

## Generated Outputs

- `.aide/refactors/current-move-map.json`
- `.aide/refactors/current-move-map.md`
- `.aide/refactors/current-salvage-map.json`
- `.aide/refactors/current-salvage-map.md`
- `.aide/refactors/path-aliases.yaml`
- `.aide/refactors/path-aliases.md`
- `.aide/refactors/reference-rewrite-plan.json`
- `.aide/refactors/reference-rewrite-plan.md`
- `.aide/refactors/migration-ledger.draft.jsonl`
- `.aide/refactors/map-validation-report.json`
- `.aide/refactors/map-validation-report.md`

These are AIDE-source evidence outputs. Target repositories must generate their
own maps after import; source-generated maps are not target truth.

## Policies And Schemas

Portable policies:

- `.aide/policies/move-map.yaml`
- `.aide/policies/salvage-map.yaml`
- `.aide/policies/path-aliases.yaml`
- `.aide/policies/reference-rewrite.yaml`
- `.aide/policies/migration-ledger.yaml`

Portable schemas:

- `.aide/refactors/move-map.schema.json`
- `.aide/refactors/move-map-entry.schema.json`
- `.aide/refactors/salvage-map.schema.json`
- `.aide/refactors/salvage-map-entry.schema.json`
- `.aide/refactors/path-aliases.schema.json`
- `.aide/refactors/path-alias-entry.schema.json`
- `.aide/refactors/path-aliases.template.yaml`
- `.aide/refactors/reference-rewrite-plan.schema.json`
- `.aide/refactors/reference-rewrite-entry.schema.json`
- `.aide/refactors/migration-ledger.schema.json`
- `.aide/refactors/migration-ledger-entry.schema.json`
- `.aide/refactors/map-validation-report.schema.json`

## Validation Boundary

`refactor validate-map` fails structural errors and forbidden states:

- `apply_allowed: true`;
- `future_applied` current map entries;
- `drop_candidate` treated as deletion approval;
- active aliases, active shims, file moves, file deletes, reference rewrites, or
  target-repo mutation implied by current map outputs.

`drop_candidate` remains review language only. It is never a deletion approval
or a safe-to-delete claim.

## Integration

Q42 consumes existing artifacts when present:

- `.aide/repo/file-inventory.json`
- `.aide/reports/file-quality-ledger.json`
- `.aide/refactors/latest-refactor-readiness.md`
- `.aide/roots/latest-root-inventory.json`
- `.aide/roots/latest-root-classification.json`
- `.aide/tools/latest-tool-inventory.json`
- `.aide/tools/latest-tool-wrap-plan.json`

The current AIDE map is intentionally conservative. It records salvage and
rewrite candidates where earlier deterministic evidence exists, but it does not
select a concrete root migration target.

## Export Boundary

The export pack carries Q42 policies, schemas, tests, golden tasks, command
support, and this reference doc. It excludes source-generated current maps,
alias plans, rewrite plans, migration ledger drafts, and validation reports as
target truth.

## Next Phase

Q43 Install Plan Model v0 consumes this no-apply map vocabulary for
preservation-first install observation, planning, and dry-run reports. Q44
Repair / Doctor Model v0 is next because repair logic must use install
conflict and preservation evidence before any future apply-capable repair phase
exists.
