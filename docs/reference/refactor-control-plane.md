# Refactor Control Plane v0

## Purpose

Q39 adds AIDE's first generic Refactor Control Plane. It is a deterministic,
repo-local, no-call planning layer for future structural change. It turns repo
intelligence, file quality evidence, intent packets, branch policy, and
validation policy into reviewable dry-run refactor readiness artifacts.

Q39 does not apply refactors. It does not move files, delete files, rewrite
references, apply migrations, mutate branches, mutate target repositories, call
providers/models/network services, publish releases, or declare anything safe
to delete.

## Command Surface

```powershell
py -3 .aide/scripts/aide_lite.py refactor status
py -3 .aide/scripts/aide_lite.py refactor plan
py -3 .aide/scripts/aide_lite.py refactor validate
py -3 .aide/scripts/aide_lite.py refactor dry-run
py -3 .aide/scripts/aide_lite.py refactor schemas
py -3 .aide/scripts/aide_lite.py refactor ledger
py -3 .aide/scripts/aide_lite.py refactor map
py -3 .aide/scripts/aide_lite.py refactor validate-map
py -3 .aide/scripts/aide_lite.py refactor map-status
```

`refactor plan` writes:

- `.aide/refactors/latest-refactor-readiness.json`
- `.aide/refactors/latest-refactor-readiness.md`
- `.aide/refactors/latest-refactor-plan.example.json`
- `.aide/refactors/latest-refactor-plan.example.md`
- `.aide/refactors/migration-ledger.example.jsonl`

These are evidence artifacts, not applied changes.

## Inputs

Q39 references compact artifacts instead of inlining large indexes:

- `.aide/repo/latest-repo-intelligence.md`
- `.aide/repo/file-inventory.json`
- `.aide/reports/file-quality-summary.md`
- `.aide/reports/file-quality-ledger.json`
- `.aide/intake/latest-intent-packet.json` when present
- `.aide/policies/git-workflow.yaml`
- `.aide/policies/verification.yaml`

If repo intelligence or the quality ledger is missing, Q39 records warnings and
keeps the plan in no-apply mode. Future WorkUnits should run `repo inventory`
and `quality ledger` first for stronger planning evidence.

## Schemas

Q39 defines schemas under `.aide/refactors/` for:

- refactor plans
- refactor operations
- move maps
- salvage maps
- path aliases
- migration ledgers
- rollback notes
- refactor risks
- refactor validation plans

Move maps, salvage maps, and path aliases are planning records. They can model
future moves, extraction, preservation, aliases, and validation needs, but Q39
does not apply any of them.

## Fate Vocabulary

- `keep`: preserve in place.
- `wrap`: preserve and place a future wrapper around behavior.
- `adapt`: preserve and adapt through a future compatibility layer.
- `extract`: candidate for future extraction after review.
- `convert`: candidate for future conversion after review.
- `archive`: candidate for future archival; not applied in Q39.
- `drop_candidate`: candidate requiring review; never deletion approval.
- `shim`: planned compatibility surface; not created in Q39.
- `alias`: planned path alias; not applied in Q39.
- `unknown`: unresolved fate requiring more evidence.

`drop_candidate` is deliberately not a delete instruction.

## Migration Ledgers

The migration-ledger schema records future migration events with an event id,
commit or timestamp, operation, source, target, status, evidence, validation,
rollback, and notes. Q39 writes only an example dry-run ledger line so later
phases have a stable record shape.

Future apply-capable phases must create reviewed, task-specific migration
ledger events after separate authorization.

## Validation

`refactor validate` checks:

- Q39 policy anchors.
- schema existence and required fields.
- latest readiness and example plan artifacts.
- `no_apply: true`.
- every operation keeps `apply_allowed: false`.
- final deletion phrases are absent.
- target-repo mutation is not implied.

`refactor dry-run` prints the current example plan summary and confirms that
apply is unavailable in Q39.

## Export Boundary

The export pack carries portable Q39 policies, schemas, docs, tests, golden
tasks, and command support. It does not export source-generated
`.aide/refactors/latest-*` artifacts or the example migration ledger as target
truth. Target repositories must generate their own refactor readiness after
import.

## Q40 Integration

Q40 Root Recycling Framework v0 now uses Q39's dry-run schemas and no-apply
validation to classify root-level files with preservation, wrapping,
adaptation, extraction, alias, or drop-candidate fates before any future
apply-capable phase exists. Q39 still remains a planning substrate only; Q40
does not apply refactors either.

## Q42 Map Integration

Q42 extends the same refactor command family with candidate move-map,
salvage-map, path-alias, reference-rewrite, and migration-ledger draft planning.
Those maps are still no-apply evidence. `refactor validate-map` fails
apply-enabled entries, deletion-approval language, active aliases or shims,
active reference rewrites, and any implied target-repo mutation.
