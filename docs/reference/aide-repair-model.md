# AIDE Repair / Doctor Model

Q44 defines how AIDE observes, diagnoses, plans, and dry-runs repairs for
broken, partial, stale, or inconsistent AIDE installs. It is deterministic,
local, no-call, and preservation-first.

Q44 does not repair files. It does not overwrite, delete, rename, move, rewrite,
migrate, install, publish releases, activate CI, mutate GitHub settings, mutate
target repositories, or call providers/models/network services.

## Lifecycle

The repair lifecycle is:

1. observe
2. diagnose
3. classify
4. plan
5. dry-run
6. review
7. future apply
8. future verify
9. future rollback

Q44 implements only `observe`, `diagnose`, `plan`, `dry-run`, `validate`,
`status`, `explain`, `classes`, and `doctor`.

## Commands

```text
py -3 .aide/scripts/aide_lite.py repair observe
py -3 .aide/scripts/aide_lite.py repair diagnose
py -3 .aide/scripts/aide_lite.py repair plan
py -3 .aide/scripts/aide_lite.py repair dry-run
py -3 .aide/scripts/aide_lite.py repair validate
py -3 .aide/scripts/aide_lite.py repair status
py -3 .aide/scripts/aide_lite.py repair classes
py -3 .aide/scripts/aide_lite.py repair doctor
py -3 .aide/scripts/aide_lite.py repair explain <issue-or-path>
```

The commands write only `.aide/repair/latest-*` generated planning outputs.

## Generated Outputs

- `.aide/repair/latest-repair-observation.json`
- `.aide/repair/latest-repair-observation.md`
- `.aide/repair/latest-repair-diagnosis.json`
- `.aide/repair/latest-repair-diagnosis.md`
- `.aide/repair/latest-repair-plan.json`
- `.aide/repair/latest-repair-plan.md`
- `.aide/repair/latest-repair-dry-run.json`
- `.aide/repair/latest-repair-dry-run.md`
- `.aide/repair/latest-doctor-repair-report.json`
- `.aide/repair/latest-doctor-repair-report.md`
- `.aide/repair/latest-repair-verification-plan.md`

These files are source-repo evidence. Target repositories must generate their
own repair observations and plans after import.

## Repair Classes

Repair classes include missing or stale portable files, stale policies or
scripts, stale command catalogs, missing hook templates, malformed managed
sections, missing or invalid generated packets, missing target memory or queue,
invalid queue status, stale golden task catalogs, invalid pack checksums, stale
pack provenance, source-state contamination, tracked local state, secret-like
files, unsupported schema versions, ambiguous ownership, target-specific
conflicts, and unknown issues.

Each class has detection hints, risk class, preservation defaults, validation
requirements, evidence requirements, and a future-apply gate. Future repair
apply is never implied by a diagnosis.

## Hard Blockers

Q44 treats tracked `.aide.local/**`, `.env`, secret-like files, raw prompt or
response logs, source-state contamination, unsupported schemas that block
validation, and ambiguous ownership as blockers or manual-review issues. The
repair plan may propose future quarantine, regeneration, restoration, refresh,
or manual review, but it does not execute those actions.

## Doctor Integration

`repair doctor` emits an advisory doctor-style repair report. The normal
`doctor` command may mention that a repair plan or repair doctor report exists,
but it does not apply repair and does not treat repair warnings as automatic
failure unless a current policy marks the issue blocking.

## Export Boundary

The portable pack includes repair policies, schemas, README, commands, tests,
golden tasks, and this reference doc. It excludes source-generated
`.aide/repair/latest-*` outputs as target truth.

## Q45 Handoff

Q45 Upgrade Model v0 is next because repair can now diagnose current state, but
upgrade still needs a preservation-first model for moving from old supported
AIDE versions to newer portable surfaces without overwriting target state.
Q45 consumes install and repair evidence when present, but it remains no-apply:
upgrade differences become candidate updates, preserved paths, conflicts, or
future migration gates.

Q46 Rollback / Uninstall Model v0 can also consume repair plans as prior-plan
evidence. Repair findings do not become rollback or uninstall approval; they
remain advisory inputs for future review-gated recovery planning.
