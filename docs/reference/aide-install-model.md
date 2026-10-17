# AIDE Install Plan Model

Q43 defines how AIDE observes and plans installation before any future install
apply phase exists. It is deterministic, local, no-call, and
preservation-first.

Q43 does not install AIDE into a target repo. It does not overwrite files,
migrate files, delete files, move files, rewrite references, activate CI,
publish releases, mutate GitHub settings, mutate target repositories, or call
providers/models/network services.

## Lifecycle

The install lifecycle is:

1. observe
2. plan
3. dry-run
4. review
5. future apply
6. future verify
7. future repair
8. future upgrade
9. future rollback
10. future uninstall

Q43 implements only `observe`, `plan`, `dry-run`, `validate`, `status`,
`explain`, `ownership`, and `conflicts`.

## Commands

```text
py -3 .aide/scripts/aide_lite.py install observe
py -3 .aide/scripts/aide_lite.py install plan
py -3 .aide/scripts/aide_lite.py install dry-run
py -3 .aide/scripts/aide_lite.py install validate
py -3 .aide/scripts/aide_lite.py install status
py -3 .aide/scripts/aide_lite.py install ownership
py -3 .aide/scripts/aide_lite.py install conflicts
py -3 .aide/scripts/aide_lite.py install explain <path>
```

The commands write only `.aide/install/latest-*` generated planning outputs.

## Generated Outputs

- `.aide/install/latest-install-observation.json`
- `.aide/install/latest-install-observation.md`
- `.aide/install/latest-install-plan.json`
- `.aide/install/latest-install-plan.md`
- `.aide/install/latest-install-dry-run.json`
- `.aide/install/latest-install-dry-run.md`
- `.aide/install/latest-ownership-ledger.example.json`
- `.aide/install/latest-conflict-report.json`
- `.aide/install/latest-conflict-report.md`
- `.aide/install/latest-preservation-report.md`
- `.aide/install/latest-verification-plan.md`

These files are source-repo evidence. Target repositories must generate their
own install observations and plans after import.

## Preservation Rules

Q43 preserves target `.aide/memory/**`, `.aide/queue/**`, generated context,
reports, target golden tasks, manual `AGENTS.md` content outside managed
sections, target docs/canon, existing tools, `.aide.local/**`, `.env`, secrets,
raw prompts, and raw responses.

Source-generated `.aide/context/latest-*`, `.aide/reports/**`, `.aide/repo`
indexes, `.aide/roots/latest-*`, `.aide/tools/latest-*`,
`.aide/refactors/current-*`, and `.aide/install/latest-*` are skipped as target
truth. They must be regenerated locally.

## Ownership And Conflicts

The ownership ledger classifies installed-file candidates, managed sections,
generated target artifacts, preserved target artifacts, manual artifacts,
local-only artifacts, source-pack artifacts, and unknown ownership.

Conflict reports use candidate and review language. Existing manual files,
target-specific files, source-state leaks, unsupported old schemas,
local-state tracking, secret-like paths, ambiguous owners, and unsafe
overwrites are never auto-fixed in Q43.

## Migration Criteria

Migration is mandatory only when an old file is unsafe, uses an unsupported
schema, blocks validation, conflicts with canonical AIDE ownership, would
create ambiguous truth, or contains source-state contamination. Q43 records
those cases as future migration candidates only.

## Export Boundary

The portable pack includes install policies, schemas, README, commands, tests,
golden tasks, and this reference doc. It excludes source-generated
`.aide/install/latest-*` outputs as target truth.

## Q44 Handoff

Q44 Repair / Doctor Model v0 consumes install observations, conflict reports,
preservation rules, and verification plans to diagnose broken, partial, stale,
or inconsistent AIDE installs without applying repairs. Install plans remain
source-repo evidence only; target repositories must generate their own install
and repair plans before any future apply-capable phase is authorized.

Q45 Upgrade Model v0 then compares a target's installed AIDE state against a
source pack, preserving the same target-state surfaces before any future
upgrade apply phase exists.

Q46 Rollback / Uninstall Model v0 adds the matching no-apply recovery and
removal planning layer. It reads install ownership evidence when present, but
missing ownership evidence blocks or manual-reviews rollback/uninstall planning
rather than authorizing deletion.

Q47 AIDE Lite Release Bundle v0 packages the portable install planning surface
into local archives from the validated export pack. It excludes
source-generated `.aide/install/latest-*` outputs as target truth and does not
authorize install apply, target mutation, publication, tags, uploads, or GitHub
Releases.
