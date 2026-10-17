# AIDE Upgrade Model

Q45 defines how AIDE observes, compares, plans, and dry-runs upgrades from an
existing installed AIDE state to a newer portable pack. It is deterministic,
local, no-call, and preservation-first.

Q45 does not upgrade files. It does not install, repair, overwrite, delete,
rename, move, rewrite, migrate, publish releases, activate CI, mutate GitHub
settings, mutate target repositories, or call providers/models/network services.

## Lifecycle

The upgrade lifecycle is:

1. observe current install
2. observe source pack
3. compare
4. classify differences
5. plan
6. dry-run
7. review
8. future apply
9. future verify
10. future rollback

Q45 implements only `observe-current`, `observe-source`, `compare`, `plan`,
`dry-run`, `validate`, `status`, `explain`, `compatibility`, `conflicts`, and
`migrations`.

## Commands

```text
py -3 .aide/scripts/aide_lite.py upgrade observe-current
py -3 .aide/scripts/aide_lite.py upgrade observe-source
py -3 .aide/scripts/aide_lite.py upgrade compare
py -3 .aide/scripts/aide_lite.py upgrade plan
py -3 .aide/scripts/aide_lite.py upgrade dry-run
py -3 .aide/scripts/aide_lite.py upgrade validate
py -3 .aide/scripts/aide_lite.py upgrade status
py -3 .aide/scripts/aide_lite.py upgrade compatibility
py -3 .aide/scripts/aide_lite.py upgrade conflicts
py -3 .aide/scripts/aide_lite.py upgrade migrations
py -3 .aide/scripts/aide_lite.py upgrade explain <path-or-issue>
```

The commands write only `.aide/upgrade/latest-*` generated planning outputs.

## Generated Outputs

- `.aide/upgrade/latest-current-install-observation.json`
- `.aide/upgrade/latest-current-install-observation.md`
- `.aide/upgrade/latest-source-pack-observation.json`
- `.aide/upgrade/latest-source-pack-observation.md`
- `.aide/upgrade/latest-upgrade-comparison.json`
- `.aide/upgrade/latest-upgrade-comparison.md`
- `.aide/upgrade/latest-upgrade-plan.json`
- `.aide/upgrade/latest-upgrade-plan.md`
- `.aide/upgrade/latest-upgrade-dry-run.json`
- `.aide/upgrade/latest-upgrade-dry-run.md`
- `.aide/upgrade/latest-upgrade-conflict-report.json`
- `.aide/upgrade/latest-upgrade-conflict-report.md`
- `.aide/upgrade/latest-upgrade-migration-report.md`
- `.aide/upgrade/latest-upgrade-compatibility-report.md`
- `.aide/upgrade/latest-upgrade-verification-plan.md`

These files are source-repo evidence. Target repositories must generate their
own upgrade observations and plans after import.

## Preservation Rules

Q45 preserves target `.aide/memory/**`, `.aide/queue/**`, generated context,
reports, target golden tasks, target `.aide/git/latest-*`, target repo indexes,
root/tool/install/repair/upgrade generated outputs, manual `AGENTS.md` content
outside managed sections, target docs/canon, existing tools, `.aide.local/**`,
`.env`, secrets, raw prompts, and raw responses.

Source-generated `.aide/context/latest-*`, `.aide/reports/**`, `.aide/repo`
indexes, `.aide/roots/latest-*`, `.aide/tools/latest-*`,
`.aide/refactors/current-*`, `.aide/install/latest-*`, `.aide/repair/latest-*`,
and `.aide/upgrade/latest-*` are skipped as source upgrade truth. Targets must
regenerate them locally.

## Compatibility

Q45 compares pack schema versions, policy schema versions, command surfaces,
golden task catalogs, managed-section formats, generated-artifact formats,
install/repair/refactor schemas, and target-specific extensions where evidence
exists. Findings use compatibility levels such as `compatible`,
`compatible_with_warnings`, `migration_required_future`, `unsupported`, and
`unknown`. It does not invent SemVer when no SemVer record exists.

## Migration Gates

Mandatory migrations are planned only when the current state is unsafe,
unsupported, validation-blocking, ambiguous, source-state contaminated, blocks
command execution, or conflicts with canonical AIDE ownership. Optional
migrations, such as legacy-but-compatible naming or target-local extensions,
are deferred. No migration is applied in Q45.

## Export Boundary

The portable pack includes upgrade policies, schemas, README, commands, tests,
golden tasks, and this reference doc. It excludes source-generated
`.aide/upgrade/latest-*` outputs as target truth.

## Rollback / Uninstall Integration

Q46 Rollback / Uninstall Model v0 consumes upgrade plans as one evidence source
for future recovery. Upgrade candidates do not become rollback or uninstall
approval. Q46 preserves target-specific state, blocks missing ownership evidence
where needed, and keeps all rollback or uninstall operations no-apply.

## Q47 Integration

Q47 AIDE Lite Release Bundle v0 packages the portable upgrade policies,
schemas, commands, tests, golden tasks, and docs into local archives from the
validated export pack. It excludes source-generated `.aide/upgrade/latest-*`
outputs as target truth and does not authorize upgrade apply, target mutation,
publication, tags, uploads, or GitHub Releases.

Q48 GitHub Release Draft v0 is next because the local bundle can now be
inspected and validated before any draft release surface is proposed.
