# AIDE Rollback / Uninstall Model

Q46 defines how AIDE observes, plans, and dry-runs rollback or uninstall work
without applying removal or recovery actions. It is deterministic, local,
no-call, and preservation-first.

Q46 does not roll back files and does not uninstall files. It does not delete,
overwrite, rename, move, rewrite, remove managed sections, publish releases,
activate CI, mutate GitHub settings, mutate target repositories, or call
providers/models/network services.

## Lifecycles

The rollback lifecycle is:

1. observe current install
2. inspect ownership ledger and prior plans
3. classify rollback candidates
4. plan
5. dry-run
6. review
7. future apply
8. future verify

The uninstall lifecycle is:

1. observe current install
2. classify owned files
3. classify preserved files
4. plan
5. dry-run
6. review
7. future apply
8. future verify

Q46 implements only `observe`, `plan`, `dry-run`, `validate`, `status`,
`explain`, and `classes` for rollback and uninstall.

## Commands

```text
py -3 .aide/scripts/aide_lite.py rollback observe
py -3 .aide/scripts/aide_lite.py rollback plan
py -3 .aide/scripts/aide_lite.py rollback dry-run
py -3 .aide/scripts/aide_lite.py rollback validate
py -3 .aide/scripts/aide_lite.py rollback status
py -3 .aide/scripts/aide_lite.py rollback classes
py -3 .aide/scripts/aide_lite.py rollback explain <path-or-issue>

py -3 .aide/scripts/aide_lite.py uninstall observe
py -3 .aide/scripts/aide_lite.py uninstall plan
py -3 .aide/scripts/aide_lite.py uninstall dry-run
py -3 .aide/scripts/aide_lite.py uninstall validate
py -3 .aide/scripts/aide_lite.py uninstall status
py -3 .aide/scripts/aide_lite.py uninstall classes
py -3 .aide/scripts/aide_lite.py uninstall explain <path-or-issue>
```

The commands write only `.aide/rollback/latest-*` and
`.aide/uninstall/latest-*` generated planning outputs.

## Generated Outputs

Rollback outputs:

- `.aide/rollback/latest-rollback-observation.json`
- `.aide/rollback/latest-rollback-observation.md`
- `.aide/rollback/latest-rollback-plan.json`
- `.aide/rollback/latest-rollback-plan.md`
- `.aide/rollback/latest-rollback-dry-run.json`
- `.aide/rollback/latest-rollback-dry-run.md`
- `.aide/rollback/latest-rollback-verification-plan.md`

Uninstall outputs:

- `.aide/uninstall/latest-uninstall-observation.json`
- `.aide/uninstall/latest-uninstall-observation.md`
- `.aide/uninstall/latest-uninstall-plan.json`
- `.aide/uninstall/latest-uninstall-plan.md`
- `.aide/uninstall/latest-uninstall-dry-run.json`
- `.aide/uninstall/latest-uninstall-dry-run.md`
- `.aide/uninstall/latest-uninstall-verification-plan.md`

These files are source-repo evidence. Target repositories must generate their
own rollback and uninstall observations and plans after import.

## Ownership Evidence

Rollback and uninstall plans read ownership and prior-plan evidence when
present:

- `.aide/install/latest-ownership-ledger.example.json`
- `.aide/install/latest-install-plan.json`
- `.aide/upgrade/latest-upgrade-plan.json`
- `.aide/repair/latest-repair-plan.json`

Missing ownership evidence is not treated as permission to remove files.
Rollback uses missing-ledger or manual-review blockers. Uninstall preserves or
manual-reviews unknown ownership instead of deleting it.

## Preservation Boundary

Q46 preserves target `.aide/memory/**`, `.aide/queue/**`,
`.aide/evidence/**`, target golden tasks, generated target context and reports,
target `.aide/git/latest-*`, repo indexes, root/tool/install/repair/upgrade
generated outputs, manual `AGENTS.md` content, docs/canon/doctrine, existing
tools, `.aide.local/**`, `.env`, secrets, raw prompts, and raw responses.

Generated target state can be marked as future-regenerable only when policy
and ownership evidence support that conclusion. Q46 still does not remove it.

## Uninstall Is Not Root Deletion

Uninstall planning is not `rm -rf .aide`. AIDE-owned portable files may become
future removal candidates when ownership is known. Target memory, queue,
evidence, target golden tasks, generated reports, manual content, existing
tools, local ignored state, and unknown ownership are preserved or sent to
manual review.

## Export Boundary

The portable pack includes rollback and uninstall policies, schemas, READMEs,
commands, tests, golden tasks, and this reference doc. It excludes
source-generated `.aide/rollback/latest-*` and `.aide/uninstall/latest-*`
outputs as target truth.

## Target Use

Future Dominium and Eureka phases must regenerate rollback and uninstall plans
inside those repositories. Dominium-specific doctrine, XStack/AuditX/RepoX/
TestX-style tools, FAST/STRICT/FULL validators, and docs/canon material remain
target-owned unless a later reviewed apply phase proves otherwise. Eureka
architecture checks, target-local golden tasks, evidence, and queue packets are
preserved by default.

## Q47 Integration

Q47 AIDE Lite Release Bundle v0 packages the portable rollback and uninstall
policies, schemas, commands, tests, golden tasks, and docs into local archives
from the validated export pack. It does not include source-generated
`.aide/rollback/latest-*` or `.aide/uninstall/latest-*` outputs as target truth,
and it does not authorize rollback apply, uninstall apply, file deletion, or
managed-section removal.

Q48 GitHub Release Draft v0 is next because the local bundle can now be
inspected and validated before any draft release surface is proposed.
