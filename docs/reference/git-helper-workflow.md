# Git Helper Workflow

Q29 adds AIDE's first local merge, land, promote, sync, and prune helper layer.
It is a dry-run-first helper surface, not live branch automation.

## Safety Model

- `main` is canonical accepted truth.
- `dev` is shareable integration truth, not release truth.
- `task/*` and equivalent task branches land to `dev`.
- `dev` promotes to `main` only through explicit review gates.
- Prune requires ancestor containment proof.
- Protected roles are never pruned.
- Force push is forbidden.
- Remote push is explicit future operator intent and is not run in Q29.

The helper inspects repo root, current branch, dirty state, local and remote
branches, upstream status, branch roles, protected roles, ancestor containment,
ahead/behind state where available, missing policy files, and unpushed
protected branches where feasible.

## Commands

```powershell
py -3 .aide/scripts/aide_lite.py git plan
py -3 .aide/scripts/aide_lite.py git sync --dry-run
py -3 .aide/scripts/aide_lite.py git land --dry-run --target dev
py -3 .aide/scripts/aide_lite.py git promote --dry-run --from dev --to main
py -3 .aide/scripts/aide_lite.py git prune --dry-run
```

`git plan` writes:

- `.aide/git/latest-helper-plan.json`
- `.aide/git/latest-helper-plan.md`

## Landing

`git land` plans a task/subtask branch merge into the integration branch:

```text
git checkout <target>
git merge --no-ff <source> -m "land: <source> into <target>"
```

It blocks dirty trees, protected source roles, unknown roles, missing target
branches, missing policy files, and missing validation evidence unless an
explicit validation acknowledgement is provided for fixture/operator-controlled
use.

## Promotion

`git promote` plans integration-to-canonical promotion:

```text
git checkout <target>
git merge --no-ff <source> -m "promote: <source> into <target>"
```

It requires an integration source, canonical target, clean tree, review
evidence, validation evidence, and changelog preview posture.

## Prune

`git prune` lists local branch prune eligibility. A branch is eligible only when
all of these are true:

- it is not the current branch;
- it is not canonical, integration, release, or deploy;
- it is a task-like branch role;
- containment is proven with `git merge-base --is-ancestor <branch> <target>`.

`--apply` deletes only eligible local branches with `git branch -d`. Q29 tests
that path only in temporary fixture repositories.

## Live AIDE Boundary

Q29 does not create `dev`, merge into `main`, push, delete, prune, promote,
call GitHub, install CI, publish releases, or call providers/models in the live
AIDE repository. Q30 is the phase that should decide how AIDE applies the
`dev`/`main` policy if appropriate.

## Portable Pack

Q31 exports the helper policy, helper command documentation, and dry-run helper
command implementation to target repos. It excludes source-generated
`latest-helper-plan.*` files, so every target repo must run `git plan` locally
and review the resulting target-specific plan before branch-sensitive work.
