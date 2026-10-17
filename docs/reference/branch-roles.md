# Branch Roles

Q28 classifies branches so agents can decide whether to edit, stop, or generate
a future helper plan from repository evidence.

## Roles

- `canonical`: `main`; accepted truth, protected, no deletion, no force push.
- `integration`: `dev`; shareable latest integration, not canonical release
  truth.
- `task`: `task/*`, `codex/*`, `aide/*`, `fix/*`, `repair/*`; bounded work
  that lands to `dev` by default.
- `subtask`: narrow child work that rolls into a parent task branch.
- `review`: `review/*`; review staging and evidence inspection.
- `quarantine`: `quarantine/*`; isolated risky or disputed work.
- `release`: `release/*`; maintained release lines only when release support
  exists.
- `hotfix`: `hotfix/*`; urgent focused repair with explicit backmerge targets.
- `deploy`: `gh-pages`; generated deploy branch only.
- `unknown`: conservative fallback.

## Recovery Behavior

Branch role is part of WorkUnit preflight:

- editing `main` directly is discouraged except for explicitly scoped repairs;
- editing `dev` directly is limited to integration repair or explicit work;
- normal work should use a bounded task branch;
- unknown role or dirty tree blocks mutation recommendations;
- duplicate prompts may no-op only after branch and evidence inspection.
- Q29 helper mutation refuses protected roles and unknown roles; `git prune`
  never prunes canonical, integration, release, or deploy branches.

## Detection

Run:

```powershell
py -3 .aide/scripts/aide_lite.py git status
py -3 .aide/scripts/aide_lite.py git roles
py -3 .aide/scripts/aide_lite.py git plan
```

The output is advisory. `git plan` writes `.aide/git/latest-helper-plan.*`.
Land, promote, and prune helpers remain dry-run by default, and Q29 does not
run `--apply` on live AIDE branches.

## AIDE Repo Roles

Q30 binds these generic roles to AIDE's own repository in
`.aide/git/aide-branch-policy.yaml`:

- `main`: canonical accepted truth.
- `dev`: intended integration branch, not canonical truth.
- `task/*`, `codex/*`, `aide/*`, `fix/*`, `repair/*`: bounded work branches.
- `review/*`, `release/*`, and `hotfix/*`: explicit review, release, or repair
  paths.

If `dev` is missing, AIDE records a plan for future explicit operator action
instead of silently creating or pushing a branch.
