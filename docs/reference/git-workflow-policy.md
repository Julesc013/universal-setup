# Git Workflow Policy

Q28 defines AIDE's local Git workflow policy before any branch mutation helpers
exist.

## Default Model

AIDE uses a trunk-based / GitHub Flow hybrid with an optional permanent `dev`
integration branch:

- `main` is canonical accepted truth.
- `dev` is shareable integration truth and must not be treated as canonical
  release truth.
- `task/*`, `codex/*`, `aide/*`, `fix/*`, and `repair/*` branches are bounded
  work by default.
- `release/*` and `hotfix/*` are explicit maintenance or emergency paths.
- `gh-pages` is a generated deploy branch when a repository actually uses it.

## Commands

```powershell
py -3 .aide/scripts/aide_lite.py git detect
py -3 .aide/scripts/aide_lite.py git doctor
py -3 .aide/scripts/aide_lite.py git status
py -3 .aide/scripts/aide_lite.py git workflow
py -3 .aide/scripts/aide_lite.py git roles
py -3 .aide/scripts/aide_lite.py git policy
py -3 .aide/scripts/aide_lite.py git plan
```

`git detect` writes `.aide/git/workflow-detection.json` and
`.aide/git/workflow-detection.md`. It reads local branch, remote-branch, tag,
status, and remote-url metadata. It does not fetch, create branches, merge,
delete, prune, push, call GitHub, call providers, or use the network.

Q29 adds dry-run helper commands:

```powershell
py -3 .aide/scripts/aide_lite.py git plan
py -3 .aide/scripts/aide_lite.py git sync --dry-run
py -3 .aide/scripts/aide_lite.py git land --dry-run --target dev
py -3 .aide/scripts/aide_lite.py git promote --dry-run --from dev --to main
py -3 .aide/scripts/aide_lite.py git prune --dry-run
```

These helpers remain dry-run/report-only by default. Q29 implements explicit
`--apply` paths for future local use, but Q29 validation exercises them only in
temporary fixture repositories and does not mutate live AIDE branches.

## Policies

- `.aide/policies/git-workflow.yaml`
- `.aide/policies/branch-roles.yaml`
- `.aide/policies/promotion-rules.yaml`
- `.aide/policies/sync-policy.yaml`
- `.aide/policies/prune-policy.yaml`
- `.aide/git/project-profiles.yaml`
- `.aide/git/helper-policy.yaml`
- `.aide/git/helper-commands.md`

Project profiles cover AIDE, Eureka, Dominium, website/static-site repositories,
native-client repos, connector-heavy repos, data-snapshot repos, and unknown
repos. Unknown repos stay conservative until inspected.

## Q28 Boundary

Q28 is policy and detection only. Q29 adds helper plans and fixture-tested
local apply paths while keeping live AIDE branch mutation out of implementation
tests. Q30 is responsible for deciding how AIDE should apply the `dev`/`main`
policy posture in this repository.

## AIDE-Specific Posture

Q30 records AIDE's repository-specific policy in
`.aide/git/aide-branch-policy.yaml` and the current non-mutating plan in
`.aide/git/aide-dev-main-plan.*`.

For AIDE itself:

- `main` is canonical accepted truth.
- `dev` is the intended shareable integration branch and is explicitly not
  canonical release truth.
- `task/*`, `codex/*`, `aide/*`, `fix/*`, and `repair/*` land to `dev`.
- `dev -> main` requires review, validation, commit, changelog, pack, and
  secret-scan gates.
- Current evidence shows `dev` is not present locally or as `origin/dev`; Q30
  records a future explicit operator plan and does not create or push it.

See [AIDE Dev/Main Workflow](aide-dev-main-workflow.md) for the AIDE-specific
runbook.

## Portable Pack

Q31 exports the generic Git workflow policies, branch-role definitions,
promotion/sync/prune policies, helper policy, helper docs, and project profiles
through `aide-lite-pack-v0`. It does not export AIDE's generated
`workflow-detection.*`, `latest-helper-plan.*`, `aide-branch-policy.yaml`, or
`aide-dev-main-plan.*` files as target truth. Target repositories must run
`git detect` and `git plan` locally after import.
