# AIDE Git Helper Commands

Q29 adds local helper commands for branch-sensitive work. They are designed to
make the next safe action explicit without mutating live AIDE branches during
this phase.

## Default Safety

- All helper commands default to dry-run/report-only behavior.
- `--apply` is required before local Git mutation.
- Q29 validation never runs `--apply` in the live AIDE repository.
- `--push` is explicit and is not executed in Q29.
- Force push is forbidden.
- Protected roles are `canonical`, `integration`, `release`, and `deploy`.
- Prune eligibility requires `git merge-base --is-ancestor <branch> <target>`.

## Commands

```text
py -3 .aide/scripts/aide_lite.py git plan
py -3 .aide/scripts/aide_lite.py git sync --dry-run
py -3 .aide/scripts/aide_lite.py git land --dry-run --target dev
py -3 .aide/scripts/aide_lite.py git promote --dry-run --from dev --to main
py -3 .aide/scripts/aide_lite.py git prune --dry-run
```

## `git plan`

Writes:

- `.aide/git/latest-helper-plan.json`
- `.aide/git/latest-helper-plan.md`

The plan includes current branch, role, dirty state, local/remote branch
summary, policy readiness, upstream status when available, recommended action,
warnings, blockers, and exact planned commands for helper operations.

## `git sync`

Dry-run reports whether the current branch has an upstream and whether a
fast-forward-only pull would be the expected local sync action. It does not
fetch, pull, rebase, merge, or push unless a future operator explicitly uses
`--apply`; Q29 does not exercise that live path.

## `git land`

Dry-run validates task/subtask source role, integration target role, clean tree,
target existence, validation evidence or explicit validation acknowledgement,
and protected-branch rules. The planned local commands are:

```text
git checkout <target>
git merge --no-ff <source> -m "land: <source> into <target>"
```

`--apply` is tested only in temporary fixture repositories.

## `git promote`

Dry-run validates integration source role, canonical target role, clean tree,
review/validation evidence, changelog preview availability or recommendation,
and protected-role semantics. The planned local commands are:

```text
git checkout <target>
git merge --no-ff <source> -m "promote: <source> into <target>"
```

`--apply` is tested only in temporary fixture repositories.

## `git prune`

Dry-run lists local branches and reasons for eligibility or refusal. Protected
roles are never eligible. Task-like branches become eligible only after
ancestor containment in the integration or canonical target is proven.

`--apply` deletes local eligible branches with `git branch -d <branch>` only in
explicitly invoked contexts. Q29 tests this only in temporary fixture
repositories.

## Q29 Boundary

Q29 does not create AIDE `dev`, merge into `main`, push remotes, delete live
branches, call GitHub, install CI, publish releases, or call providers/models.
