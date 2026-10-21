# Promotion Policy

Q28 records promotion policy so Q29 can implement safe helper plans without
inventing branch semantics.

## Task To Dev

`task/*` branches land to `dev` only after:

- the worktree is clean or explicitly understood;
- task evidence exists;
- local validation passes or warnings are classified;
- structured commit checks pass;
- the target integration branch is synchronized before merge.

Q29 exposes this as a dry-run-first helper:

```powershell
py -3 .aide/scripts/aide_lite.py git land --dry-run --target dev
```

Q29 tests `--apply` only in temporary fixture repositories. It does not land a
live AIDE task branch into `dev`.

## Dev To Main

`dev` promotes to `main` only after:

- a dev review packet exists;
- full validation passes or warnings are classified;
- changelog preview is generated;
- generated artifacts are reviewed;
- required queue blockers are resolved or classified;
- explicit promotion evidence exists.

`main` remains canonical. `dev` is integration truth and cannot become a second
release source of truth.

Q29 exposes promotion planning as:

```powershell
py -3 .aide/scripts/aide_lite.py git promote --dry-run --from dev --to main
```

Promotion `--apply` is fixture-tested only in Q29. A live AIDE `dev -> main`
decision belongs to Q30 and later reviewed promotion gates.

## Sync And Prune

Sync policy favors explicit fetch/fast-forward decisions and forbids implicit
merge or rebase of shared branches. Q28 detection itself does not fetch.

Pruning requires ancestor containment proof before any deletion:

```text
git merge-base --is-ancestor <branch> <target>
```

Protected roles such as canonical, integration, release, and deploy are never
eligible for routine prune. Q29 exposes prune planning as:

```powershell
py -3 .aide/scripts/aide_lite.py git prune --dry-run
```

Q29 tests local `git branch -d` only in temporary fixture repositories.

## Future Work

Q30 records the AIDE-specific dev/main policy and confirms that live `dev`
creation, live branch pushes, and live `dev -> main` promotion remain future
explicit operator actions. GitHub branch protection and CI enforcement are later
advisory/application phases.
