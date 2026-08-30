# Workspace hygiene

Universal Setup uses one clean primary control checkout and at most one
secondary task worktree. Builds, package staging, qualification evidence, and
task worktrees live in the shared external development store selected by
`FACMAN_DEV_ROOT`; they do not live in the source checkout or at a drive root.

```text
<development-base>/
  repositories/<repository-name-and-path-key>/
    tasks/<task-or-branch-id>/
      .facman-development-root.v1.json
    worktrees/
      .facman-worktree-store.v1.json
      .records/<branch-and-hash>.json
      <task-or-branch-id>/
```

Linked worktrees resolve the shared control checkout through Git's common
directory. Store and worktree records bind the repository, control checkout,
canonical path, branch, and declared merge target. Missing or mismatched
ownership is a refusal, never implied permission.

Run observation before branch- or build-heavy work:

```powershell
python tools\workspace_hygiene.py paths
python tools\workspace_hygiene.py doctor --measure --max-worktrees 1
```

Create ordinary work only through the helper:

```powershell
python tools\workspace_hygiene.py worktree-add `
  task/<work-item> --start origin/dev --max-worktrees 1
```

Cleanup is plan-first:

```powershell
python tools\workspace_hygiene.py clean
python tools\workspace_hygiene.py worktrees
```

Task roots expire after seven days but are retained while their registered
worktree is active. Linked roots are refused. Worktree retirement requires a
clean, unlocked, canonical, marker-owned worktree; branch/head equality; exact
head reachability from the declared target; an exact-head GitHub PR merged to
that target; and no open PR using the retiring branch as a base. The helper
does not force removal, prune unrelated records, or delete branches.

`task/*` retires against `origin/dev`; `release/*` and `hotfix/*` retire against
`origin/main`; `evidence/*` requires an explicit target. Detached comparison
worktrees require a separately governed disposable receipt. Qualification uses
fresh independent clones rather than linked worktrees.

At idle, the repository has one worktree and only `main` and `dev` local
branches. GitHub deletes merged remote task branches. Git incremental
maintenance owns object-database upkeep; aggressive garbage collection and
unbounded `git clean` are not routine operations.

