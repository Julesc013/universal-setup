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
python tools\workspace_hygiene.py doctor --base origin/dev --measure --max-worktrees 1
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

Retirement also inspects all untracked and ignored entries, nested repositories,
contained links, and observed process command lines. Missing observations refuse
retirement, including a missing command line for any user process. Only Windows
kernel Idle/System entries are excluded. A normal clean Git status alone is insufficient. Preserve unknown
ignored material before retiring a worktree; cached bytecode is disposable only
after its source or unmatched bytes have been preserved. Observe state again
immediately before removal. Command-line observation cannot establish the absence
of every editor or open handle; Git locks and normal non-forced removal remain
additional protections.

## Resource admission

Output creation requires an explicit absolute, non-linked `FACMAN_DEV_ROOT`.
`FACMAN_TASK_ROOT` must identify the canonical task root. Read-only layout discovery
retains its portable fallback; creating output does not use that fallback.

`doctor --measure` counts the entire repository development area: worktrees,
tasks, labs, sibling builds, packages, caches, and other files. It also counts
the canonical source checkout and Git database, and the same repository's old
Windows fallback store. Supply remaining attributable legacy locations with
`--extra-root <exact-path>` or `--extra-roots-file <existing-inventory.json>`.
Observation does not authorize deletion.
Overlapping roots and allocated hard-link storage are counted once. Logical bytes
and filesystem allocation are reported separately; neither is a claim that all
that space can be reclaimed. Links are not followed and incomplete observation
cannot pass the quota check. Unknown locations require discovery, not a claim of
machine-wide coverage.

Use the same helper to launch campaign builds and tests:

```powershell
python tools\workspace_hygiene.py run --disk-bytes 1073741824 `
  --ram-bytes 2147483648 -- python -m unittest discover -s tests
```

The estimates must describe the actual job. A kernel lock admits one heavy job
across cooperating runners, charging its complete estimate before launch. The
existing 20 GiB storage quota, eight task roots, one secondary worktree, and
seven-day task retention remain. Admission also retains 10 GiB free on each
affected volume and 2 GiB available RAM and commit headroom, in addition to the
estimate. Jobs may tighten these limits but cannot weaken them. Worktree creation
uses the same lock and checks a conservative 256 MiB disk / 128 MiB RAM estimate.

Children inherit the approved root and task-local TMP/TEMP/TMPDIR and caches.
Build parallelism defaults to two compiler processes and build-server reuse is
disabled in the child environment. The runner checks cheap
free-space and memory counters every two seconds and cancels its own child when
reserves or the disk estimate are exhausted. Windows job objects close owned
build-server descendants and cap their combined commit to the RAM estimate.
The child is assigned while suspended before any code can launch descendants.
This is cooperative admission and monitoring, not an
OS disk quota or a sandbox preventing arbitrary commands from writing elsewhere.
Unrelated activity can trigger a conservative cancellation.
Counters are refreshed after worktree inspection and immediately before launch.
After owned descendants exit, one terminal storage walk checks actual logical
growth and quotas, including rapid or sparse-file output that free-space polling
cannot measure. A job that exceeds its estimate is not recorded as passed.

Logs retain at most 128 KiB plus a terminal receipt. Successful job-local temporary
and cache output is removed. Failure/cancellation preserves it for diagnosis;
the receipt states that reconciliation is required. A runner crash releases the
kernel lock but leaves a running/starting receipt: inspect that process and output
before cleanup or restart. Reuse compatible task-local incremental builds, retain
necessary evidence, and explicitly retire obsolete builds after qualification.

VM backing disks and checkpoint chains count against the same storage quota.
Keep automatic checkpoints disabled on campaign VMs. Before a requested snapshot,
reserve its estimated disk and RAM demand through the runner; retain only the
named snapshots needed for the current experiment or unresolved evidence.
Delete obsolete checkpoints through Hyper-V, after checking VM/disk identities,
all references, dependencies, and merge headroom. Never delete AVHD/AVHDX files
directly. Keep a lab off when the campaign quota cannot admit it.

`task/*` retires against `origin/dev`; `release/*` and `hotfix/*` retire against
`origin/main`; `evidence/*` requires an explicit target. Detached comparison
worktrees require a separately governed disposable receipt. Qualification uses
fresh independent clones rather than linked worktrees.

At idle, the repository has one worktree. Preserve owner-required historical
evidence branches and unsynced commits; do not delete them to satisfy a dashboard.
GitHub deletes merged remote task branches. Git incremental
maintenance owns object-database upkeep; aggressive garbage collection and
unbounded `git clean` are not routine operations.
