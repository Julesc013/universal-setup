# Universal Setup workspace hygiene checkpoint

Date: 2026-08-31  
WorkUnit: `UNIVERSAL-SETUP-WORKSPACE-HYGIENE-01`

The repository now carries the same marker-owned, target-aware hygiene core as
FacMan and Universal Launcher, with a one-secondary-worktree provider ceiling.

Before this WorkUnit, stale Git administrative records were pruned without
deleting filesystem content. The one remaining detached legacy worktree at
`32488fc13bd2439f9f6e52e83a97f6da345a7650` was inspected, found clean and
reachable from both `origin/main` and `origin/dev`, and removed with plain
`git worktree remove`. The primary checkout was then moved from a reachable
detached historical revision to clean synchronized `dev`.

The repository merge controls now allow merge commits only, automatically
delete merged branches, and leave auto-merge disabled. Open stacked PRs #27
and #28 and their head/base branches remain protected from cleanup.

Eleven additional remote task refs whose tips were already reachable from
`origin/dev` and had no open head or dependent PR were deleted, along with four
matching merged local refs. The only unmerged local-only legacy branch,
`task/usetup-verify-01` at `07a7b71d3537f1ac21854c17fc11795b61e0109d`,
was preserved before ref deletion in the verified complete-history bundle:

```text
D:\Projects\Factorio\.backups\universal-setup\usk-usetup-verify-01-2026-08-31.bundle
SHA-256 7B25DE565DFDD4A2CC57CB628D178133BF1DEE0698F9EDFB4A9366CCE7E6ECD3
```
