# Prune Policy

Q28 never deletes branches. It records the safety law for later helpers.

After task integration/closure, review published task refs for retirement. Keep
active, important, persistent, uncontained or uncertain branches and refs with an
open collaboration obligation. Require fresh exact remote tips, preserved work,
closed/acknowledged ownership, no active worktree or open PR, and a retained
branch-to-commit recovery record before an authorized deletion. Age and ancestry
alone are insufficient. A timeout requires observing actual refs before retry.
The existing helper's ancestry eligibility is only one input to that decision;
it is not remote-deletion authority. No blanket or force deletion is permitted.

- Prune only after ancestor containment is proven.
- Protected branches are never pruned: `main`, `dev`, `release/*`, `gh-pages`.
- Task/review/quarantine branches are eligible only after containment in the
  configured integration or canonical target.
- Remote pruning is future-gated and requires explicit command flags plus
  evidence.
- Hotfix branches are retained until contained in all required targets.
- Release branches are retained while their release line is maintained.
