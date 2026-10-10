# Prune Policy

Q28 never deletes branches. It records the safety law for later helpers.

- Prune only after ancestor containment is proven.
- Protected branches are never pruned: `main`, `dev`, `release/*`, `gh-pages`.
- Task/review/quarantine branches are eligible only after containment in the
  configured integration or canonical target.
- Remote pruning is future-gated and requires explicit command flags plus
  evidence.
- Hotfix branches are retained until contained in all required targets.
- Release branches are retained while their release line is maintained.
