# Branch Roles

Q28 defines branch roles so AIDE can reason about current Git state before
editing.

- `main`: canonical truth, protected, no force push, no deletion, release tags
  usually point here.
- `dev`: shareable integration truth, not canonical release truth; task
  branches land here and it promotes to `main` only through review gates.
- `task/*`, `codex/*`, `aide/*`, `fix/*`, `repair/*`: bounded work branches,
  local by default, remote only when shared or resumable.
- `review/*` and `quarantine/*`: review/isolation branches, never canonical.
- `release/*`: maintained release lines only when a public/stable release line
  exists.
- `hotfix/*`: urgent repairs that must be merged or cherry-picked back to all
  required targets.
- `gh-pages`: generated deploy branch only; no hand edits.
- unknown names: conservative fallback; inspect before trusting.

Q28 does not create, delete, merge, push, prune, or fetch branches.
