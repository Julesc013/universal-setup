# Branch Roles

Q28 defines branch roles so AIDE can reason about current Git state before
editing.

- `main`: canonical truth, optional hosting protection, no force push, no deletion, release tags
  usually point here.
- `dev`: shareable integration truth, not canonical release truth; task
  branches land here and it promotes to `main` only through review gates. Hosting
  protection is normally disabled; existing settings and project overrides remain.
- `task/*`, `codex/*`, `aide/*`, `fix/*`, `repair/*`: bounded work branches,
  short-lived and local by default; publish for collaboration, important checkpoints
  or blocked continuity. Record the sharing reason and next action.
- `review/*` and `quarantine/*`: review/isolation branches, never canonical.
- `release/*`: maintained release lines only when a public/stable release line
  exists.
- `hotfix/*`: urgent repairs that must be merged or cherry-picked back to all
  required targets.
- `gh-pages`: generated deploy branch only; no hand edits.
- unknown names: conservative fallback; inspect before trusting.

Q28 does not create, delete, merge, push, prune, or fetch branches.
