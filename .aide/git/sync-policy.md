# Sync Policy

Q28 sync policy is advisory and report-only.

- Future helpers should fetch before branch decisions, but Q28 commands do not
  fetch.
- Canonical and integration branches should fast-forward where possible.
- Sync must not imply merge or rebase.
- Shared branches should not be rebased after push.
- Dirty trees block sync mutation and produce warnings in Q28.
- `dev` may be the latest shareable integration branch, but it is not
  canonical truth.
- Task branches are local by default and remote only by explicit shared or
  resumable need.
