# Sync Policy

Q28 sync policy is advisory and report-only.

The portable workflow default is frequent integration: after each useful validated
increment, commit coherent work with detailed rationale/checks, assess landing to
`dev`, synchronize its remote, and promote qualified increments to `main` promptly
through the project's review gates. Use standing grants for ordinary authorized
effects. Fetch/inspect before each effect and verify the actual remote result.
Project overrides and other contributors' changes remain authoritative. A changed
remote requires reconciliation, never a force push. Code handles bounded waiting;
there is no model polling or implied unattended Git service.

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
