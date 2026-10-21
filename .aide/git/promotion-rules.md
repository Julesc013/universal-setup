# Promotion Rules

Q28 records promotion policy only. It does not execute any promotion.

Evaluate landing and remote sync at useful task boundaries, then promote accepted
`dev` increments promptly. Frequent means small complete verified increments,
not commits after every tool call or automatic promotion of failing work. Existing
project grants carry across steps; new trust boundaries retain their own gates.
Source promotion does not qualify a different development pack or release asset.

- `task -> dev`: requires clean or understood current branch, task evidence,
  local validation, commit checks, and target sync.
- `dev -> main`: requires review packet, full validation or classified
  warnings, changelog preview, no unreviewed generated artifacts, no unresolved
  required blocked queue items, and explicit promotion evidence.
- `main -> release/*`: only when a maintained release line exists.
- `hotfix/* -> main/release/*`: requires urgency rationale, focused
  validation, and backmerge plan.
- `release/* -> main`: backmerge or cherry-pick only by explicit evidence.
- `gh-pages`: generated deploy branch only, not source truth.

Q29 will implement dry-run/helper behavior against these rules.
