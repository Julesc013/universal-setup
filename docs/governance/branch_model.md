# Repository branch model

Universal Setup is continuously integrated and independently releasable. The
machine-readable authority is
[`release/index/branch_policy.v2.toml`](../../release/index/branch_policy.v2.toml).
The superseded v1 policy remains in Git and in the tree as an explicit
historical record.

| Ref | Role |
| --- | --- |
| `main` | Stable, canonical, releasable provider source |
| `dev` | Green integration train, returned to containing `main` by closeout |
| `task/*` | One bounded WorkUnit based on an exact recorded `dev` SHA |
| `hotfix/*` | Emergency correction based on `main`; reconciliation is separately reviewed |
| tags | Releases created only from accepted `main` |

Normal work follows `task/* -> dev -> consumer canary -> main`. A completed
provider WorkUnit must not accumulate on `dev` behind more than one other
completed-but-unpromoted WorkUnit. Product-only changes do not create provider
commits or broaden Setup authority.

The only `main -> dev` route is the narrow zero-content normal-PR closeout
after a normal `dev -> main` promotion. It is admitted only when the live
`main` tip is the two-parent promotion merge of the exact live `dev` tip, its
tree is identical to that `dev` tip, and GitHub associates that merge with the
unique exact merged `dev -> main` PR. The closeout is not a fast-forward,
direct write, hotfix synchronization, or a route for arbitrary `main` history.

Stable consumers pin exact commits reachable from provider `main`. Canary jobs
may test an exact `dev` SHA supplied as an input, but they do not change the
tracked consumer lock. After promotion, adoption is a separate exact-pin pull
request. No provider merge directly changes a consumer revision.

`main` and `dev` are protected from force pushes, deletion, bypasses, and
direct writes. A normal GitHub PR merge is not a direct protected push. Under
the active campaign authority, the merge executor may be the PR author after
an exact-head, exact-base, green-check gate and a separately identified
technical review context pass. An agent review is recorded as agent review; it
is never presented as a human or GitHub approval.

The same standing authority covers qualified `dev` promotion and release
execution. Signing uses only an already configured purpose-authorized signer,
and publication requires exact qualified candidate bytes plus remote
tag/asset/digest readback. It grants no permission to create or export
credentials, move immutable tags, bypass a failing gate, mutate unrelated
data, or turn repository authority into customer-machine runtime consent.

See [campaign authority](campaign_authority.md) for binding and review rules.
