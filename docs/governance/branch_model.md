# Repository branch model

Universal Setup is continuously integrated and independently releasable. The
machine-readable authority is
[`release/index/branch_policy.v1.toml`](../../release/index/branch_policy.v1.toml).

| Ref | Role |
| --- | --- |
| `main` | Stable, canonical, releasable provider source |
| `dev` | Green integration train that always contains `main` |
| `task/*` | One bounded WorkUnit based on an exact recorded `dev` SHA |
| `hotfix/*` | Emergency correction based on `main`, synchronized back to `dev` |
| tags | Releases created only from accepted `main` |

Normal work follows `task/* -> dev -> consumer canary -> main`. A completed
provider WorkUnit must not accumulate on `dev` behind more than one other
completed-but-unpromoted WorkUnit. Product-only changes do not create provider
commits or broaden Setup authority.

Stable consumers pin exact commits reachable from provider `main`. Canary jobs
may test an exact `dev` SHA supplied as an input, but they do not change the
tracked consumer lock. After promotion, adoption is a separate exact-pin pull
request. No provider merge directly changes a consumer revision.

`main` and `dev` are protected from force pushes, deletion, and direct writes.
Promotion and hotfix synchronization preserve ancestry; unrelated divergence
fails for human review. Automation may write only bot-owned task branches and
pull requests. It may not approve or merge its own work, sign, publish, use
product credentials, or bypass protection.
