# Specification-to-release campaign authority

The repository-owned record
[`release/index/campaign_authority.v1.toml`](../../release/index/campaign_authority.v1.toml)
captures the owner's standing instruction for `USK-SPEC-TO-RELEASE-01`. It is
the authority source for ordinary implementation, tests, documentation,
branches, PRs, qualified merges/promotions, packaging, immutable tagging,
configured signing, and qualified publication. A new owner approval is not
required for every WorkUnit.

WorkUnit definitions remain inert templates. Before work begins,
`tools/campaign_task_binding.py` derives a binding to the active campaign,
exact accepted source commit/tree, exact task definition, current
specification aggregate, non-widened task scope, predecessor receipts, and the
actual environment class. Source movement makes that binding stale and causes
rebinding; it does not revoke the campaign.

Endpoint or user-state effects additionally require an exact target/environment
receipt. This is a factual safety boundary, not a renewed owner-permission
ceremony. If that target is unavailable, specification, test design, local
builds, and other dependency-ready work may continue.

The merge oracle in `tools/branch_policy_check.py` requires exact head and
base identities, successful required checks bound to both identities, no
unresolved threads, a mergeable non-draft PR, and exact-head technical review
from a different context. The executor may also be the PR author. Direct
protected pushes, force updates, ruleset bypasses, fake approvals, and red or
stale merges remain forbidden.

The campaign record does not establish product behavior, customer-machine
consent, machine qualification, human experience, signing-key availability,
or release completion. Those claims still require their substantive evidence.
