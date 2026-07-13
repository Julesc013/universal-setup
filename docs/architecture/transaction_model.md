# Transaction Model

Setup mutation is plan-first, ownership-bounded, and audit-first. A reviewed
plan binds its recipe, source, target, state, ownership, policy, and provider
inputs as applicable. Apply revalidates those identities immediately before
the first mutation and refuses drift.

The durable journal state machine is:

```text
created -> validated -> planned -> staging -> staged -> verified
        -> committing -> committed -> completed
```

Terminal and intervention states are:

```text
refused
failed
recovery_required
rolled_back
abandoned_by_operator
```

The journal transition is durable before its corresponding externally visible
effect. A failure must therefore leave either the prior valid state, a fully
committed new state, or an explicit `recovery_required` record.

The WU4 implementation proves this model inside disposable fixture roots. It
uses exclusive journal publication, stable directory identities, exclusive
staged-file creation, stable content re-verification, and a platform-native
no-replace directory rename. If the host kernel or filesystem cannot provide
that last primitive, commit fails closed and records `recovery_required`; it
does not substitute a check-then-rename sequence.

Rollback is ownership-bounded. It removes only files recorded by the live
transaction and only then removes empty directories derived from those paths.
Changed or foreign content is retained for recovery rather than traversed by a
general recursive cleanup.

No frontend may skip directly from user intent to filesystem mutation. A plan
lists exact roots and effects, and effects are constrained to the selected
owned target, setup state, staging, or audit roots. This model does not claim a
global filesystem transaction.

For move, the new root is copied, closure-verified, committed, and reflected in
references before the old root is retired. The old root remains retained until
separate acceptance permits removal of recorded owned state.

The session remains fixture-only and is not a public apply command. Install and
repair commits are same-volume; move selects destination-volume staging before
its no-replace destination commit.

WU6 now supplies a constrained recovery executor for the post-rename
finalization window. It may reopen only a journal whose target is visible and
whose staging root is absent, and only in `committing`, `committed`, or
`recovery_required`. The existing transition chain and digest, reviewed plan
identity, operation, and roots are revalidated before missing ownership, state,
and audit records can be completed. Pre-commit replay is still refused.
