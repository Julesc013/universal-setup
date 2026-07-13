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

No frontend may skip directly from user intent to filesystem mutation. A plan
lists exact roots and effects, and effects are constrained to the selected
owned target, setup state, staging, or audit roots. This model does not claim a
global filesystem transaction.

For move, the new root is copied, closure-verified, committed, and reflected in
references before the old root is retired. The old root remains retained until
separate acceptance permits removal of recorded owned state.
