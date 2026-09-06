# Managed Portable Lifecycle

This module composes planning, transaction, state, ownership and audit primitives
for local managed portable install, verify, repair, move, uninstall and recovery.
Public commands require target-policy acceptance, explicit apply confirmation and
immediate reviewed-plan revalidation. Source payloads use bounded stored/Deflate
ZIP readers; the public C ABI remains 1.0.

`install_local.apply` accepts an optional explicit `restart_from` object containing
the prior `transaction_id`, full `journal_snapshot_sha256` and `audit_chain_digest`.
The original `plan_request`, reviewed plan ID/digest, new transaction ID and apply
confirmation remain required. Read-only recovery inspection exposes these snapshot
and audit observations; an unavailable audit digest is null and cannot authorize
replay. Ordinary requests retain their existing behavior.

Replay rebuilds fresh archive readers, validates recorded source and entry-set
identities, checks the exact old journal/audit context, and copies each entry from
byte zero into a fresh transaction. The original setup/root native identities are
recorded in a versioned source-digested context. Initial setup-layout creation can
be reconciled only while those identities and the source/target/policy context
remain exact. An old pathname or identical marker/file bytes cannot substitute for
these identity observations. Caller-supplied arbitrary old policy digests are not
accepted.

The new journal records lineage and retained cleanup policy before new staging
and audit effects. Each replay creates its own exclusive audit chain. Its genesis
binds the captured old chain/head, old transaction/snapshot, plan and source.
The old audit chain, staging and journal remain read-only. Failure after the first
journal attempt reports `restart_effects_retained`; a duplicate audit chain is
never overwritten. Inspection remains available after process death before or
during new-chain creation, although a missing genesis cannot authorize replay.

Any historical committing/committed/completed transition refuses replay, including
an absent target after a possible commit. Visible-target finalization remains its
separate exact-context operation. Competing original/replay transactions use the
existing no-replace target commit and retain the loser.

See [ZIP replay qualification](../../../docs/architecture/zip_entry_replay.md).
Automatic retry, stale-owner leases, retained-child cleanup and child ownership
through the verification-to-commit interval remain separate qualification work.
