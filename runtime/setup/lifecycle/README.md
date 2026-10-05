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

A fresh install for a retired identity starts a deterministic audit generation
derived from the terminal uninstall transaction only after the current state and
prior audit head prove a clean retirement. Exclusive generation creation prevents
concurrent contenders from both proceeding. Its precommit chain contains one
event, so restart inspection remains bounded even when an older generation has a
long repair, move or verification history. Active, stale, incomplete, or
incompatible identities are refused before transaction effects.

Any historical committing/committed/completed transition refuses replay, including
an absent target after a possible commit. Visible-target finalization remains its
separate exact-context operation. Competing original/replay transactions use the
existing no-replace target commit and retain the loser.

## Reviewed post-commit finalization

Repair, move and uninstall now bind an `usk.maintenance_source_context.v1`
document in the first durable transaction journal, before staging creation.
It records the original immutable installed-state transaction and digest,
ownership manifest, reviewed plan and policy, applied time, operation target,
and native observations of the installed and setup roots. No-follow installed-root
status checks refuse linked, wrong-type and indeterminate observations; a genuinely
missing root can retain a null identity with its observed parent. Reopening the original
installed snapshot does not require the source archive. These observations
remain recovery inputs rather than mutation or pathname cleanup authority;
the stream journal retains incomplete effects for inspection. Operation-specific
effect replay and public maintenance finalization are still incomplete.

Maintenance also appends create-only `usk.maintenance_effect_record.v1` records
under the original transaction's `.maintenance` directory. The first record binds
that same source context and the journal directory observation. Each publication,
backup, replacement, removal and metadata write has an intent before the effect
and a completion afterward; the digest chain is sealed after operation cleanup.
An interruption between the two records leaves an unresolved intent, including
when the effect happened. Repair retains its original backup when replacement
publication is uncertain rather than attempting an unrecorded compensating rename.
Source-free inspection validates the closed record format, chain and context,
with a 32 KiB record bound, a 64 MiB journal bound and at most 200,002 records.
These are observations of the existing internal maintenance routines. They do
not authenticate a writable journal, establish held native payload authority,
or enable public maintenance replay. The registered maintenance route and
operation-specific recovery remain unfinished.

The internal source-free reconciler reopens the original immutable installed
snapshot and compares a pending effect with current native identity, hash and
size observations, or the exact ownership, installed-state or audit input.
It distinguishes compatible before/after states from indeterminate observations;
a missing leaf reached through an unsafe or indeterminate parent is not absence.
Audit inspection is bounded to 256 events and larger histories stay indeterminate.
Record resumption requires the exact inspected history digest, refuses sealed
histories, and appends to the original context and sequence. It changes neither
the transaction state nor payload objects. These comparisons do not prove the
actor or grant effect completion: the registered resumer still needs current
native custody, revision, operation and worker fences before completing or
executing an effect. Whole maintenance recovery and public routing remain WIP.

New installed-state intents retain a bounded revision postimage, and audit
intents retain the bounded canonical input. Read-only reconstructors join these
with the original immutable installed snapshot and ownership rather than
choosing new metadata during replay. Legacy hash-only intents remain readable;
they cannot supply a missing installed-state or audit write.

The internal pending-effect executor requires an operation-owned backend that
retains native custody and checks its revision, generation and worker fences.
It has no pathname fallback. It pins the transaction and effect history around
the effect and completion record, requires a durable commit-start transition,
refuses rolled-back or terminal transactions,
and retains an unresolved intent after an uncertain effect. Resolving one
intent neither resumes nor completes the whole transaction. Ordinary fixture
backends exercise this orchestration; a registered native maintenance backend
and its hosted runtime qualification remain unfinished.

`recovery.inspect`, `recovery.plan`, and `recovery.apply` can complete the
post-commit install-local window only after a caller has reviewed the exact
recovery plan. `recovery.apply` accepts `selected_action: "finalize"` only for
an `install_local` transaction whose target is visible, whose original install
request and reviewed source context still rebuild to the durable plan identity,
and whose source is validated immediately before finalization. Repair, move,
and uninstall recovery retain their existing refusal behavior; staged rollback
is unchanged.

Finalization completes the missing ownership, installed-state, audit, and
journal metadata for the already published target. It does not call ordinary
install apply, restage payloads, or replay archive readers into the target.
The original target-capacity decision is represented by a durable
`capacity_satisfied` predicate so this metadata-only work does not impose a
new full-payload capacity requirement after publication. Setup-state writes
remain subject to their normal live authority checks.

Public finalization requires the current versioned source context and the v2
stream-journal publication observation. Older v1 or legacy journals remain
readable and retain their established native restart/inspection behavior, but
do not gain public visible-target finalization authority.

See [ZIP replay qualification](../../../docs/architecture/zip_entry_replay.md).
Automatic retry, stale-owner leases, retained-child cleanup and child ownership
through the verification-to-commit interval remain separate qualification work.

## Staged child commit requirement

Commit preparation rejects already-changed verified file/directory closure and durably retains staging on refusal. Optional `staged_child_bound_v1` has no qualified success publisher; explicit lifecycle apply refuses before effects and directly staged native attempts retain/refuse. See [the authority boundary](../../../docs/architecture/staged_child_commit_authority.md) for the exact observation limits, journal compatibility and outstanding atomic publication work.

`update.plan` is a read-only whole-root replacement preview. It binds the exact installed-state and ownership preimage, complete old-root native identity and snapshot, candidate archive and closure, transition, and retained-root policy. `update.apply` requires `staged_child_bound_v1` and is deliberately refused before effects until a host publisher is qualified. The internal replacement journal uses durable append-only phase records before each root rename and retains both old and new roots for recovery inspection.

The native fixture classifier distinguishes no replacement effect, old root retained with no live root, new root active with old root retained, completion, and indeterminate/corrupt layouts. Until operation-specific resume/rollback and a per-install lease are implemented, every incomplete layout exposes only `retain_for_operator`.
