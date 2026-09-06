# Explicit ZIP entry replay

`install_local.apply` can explicitly replay an interrupted stored/Deflate ZIP
install into a new transaction. The C ABI remains 1.0. The optional strict
`restart_from` object requires the old transaction ID, exact full journal bytes
SHA256 and exact audit-chain head digest; it grants no automatic retry behavior.
The original plan request and reviewed plan identity remain required.

Admission reconstructs fresh ZIP readers and validates archive filesystem
identity, complete archive digest, entry-set digest and file identities. The
original stream context is versioned, canonical, bounded to 16 KiB and covered by
its source digest and the full expected journal snapshot. It records original
plan/policy context and native identities for setup, state, journal, audit,
staging-parent and target-parent directories. Initial setup creation is reconciled
only against those original observed identities, current ownership marker and
accepted policy; every other source/target/policy comparison remains exact.
Same-byte archive or same-path setup-root replacements refuse before replay effects.
Content hashes do not authenticate an untrusted journal or grant object ownership.

The fresh transaction durably records original transaction/snapshot lineage,
source binding, retain-only policy and null rollback authority in its first
journal. Each replay creates a separate no-replace audit chain; its first event
binds the old chain/head, journal snapshot, plan/source and new transaction.
The old chain and staging are never appended to, truncated, reused or removed.
Each source reader starts at byte zero. A failed exclusive chain creation leaves
an inspectable retained transaction, and a duplicate journal cannot add audit
effects. Missing/partial audit genesis remains an explicit refusal, not a repair
or automatic cleanup invitation.

The native ZIP regression covers stored and Deflate multi-buffer payloads,
process exits at entry intent/open/write/complete, staged/verified and commit
boundaries, plus new journal/audit creation boundaries. It checks same-byte source
and setup replacement, changed snapshot/audit digests, recomputed forged policy
context, foreign journal/audit collisions, original byte preservation, replay
lineage, native visible-target finalization and competing original/replay commits.
Final qualification requires exact-source independent review, clean-source
static/shared/combined SDK gates and fresh hosted platform checks; local fixtures
do not confer other platform qualification. Windows fixture paths stay within the
separately admitted 259/247 UTF-16 file/directory capacities.

Read-only recovery inspection observes at most 32 audit events, each using the
existing 1 MiB record read limit. A valid longer chain leaves the audit-head digest
null while preserving journal inspection and all stored bytes. This observation
cap is separate from replay admission: a null observation cannot authorize replay,
and replay still requires the exact single precommit event for each ancestor.

Replay also validates up to 64 retained ancestor journal snapshots and their exact
precommit audit heads, reading at most one event per ancestor. Changed ancestor
state, cycles, excess depth or an uncertain ancestor commit refuse before effects.
This prevents a replay-of-replay from forgetting a prior owner that progressed
after the intermediate replay was created.

A prior journal that ever entered committing remains ineligible even if its target
is now absent. No-replace commit admits at most one target and retains competing
staging; it does not prove each child stayed owned after mark_verified. The concrete
follow-on must bind or revalidate staged-child identity through actual commit,
including identical-byte substitution after verification. Generation/stale-owner
leases, automatic recovery, retained-child cleanup and FacMan adoption remain
separate prerequisites. This replay slice closes none of those obligations.
