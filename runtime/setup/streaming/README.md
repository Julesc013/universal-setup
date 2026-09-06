# Private source-to-target streaming

This internal C++17 slice preserves the public C ABI 1.0. It describes a safe
local directory source, reopens every file through `StableFile`, copies through
one fixed 64 KiB buffer, checks incremental SHA-256 and CRC32, stages through
`TransactionSession`, commits with the existing no-replace transaction, and
appends a chained audit event.

The public lifecycle now uses the same reader-to-transaction-sink primitive for
reviewed stored and Deflate ZIP entries. Archive planning retains only
normalized path, compression method, exact sizes, CRC32, SHA-256, stable-source
identity, and a bounded reader; install and repair apply stream directly into
transaction staging. Deflate readers are sequential and lazily allocate one
64 KiB compressed-input buffer; the transaction supplies one 64 KiB output
buffer. The old complete-payload materializer remains private only for
regression characterization and is no longer used by public lifecycle commands.
The internal apply path also checks cancellation before and after each fixed
buffer transfer and once more immediately before target visibility; cancellation
during staging retains recovery evidence without exposing a target. These internal additions do
not add or change a public C ABI symbol.

The peak_payload_buffer_bytes observation measures only the fixed streaming
payload buffer. It is not a total-process RSS claim. The apply entry limit is
checked before admitting a transaction, even if inspection used a larger limit.

Before a streamed file or directory effect, the journal durably records
stream_cleanup_policy=retain_only. A streamed pre-visibility failure retains
staging and reports recovery_required_no_target_visible. Automatic cleanup and
live or restarted rollback perform no pathname deletion: path, size and hash
cannot establish ownership of a substituted object, including identical bytes.
Retained-child cleanup remains operator-assisted until separate work adds
object-bound authority. Explicit private directory-source replay is described
below; it never cleans or reuses the retained tree. Rejected source identity before stream effects
continues to use the existing non-streaming rollback behavior.

Retained journals deliberately serialize staging_identity=null while the live
session retains its identity for verification and successful commit. Older
rollback readers also refuse that absent authority if they ignore the optional
policy field. The field accepts only retain_only and requires the null identity;
absent policy preserves existing non-streaming journal behavior. Successful
commit and visible-target finalization remain supported; post-commit audit
failure requires recovery/audit completion.

Native regressions cover exclusive-create collision, refusal before creation,
file and directory replacement, identical-byte foreign replacement with the
original outside staging, destruction/reopen, ignored or malformed policy
fields, and budget refusal without transaction effects. No race-prone
identity-check-then-delete path is retained for streamed error cleanup.

## Explicit entry replay

`StreamRequest` may name an original transaction and the exact SHA-256 of its
journal bytes. The request transaction ID must be fresh, while source entry-set
digest, original source identities, plan and four roots must still match. All
original source identities are checked before the fresh replay transaction.
Every entry starts at byte zero and is independently re-read and verified into
fresh staging. Previous entries and incomplete files remain untouched in the
old tree; identical bytes never grant reuse or cleanup authority.

The first fresh journal durably records the original transaction and snapshot,
source binding, retain-only policy and null rollback authority before staging
creation. A prior journal that ever entered `committing` is ineligible, even
when its target is now absent. Up to 64 retained ancestor journal snapshots are
also checked exactly; changed or committing ancestor state cannot be forgotten
by a replay-of-replay. Its existing finalization/inspection path must resolve
that ambiguity. Multiple explicit replay attempts have distinct staging
roots; the existing no-replace commit admits one target and retains a loser.
This is not generation-lease ownership or stale-owner reconciliation.

Each stream records intent before directory/file effects, writing after native
identity is observed on the original creation handle, and complete only after
flush and integrity checks. `writing` does not claim a durable byte offset.
Verification checks the recorded output identity as well as size and hash.
Snapshots have a 4 MiB serialized journal bound and bounded parsing; metadata
scales with entry count and is separate from the fixed 64 KiB payload buffer.
The stream subdocument has its own corruption-detection digest. Restart binds
the full journal bytes, because the older journal digest covers transitions.
Neither digest is an authentication credential or deletion capability.

The public C ABI and JSON recovery actions are unchanged. This private adapter
accepts directory sources. The lifecycle adapter also provides explicit stored
and Deflate ZIP replay through an optional `install_local.apply.restart_from`
request; see [its contract](../lifecycle/README.md). Archive source/entry identity
and versioned original install/root context are persisted before entry effects.
Legacy callers without a separate source binding retain their plan-digest entry
observations and cannot acquire ZIP replay authority. Automatic recovery,
mid-Deflate seek, leases and retained-child cleanup remain separate work.
`usk_entry_restart_smoke` exercises nine abrupt child-process exits, changed
source/plan/snapshot refusals, malformed metadata, same-byte replacement with
the original outside staging, lineage publication and concurrent commit losers.

The output identity check occurs during `mark_verified`. The unchanged commit
primitive checks the staging root and parent before its no-replace directory
rename; it does not hold every child object through the verification-to-commit
interval. Concurrent child substitution in that interval is not qualified by
this replay slice. Generation/commit authority work must address that boundary
before claiming atomic child ownership. No such authority is inferred from a
matching hash, a matching pathname, or the new observation record.
