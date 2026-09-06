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
This is a retention/refusal path, not a completed rollback or restartable-entry
claim. Operator-assisted recovery remains necessary until separate work adds
object-bound cleanup authority. Rejected source identity before stream effects
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
