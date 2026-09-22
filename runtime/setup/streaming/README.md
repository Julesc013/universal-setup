# Private source-to-target streaming

This internal C++17 slice preserves the public C ABI 1.0 and the existing
whole-payload lifecycle path. It describes a safe local directory source,
reopens every file through StableFile, copies through one fixed 64 KiB buffer,
checks incremental SHA-256 and CRC32, stages through TransactionSession,
commits with the existing no-replace transaction, and appends a chained audit
event.

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
