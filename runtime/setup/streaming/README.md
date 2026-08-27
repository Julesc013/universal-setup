# Private source-to-target streaming

This internal C++17 slice preserves the public C ABI 1.0. It describes a safe
local directory source, reopens every file through `StableFile`, copies through
one configured buffer, checks incremental SHA-256 and CRC32, stages through
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

`peak_payload_buffer_bytes` measures only the configured streaming payload
buffer. It is not a total-process RSS claim. A failure before target visibility
rolls back when the recorded staging closure is intact; a post-commit audit
failure reports a visible target requiring recovery/audit completion.
