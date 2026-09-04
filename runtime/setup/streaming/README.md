# Private source-to-target streaming

This internal C++17 slice preserves the public C ABI 1.0 and the existing
whole-payload lifecycle path. It describes a safe local directory source,
reopens every file through `StableFile`, copies through one fixed 64 KiB buffer,
checks incremental SHA-256 and CRC32, stages through `TransactionSession`,
commits with the existing no-replace transaction, and appends a chained audit
event.

`peak_payload_buffer_bytes` measures only the fixed streaming payload
buffer. It is not a total-process RSS claim. A failure before target visibility
rolls back when the recorded staging closure is intact; a post-commit audit
failure reports a visible target requiring recovery/audit completion.
