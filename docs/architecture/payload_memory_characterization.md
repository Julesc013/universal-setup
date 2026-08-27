# Stored-ZIP payload memory and streaming characterization

`USK-PROVIDER-PACKAGE-TRUTH-01` recorded the former lifecycle memory model.
`USK-STORED-ZIP-STREAMING-01` retains that baseline as a regression
characterization and replaces the public install and repair path with bounded
stored-entry readers. Neither WorkUnit changes public C ABI 1.0.

## Former complete-payload ownership

`inspect_stored_payload` first reads bounded ZIP metadata, then reads every
selected stored entry into its own `std::vector<unsigned char>`. Each vector is
moved into `StoredArchivePayload::files` and retained until the lifecycle
operation finishes. The caller therefore owns the complete selected logical
payload at once. Peak payload-vector capacity grows with logical payload size;
the implementation is ceiling-bounded, not input-size-independent.

The private `PayloadMemoryObservation` records:

- the unchanged hard materialization ceiling;
- final logical payload bytes;
- final retained vector capacity;
- peak simultaneously owned payload-vector capacity;
- largest entry size and selected file count; and
- the explicit fact that the complete payload is retained.

It deliberately excludes ZIP metadata, path strings, container bookkeeping,
allocator headers, executable image, and unrelated process memory. Claims are
therefore limited to payload-vector ownership, not process RSS.

## Synthetic proof

`usk_archive_inspect_smoke` constructs stored ZIP packages with two 64 KiB
entries and with 4 MiB plus 2 MiB entries. It requires the larger package to
produce a larger observed peak, requires the final retained capacity to cover
all logical bytes, and requires every peak to remain below the unchanged
536,870,912-byte ceiling. The executable emits one canonical JSON observation
line for a durable test receipt.

This retained characterization prevents the legacy helper from being
misrepresented as streaming.

## Current public lifecycle ownership

`inspect_streaming_stored_payload` performs the same bounded ZIP and path
inspection, reopens the exact stable archive, revalidates its source digest,
and incrementally calculates CRC32 and SHA-256 through one configured buffer.
It returns metadata and offset-bounded readers, not entry byte vectors. Install
and repair plans bind the metadata; apply feeds each reader into
`TransactionSession::stage_file_stream`, which independently verifies size and
SHA-256 before target visibility.

`StreamingPayloadMemoryObservation` is deliberately limited to logical payload
bytes, selected file count, configured peak payload-buffer capacity, and
whether a complete payload is retained. It is not a process RSS claim and does
not include ZIP central-directory metadata, descriptors, strings, allocator
headers, transaction buffers outside the measured payload buffer, or executable
image memory.

The native archive proof compares 128 KiB and 6 MiB logical stored payloads and
requires both to retain a 65,536-byte peak payload buffer with
`complete_payload_retained=false`. Lifecycle and public-command tests prove
install and repair staging; fault tests prove source-read, integrity, and write
failures leave no target visible and transition intact recorded staging to
`rolled_back`. Failures after target visibility remain recovery-required.

An opt-in slow proof (`USK_LARGE_STREAMING_MEMORY_PROOF=1`) constructs its ZIP
fixtures directly on disk through a 1 MiB test buffer rather than materializing
their entries. It inspects separate 1 MiB, 64 MiB, and 512 MiB stored entries,
requires every observation to report the same 65,536-byte peak payload buffer
and `complete_payload_retained=false`, and reads the first and last 4 KiB of
each returned offset-bounded reader. The normal two-entry proof above remains
the multiple-entry case. This is a payload-buffer characterization, not a
whole-process memory or RSS claim.

Stored classic ZIP and single-disk ZIP64 entries use this path. Deflate remains
outside the lifecycle boundary because no reviewed decompressor dependency is
present.
