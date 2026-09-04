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

`inspect_streaming_payload` performs the same bounded ZIP and path inspection,
reopens the exact stable archive, revalidates its source digest, and
incrementally calculates CRC32 and SHA-256. Stored entries use one exact
65,536-byte
output buffer. Deflate entries use one equally bounded private compressed-input
buffer plus the output buffer and require sequential reviewed offsets. It
returns metadata and bounded readers, not entry byte vectors. Install and
repair plans bind the metadata; apply feeds each reader into
`TransactionSession::stage_file_stream`, which independently verifies size and
SHA-256 before target visibility.

`StreamingPayloadMemoryObservation` is deliberately limited to logical payload
bytes, selected file count, configured output/input/combined stream-buffer
capacity, and whether a complete payload is retained. It is not a process RSS
claim and does not include ZIP central-directory metadata, descriptors,
strings, allocator headers, zlib's bounded internal window/state, transaction
metadata, or executable image memory.

The native archive proof compares 128 KiB and 6 MiB logical stored payloads and
requires both to retain a 65,536-byte peak payload buffer with
`complete_payload_retained=false`. Lifecycle and public-command tests prove
install and repair staging; fault tests prove source-read, integrity, and write
failures leave no target visible and transition intact recorded staging to
`rolled_back`. A mid-entry cancellation regression proves the same pre-visibility
rollback, and nonexact stream-buffer sizes are rejected. Failures after target
visibility remain recovery-required.

An opt-in slow proof (`USK_LARGE_STREAMING_MEMORY_PROOF=1`) constructs its ZIP
fixtures directly on disk through a 1 MiB test buffer rather than materializing
their entries. It inspects separate 1 MiB, 64 MiB, and 512 MiB stored and raw
Deflate-block entries. Stored observations retain the same 65,536-byte output
buffer; Deflate observations retain 65,536-byte input and output buffers, or
131,072 configured stream-buffer bytes total. Every case requires
`complete_payload_retained=false` and streams reviewed boundary content. The
normal two-entry proof above remains the multiple-entry case. This is a
stream-buffer characterization, not a whole-process memory or RSS claim.

Stored and Deflate classic ZIP and single-disk ZIP64 entries use this path.
Deflate is raw RFC 1951 (`inflateInit2(..., -MAX_WBITS)`) from an exact,
unmodified zlib 1.3.2 private subset compiled with `Z_PREFIX`. Every stream must
terminate at the exact
declared compressed and uncompressed boundaries; trailing bytes, truncation,
malformed trees/distances, size drift, CRC drift, and source drift fail before
target visibility.
