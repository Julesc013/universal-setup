# Stored-ZIP payload memory characterization

`USK-PROVIDER-PACKAGE-TRUTH-01` records the current private lifecycle memory
model before any streaming implementation is attempted. It does not change the
public C ABI or the 512 MiB materialization ceiling.

## Current ownership

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

This characterization prevents the existing whole-payload model from being
misrepresented as streaming. A later private reader-to-sink slice must prove a
peak bound independent of logical input size before it can replace this path.
It must preserve stable-file identity, CRC and SHA-256 verification, normalized
path and collision refusals, transaction staging, and recovery semantics.
