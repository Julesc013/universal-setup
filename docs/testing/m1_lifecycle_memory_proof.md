# M1 lifecycle bounded-preimage evidence

USK-WU-005 replaces the move and update old-tree representation with
`PreimageFile`: relative path, SHA-256, size, and a native resource
observation. It intentionally has neither a byte vector nor a payload reader.
`PayloadFile` remains the source/archive representation and is not used for an
old-tree scan.

## Fixed limits and observations

The scan uses `StableFile::sha256_hex`, which reads a single 64 KiB buffer from
one stable native handle. It refuses a root with more than 100,000 files,
200,000 total entries, a file over 4 GiB, more than 16 GiB logical file bytes,
or a canonical snapshot index above 64 MiB. The index charge is explicit and
overflow checked before allocation. Verification also refuses instead of
retaining more than 10,000 unknown paths.

`MovePlan::resource_observation` reports the deterministic in-process bounds:
`peak_payload_buffer=65536`, `peak_open_source_files=1`,
`retained_payload=0`, and `complete_payload_retained=false`. During move
apply, every file is re-opened as a `StableFile`, checked against its reviewed
volume/file identity, size, mtime, and link count, streamed directly into the
transaction staging file, hash/size verified by staging, then revalidated.

The `usk.replacement_snapshot.v1` digest is hashed directly in canonical byte
order; it does not construct a complete JSON `Value::Array`. The native smoke
test compares the update-plan old digest with the existing
`transaction::replacement_snapshot_digest` helper on the same topology.

## Lifecycle coverage and limits of the claim

The native lifecycle smoke covers streamed install payloads, cancellation,
integrity/read failure retention, install recovery, verify, repair, move,
move stream-intent failure retention, update preimage planning and snapshot
compatibility, and uninstall. The adversarial and public lifecycle smoke
remain part of the targeted run. A move retains the old root after successful
publication. Before a streaming intent, move attempts ordinary safe rollback;
after intent, the transaction journal retains staging for an operator. After
visibility, existing recovery-required handling remains in force.

Portable evidence consists of the explicit `StableFile` checks and deterministic
resource observation above. Native Windows x64 evidence is the targeted native
CMake/CTest execution recorded with the work unit. No OS peak-memory
child-process probe is claimed in this slice: it cannot be added as a separate
target without changing the root CMake file, which is outside WU005 scope.

Whole-root update recovery/publication and the transaction snapshot helper
remain WU006-owned. This document records implementation evidence only; it
does not claim acceptance execution or qualification.
