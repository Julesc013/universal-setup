# M1 lifecycle bounded-preimage evidence

USK-WU-005 replaces the move and update old-tree representation with
`PreimageFile`: relative path, SHA-256, size, and a native resource
observation. It intentionally has neither a byte vector nor a payload reader.
`PayloadFile` remains the source/archive representation and is not used for an
old-tree scan.

## Fixed limits and observations

The scan uses `StableFile::sha256_hex`, which reads a single 64 KiB buffer from
one stable native handle. The current lifecycle profile refuses more than 4,096
files, 8,192 directories, 1 MiB each of file and directory path text, a path above 1,024
bytes, a file above 4 GiB, 16 GiB of logical file bytes, or a canonical
snapshot index above 64 MiB. Materialized (non-reader) payloads have a separate
64 MiB aggregate retained-byte ceiling. These new-plan and preimage-scan refusal
bounds are not proof that the allocator uses exactly the charged number of bytes;
entry-count scaling is measured below. Verification of an already persisted
ownership manifest retains the earlier behavior, including larger closures and
unknown-path reports, so existing installs remain available for verification and
uninstall planning. Its repository record passes through a 4 MiB JSON parser
input limit, but its full report allocation is outside the measured new-plan
memory envelope.

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
compatibility, uninstall, and verification plus uninstall planning of a
prior-format 4,097-file ownership record. The adversarial and public lifecycle smoke
remain part of the targeted run. A move retains the old root after successful
publication. Before a streaming intent, move attempts ordinary safe rollback;
after intent, the transaction journal retains staging for an operator. After
visibility, existing recovery-required handling remains in force.

`tests/lifecycle_memory_probe.py` launches an isolated mode of the existing
`usk_lifecycle_smoke` target, so no root CMake change is needed. It records the
OS child-process peak working set on Windows or child maximum RSS on POSIX,
binary digest, source identity, filesystem profile, operation, source kind,
entry count and payload bytes. Streaming and materialized-source cases distinguish
fixed buffers from caller-retained payload. Each operation runs in its own process;
install preparation is included in the peak for verify, repair, move and update.
The native smoke independently checks output and refusal behavior. The 24
observations in `m1_lifecycle_memory_observations.v1.json` bind source commit
`d1e4e506285a4d6eaca737123d69d4050ee358de`, its tree and the measured
binary digest. On the measured Windows NTFS Debug fixture, six streaming
operations at 1 MiB and 32 MiB each stayed at or below 11.1 MiB peak working
set; the 128-entry, 1 MiB cases peaked at or below 14.2 MiB. The materialized
install, repair and update-validation cases rose from about 11.5 MiB to about
42.5 MiB as their retained payload rose from 1 MiB to 32 MiB. The matrix
records exact bytes and pass thresholds, and distinguishes source-kind and
entry-count scaling. It does not extrapolate those observations into an OS
peak claim at the 4,096-file ceiling or claim multi-gigabyte acceptance.

Move planning binds the source root's native identity. Move staging checks root
identity and ancestor path safety before and after each source read and again
before publication; the native test injects a root swap after moving the original
files into the substitute root, preserving each file's native identity and link count.
These pathname checks reject observed substitutions but do not establish an
atomic adversarial namespace guarantee on a concurrently writable POSIX root.
That qualification belongs with the protected publisher and lease work.

Whole-root update recovery/publication and the transaction snapshot helper
remain WU006-owned. This document records implementation evidence only; it
does not claim acceptance execution or qualification.
