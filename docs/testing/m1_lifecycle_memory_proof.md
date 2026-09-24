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
`140b08b1f4d3a16515a34e848fb55a56cee35fe6`, its tree and the measured
binary digest. On the measured Windows NTFS Debug fixture, six streaming
operations at 1 MiB and 32 MiB each stayed at or below 11.1 MiB peak working
set; the 128-entry, 1 MiB cases peaked at or below 14.2 MiB. The materialized
install, repair and update-validation cases rose from about 11.5 MiB to about
42.5 MiB as their retained payload rose from 1 MiB to 32 MiB. The matrix
records exact bytes and pass thresholds, and distinguishes source-kind and
entry-count scaling. It does not extrapolate those observations into an OS
peak claim at the 4,096-file ceiling or claim multi-gigabyte acceptance.

The follow-up `m1_lifecycle_memory_ceiling_observations.v1.json` records four
additional isolated Windows 10 build 19045, C: NTFS Debug child-process
observations from source commit `2d899f434019dfbb90ee3eae7c542d42ce6268dd`.
A streamed 2 GiB, one-file install and its verification completed with an
11,411,456-byte peak working set. A plan-only 128-entry, 1 MiB case peaked at
11,128,832 bytes; the same total payload spread across 4,096 entries peaked at
42,246,144 bytes. At 4,096 entries, increasing the total declared and sourced
payload from 1 MiB to 32 MiB changed the plan peak by 61,440 bytes. These
observations separate payload size from entry-count metadata growth. Planning
does not stage files or persist a transaction journal, so its 4,096-entry
measurements do not establish a complete lifecycle memory ceiling.

A full 4,096-entry install experiment did not complete. After 2,571 entries,
the disposable fixture was deliberately made to fail its next exclusive file
creation, allowing cleanup. The transaction currently persists a growing
journal snapshot per staged file, making this shape slow; the failed run is
diagnostic evidence, not a passing ceiling observation. A complete 4,096-entry
install/verify/repair/move/update/recovery matrix and legacy-report budget remain
open. The 2 GiB result establishes one multi-gigabyte install shape, not the
full corpus or release acceptance.

The R4 continuation completed one full 4,096-entry streamed install with a
1 MiB total payload on Windows 10 build 19045, C: NTFS, Debug. The isolated
child exited successfully with a 92,921,856-byte OS peak working set over
2,756,388 ms. `m1_lifecycle_memory_4096_install_r4.v1.json` binds source
`2dcb067044925c43cd76ef6223453029c13de611`, tree
`2a57cb175b613abbab514a0cb23ed4d225dfdb23`, and the measured binary
SHA-256. The 4,096-file staging and install/verification path ran end to end;
the output does not measure the other operations, and a later report-budget
source change means this historical binary observation cannot be silently
rebound to the changed bytes.

`m1_lifecycle_legacy_report_memory_observations.v1.json` measures the
prior-format ownership reader separately for verify and uninstall planning.
The native fixture writes one-byte files and a real ownership record in a
separate setup process, then a fresh measured child invokes the public
lifecycle function. On Windows 10 build 19045, C: NTFS Debug, 128-file verify
and uninstall planning peaked at 11,440,128 and 11,489,280 bytes respectively.
At 4,097 files the peaks were 53,506,048 and 53,542,912 bytes; at 8,192 files
they were 97,431,552 and 97,804,288 bytes. A combined 4,097-file sequence,
with its first report released before planning, peaked at 53,776,384 bytes.
Fixture construction and cleanup are outside the measured process. Its peak
includes record parsing, reporting, and plan hashing, so it does not isolate
allocator ownership by subsystem. Those 8,192-file cases exceeded a 64 MiB
comparison threshold, and the legacy reader had no aggregate report budget
at that shape. Compatibility is preserved, but full lifecycle memory
qualification remains open.

The follow-up `m1_lifecycle_legacy_report_memory_observations.v2.json` binds
source commit `9a8489a63621a075e98d6af6966afba3c4cd8a1e`, its tree and the
measured Debug binary. The ownership reader releases the input JSON tree
before retaining the validated manifest, and hashes that manifest without a
second full tree. Verification and uninstall planning hash their v1 canonical
reports directly from entries. Native tests rebuild the former JSON payloads
and compare their digests with the new streaming results. Each 128, 4,097 and
8,192-file reader, verify and uninstall-plan observation ran in a fresh Windows
10 build 19045 C: NTFS child after separate fixture preparation. The 8,192-file
peaks were 64,434,176, 64,520,192 and 64,630,784 bytes respectively, below the
67,108,864-byte comparison ceiling. This measured improvement is not an
enforced aggregate report allocation budget or a completed full 4,096-file
lifecycle matrix. The new observations remain local ordinary-user Debug
evidence; they do not qualify the protected publisher or release acceptance.

Verification now charges every owned file, owned directory, and observed
unknown path to a combined limit of 16,384 report entries and 4 MiB of
cumulative relative-path text. Crossing either limit raises an explicit
resource-budget error before a report or uninstall plan is returned. An
isolated native `--report-budget-smoke` fixture installs a small owned payload,
adds 16,384 unknown files, and observes budget refusal from both verification
and uninstall planning while all owned and unknown files remain present. This
is a deterministic count/path-text bound, not an exact allocator-byte ceiling;
the current-source process peak and full operation matrix remain to be measured.

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
