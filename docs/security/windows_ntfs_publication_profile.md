# Windows NTFS publication profile — candidate only

`windows_nt_x64_local_ntfs_service_sid_noreplace_v1` is a proposed design, not a platform proof. Its production record remains `implementation: absent`, `availability: false`, `qualification: not_run`, and `support: unsupported`. Nothing here authorizes endpoint mutation or changes the runtime's current refusal behavior.

## Exact admitted platform and adversary

The candidate floor is Windows NT x64 build 17763 (Windows 10 version 1809 or Windows Server 2019) with Windows SDK `10.0.17763.0`, because the design depends on `FileCaseSensitiveInfo`. The source, service binary, SDK/runtime closure, endpoint build, local NTFS configuration, volume identity, and disposable-lab authority must still be bound by later qualification.

Included adversaries are an unrelated local unprivileged login, a hostile process under the initiating login that lacks the publisher-service token and publisher handles, and a concurrent cooperative installer. Included attacks cover same-name identical-byte or changed-byte descendant replacement, insertion or removal, parent substitution, destination precreation, reparse traversal, case-sensitive directories, alternate streams, hard links, owner/DACL change, and rename races.

Excluded adversaries are administrators, `SYSTEM`, publisher-service compromise, kernel or filesystem-filter compromise, offline storage manipulation, denial of service, and unqualified power loss. The design makes no atomic-replacement, continuous-reader, global-handle-enumeration, availability, qualification, or support claim.

## Service identity and exact security descriptor

The publisher is a dedicated service with a stable service SID configured as `SERVICE_SID_TYPE_RESTRICTED`. The profile requires a qualified dedicated volume whose filesystem root is the explicit parent-namespace boundary; the volume root has no filesystem parent that could independently exercise `FILE_DELETE_CHILD`. Its handle-bound owner, DACL, effective rights, identity, reparse, case, volume, and locality facts are evidence, not an availability assumption. Beneath it, the single-component publication root, staging root, destination parent, state anchor, and journal anchor are created by the service from inception with one atomic protected security descriptor; a pre-existing or inherited anchor makes the profile unavailable. Every ancestor and every staged descendant is also in the revalidation set. Each protected root/anchor/ancestor role has its own case-insensitively distinct canonical volume-relative path and composite file identity from the same handle. The chain starts at `volume_root=.` and its publication-root child, every following ancestor is its immediate child, and every anchor is a distinct direct child of the deepest recorded ancestor. Omitting either boundary, repeating one handle observation under several role labels, or supplying distinct but unrelated paths refuses the profile; no `ancestors_revalidated` Boolean can replace this evidence.

The owner is exactly `SYSTEM` (`S-1-5-18`). The DACL is protected, contains no inherited ACEs, and initially contains exactly two allow ACEs: `SYSTEM` and the dedicated restricted publisher service SID. Each has the full set needed by the model: `DELETE`, `FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`, `FILE_APPEND_DATA`, `FILE_DELETE_CHILD`, `FILE_EXECUTE`, `FILE_LIST_DIRECTORY`, `FILE_READ_ATTRIBUTES`, `FILE_READ_DATA`, `FILE_READ_EA`, `FILE_TRAVERSE`, `FILE_WRITE_ATTRIBUTES`, `FILE_WRITE_DATA`, `FILE_WRITE_EA`, `READ_CONTROL`, `SYNCHRONIZE`, `WRITE_DAC`, `WRITE_OWNER`. There are no other allow or deny ACEs in the admitted descriptor.

Before visible binding there is no consumer grant. After exact visible binding, a future implementation may add a separately specified consumer allow ACE containing read, execute, traverse, synchronize, and read-control rights only. No untrusted principal may receive delete, write, append, add-file, add-subdirectory, delete-child, `WRITE_DAC`, or `WRITE_OWNER` rights. This prohibition includes `FILE_DELETE_CHILD` effective access on the volume-root boundary and every other parent directory.

For every anchor, ancestor, root, and descendant, an independent observer consumes `GetSecurityInfo` output from the same handle used for identity and reports the parsed owner, DACL protection flag, inherited ACEs, exact ordered ACEs/rights, all other ACEs, and explicit effective-right sets for the initiating and untrusted principals. The deterministic model serializes those closed parsed facts as sorted-key compact UTF-8 JSON and recomputes their SHA-256; an arbitrary digest change without matching structured facts rejects. The two untrusted effective-right sets are empty before binding. This consistency oracle does not substitute for Windows `AccessCheck`, an attacker harness, or platform proof.

## Handle provenance instead of global enumeration

A hostile handle is any handle held outside the restricted publisher service that can mutate identity, bytes, streams, names, descendants, owner, or DACL. Relevant access includes `DELETE`, `FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`, `FILE_DELETE_CHILD`, `FILE_WRITE_ATTRIBUTES`, `FILE_WRITE_EA`, `WRITE_DAC`, and `WRITE_OWNER`, including a directory handle usable for relative mutation.

The profile does not pretend that system-wide handle enumeration is complete or race-free. Eligibility instead derives from protected anchors created by the service from inception and handle provenance maintained without a gap: publisher handles are opened non-inheritable, are never inherited by child processes, and are never duplicated outside the restricted service. Pre-existing anchors, inherited handles, duplicated handles, or loss of provenance make the profile unavailable. Consumer handles are opened only after visible binding and are non-mutating.

## Race-free interval and handle observations

The claimed interval begins with atomic creation of the protected empty staging anchor and ends only after the visible root and every visible descendant have been rebound and the `visible_bound` milestone is durable. All traversal and mutation use handles; path strings and caller booleans are only untrusted assertions.

At admission, seal, immediately before rename, and after rename/reopen, the service emits a new closed phase observation and revalidates all of the following; later phases never reuse or default to admission values:

- parsed owner, protected exact DACL, all ACEs/effective rights, and canonical structured-evidence digest through independent `GetSecurityInfo` observation on the same handle;
- composite volume/file identity through `GetFileInformationByHandleEx(FileIdInfo)`;
- attributes and reparse tag through `FileAttributeTagInfo`, rejecting every reparse point;
- link count through `FileStandardInfo`, requiring exactly one link;
- streams through `FileStreamInfo`, allowing a file's unnamed `::$DATA` stream only and no directory streams;
- case sensitivity through `FileCaseSensitiveInfo`, requiring it disabled on every ancestor and directory;
- the volume label from `GetVolumeInformationByHandleW`'s volume-name buffer (which is not a volume GUID path), its 32-bit serial, filesystem name, maximum component length, and the exact raw filesystem-flags DWORD in `0..0xffffffff`, requiring the profile bits while preserving every returned extra bit;
- the `FILE_ID_INFO` 64-bit volume serial with its low-order 32 bits equal to the `GetVolumeInformationByHandleW` serial; it is not assumed to be a zero-extension;
- an attempted `GetFileInformationByHandleEx(FileRemoteProtocolInfo)` that returns `ERROR_INVALID_PARAMETER` (87) with no protocol structure for this admitted local NTFS profile, rather than a fabricated all-zero tuple or caller `local=true` assertion;
- an equal parsed volume prefix on every anchor, ancestor, sealed/visible root, and descendant file ID, plus the same bound destination parent;
- unchanged ancestor identities and security descriptor digests;
- the destination-parent handle name and post-rename visible final component from `FileNameInfo`, equality with the stored validated `destination_name`, an independent pre-rename relative open result of `ERROR_FILE_NOT_FOUND`, and `ReplaceIfExists=FALSE`.

Each phase observation contains the complete volume-root/publication-root/ancestor/anchor set with path, identity, security, reparse, and case facts, plus the complete volume/filesystem/locality tuple. Seal and immediate pre-rename observations must equal admission. Post-rename must also equal admission except that the staging-root identity's path must move to exactly `destination_parent/destination_name`; its identity and security remain unchanged. Ancestor rename or substitution, DACL/effective-right change, case or reparse change, volume change, or locality change therefore refuses before rename or enters retained recovery after an applied rename.

The destination and closure use a canonical case-insensitive Windows relative namespace. Absolute, drive-relative, UNC, device-prefixed, backslash-ambiguous, empty, dot, dot-dot, colon/ADS, control-character, Win32-forbidden-character, trailing-dot/space, and reserved DOS device components refuse. Components are NFC and at most 255 UTF-16 units; depth is at most 128. Case-fold aliases refuse. Every nested entry's intermediate parent must be present in the closure as a directory, so a missing parent or file-as-parent refuses.

The closure contains at most 200,000 descendants, serialized evidence at most 256 MiB, and total content at most 16 TiB. Every entry records canonical relative path, file or directory type, composite volume/file identity, file content SHA-256 (mandatory for files and absent for directories), size, attributes, structured security facts/digest, link count exactly one, exact stream set, reparse flag, and reparse tag. The sealed/visible root must be the protected staging-root identity. Every descendant identity is pairwise distinct and disjoint from every protected root, anchor, and ancestor identity; repeating the destination-parent or any other protected identity as a child refuses. Attributes form a sorted, duplicate-free admitted set, and `FILE_ATTRIBUTE_DIRECTORY` is present if and only if the entry type is directory. Reparse attribute/flag/tag facts must agree and every reparse object ultimately refuses. Files permit only unnamed `::$DATA`; directories permit no data streams. Missing evidence is not replaced with a verified value. The exact visible root and exact ordered descendant closure must equal the sealed root and closure, including same-path file identities and hashes. A wholesale closure with internally consistent IDs from another volume prefix refuses.

## Protocol and terminal outcomes

The model sequence is `unavailable -> protected_empty -> materializing -> sealed -> publish_prepared -> renamed_unconfirmed -> visible_bound -> metadata_pending -> completed`. `refused_retained` and `recovery_required` are terminal. Preflight cannot run from a later phase; rename cannot repeat; `ReplaceIfExists=TRUE` is forbidden; replay stops after every refusal, recovery, invalid trace, or completion.

`publish_prepared`, containing bound parent/root/closure evidence, is durable before a target-qualified handle-relative no-replace rename is attempted. The candidate is `NtSetInformationFile(FileRenameInformation)` with `RootDirectory` bound to the destination-parent handle and `ReplaceIfExists=FALSE`. A disposable probe on 2026-09-24 under the ordinary `BLACKGLASS-WIN1\Jules` login on Windows NT 10.0.19045, `C:` local NTFS found that `SetFileInformationByHandle(FileRenameInfo)` with that non-null parent handle returned error 87 while the native call succeeded. This was not the dedicated-volume restricted-service target. An absolute destination-name fallback does not preserve the required parent binding. This observation changes the candidate call, not the profile's qualification status or security claim. Rename has three outcomes: `applied`, `not_applied`, or `unknown`. A crash or response loss around rename may produce `unknown`; it is never converted into no-effect. After an applied rename, an excluded privileged attacker also yields retained `recovery_required`, never a protected/no-effect label.

After rename, the service independently opens the visible root relative to the still-bound parent, repeats the complete observations, requires exact equality, and durably records `visible_bound`. Metadata begins only then. A metadata failure retains the visible object for recovery. Recovery may re-observe and classify but cannot manufacture profile eligibility, publication capability, ownership, or completion; it never deletes material whose ownership is ambiguous. A destination generation can complete at most once.

## Evidence status and WU-006 gate

The deterministic reference model and explicit corpus exercise these rules but do not establish Windows behaviour. Required evidence still includes an implementation candidate, admitted disposable target, exact target/configuration receipt, independent attacker harness, crash/fault injection around rename, independent post-state observation, and independent technical/security review.

OD-001 therefore remains open and blocks WU-006 qualification and production enablement. Candidate implementation and disposable probing can proceed to produce the missing evidence. WU-006 must not treat this profile document, the deterministic model, fixture data, or caller claims as target-bound evidence or a resolved platform-security decision.

The parent-bound create-only candidate now covers regular files as well as
directory anchors. A disposable ordinary-user C: NTFS probe writes and flushes
a newly created file through its returned non-inheritable handle, refuses
same-name collisions, and checks that replacing the parent's path does not
redirect creation through the held parent handle. It does not establish a
service-created protected staging tree or change the profile status above.

The hosted PR #97 observation at source head
faf457919fcfb416c127b7db4f7e6e20434d6012 and CI run 36076348039
created a fresh file-backed NTFS VHD on Windows build 10.0.20348.0. Its
generated own-process LocalSystem service had SERVICE_SID_TYPE_RESTRICTED;
the service SID appeared as an enabled process group and a restricting SID,
and independent SCM and native process IDs matched. The native service opened
the VHD's volume GUID root, observed local NTFS, and the lab removed the
service and VHD. The retained JSON artifact SHA-256 is
3ced569d8f1a0ee8b07b3e4f88b41a70435c5025e82ff155ff2c553ccdd51111.
This qualifies the disposable service and volume observation only. It does not
establish protected anchors, publication, recovery, or OD-001 resolution.

The hosted PR #98 observation at source head
6d3a73910df3f672efcde13e6d3f7e40c0c6097b and CI run 36083054549
used Windows build 10.0.20348.0 and a fresh file-backed NTFS VHD. The lab
bound the VHD backing file, attached device, sole volume extent and observed
disk number before adding only the generated service SID to that disposable
volume device's DACL. The restricted own-process service protected the
already formatted volume root and created the publication root, staging root,
destination parent, state and journal anchors. Its native probe required
unchanged second-phase observations. Independent receipt checks found six
distinct file IDs, SYSTEM ownership, exact protected SYSTEM/service-SID DACLs,
and no reparse points. The service was stopped and deletion requested, and the
VHD was dismounted and removed. The retained JSON receipt
SHA-256 is
862d8c3858adc01d064e2c790683dfab8b49a08e67aeb465816d7113ad4c19d8.
This establishes the disposable protected-anchor laboratory step only. It does
not qualify staged publication, hostile rights, crash recovery or OD-001.

The dependent PR #100 staged-child probe at source head
487d994d43fb5df8123b86f7d526d4e0a75bde83 and hosted CI run 36083996703
created a `candidate` directory relative to the retained protected staging
handle and a `payload.bin` file relative to the retained candidate handle.
The restricted service wrote and flushed 25 bytes, observed the staged tree
twice, and required unchanged identity, security and content. Independent
receipt checks found the expected SHA-256
92ca2ba61185c0d9598b81fde8cbef1126ab69477c3f210f44de36fafe30120f,
path, size, and eight distinct protected root/anchor/staged IDs. The retained
JSON receipt SHA-256 is
b344d102c4ae5139b7eeb0095fbd91eead4a262dc61151cf308cf4cfd66d28e0.
This qualifies protected staging in the disposable lab only. It does not
establish a durable publish intent, no-replace rename, visible closure,
hostile-rights resistance, crash recovery or production publication.

The PR #102 disposable run 36088974062 at source head
ef95390e61f3b42e1796caf9375b4a3b02820a90 used a fresh file-backed NTFS
VHD on Windows build 10.0.20348.0 with a generated own-process restricted
service. Its service closed the destination parent's create-only handle,
reopened the exact listed directory through the retained publication parent,
and observed a successful handle-relative no-replace rename. The source root
and visible root had the same composite file ID; the independently reopened
visible payload retained SHA-256
92ca2ba61185c0d9598b81fde8cbef1126ab69477c3f210f44de36fafe30120f.
Two file-flushed lab summary markers were checked by the runner, and the
service and VHD were cleaned up. The retained JSON receipt SHA-256 is
1fa28eac1c2e8a3830f261c8b874072dac4f46cb1c9c1595f31db181a5936af1.
These markers are not full `publish_prepared` and `visible_bound` records;
they omit complete durable closure evidence and replay. The run does not
qualify hostile-rights resistance, crash recovery, production enablement or
OD-001.
