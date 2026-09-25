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
Two file-flushed lab summary markers were checked by the runner. The receipt
reports that the service was stopped with deletion requested, the VHD was
dismounted, and its backing file was removed. The retained JSON receipt SHA-256 is
1fa28eac1c2e8a3830f261c8b874072dac4f46cb1c9c1595f31db181a5936af1.
These markers are not full `publish_prepared` and `visible_bound` records;
they omit complete durable closure evidence and replay. The run does not
qualify hostile-rights resistance, crash recovery, production enablement or
OD-001.

The dependent PR #103 source head 7540aef110078fcfc89adb38dc31c11da31961c2
passed its disposable restricted-service probe in hosted run 36090975621 on
Windows build 10.0.20348.0. On a fresh NTFS VHD, the service wrote and
file-flushed schema-tagged prepared and visible lab records, closed each file,
reopened it relative to the held journal, and compared the exact stored bytes.
The records were 4,491 and 4,471 bytes; the visible record contains the
prepared record's SHA-256. The independent runner checked the recorded anchor
roles, volume, root and descendant identities, path, size, payload digest and
linkage. The receipt reports that the service was stopped with deletion
requested, the VHD was dismounted, and its backing file was removed. Retained
JSON receipt SHA-256:
4a0caac176a15b28723ea17048dedb2f4196523ad6b64b8c4db31eb8103b9782.
These are still lab phase records. They omit effective-rights and exact-stream
evidence and have no crash replay. OD-001 and production publication remain
unqualified.

A dependent source candidate now retains exact root and descendant stream
observations in the sealed and visible tree records and rejects a change in
stream name, size, or allocation size across phases. Its local Windows Debug
fixture passes. Hosted PR #104 run 36092385074 at source head
8b45cc87608c3331c5b10dc80f21b5a24bf40509 passed all seven CI jobs.
The disposable restricted service on Windows build 10.0.20348.0 recorded an
empty root stream set and one unnamed 25-byte payload stream with equal
allocation size in the prepared and visible records. The retained JSON receipt
SHA-256 is
3f8795fb7a8fe2d675ccad0b0580e2a4d15d08c77be98ef59f4994888ed3c3c4;
it reports service stop/deletion request and VHD dismount/backing-file removal.
The independent runner checked the recorded stream shape but did not query the
OS stream allocation separately. Effective-rights facts, hostile-rights
testing, crash replay and independent power-loss proof remain open. OD-001
remains unresolved.

A further disposable-lab candidate creates a generated local login on the
hosted Windows runner after the protected visible tree is observed. A separate
process under that login attempts direct read, write, child creation and delete
against the freshly created VHD tree; the runner checks the account SID,
non-administrator token, absence of the publisher service SID, four explicit
access-denied results and the unchanged running service PID. It then attempts
to remove the generated account and its separate temporary output folder, and
fails the run if cleanup is unconfirmed. Hosted PR #105 native Windows step
passed at source head 02a7512a1216e6103f1c2f47e50711e0f0fe5ca1 in run
36093907801 on Windows build 10.0.20348.0. The generated standard account's
separate process returned access-denied HRESULT `0x80070005` for all four
attempts. The receipt reports the generated account and output folder deleted,
the restricted service stopped with deletion requested, and the VHD dismounted
with its backing file removed. Retained JSON receipt SHA-256:
0336a4f0879182e7ff2e2bb585165a4c362b1567b8504df8c7a86a565c7cec17.
This covers four path operations at one post-publication instant; it does not
identify which ACL layer denied access or establish all effective rights,
every ancestor/descendant, a concurrent race, crash replay or power loss.
OD-001 and production enablement remain open.

The dependent PR #106 native Windows step in run 36095483920 at source head
`c40bb197ff722585da50bb3c7f054645a1bff182` passed on build
10.0.20348.0. After the service flushed its prepared lab record on a new
file-backed NTFS VHD, it exposed a flushed readiness marker and waited. A
generated standard-account child then received `0x80070005` for staged
payload read, staged payload write, staged-child insertion and destination
precreation. The runner observed the same running service PID before and after
the attack, then released the service through a flushed marker. The service
re-observed its tree and anchors before the held-parent no-replace rename; the
postpublication four-operation probe also passed. The retained JSON receipt
SHA-256 is
`5f18072e30560427a70a05322a0f65280b56fb277f9663f95bb3225c8bd3b3d5`;
it reports account/output cleanup, service stop/deletion request, and VHD
dismount/backing-file removal. This is one paused laboratory interval. The
readiness signal came from the service, so it is not independent prepared-record
readback. ACL-layer attribution, complete effective rights, continuous race
exclusion, crash replay, power loss and production publication remain unproved.
The final PR #106 head `4ed57ec95a8147cc459d1d75ff6adce5a6c43c2b`
also passed all seven CI jobs in run 36095889169. Its retained probe JSON
SHA-256 is
`fca2275098672c3e59121b25f0060440875ea11e96223c4361562711298c642c`;
the same lab-only limits apply.

The dependent PR #107 final source head
`cdfc71e0d290d67913c8b3a89442b632d8a8d465` passed all seven hosted CI
jobs in run 36098013393 on Windows build 10.0.20348.0. While the restricted
service was paused after its prepared lab record, a separate elevated runner
process used backup-mode copying to read the protected journal file from the
fresh VHD, parsed and hashed its 4,563 bytes, then required the later native
record to have the same SHA-256, length, source identity and destination-parent
identity. The readback SHA-256 was
`d6459696c37aaa1a27bf3c93f817cdd39fef899814ebc1695820d20a7cb75094`;
the retained probe JSON SHA-256 is
`89151606829ced2ef99827178e8cfd0c09a1e1da97a8183eedec0d3e0476de11`.
The run reports service stop/deletion request and VHD dismount/backing-file
removal. This is one paused lab readback. Backup-mode success does not isolate
which privilege granted access; the drive-letter read and before/after VHD
checks are not an atomic held-volume observation. Crash replay, power-loss
survival, continuous hostile-race exclusion, OD-001 and production publication
remain open.

A separate campaign-owned Hyper-V VM experiment used VM ID
`6a23c3f9-272c-4711-b846-152f82bf93d2` and Windows Server build
10.0.20348.0. A newly created 1 GiB VHDX inside that guest was independently
bound to non-system disk 1 and an NTFS volume GUID. The candidate lab helper
refused a wrong Hyper-V guest ID before changing the volume device ACL, then
accepted the exact guest ID, VHDX backing file, disk extent and generated
restricted-service SID. A statically linked lab service paused after flushing
its prepared record; a separate backup-mode read found 4,543 bytes with
SHA-256 `c1450d0eca0c548839da69b7aacfd0741da4b28311f7d7001ee73d5d58825b40`.
The host forcibly turned off only this VM at 2026-09-25T05:39:08Z, then
restarted it. Windows had detached the guest VHDX; after reattaching that
exact backing file, the observer found the same non-system disk and volume
identity and the same prepared-record bytes. The service was stopped, the
release marker and visible destination were absent, and no final native
receipt existed. The host-held observations and owned-resource manifest are
retained outside the repository. This is a forced VM power-off observation of
one prepared state, not a physical host power-loss test. It does not implement
or qualify journal replay, completed recovery, hostile race exclusion, OD-001
resolution or production publication.

The next lab-only service mode classifies that retained prepared state after
restart. It opens the volume and listed descendants through read-only held
handles, checks the exact canonical prepared journal bytes, compares the
protected anchors and sealed staged tree with fresh OS observations, and
requires the destination and state directories to be empty. It writes only a
receipt outside the protected volume and returns `recovery_required`; it does
not replay the journal or make the candidate visible. On the campaign VM, the
restricted service independently matched the surviving 4,543-byte prepared
record SHA-256
`c1450d0eca0c548839da69b7aacfd0741da4b28311f7d7001ee73d5d58825b40`
and staged payload SHA-256
`92ca2ba61185c0d9598b81fde8cbef1126ab69477c3f210f44de36fafe30120f`.
The externally captured positive observation SHA-256 is
`4d436bad94217c0c87d3c9d6d73779d6c6d13ac60afbe3af6dfdc84e37042e73`.
A checkpoint of only the campaign VM then permitted a backup-mode overwrite
of the staged payload. The service refused that altered tree with
`recovery staged closure differs from prepared record`. A later test of the
final binary repeated this refusal: the external negative observation SHA-256
is `51edb22f8f655d430999d544d93b23fe9a0998a4d9805c5434b2552e4dcbc8e9`.
A separate backup-mode read bound the changed 25-byte staged file to digest
`e9855c73d9e98b99e2ee84cdd4ca50114c1d3849ee7d6e394ae54a7a44aad763`;
its external observation SHA-256 is
`f2d6a5a3dfa269b87734c45a4da5fc86849d959e54adcd63418a59e2b5b5f70a`.
The VM was restored to the recorded checkpoint, and another backup-mode read
confirmed the original staged payload digest. Its external observation
SHA-256 is `311195cedd750f0735369c47d4703f9f03197fba1865548aa651aa40d60eba9b`.
This checks one persisted prepared state and one staged-content mismatch. It
does not qualify complete replay, interrupted visible-phase recovery,
power-loss durability, race exclusion, OD-001 resolution, or production
publication.

After adding a second journal and empty-role observation, exact publication
anchor count, and a receipt-path restriction to the classifier, the restored
VM passed a fresh positive run. The final lab service executable
SHA-256 is
`e8eb2666bef29dc3b773a95acf2f02a5087c932ba55ad0df727746f767e5f01f`;
the final external observation SHA-256 is
`9e502f7778931c2b3cb5b5d91685c3306f5c21beb1fd251036061ccfc617842c`.

A second new 1 GiB VHDX inside the same campaign VM exercised the gap after
the native no-replace rename and before the visible-phase journal record. A
separate postrename gate emitted a flushed marker only after the native call
returned; an elevated backup-mode observer found the visible 25-byte payload,
the prepared journal record, and no visible-phase record while the restricted
service was still paused. The pre-power-off observation SHA-256 is
`b894c787c4eba5ab45123a64a3b9153c16436b3772b6df548086ba4040383f8b`.
The host forcibly powered off only the recorded campaign VM. After restart,
Windows had detached the guest VHDX; the observer reattached the exact file
and found the same non-system disk unique ID, NTFS volume GUID, prepared
record SHA-256
`41464b826d3a8c39d8f84ba429891ba0c04731b22e37b1d79bb124643baf34f7`,
and visible payload SHA-256
`92ca2ba61185c0d9598b81fde8cbef1126ab69477c3f210f44de36fafe30120f`.
The restricted service was stopped, with no release marker, visible journal
record, or final publication receipt. The post-power-off observation SHA-256
is `1a387130a6d384939d26d7ad668f65d0dac2680dd07a20e016efe990a3b4c9ca`.

The read-only classifier now recognizes exactly this prepared-journal,
visible-tree shape. It requires staging to be empty, the destination to
contain only `visible`, and the observed visible tree to match every sealed
field after rebasing native names from `staging/candidate` to
`destination/visible`. It rechecks the journal, protected anchors, tree and
namespace before reporting `recovery_required` with
`visible_without_visible_record`; it does not write a visible record or
resume publication. The VM classifier observation SHA-256 is
`fba33c6103dd4d3df27a89228dc879fcb9adb19efa870e31f5f90c8c0a6beaca`.
A checkpoint of that visible state allowed a backup-mode payload overwrite;
the independent mutation receipt SHA-256 is
`fee5977bfb361abcf5c06e9f275b8b8e5c9267e36bc3b28096963f9aeed2a790`.
The same classifier binary refused the changed visible tree; refusal receipt
SHA-256 is `2d0c6d6fcbf9eb26a2d5dabae676affd0b6a6e9f6f96b7c73fb0ba5b848b0461`.
After exact VM snapshot restoration, a separate backup-mode read found the
original visible payload digest again; restore receipt SHA-256 is
`ddd11fa00dd3f3ec024ecdcd1f624c2f24aee888712196302640295f12f17c75`.
The same binary also reclassified the first, still-staged prepared state,
with regression receipt SHA-256
`78f1bae1e98aa8fd3a80a52c56623ea92db6ae6f4690b58ee792d9e1245b43e0`.
These are two forced VM power-off windows and bounded lab classifications,
not physical host power-loss proof, complete replay, continuous hostile-race
exclusion, OD-001 resolution, or production publication.

The recovery classifier now also observes the prepared journal as a complete
protected tree. It requires the held journal root's file identity to match the
anchor, exactly one named record with the readback size and SHA-256, the
protected SYSTEM/service-SID security shape on both objects, and an unchanged second
tree observation. This closes a lab classifier gap where canonical bytes alone
could be accepted after the record file's ACL changed.

On the campaign VM, the new statically linked Release service binary SHA-256
`831ed678201e471302192660ad3f2f25ddf5733c27ca48a4f7c0bec304221b5e`
classified both retained states as `recovery_required`: visible observation
receipt SHA-256
`de8013910f32bf7efd0c9cee3e447d8503f76d4481795426eae381a94defc257`
and staged observation receipt SHA-256
`2c3dbc216b0c1af1702e1211b57d2cb63480e05a5ddc0a15c81f9281f58c2b3a`.
After an exact campaign VM checkpoint, a temporary SYSTEM scheduled task
widened only the prepared journal file's ACL on the recorded second VHDX;
the journal bytes retained SHA-256
`41464b826d3a8c39d8f84ba429891ba0c04731b22e37b1d79bb124643baf34f7`.
The preceding classifier binary still returned `recovery_required` (receipt
SHA-256 `80ccbe38255ed5f707ed858e9d87cabc705749d1074bdc559e60e15df84a3924`),
whereas the new binary refused the altered protected-object shape (receipt
SHA-256 `fa7ab4749c76edd5ea9e67fb9a38217b36f97c367778bc1aa1b83f48dd7cdaa1`).
The task was removed and the exact VM snapshot restored; the mutated guest
receipts were absent and the new classifier again observed the original visible
state (receipt SHA-256
`1e6bacdc3c9807516f50f82fbaff65dd0fe9ae94a5e153d0309a215c5436d572`).
The external lab manifest SHA-256 is
`75471bd32c1be5f786878d8e4039707b22f88b4d1ed5dd14550a2b1d515abb80`.
This is a disposable VM ACL-negative proof, not journal replay, physical
power-loss durability, hostile-race qualification, OD-001 resolution, or
production publication.

The read-only recovery classifier also distinguishes a visible tree with both
canonical journal records from the earlier prepared-only crash states. It
requires the visible record to bind the prepared SHA-256, protected anchors,
destination parent, source file ID, payload SHA-256 and complete visible tree;
it repeats the journal and namespace observations before reporting
`recovery_required` with `visible_with_visible_record`. It still performs no
replay, cleanup or production publication.

On a third campaign-created 1 GiB NTFS VHDX in VM
`6a23c3f9-272c-4711-b846-152f82bf93d2` (Windows build `10.0.20348.0`),
the restricted service completed the lab publication and an independent
backup-mode read found exactly two journal records. The prepared record
SHA-256 was `2c632d1374cdeee591c3b75bf13a8438f55fe0a7315c7f73d85e7feb0f3a25a1`;
the visible record SHA-256 was
`1fb901825a379a8784bc98d23059397a8a00000bcf563bc9e7ca86060ecf8f74`.
The new service binary SHA-256
`a073c1a10b31d9ce835fb24e6c0f3194c4d906cf796bb3426a31a508ab13c1fd`
classified this state as `visible_with_visible_record` (external receipt
SHA-256 `9c20ae293525193ba09cddab0d784e6a74c963f2333dc6b0f1b7c6084f164f75`).
After exact VM checkpoint `dec7d56f-c474-4fa3-849f-fb6a0162bc2a`, a temporary
SYSTEM task widened only the visible journal record ACL while its bytes stayed
unchanged. The classifier refused the altered protected-object shape (external
receipt SHA-256 `6109c8a69bbb17f23dafe443398744bcacd25583abc7f8f1614e90c635ee55f8`).
The task was unregistered and the exact checkpoint restored. Independent
backup-mode hashes again matched both original records, the mutation receipts
were absent, and a fresh classifier run returned
`visible_with_visible_record` (external receipt SHA-256
`d708c50cc17493c851fee60ef35e2c7499b20eb54b8bd698cc6fa93409cf87ec`).
A rebuilt static service binary SHA-256
`9fddced4ccaed007f76f75c35ffcc9d56f1c5e03c8a3b5b67d47dca785fdf8ad`
also classified the restored bytes identically (external receipt SHA-256
`c049c7987446267275d4701b9137b3477082cd6022830b25e419a49e3cbe1718`).
The separate external resource manifest SHA-256 is
`98bbdd8410eee4b9cde12e167c8111cd27da42c290f0afbcb55b63904ba45917`.
This normal completion and ACL-negative experiment does not prove an
interrupted state after the visible record, power-loss durability, actual
replay, hostile-race exclusion, or production readiness.

A separate VM-only postjournal gate now pauses the restricted lab service
after its visible-phase record has been written, flushed, read back, and
observed in the protected journal tree, but before any final service receipt.
On a fourth new campaign-owned 1 GiB NTFS VHDX (disk unique ID
`6002248089F547088289F8F076DA613B`, volume GUID
`\\?\Volume{d988827f-ff51-4de0-8e78-b53124ebfdae}\`), an independent
backup-mode observer saw both journal records and the visible payload while
service `USK_VM_e5137a9935104c9e84a79560c9b131de` was paused. The
pre-poweroff receipt SHA-256 is
`5b24b41081a48cd998105585486aba467db23ccd3c6ceabce122bfcf03c7a7d4`.
The host forcibly powered off only campaign VM
`6a23c3f9-272c-4711-b846-152f82bf93d2` (event receipt SHA-256
`5e1e06b52a2ce2507c5eda261098fb45ea68620d9630cbe78dc0c5776e87c9c9`).
After restart and exact VHDX reattachment, independent guest inspection found
the same NTFS volume identity, prepared record SHA-256
`cc525757c228fb486e5e4cbe063400098f0a0c2c013ec1f61d278ce41cb7fd11`,
visible record SHA-256
`99f5c5ea185e2e4b55b6dc9bedbf0ca75537489322787cb960c12377a89cea50`,
and payload SHA-256
`92ca2ba61185c0d9598b81fde8cbef1126ab69477c3f210f44de36fafe30120f`.
The service was stopped and had neither a release marker nor final receipt;
post-poweroff observation SHA-256 is
`e77151b842039216c9b4578dfdf8c65bf4a949adafd8632b3b9d5389b7477bec`.
The restricted classifier then returned `recovery_required` with
`visible_with_visible_record` (external receipt SHA-256
`20690f3d3c9df0b67271548c42ca0582a2a4fc0b71420a56df1f2e6fa0e07d97`).
The external owned-resource manifest SHA-256 is
`3ce3ee46ad1d473d399e0b42d6cb95e0e716d2e601dbe0235d9aaa518ecf1b1a`.
This is one forced VM poweroff window, not physical host power-loss proof or
journal replay. It does not resolve OD-001 or qualify production publication.

A separate source-level candidate now streams a dedicated regular-file source
through a fixed 64 KiB buffer into a create-only child under a held parent,
using the supplied creation-time descriptor. It requires a declared source size
and SHA-256, checks source identity and metadata before and after streaming,
flushes the child, and retains the created file on post-creation refusal.
The ordinary-user Windows smoke covers a multi-buffer source, exact bytes,
digest failure retention, pre-creation size refusal and collision refusal.
It does not establish a trusted source, protected-parent provenance, complete
tree closure, service execution, publisher durability, recovery or production
availability.

## Restricted-service forward recovery candidate (2026-09-25)

The campaign VM-only service now has a separate `--recover-visible-bound`
mode. It reopens the exact protected anchors and prepared journal through held
parent handles, checks the recorded staged/visible closure, and either performs
one no-replace parent-bound rename from the prepared stage or accepts the
already-visible root. It writes the missing create-only visible-phase record,
reads it back, and reobserves the protected journal, visible tree, anchors and
staging/destination names. A second run on an already-bound record returns
`already_visible_bound` without another rename. Replay errors report
`recovery_required` with a nonzero service exit; retained material is not
removed.

The statically linked x64 candidate binary SHA-256
`00dd1365346b7d41154b88e3a749a269e3b9ffc78916690fd8d5455b630e99e2`
ran in campaign VM `6a23c3f9-272c-4711-b846-152f82bf93d2` on Windows
build `10.0.20348.0`. From the retained prepared-stage snapshot, service
`USK_VM_92fb97d0fc9141f9b527a8d70f967d4c` returned
`visible_bound_forward`; independent guest backup-mode reads matched the
prepared record SHA-256
`c1450d0eca0c548839da69b7aacfd0741da4b28311f7d7001ee73d5d58825b40`,
visible record SHA-256
`bf557f838c5eb1fa76b35b7157ddfddf6f9ba7e6b8d746c9090209151920ff7d`,
and 25-byte payload SHA-256
`92ca2ba61185c0d9598b81fde8cbef1126ab69477c3f210f44de36fafe30120f`.
The external service and independent receipts have SHA-256
`842105a0b977dfa1ae522768d9594c6e5ce7ff1859292a02a1ae76a0272d6c78`
and `55fa6ec80fea708ede456414025681ac35bd4f9279254d10e4ca7deb77ab065b`.

From the retained post-rename, pre-visible-record snapshot, the same binary
under service `USK_VM_520904d4080540099d7370bd83a472d7` returned
`visible_bound_forward`. Independent reads matched prepared SHA-256
`41464b826d3a8c39d8f84ba429891ba0c04731b22e37b1d79bb124643baf34f7`,
visible record SHA-256
`0923736859b0419aad70499bf7a57860fb177dad8d4da7c25c02936d3ec1535d`,
and the same payload digest. A repeated service run returned
`already_visible_bound` with the same visible record hash. The external
service, independent, and repeat receipt SHA-256 values are respectively
`d6ac9533fac1e533b805405d231e1651ee3f2e50c4662038aa88f6c3ccbe0cc3`,
`b8cefc77ffd75e7a760a8f854da493f8a559b1cd33128fb676fdf0eead24e083`,
and `3d617dbcc256e91a776b5b589ba3c677fbe90955179faebe3d644c0f74d860a2`.
The VM was restored to its pre-test campaign checkpoint; the two successful
end states remain in separate owned snapshots.

These observations cover a single fixed service-owned 25-byte lab payload and
two retained VM crash windows. They do not provide a general source or
selected-payload publisher, installed-state completion, lease fencing,
hostile-race qualification, physical-host power-loss proof, or production
availability. A crash during visible-record creation can leave an incomplete
record that this replay conservatively refuses. OD-001 remains open.

## Selected archive entry through the restricted service (2026-09-25)

The next VM-only candidate accepts one `payload.bin` entry from a local ZIP.
It inspects the archive with the existing bounded streaming reader, checks its
complete SHA-256 against the service invocation, revalidates the held archive
source before and after a 64 KiB buffered stream, and creates the staged file
relative to the protected candidate handle. The existing protected tree,
prepared journal, parent-bound no-replace rename and visible journal checks
then run on those streamed bytes. A failed source check before creation leaves
no file; a failure after creation retains the staged child. The focused Windows
test covers a multi-buffer reader, preflight refusal and retained digest
failure.

An external-style authoring fixture finalized a required `core` component and
left an optional `addon` unselected. Its selection receipt SHA-256 is
`54b53d7c7fd6bd256a3a0a14ceb8f1854e4c4e53c08de75b077701270cf6e137`;
the selected bundle manifest SHA-256 is
`081d689da9daac528691228a48a4b011a14374a4dea058e477828afb5f129d06`.
The selected archive SHA-256 is
`4bf00b6da426e2728f0560f683f0a72ccdeaee51f8cdce324623b774353f0e94`.
The source fixture receipt SHA-256 is
`bde9296bb4db2ce1cfc8a793c07ce18a047dffe69f38803adae7ed3629430458`.

Statically linked service binary SHA-256
`49c3fdd442b3f8177b41635abe83edc27cdb757102ddb9dbbad9137a7c0c9470`
ran on campaign VM `6a23c3f9-272c-4711-b846-152f82bf93d2`, Windows build
`10.0.20348.0`, through restricted own-process service
`USK_VM_73186aa540864d648480f3428c01c2ea` and a newly created 1 GiB
file-backed NTFS VHDX, disk 2, volume
`\\?\Volume{83d0d45e-ae4a-4d10-9d29-01787fe20367}\`. The VHDX identity
receipt SHA-256 is
`f31cab79908646b59741a3ac28514e0ed4946b05c2ae1c5b4892f2b2d48ce967`.
The service reported success. A separate guest backup-mode read of the visible
file measured 491,525 bytes and SHA-256
`15f7b1518b0478937a43d98aa2f6a57f641617dbc71728ad2ee1f4f34593b275`.
Independent reads of the prepared and visible journal records measured SHA-256
`3b73dca766aa165fb4d613aa02125764284e83f209a0dc56873c3d30582c8e1f`
and `881cdd3adbecca89245a780931ae09446cb53bd7eb8ec5690481ae92ba3fd685`.
The native service receipt SHA-256 is
`913164ef3eea1b1e86ca6602349026306e3b10f7570ac51efd609b77f17cd162`;
the external independent-observation receipt SHA-256 is
`f68b7fe5f0d4a2aeecc602f5f48d69d7ec9dbde9cf8f01a5417d5608f9d235a8`.
The successful guest state is retained as campaign snapshot
`149ea46c-685e-4b6b-b1e5-9316f5f05c7a`, and the working VM was restored
to pre-test snapshot `5fbd0c44-3891-4ded-972a-cefbc58906ce`.

This observation connects actual authored selected archive bytes to protected
service publication. The service invocation still supplies the archive path
and expected hash; it does not authenticate a reviewed public plan or bind the
bundle manifest to an installed-state transaction. The prepared journal seals
the published payload and tree, but it does not retain the selected archive
hash or source identity. Recovery therefore cannot independently establish
which selected archive supplied those bytes after a crash. This one-root-file lab
profile has no general selected closure, lease fencing, concurrent attacker
test, crash replay of this source, production enablement or release
qualification. The public strict lifecycle remains unavailable and OD-001
remains open. The first attempt to run the guest device-ACL helper used a
dynamic-runtime binary and returned NTSTATUS `0xC0000135`; the existing
static helper then succeeded on the same owned VHDX.

The rebuilt static binary SHA-256
`1125752e6345ba8387adea2264b89e5ce8f2ebd8969bea08bfc53fef79152564`
was rerun on the same campaign VM in restricted service
`USK_VM_a779ef15d08d41ffbd3a2698f2ccd16e`, using a second newly created
1 GiB file-backed NTFS VHDX, disk 2, volume
`\\?\Volume{60d4ff85-e1ba-4fe7-bb48-9632a449b0bb}\`. The selected ZIP SHA-256
remained `4bf00b6da426e2728f0560f683f0a72ccdeaee51f8cdce324623b774353f0e94`.
The service returned `pass`; separate backup-mode reads found the 491,525-byte
visible payload SHA-256
`15f7b1518b0478937a43d98aa2f6a57f641617dbc71728ad2ee1f4f34593b275`
and matched both prepared and visible journal hashes. The native receipt SHA-256
is `9e9208f2e4e8ee3f9d20f0c24ebbbc44790c7f10ed8ee07e1bcb0604979105c0`;
the independent exact-candidate observation SHA-256 is
`8407c6b42ded6d22a1faf1fa616542f6f8c62ccd6bbc5af3c96ccce1f220e1e0`.
The successful state is preserved in campaign snapshot
`1e65483a-9d96-4da1-8e24-d93b7896df11`; the working VM was restored to
pre-test snapshot `5fbd0c44-3891-4ded-972a-cefbc58906ce`. This confirms
the rebuilt binary's one-file lab path only; it does not change the production
and recovery limitations above.

## Selected source recovery after VM power-off (2026-09-25)

A subsequent VM-only candidate writes the inspected selected ZIP's complete
SHA-256, held source-identity digest and entry-set digest into its protected
`publish_prepared` record. Selected runs give their pause markers a unique
receipt-derived name; an earlier probe was refused by a historical lab marker
collision, whose receipt SHA-256 is
`49729eadb2d0e2479044d09f7fefef3b801486143a5fac622a15a05008404ea0`.
The collision changed no visible target and is not counted as a crash proof.

Static service binary SHA-256
`8453b627663258af3a46f8667d1e87af40b64072d3fb1c8c22f77eb26fed37c8`
was exercised in the same owned Windows VM on two further newly created 1 GiB
NTFS VHDXs. At the prepared-before-rename gate, independent backup-mode reads
matched prepared record SHA-256
`da1106a31715123ae252173acec11a445cd0c017777af1bb1bc64b5b1bb01765`
and the 491,525-byte selected payload SHA-256
`15f7b1518b0478937a43d98aa2f6a57f641617dbc71728ad2ee1f4f34593b275`.
The host Hyper-V Worker event log records that this exact VM was turned off
(event 18502, record 13404 at 13:09:02 UTC) and started again (event 18500,
record 13409 at 13:09:08 UTC). Those original host records were read back
retrospectively in receipt SHA-256
`5ae51c086785aac986a17c418a376e205408f056bb0b66d36d8e979e9974e6dd`;
they are not a contemporaneous command transcript. After this observed
turn-off and guest restart, the newly created VHD had detached
and the newly registered service had not persisted. The test reattached only
the recorded VHD, checked its disk unique ID and volume GUID, recreated the
same restricted service name/SID, and reapplied its device ACL. Fresh reads
matched the prepared record and staged payload. Recovery returned
`visible_bound_forward`; a repeat returned `already_visible_bound`. The
pre-crash, post-crash, recovery and repeat observation SHA-256 values are
`124bec8c93feae0c0582d91382b04dfee937d4cec1ad0ffe87a882c0200fba41`,
`0ad6eef542161aa363ee646f3a4009d1e7689b84f18aa7e169de9f248c7d8ffc`,
`e9ece812d1e2babf73c71289ecb898b8222018506c8086622df5979a3af9c7bb`
and `b4496af65a62e61d648f392fb0f7406489126fddace478acd2836574cb95ad85`.
The recovered state is retained in snapshot
`8cb5c857-1cd3-4aad-9586-7e21717787e9`.

At the post-rename-before-visible-record gate, the same binary published the
selected bytes and paused. The host forced the owned VM to `Off` using
`Stop-VM -TurnOff -Force` (host receipt SHA-256
`20575eaf3641adf8543a3536f02d824e7f7c705b6d5c574be8355c85c96eb71e`).
After restart and exact VHD reattachment, a fresh backup-mode read matched
prepared SHA-256
`7c67a9038bbdff34806a0a0049813e8ec9a32bc85a11ac24434f77d6d49a4625`
and the visible payload; no visible journal record existed. Recreating the
same restricted service identity and running recovery returned
`visible_bound_forward` without another rename, then independent readback
matched the payload and visible-record SHA-256
`7152408629ec1c0cba093ecc5a42ac3edc894b9f74aa14852d0d279901fb5c88`.
The post-crash and recovery observation SHA-256 values are respectively
`b1a0c33299d6ceca9b352266c72b702548d90524ce6ee7911e629fbe32b6590d`
and `94f53417dab206d258da37b697331f06ae7b362081b89b88026d9170651d9384`.
The recovered state is retained in snapshot
`f230c4ec-c144-467b-805e-53a05d3ae48f`; the working VM was restored to
pre-test snapshot `5fbd0c44-3891-4ded-972a-cefbc58906ce`.

These are VM turn-off and restart observations, not physical-host power-loss
proof. The second window also has a contemporaneous forced turn-off receipt.
The protected prepared record now retains selected archive identity, but that
identity originates from the lab invocation and is not authenticated against
a reviewed public plan or selection manifest. Recovery validates the stored
binding's shape and the sealed protected payload/tree; it does not reacquire
or revalidate the original ZIP after restart. General selected closure,
installed-state completion, lease fencing, hostile-rights qualification,
production enablement and OD-001 remain open.

## Selected-source lab completion after visibility (2026-09-26)

The restricted service now writes a protected, canonical
`usk.publisher.lab_installed_state.v1` record after the visible journal phase
for its one-file selected-source mode. It binds the selected archive/source/
entry-set digests, prepared and visible journal SHA-256 values, observed
volume, destination parent and visible root identities, service SID and payload
SHA-256. Recovery checks the exact existing record or, when a verified visible
journal and sealed tree exist without it, writes and reopens that record. A
repeat returns `already_visible_bound` without changing its bytes.

The first candidate binary used the dynamic MSVC runtime and the campaign
service failed to start before a native receipt; the failed attempt is retained
at receipt SHA-256
`93e9ba81c14a16a146dadc549c3d69eb6c57f766c9cae4412aeff1326d579c2c`.
The exact startup cause was not established. A static CRT rebuild (binary
SHA-256 `a521bf553ffaae8cf49200561269c63e971cf104baaa00a67f573b913036d5fa`)
then ran on a second new 1 GiB NTFS VHDX in the owned Windows build
`10.0.20348.0` VM. Independent backup-mode reads matched the 491,525-byte
payload, both journal records and completion record SHA-256
`f29b9e6ff3438ee155818d2033b0c3d45abd8c56dc36414f0a88f900d6324e6d`.
The live observation receipt SHA-256 is
`9eeb351e821b053907ad13cb75d6876f94ce4d4f6199e3955345f1fd646cd9b4`;
a second service invocation returned `already_visible_bound` and independently
read the same completion SHA-256 (receipt
`36efc0cc6254a82bc62e20e51e5206949a38701ba23f7103e56f89263d7baa76`).

A third newly created 1 GiB NTFS VHDX exercised the interruption between
the flushed visible journal and completion state. Static binary SHA-256
`2749c09c6d92fe424881c8d5eabc682088d799205bcfc5096606c78ed6f14767`
paused at that gate. Independent pre-crash backup reads matched prepared
SHA-256 `60cfaef1a43501e392d83a049e6275395e09b3c6d0b73e07d69004acf5e4c460`,
visible SHA-256 `d26f76bcc55dc9e0cc255d829a64f1eccbbef53af3950101948719786acf7ce8`
and payload SHA-256
`15f7b1518b0478937a43d98aa2f6a57f641617dbc71728ad2ee1f4f34593b275`;
the completion file was absent (observation receipt
`c06f6cf9e59b62e7d690cf1aa7b04a1851d35ab4befa19bd0a025eb705811d05`).
The host recorded exact-VM `Off` before restart (receipt
`230394b85698252af86700cb1287837ce5f136b3276c2b74bc7d551a88f00bf6`)
and a separate running-state receipt
`3f1b949e31f8bc758d51ada161fcfd016733caef26b07bee9c5d9e7766f6205d`.
After exact owned-VHD reattachment, fresh independent reads still matched
both journal records and payload and found completion absent (receipt
`354082f1342aea8b0586b0a983d14571bc20fccf774b65b652caeb4e5a6bb2ee`).
Recovery returned `installed_state_completed_forward` and wrote completion
SHA-256 `2d94dfe0c98b9d149302a1f98998a0e126629be38f9433d38eddbe64a709cc6f`
(receipt `ff68c921c4ed3870c396f8bb9e37b103ad715b01da568f5ec3ac774daf20b034`).
Another invocation returned `already_visible_bound` with the same independently
read completion digest (receipt
`1c4c189a31966670d3df83efb741fbe7134c08b144355d647b63c067a25e17fd`).

This is a laboratory completion record, not the public
`usk.installed_state.v1` or a successful packaged setup installation. The
source is still one selected entry, and its binding originates from the lab
invocation rather than an authenticated reviewed plan. General source closure,
installed-state/ownership/audit integration, leases, hostile-rights attacks,
physical-host power-loss qualification, production enablement and OD-001
remain open.
