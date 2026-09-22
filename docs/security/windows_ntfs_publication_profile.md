# Windows NTFS publication profile — candidate only

`windows_nt_x64_local_ntfs_service_sid_noreplace_v1` is a proposed design, not a platform proof. Its production record remains `implementation: absent`, `availability: false`, `qualification: not_run`, and `support: unsupported`. Nothing here authorizes endpoint mutation or changes the runtime's current refusal behavior.

## Exact admitted platform and adversary

The candidate floor is Windows NT x64 build 17763 (Windows 10 version 1809 or Windows Server 2019) with Windows SDK `10.0.17763.0`, because the design depends on `FileCaseSensitiveInfo`. The source, service binary, SDK/runtime closure, endpoint build, local NTFS configuration, volume identity, and disposable-lab authority must still be bound by later qualification.

Included adversaries are an unrelated local unprivileged login, a hostile process under the initiating login that lacks the publisher-service token and publisher handles, and a concurrent cooperative installer. Included attacks cover same-name identical-byte or changed-byte descendant replacement, insertion or removal, parent substitution, destination precreation, reparse traversal, case-sensitive directories, alternate streams, hard links, owner/DACL change, and rename races.

Excluded adversaries are administrators, `SYSTEM`, publisher-service compromise, kernel or filesystem-filter compromise, offline storage manipulation, denial of service, and unqualified power loss. The design makes no atomic-replacement, continuous-reader, global-handle-enumeration, availability, qualification, or support claim.

## Service identity and exact security descriptor

The publisher is a dedicated service with a stable service SID configured as `SERVICE_SID_TYPE_RESTRICTED`. The single-component publication root, staging root, destination parent, state anchor, and journal anchor are created by that service from inception with one atomic protected security descriptor; a pre-existing or inherited anchor makes the profile unavailable. Every ancestor and every staged descendant is also in the revalidation set. Each protected root/anchor/ancestor role has its own case-insensitively distinct canonical volume-relative path and composite file identity from the same handle. The chain starts at the mandatory publication-root boundary, every following ancestor is its immediate child, and every anchor is a distinct direct child of the deepest recorded ancestor. Omitting that boundary, repeating one handle observation under several role labels, or supplying distinct but unrelated paths refuses the profile; no `ancestors_revalidated` Boolean can replace this evidence.

The owner is exactly `SYSTEM` (`S-1-5-18`). The DACL is protected, contains no inherited ACEs, and initially contains exactly two allow ACEs: `SYSTEM` and the dedicated restricted publisher service SID. Each has the full set needed by the model: `DELETE`, `FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`, `FILE_APPEND_DATA`, `FILE_DELETE_CHILD`, `FILE_EXECUTE`, `FILE_LIST_DIRECTORY`, `FILE_READ_ATTRIBUTES`, `FILE_READ_DATA`, `FILE_READ_EA`, `FILE_TRAVERSE`, `FILE_WRITE_ATTRIBUTES`, `FILE_WRITE_DATA`, `FILE_WRITE_EA`, `READ_CONTROL`, `SYNCHRONIZE`, `WRITE_DAC`, `WRITE_OWNER`. There are no other allow or deny ACEs in the admitted descriptor.

Before visible binding there is no consumer grant. After exact visible binding, a future implementation may add a separately specified consumer allow ACE containing read, execute, traverse, synchronize, and read-control rights only. No untrusted principal may receive delete, write, append, add-file, add-subdirectory, delete-child, `WRITE_DAC`, or `WRITE_OWNER` rights.

For every anchor, ancestor, root, and descendant, an independent observer consumes `GetSecurityInfo` output from the same handle used for identity and reports the parsed owner, DACL protection flag, inherited ACEs, exact ordered ACEs/rights, all other ACEs, and explicit effective-right sets for the initiating and untrusted principals. The deterministic model serializes those closed parsed facts as sorted-key compact UTF-8 JSON and recomputes their SHA-256; an arbitrary digest change without matching structured facts rejects. The two untrusted effective-right sets are empty before binding. This consistency oracle does not substitute for Windows `AccessCheck`, an attacker harness, or platform proof.

## Handle provenance instead of global enumeration

A hostile handle is any handle held outside the restricted publisher service that can mutate identity, bytes, streams, names, descendants, owner, or DACL. Relevant access includes `DELETE`, `FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`, `FILE_DELETE_CHILD`, `FILE_WRITE_ATTRIBUTES`, `FILE_WRITE_EA`, `WRITE_DAC`, and `WRITE_OWNER`, including a directory handle usable for relative mutation.

The profile does not pretend that system-wide handle enumeration is complete or race-free. Eligibility instead derives from protected anchors created by the service from inception and handle provenance maintained without a gap: publisher handles are opened non-inheritable, are never inherited by child processes, and are never duplicated outside the restricted service. Pre-existing anchors, inherited handles, duplicated handles, or loss of provenance make the profile unavailable. Consumer handles are opened only after visible binding and are non-mutating.

## Race-free interval and handle observations

The claimed interval begins with atomic creation of the protected empty staging anchor and ends only after the visible root and every visible descendant have been rebound and the `visible_bound` milestone is durable. All traversal and mutation use handles; path strings and caller booleans are only untrusted assertions.

At admission, seal, immediately before rename, and after rename where applicable, the service observes and revalidates:

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

The destination and closure use a canonical case-insensitive Windows relative namespace. Absolute, drive-relative, UNC, device-prefixed, backslash-ambiguous, empty, dot, dot-dot, colon/ADS, control-character, Win32-forbidden-character, trailing-dot/space, and reserved DOS device components refuse. Components are NFC and at most 255 UTF-16 units; depth is at most 128. Case-fold aliases refuse. Every nested entry's intermediate parent must be present in the closure as a directory, so a missing parent or file-as-parent refuses.

The closure contains at most 200,000 descendants, serialized evidence at most 256 MiB, and total content at most 16 TiB. Every entry records canonical relative path, file or directory type, composite volume/file identity, file content SHA-256 (mandatory for files and absent for directories), size, attributes, structured security facts/digest, link count exactly one, exact stream set, reparse flag, and reparse tag. The sealed/visible root must be the protected staging-root identity. Every descendant identity is pairwise distinct and disjoint from every protected root, anchor, and ancestor identity; repeating the destination-parent or any other protected identity as a child refuses. Attributes form a sorted, duplicate-free admitted set, and `FILE_ATTRIBUTE_DIRECTORY` is present if and only if the entry type is directory. Reparse attribute/flag/tag facts must agree and every reparse object ultimately refuses. Files permit only unnamed `::$DATA`; directories permit no data streams. Missing evidence is not replaced with a verified value. The exact visible root and exact ordered descendant closure must equal the sealed root and closure, including same-path file identities and hashes. A wholesale closure with internally consistent IDs from another volume prefix refuses.

## Protocol and terminal outcomes

The model sequence is `unavailable -> protected_empty -> materializing -> sealed -> publish_prepared -> renamed_unconfirmed -> visible_bound -> metadata_pending -> completed`. `refused_retained` and `recovery_required` are terminal. Preflight cannot run from a later phase; rename cannot repeat; `ReplaceIfExists=TRUE` is forbidden; replay stops after every refusal, recovery, invalid trace, or completion.

`publish_prepared`, containing bound parent/root/closure evidence, is durable before `SetFileInformationByHandle(FileRenameInfo)` is attempted relative to the bound destination parent. Rename has three outcomes: `applied`, `not_applied`, or `unknown`. A crash or response loss around rename may produce `unknown`; it is never converted into no-effect. After an applied rename, an excluded privileged attacker also yields retained `recovery_required`, never a protected/no-effect label.

After rename, the service independently opens the visible root relative to the still-bound parent, repeats the complete observations, requires exact equality, and durably records `visible_bound`. Metadata begins only then. A metadata failure retains the visible object for recovery. Recovery may re-observe and classify but cannot manufacture profile eligibility, publication capability, ownership, or completion; it never deletes material whose ownership is ambiguous. A destination generation can complete at most once.

## Evidence status and WU-006 gate

The deterministic reference model and explicit corpus exercise these rules but do not establish Windows behaviour. Required evidence still includes an implementation candidate, admitted disposable target, exact target/configuration receipt, independent attacker harness, crash/fault injection around rename, independent post-state observation, and independent technical/security review.

OD-001 therefore remains open and blocks WU-006. WU-006 must not treat this profile document, the deterministic model, fixture data, or caller claims as target-bound evidence or a resolved platform-security decision.
