---
type: "Engineering Specification"
title: "Protected staging and publication authority"
description: "Prevent staged-object substitution across the verification-to-publication interval."
tags: ["universal-setup","lifecycle"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"},{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "MS-FILE-RENAME","resource": "https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info","title": "Microsoft Learn: FILE_RENAME_INFO"},{"id": "MS-FILE-ID","resource": "https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info","title": "Microsoft Learn: FILE_ID_INFO"},{"id": "MS-FILE-SECURITY","resource": "https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights","title": "Microsoft Learn: File Security and Access Rights"},{"id": "MS-FILE-ATTRIBUTE-TAG","resource": "https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_attribute_tag_info","title": "Microsoft Learn: FILE_ATTRIBUTE_TAG_INFO"},{"id": "MS-FILE-STANDARD","resource": "https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_standard_info","title": "Microsoft Learn: FILE_STANDARD_INFO"},{"id": "MS-FILE-STREAM-INFO","resource": "https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_stream_info","title": "Microsoft Learn: FILE_STREAM_INFO"},{"id": "MS-CASE-SENSITIVITY","resource": "https://learn.microsoft.com/en-us/windows/wsl/case-sensitivity","title": "Microsoft Learn: Windows filesystem case sensitivity"},{"id": "MS-FILE-INFO-CLASS","resource": "https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ne-minwinbase-file_info_by_handle_class","title": "Microsoft Learn: FILE_INFO_BY_HANDLE_CLASS"},{"id": "MS-VOLUME-BY-HANDLE","resource": "https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew","title": "Microsoft Learn: GetVolumeInformationByHandleW"},{"id": "MS-REMOTE-PROTOCOL","resource": "https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_remote_protocol_info","title": "Microsoft Learn: FILE_REMOTE_PROTOCOL_INFO"},{"id": "MS-FILE-NAME-INFO","resource": "https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_name_info","title": "Microsoft Learn: FILE_NAME_INFO"},{"id": "MS-WINDOWS-NAMES","resource": "https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file","title": "Microsoft Learn: Naming Files, Paths, and Namespaces"},{"id": "MS-FILE-STREAMS","resource": "https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams","title": "Microsoft Learn: File Streams"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-PUB","revision": "2","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-TXN","USK-S-CAPS"]}
---

# Protected staging and publication authority

## Threat model first
Name adversaries separately: unrelated unprivileged principal, malicious process under the same principal, administrator/root, privileged kernel actor, compromised storage and concurrent cooperative installers. A platform cannot honestly defeat every actor. A publisher profile specifies exactly which namespace/object changes it excludes and by what OS mechanism.

The prior staged-child substitution finding is a retained regression. Rehashing once or observing the parent again does not by itself protect verified descendants until publication. The strong `staged_child_bound_v1` promise needs a qualified platform implementation, not a trust Boolean.

## Protocol obligations
Create staging beneath an authorized protected parent; bind native handles/identities and access policy; materialize with no-follow semantics; prevent or detect prohibited descendant insertion/replacement; verify full selected closure; publish into an independently bound destination namespace; confirm the visible object matches the verified object; durably record publication. A target-specific sequence must document residual race windows and reader visibility.

For same-principal adversaries, explicit sandbox/broker separation or a weaker documented assumption may be required. A path string, same-binary process mode or worktree does not create isolation. If no available provider satisfies the recipe's guarantee, refuse; do not fall back silently.

## Candidate handle-bound protocol
The candidate `windows_nt_x64_local_ntfs_service_sid_noreplace_v1` is unavailable and unsupported pending evidence. Its minimum design target is Windows NT x64 build 17763 with Windows SDK `10.0.17763.0`; Microsoft documents that per-directory case sensitivity began in build 17107, but this profile deliberately chooses the later Windows 10/Server 2019 servicing floor.[^MS-CASE-SENSITIVITY] If later implemented and independently admitted on that exact profile, it MUST use a dedicated `SERVICE_SID_TYPE_RESTRICTED` publisher and atomically create protected staging, destination-parent, state, and journal anchors from inception. Each anchor is owned by `SYSTEM`; its DACL is protected, has no inherited ACEs, and grants control only to `SYSTEM` and the exact service SID. A consumer can receive read/execute only after visible binding. No untrusted principal receives delete, write, append, add-child, delete-child, `WRITE_DAC`, or `WRITE_OWNER`. A pre-existing/inherited anchor makes the profile unavailable.

The same-login claim depends on that service boundary and handle provenance, not global handle enumeration: handles are non-inheritable and never inherited or duplicated outside the restricted service. A hostile handle is an outside-service handle carrying any content, namespace, owner, or DACL mutation access. Lost provenance or such a handle makes the profile unavailable. The protected set includes all anchors, roots, ancestors, and descendants. Every protected root/anchor/ancestor role binds a distinct canonical volume-relative `FileNameInfo` path and composite stable identity from the same handle. A mandatory single-component publication-root observation starts the complete immediate-parent chain, and every anchor is a direct child of its deepest recorded ancestor; an omitted root boundary, aliases, unrelated paths, and a caller `ancestors_revalidated` Boolean are refused.

An independent observer parses owner, control flags, every ACE, and effective rights from `GetSecurityInfo` output obtained from the same object handle used for identity. Every anchor, ancestor, root, and descendant must show `SYSTEM` ownership, a protected DACL, no inherited or other ACEs, exactly the `SYSTEM` and restricted-service-SID allow sets, and no mutation rights for the initiating or untrusted principals. The model recomputes a deterministic SHA-256 over those canonical parsed facts, so changing an opaque digest cannot satisfy the predicate. This is a consistency check over independent observer output, not a replacement for Windows `AccessCheck`, an attacker harness, or platform proof.[^MS-FILE-SECURITY]

The observer obtains stable identity using `GetFileInformationByHandleEx(FileIdInfo)`; attributes and reparse tags using `FileAttributeTagInfo`; link count using `FileStandardInfo`; exact streams using `FileStreamInfo`; and disabled per-directory case sensitivity using `FileCaseSensitiveInfo`.[^MS-FILE-ID][^MS-FILE-ATTRIBUTE-TAG][^MS-FILE-STANDARD][^MS-FILE-STREAM-INFO][^MS-FILE-INFO-CLASS][^MS-CASE-SENSITIVITY] `GetVolumeInformationByHandleW` supplies the volume label (not a GUID path), 32-bit serial, filesystem name, maximum component length, and exact raw filesystem-flags DWORD; the value must be in `0..0xffffffff`, and required bits are tested by mask without discarding extra returned bits.[^MS-VOLUME-BY-HANDLE] The `FILE_ID_INFO` 64-bit volume serial has that DWORD as its low-order 32 bits but is not required to be its zero-extension. On the admitted local NTFS probe, `FileRemoteProtocolInfo` returns `ERROR_INVALID_PARAMETER` (87) and no output structure; a fabricated all-zero protocol tuple is refused.[^MS-REMOTE-PROTOCOL] Every anchor, ancestor, sealed/visible root, and descendant `FILE_ID_INFO` composite is parsed and its volume prefix must equal the admitted 64-bit serial. A wholesale root move to another prefix refuses even if all moved entries agree with each other.

`FileNameInfo` binds the destination-parent handle name and, after rename, the actual visible final component; the profile stores that `destination_name`, validates it before use, and requires the post-rename component to match. An independent relative open must return `ERROR_FILE_NOT_FOUND` before the no-replace rename.[^MS-FILE-NAME-INFO] The destination and every closure component use one canonical relative representation: no absolute, drive, UNC, device-prefix, backslash, empty, dot/dot-dot, colon/ADS, control, forbidden Win32 character, trailing dot/space, or reserved DOS device name; each component is at most 255 UTF-16 units.[^MS-WINDOWS-NAMES][^MS-FILE-STREAMS] Case-fold aliases refuse. Every intermediate path must exist in the closure as a directory, so missing parents and file-as-parent trees refuse. Closure limits remain 200,000 descendants, depth 128, 256 MiB serialized evidence, and 16 TiB total content. Every root/entry binds type, composite stable identity, file SHA-256 where applicable, size, attributes, structured security evidence/digest, link count exactly one, exact unnamed `::$DATA` stream for files/no streams for directories, and consistent reparse attribute/flag/tag facts; every reparse entry is ultimately refused. The sealed root equals the protected staging root; descendants are pairwise identity-distinct and disjoint from all protected identities. Attributes are a canonical duplicate-free admitted set, with `FILE_ATTRIBUTE_DIRECTORY` present exactly for directory entries; cross-set identity reuse or type/attribute contradiction refuses.

The state sequence is `unavailable`, `protected_empty`, `materializing`, `sealed`, `publish_prepared`, `renamed_unconfirmed`, `visible_bound`, `metadata_pending`, `completed`, with terminal `refused_retained` and `recovery_required`. Before visibility it durably records `publish_prepared`, including bound parent/root/closure evidence. It calls `SetFileInformationByHandle` with `FileRenameInfo` and `ReplaceIfExists=FALSE` relative to the bound destination parent. Rename is explicitly `applied`, `not_applied`, or `unknown`; crash ambiguity is retained recovery. It then reopens the visible object relative to the bound parent and requires explicit exact root and per-descendant equality—missing observation never defaults to sealed evidence—before durable `visible_bound` and metadata.[^MS-FILE-RENAME][^MS-FILE-ID][^MS-FILE-SECURITY]

Preflight from a later phase, repeat rename, replacement, and continuation after a terminal result are invalid/refused. A foreign object never completes; a destination generation completes once only. Any failure, ambiguity, crash, or excluded privileged actor after an applied/unknown rename retains material and returns `recovery_required`, never no-effect. Recovery cannot manufacture profile evidence, capability, ownership, or completion and never deletes ambiguous visible material. These API names and the deterministic model describe a target design; they are not evidence of an existing implementation or platform proof.

## Recovery boundaries
Keep enough metadata to distinguish not published, published but state incomplete, and ambiguous. Never delete a visible object whose ownership cannot be proved from the original plan and current identity. Recovery can retain-for-operator rather than claiming an unsafe automated undo.

## Verifiable requirements

### USK-R-PUB-001 — Bind descendants through publish

**Requirement.** A publisher claiming protected staged-child authority MUST exclude or detect unauthorized substitution of every verified published descendant throughout its claimed protection interval.

**Rationale.** Parent identity and one hash are insufficient.

**Acceptance.** `USK-AT-PUB-001` in the acceptance catalogue.

### USK-R-PUB-002 — Unmet publisher refuses

**Requirement.** Unavailable publication protection MUST remain an explicit no-effect refusal for profiles requiring it.

**Rationale.** No feature demo may widen guarantees.

**Acceptance.** `USK-AT-PUB-002` in the acceptance catalogue.

### USK-R-PUB-003 — Publication evidence

**Requirement.** Publication receipts MUST bind the verified closure and actual visible target identity, including incomplete metadata disposition.

**Rationale.** Metadata can fail after commit.

**Acceptance.** `USK-AT-PUB-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^USR-SYSPANE], [^USR-DISKED], [^CONVERSATION], [^MS-FILE-RENAME], [^MS-FILE-ID], [^MS-FILE-SECURITY], [^MS-FILE-ATTRIBUTE-TAG], [^MS-FILE-STANDARD], [^MS-FILE-STREAM-INFO], [^MS-CASE-SENSITIVITY], [^MS-FILE-INFO-CLASS], [^MS-VOLUME-BY-HANDLE], [^MS-REMOTE-PROTOCOL], [^MS-FILE-NAME-INFO], [^MS-WINDOWS-NAMES], [^MS-FILE-STREAMS].

[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^MS-FILE-RENAME]: [Microsoft Learn: FILE_RENAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info).
[^MS-FILE-ID]: [Microsoft Learn: FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info).
[^MS-FILE-SECURITY]: [Microsoft Learn: File Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).
[^MS-FILE-ATTRIBUTE-TAG]: [Microsoft Learn: FILE_ATTRIBUTE_TAG_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_attribute_tag_info).
[^MS-FILE-STANDARD]: [Microsoft Learn: FILE_STANDARD_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_standard_info).
[^MS-FILE-STREAM-INFO]: [Microsoft Learn: FILE_STREAM_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_stream_info).
[^MS-CASE-SENSITIVITY]: [Microsoft Learn: Windows filesystem case sensitivity](https://learn.microsoft.com/en-us/windows/wsl/case-sensitivity).
[^MS-FILE-INFO-CLASS]: [Microsoft Learn: FILE_INFO_BY_HANDLE_CLASS](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ne-minwinbase-file_info_by_handle_class).
[^MS-VOLUME-BY-HANDLE]: [Microsoft Learn: GetVolumeInformationByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew).
[^MS-REMOTE-PROTOCOL]: [Microsoft Learn: FILE_REMOTE_PROTOCOL_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_remote_protocol_info).
[^MS-FILE-NAME-INFO]: [Microsoft Learn: FILE_NAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_name_info).
[^MS-WINDOWS-NAMES]: [Microsoft Learn: Naming Files, Paths, and Namespaces](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).
[^MS-FILE-STREAMS]: [Microsoft Learn: File Streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams).
