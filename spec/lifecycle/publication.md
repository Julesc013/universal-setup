---
type: "Engineering Specification"
title: "Protected staging and publication authority"
description: "Prevent staged-object substitution across the verification-to-publication interval."
tags: ["universal-setup","lifecycle"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"},{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "MS-FILE-RENAME","resource": "https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info","title": "Microsoft Learn: FILE_RENAME_INFO"},{"id": "MS-FILE-ID","resource": "https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info","title": "Microsoft Learn: FILE_ID_INFO"},{"id": "MS-FILE-SECURITY","resource": "https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights","title": "Microsoft Learn: File Security and Access Rights"}]
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
The candidate `windows_nt_x64_local_ntfs_service_sid_noreplace_v1` is unavailable and unsupported pending evidence. Its minimum design target is Windows NT x64 build 17763 with Windows SDK `10.0.17763.0`. If later implemented and independently admitted on that exact profile, it MUST use a dedicated `SERVICE_SID_TYPE_RESTRICTED` publisher and atomically create protected staging, destination-parent, state, and journal anchors from inception. Each anchor is owned by `SYSTEM`; its DACL is protected, has no inherited ACEs, and grants control only to `SYSTEM` and the exact service SID. A consumer can receive read/execute only after visible binding. No untrusted principal receives delete, write, append, add-child, delete-child, `WRITE_DAC`, or `WRITE_OWNER`. A pre-existing/inherited anchor makes the profile unavailable.

The same-login claim depends on that service boundary and handle provenance, not global handle enumeration: handles are non-inheritable and never inherited or duplicated outside the restricted service. A hostile handle is an outside-service handle carrying any content, namespace, owner, or DACL mutation access. Lost provenance or such a handle makes the profile unavailable. The protected set includes all anchors, roots, ancestors, and descendants.

The service observes owner and the exact self-relative security descriptor using `GetSecurityInfo`; stable identity using `GetFileInformationByHandleEx(FileIdInfo)`; reparse facts using `FileAttributeTagInfo`; link count using `FileStandardInfo`; exact streams using `FileStreamInfo`; and disabled case sensitivity using `FileCaseSensitiveInfo`. It requires local NTFS, one volume, non-reparse/case-insensitive ancestors, unchanged ancestor identity/security, a single final component, destination absence, and no replacement. Closure limits are 200,000 descendants, depth 128, 255 UTF-16 code units per component, 256 MiB serialized evidence, and 16 TiB total content. Every root/entry binds type, stable identity, file SHA-256 where applicable, size, attributes, exact binary-security-descriptor SHA-256, link count, exact stream set, and reparse facts.

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

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^USR-SYSPANE], [^USR-DISKED], [^CONVERSATION], [^MS-FILE-RENAME], [^MS-FILE-ID], [^MS-FILE-SECURITY].

[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^MS-FILE-RENAME]: [Microsoft Learn: FILE_RENAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info).
[^MS-FILE-ID]: [Microsoft Learn: FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info).
[^MS-FILE-SECURITY]: [Microsoft Learn: File Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).
