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
The candidate `windows_nt_x64_local_ntfs_service_sid_noreplace_v1` is unavailable and unsupported pending evidence. If later implemented and independently admitted on its exact profile, it MUST first preflight the bound destination parent and same live local NTFS volume, then create explicit protected staging and destination DACL anchors owned by `SYSTEM` through the dedicated restricted service SID. It materializes the selected closure through handles only, with bounded count/depth/name/byte closure checks; it refuses reparse or case-sensitive ancestors, ADS, multiple links, and hostile pre-opened handles.

Before visibility it durably records `publish_prepared`, including bound parent/file identities and closure. It calls `SetFileInformationByHandle` with `FileRenameInfo` and `ReplaceIfExists=FALSE` using the bound destination parent, then confirms `FILE_ID_INFO` identity and complete closure from the visible object, durably records `visible_bound`, and only then records metadata. These API names describe a target design; they are not evidence of an existing implementation.[^MS-FILE-RENAME][^MS-FILE-ID][^MS-FILE-SECURITY]

Any failure, ambiguity, or crash retains the staging/visible material for an operator and returns `recovery_required`; recovery never manufactures an unavailable capability and never deletes an ambiguous visible object. The candidate's replacement operation, if expressly authorized by a future profile, is a journaled two-rename procedure with a reader visibility gap. It is not an atomic exchange and MUST NOT be advertised as one.

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
