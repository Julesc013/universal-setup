---
type: "Engineering Specification"
title: "Targets, capabilities, guarantees and support claims"
description: "Select concrete implementations without conflating representation, permission, proof and support."
tags: ["universal-setup","model"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "MS-SERVICE-SID","resource": "https://learn.microsoft.com/en-us/windows/win32/services/service-sids","title": "Microsoft Learn: Service SIDs"},{"id": "MS-FILE-SECURITY","resource": "https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights","title": "Microsoft Learn: File Security and Access Rights"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-CAPS","revision": "2","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-ID"]}
---

# Targets, capabilities, guarantees and support claims

## Target profile
A target profile binds OS family/minimum, architecture, instruction baseline, ABI, runtime libraries, executable form, filesystem assumptions, chosen frontend, delivery model and security assumptions. Build-host tools have a separate profile. A cross-build is not a target execution result.

## Capability record
Represent independently: known semantics, implementation state, realization mode, provider identity, current availability, required privilege, permission, qualification scope, support state and recovery ceiling. A record can be implemented but unauthorized, represented but unavailable, or qualified on NTFS but unqualified on removable exFAT.

Resolution intersects requirement, target constraints, provider capabilities, guarantee floor, trust policy, administrator/deployment/product policy and current observations. Explicit preferences break ties only among eligible providers. An unresolved tie refuses. Never select by directory enumeration, PATH or module load order.

A selected-provider result records rejected candidates and reasons, effective constraints, relevant evidence references, exact implementation digest and plan invalidation inputs. Runtime revalidation may refuse a stale selection; it must not silently choose a materially different provider after plan review.

## Candidate publication profile record
The selected design direction is `windows_nt_x64_local_ntfs_service_sid_noreplace_v1`: Windows NT x64, one live local NTFS volume, and a dedicated restricted-service-SID publisher. Its record is deliberately `implementation: absent`, `availability: false`, `qualification: not_run`, and `support: unsupported`. The record is a candidate design, not an eligible provider and not a support declaration.[^MS-SERVICE-SID][^MS-FILE-SECURITY]

The minimum candidate platform is Windows NT x64 build 17763 with SDK `10.0.17763.0`. Eligibility requires closed, independently typed same-handle evidence for the restricted service SID; per-object `SYSTEM` ownership, protected non-inherited exact DACL/ACE/effective-right facts and their recomputed canonical digest; service-created-from-inception anchors and never-inherited/never-duplicated handle provenance; a qualified dedicated volume-root boundary with no untrusted `FILE_DELETE_CHILD` and no filesystem parent outside the evidence chain; pairwise-distinct observed paths and identities forming a complete immediate chain from that root through the publication root to the anchors; the handle-returned NTFS volume label, DWORD serial, full raw flags constrained to `0..0xffffffff`, and local `FileRemoteProtocolInfo` failure `ERROR_INVALID_PARAMETER` (87), not a synthetic zero tuple; the `FILE_ID_INFO` 64-bit serial whose low DWORD matches the volume-information serial, without a zero-extension assumption; matching parsed volume prefixes, the sealed root equal to the protected staging root, and closure identities disjoint from every other protected identity; non-reparse, case-insensitive, identity/security-revalidated ancestors; actual `FileNameInfo` destination component plus absent-open result and no-replace rename; canonical Windows components, type/`FILE_ATTRIBUTE_DIRECTORY` agreement, and complete directory ancestry; and exact bounded root/descendant facts. Admission, seal, immediate pre-rename, and post-reopen each require the full protected-chain and volume/locality observation; only the staging root's expected post-rename path may differ. Bounds are 200,000 descendants, depth 128, 255 UTF-16 units per component, 256 MiB serialized evidence, and 16 TiB content. Evidence is obtained with the documented handle APIs for security, `FileIdInfo`, `FileAttributeTagInfo`, `FileStandardInfo`, `FileStreamInfo`, `FileCaseSensitiveInfo`, `GetVolumeInformationByHandleW`, `FileRemoteProtocolInfo`, and `FileNameInfo`.

Unknown/missing fields, invalid types, pre-existing anchors, lost provenance, named streams, multiple links, or a caller-provided `available`, trusted-path, hash, journal identifier, or equivalent Boolean/claim MUST NOT upgrade any record dimension or satisfy a required guarantee. Until independent target evidence changes the production record, resolution for a protected-publication request is a no-effect refusal. The deterministic model is specification evidence only, not a platform proof.

## Guarantee profile
Use independent dimensions: publication visibility, identity protection, restart recovery, durability, concurrent-reader behavior, rollback/compensation, cross-volume behavior and external-owner delegation. T0/T1/T2/T3 may be UI summaries, not substitutes for those dimensions. T3 requires actual abrupt-power-loss evidence on the named storage profile. Do not define all guarantees as a single sortable integer: they form a constrained compatibility relation.

Historical targets may inspect modern records without implementing modern mutation. A modern helper or remote gateway is an explicitly selected different topology with its own trust boundary, not a hidden downlevel implementation.

## Verifiable requirements

### USK-R-CAPS-001 — No support Boolean

**Requirement.** Capability discovery MUST expose implementation, authority, qualification and support separately.

**Rationale.** Avoids claims inferred from enum existence.

**Acceptance.** `USK-AT-CAPS-001` in the acceptance catalogue.

### USK-R-CAPS-002 — Deterministic selection

**Requirement.** Equal eligible provider candidates without an explicit tie-break policy MUST produce ambiguity refusal before effects.

**Rationale.** Selection order is not policy.

**Acceptance.** `USK-AT-CAPS-002` in the acceptance catalogue.

### USK-R-CAPS-003 — Qualified guarantees

**Requirement.** An operation MUST refuse when any required guarantee is not supplied by the selected profile.

**Rationale.** No silent security downgrade.

**Acceptance.** `USK-AT-CAPS-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^MS-SERVICE-SID], [^MS-FILE-SECURITY].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^MS-SERVICE-SID]: [Microsoft Learn: Service SIDs](https://learn.microsoft.com/en-us/windows/win32/services/service-sids).
[^MS-FILE-SECURITY]: [Microsoft Learn: File Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).
