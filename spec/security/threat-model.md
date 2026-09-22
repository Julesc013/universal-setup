---
type: "Engineering Specification"
title: "Threat model and security claims"
description: "Bind every protection claim to an adversary, trust boundary and independently testable mechanism."
tags: ["universal-setup","security"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "MS-SERVICE-SID","resource": "https://learn.microsoft.com/en-us/windows/win32/services/service-sids","title": "Microsoft Learn: Service SIDs"},{"id": "MS-SERVICE-SID-INFO","resource": "https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info","title": "Microsoft Learn: SERVICE_SID_INFO"},{"id": "MS-FILE-SECURITY","resource": "https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights","title": "Microsoft Learn: File Security and Access Rights"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-THREAT","revision": "2","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-PUB","USK-S-POLICY"]}
---

# Threat model and security claims

## Assets and actors
Protect product payload identity, installation ownership, user data, setup journals, recovery material, publisher keys, credentials and legitimate native-package-manager state. Consider malicious archives, compromised mirrors, untrusted themes/connectors, hostile UI clients, local unprivileged users, same-principal processes, concurrent installers, stale workers and storage/OS failure.

Administrator/root and compromised kernel access are not automatically defeated by a user-mode installer. A provider may protect against weaker actors and explicitly exclude stronger ones. OS access control, process separation and exact authentication must support the claim. A local process is a crash boundary, not inherently a security sandbox; a Git worktree is not a sandbox.

## Trust boundaries
Source acquisition -> quarantine; bundle parser -> bounded semantic model; planner -> authorization; frontend -> worker; worker -> privileged broker; provider -> native OS; state -> independent verification; recovery source -> installed payload. Imported descriptions, document examples and AI output are untrusted data at every execution boundary.

## Candidate publication adversary ceiling
`windows_nt_x64_local_ntfs_service_sid_noreplace_v1` is a candidate design only. It admits an unrelated local unprivileged principal and a malicious same-user process attempting namespace or object substitution after plan authorization. Its intended enforcement boundary is a dedicated publisher service configured with `SERVICE_SID_TYPE_RESTRICTED`, creating the protected staging and destination DACL anchors as `SYSTEM`; it is not a claim that a service name, process mode, or caller assertion alone creates isolation.[^MS-SERVICE-SID][^MS-SERVICE-SID-INFO][^MS-FILE-SECURITY]

The candidate includes attacks attempting descendant insertion or replacement, identical-byte or changed-byte substitution, case-sensitive/reparse ancestor traversal, alternate data streams, multiple links, destination precreation, parent substitution, owner/DACL mutation, and concurrent publication. The profile requires the same live local NTFS volume observed through bound handles; it refuses any reparse point or case-sensitive ancestor, ADS, multiple-link object, pre-opened hostile handle, remote/non-NTFS/cross-volume target, or failed service-SID setup.

The ceiling explicitly excludes administrator, `SYSTEM`, publisher-service compromise, kernel or file-system filter compromise, offline-storage manipulation, denial of service, and unqualified power loss. A caller Boolean, path claim, content hash, or journal ID cannot raise the candidate's availability, qualification, authority, or support status. No runtime implementation, qualification, or support claim follows from this design.

## Security invariants
No implicit provider search; no shell command concatenation; no unchecked length/offset arithmetic; no untrusted symlink traversal; no mutable configuration reread after authorization; no raw credentials in plans; no unreviewed effects; no cleanup outside proven ownership; no quiet reduction of guarantees.

## Assurance
Maintain an attack tree and regression case for each trust boundary. Every new provider declares threat assumptions, residual risks and qualification. Standards/conformance citations are supporting methods, not certification. Security findings remain visible even when the current capability is intentionally refused.

## Verifiable requirements

### USK-R-THREAT-001 — Explicit adversary scope

**Requirement.** Security claims MUST identify excluded and included adversaries and actual OS enforcement mechanisms.

**Rationale.** Otherwise impossible guarantees become release promises.

**Acceptance.** `USK-AT-THREAT-001` in the acceptance catalogue.

### USK-R-THREAT-002 — Untrusted descriptions

**Requirement.** Imported metadata, themes, logs and AI suggestions MUST NOT be interpreted as executable instructions or grants.

**Rationale.** Prompt injection and code injection cross the same authority boundary.

**Acceptance.** `USK-AT-THREAT-002` in the acceptance catalogue.

### USK-R-THREAT-003 — Security regression retention

**Requirement.** A fixed security defect MUST retain a bounded reproducible regression test and affected-profile description.

**Rationale.** Knowledge must survive agents and refactors.

**Acceptance.** `USK-AT-THREAT-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^MS-SERVICE-SID], [^MS-SERVICE-SID-INFO], [^MS-FILE-SECURITY].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^MS-SERVICE-SID]: [Microsoft Learn: Service SIDs](https://learn.microsoft.com/en-us/windows/win32/services/service-sids).
[^MS-SERVICE-SID-INFO]: [Microsoft Learn: SERVICE_SID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info).
[^MS-FILE-SECURITY]: [Microsoft Learn: File Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).
