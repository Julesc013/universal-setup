---
type: "Engineering Specification"
title: "Journals, recovery and independent maintenance"
description: "Recover exact operations without turning inspection into mutation or losing uncertainty."
tags: ["universal-setup","lifecycle"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"},{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-REC","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-TXN","USK-S-LEASE"]}
---

# Journals, recovery and independent maintenance

## Journal records
Each record contains format version, installation/operation/attempt IDs, sequence, previous-record digest, transition type, plan/policy/provider bindings and effect observations. Append and flush rules are profile-specific. A digest chain detects accidental alteration relative to a trusted anchor; it is not authenticity against an attacker who controls both records and anchor.

Readers validate bounded size, sequence, legal transitions, checksums, installation identity and format compatibility. Truncated final records may be classified as incomplete, not silently discarded if they affect authority. Unknown critical record types block automatic recovery. Recovery readers are kept available longer than writers.

## Recovery operation
Inspect is read-only. Recovery plan binds original operation, current observations and one permitted disposition: retry idempotent step, complete forward, compensate, restore retained generation, retain for operator. Apply revalidates everything again under an installation lease. Repeated recovery is idempotent or returns already-completed.

Repairing the application requires an intact trusted source even when maintenance is embedded in the primary executable. A recovery capsule records identities, format versions and acceptable source references, not secrets or fictitious authority. Self-maintenance executes outside the payload being replaced/removed; authenticated handoff and cleanup are separate qualified steps.

## Evidence retention
Retained staging, unknown files and unresolved recovery material are never age-deleted merely to tidy a workspace. Garbage collection uses explicit reachability and unresolved-operation pins. Support export redacts sensitive locators while retaining exact local audit references.

## Verifiable requirements

### USK-R-REC-001 — Read-only recovery inspection

**Requirement.** Recovery inspection MUST NOT mutate staging, targets, journals or ownership.

**Rationale.** Inspect cannot infer permission to repair.

**Acceptance.** `USK-AT-REC-001` in the acceptance catalogue.

### USK-R-REC-002 — Idempotent recovery

**Requirement.** A recovery apply MUST bind original context and remain safe across repeated invocation and interruption.

**Rationale.** Recovery itself can fail.

**Acceptance.** `USK-AT-REC-002` in the acceptance catalogue.

### USK-R-REC-003 — Damaged binary recovery

**Requirement.** Each maintained profile MUST provide a recovery route independent of the executable being repaired.

**Rationale.** Broken embedded code cannot repair itself.

**Acceptance.** `USK-AT-REC-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^USR-DISKED], [^USR-SYSPANE], [^CONVERSATION].

[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
