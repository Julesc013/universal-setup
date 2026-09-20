---
type: "Engineering Specification"
title: "Verification levels, TCK and independent acceptance"
description: "Tie every requirement to an oracle and evidence without mistaking test designs for executed proof."
tags: ["universal-setup","verification"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "USR-FACMAN","resource": "urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4","title": "User-supplied September 6 FacMan and native-interface programme; historical"},{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-TEST","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-AUTH","USK-S-REL"]}
---

# Verification levels, TCK and independent acceptance

## Evidence classes
E0 syntax/schema/static; E1 unit/property/reference-model; E2 provider/integration; E3 exact package/clean-host; E4 real consumer/route; E5 human experience. A capability selects the required classes and target profiles. Passing a spec validator establishes only specification-package integrity/consistency, not E1–E5 product conformance.

## TCK families
Source/stream, archive/path, target/publication, transaction/recovery, state/migration, trust, native effects, prerequisites, process protocol, presentation, authoring, embedding SDK and consumer integration. Each includes positive, negative, repeated, corrupted, concurrency and failure scenarios as relevant. Test doubles must not supply their own unverified success oracle.

## Evidence identity
Each result binds source/spec/contract hashes, dependencies, toolchain, target/filesystem, fixture, command, start/end, observed status, output artifacts, failures/skips and limitations. Support evidence is immutable; a new report may supersede it but must not edit failed history into a pass. Skips need reason and admission impact.

## Scaling assurance
Fast PR checks run affected tests. Accepted integration runs the full hosted matrix. Candidate builds add clean machines and package lifecycle. Extended fault/endurance/destructive tests use separately admitted labs. Unknown test impact selects conservative review. Source/doc changes do not all invalidate the same evidence, but actual signed package-byte changes may invalidate package/human receipts.

## Verifiable requirements

### USK-R-TEST-001 — Requirement trace

**Requirement.** Every normative requirement MUST reference at least one acceptance definition with fixture, procedure, expected result, negative control and independent oracle.

**Rationale.** Unverifiable prose cannot guide autonomous completion.

**Acceptance.** `USK-AT-TEST-001` in the acceptance catalogue.

### USK-R-TEST-002 — Evidence exactness

**Requirement.** A result MUST bind exact material inputs and preserve failures and skips.

**Rationale.** Old passing evidence must not certify changed behavior.

**Acceptance.** `USK-AT-TEST-002` in the acceptance catalogue.

### USK-R-TEST-003 — Human acceptance distinct

**Requirement.** Native usability and accessibility acceptance MUST not be synthesized from automated screenshots or tree checks alone.

**Rationale.** Machine structure is not human experience.

**Acceptance.** `USK-AT-TEST-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^USR-FACMAN], [^USR-SYSPANE].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^USR-FACMAN]: User-supplied September 6 FacMan and native-interface programme; historical. [Source registry](../provenance/sources.json); identity `urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4`.
[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
