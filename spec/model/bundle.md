---
type: "Engineering Specification"
title: "Product Setup Bundle and machine-specific resolution"
description: "Distinguish signed deployment possibilities from exact local installation plans."
tags: ["universal-setup","model"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"},{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-BUNDLE","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-ID","USK-S-POLICY"]}
---

# Product Setup Bundle and machine-specific resolution

## Three artifacts
1. Product Setup Bundle: immutable release-time payloads, component alternatives, target selectors, recipes, provider requirements and presentation assets.
2. Machine Setup Plan: one resolved selection on a specific observed machine and installation.
3. Operation receipt: actual effects, verification, outcome and recovery records.

The bundle cannot precompute every customer path, installed predecessor, available disk space or maintenance window. It defines the allowed deployment space. Machine planning selects within that space and binds the result. A product-specific compiler may produce the bundle, or the USK authoring kit may compile declarative inputs; both feed the same contracts.

## Required bundle data
Publisher/product identity; opaque product version plus comparison scheme; channels; component graph; payload inventories; target variants; optional presentation pack; preservation classes; permitted scopes; prerequisite rules; migration edges; required runtime/USK versions; trust references; licensing/SBOM/provenance references; and a format version.

An artifact reference binds content digest, size, media/format type and expected inventory. Locations are separate acquisition hints. Secrets are never embedded. Consumer resources are finalized and signed before their payload inventory is fixed; setup wraps those exact bytes rather than rebuilding an installer edition.

## Component resolution
Inputs are bundle, requested features, host observations, existing installation, policy and provider catalogue. Validate IDs and target predicates; compute dependency closure; detect cycles/conflicts; select eligible variants; solve prerequisite ownership; calculate space and effects; emit explanations. Bounded deterministic resolution must stop with a typed complexity/resource limit rather than hang on adversarial graphs.

The prototype schemas in this archive intentionally model only a narrow reviewable core. Extension promotion to `contracts/` is required before real products may treat them as accepted contracts.

## Verifiable requirements

### USK-R-BUNDLE-001 — Separate bundle and plan

**Requirement.** A bundle MUST retain allowed deployment choices; a machine plan MUST bind the actual target, selections and observations.

**Rationale.** A build artifact cannot know customer state.

**Acceptance.** `USK-AT-BUNDLE-001` in the acceptance catalogue.

### USK-R-BUNDLE-002 — Exact portable payload

**Requirement.** A setup envelope MUST carry the same finalized payload bytes as the selected portable release.

**Rationale.** Avoids installer-only binaries and unverifiable rebuilding.

**Acceptance.** `USK-AT-BUNDLE-002` in the acceptance catalogue.

### USK-R-BUNDLE-003 — Bounded component solver

**Requirement.** Dependency resolution MUST detect cycles/conflicts and enforce declared computational limits.

**Rationale.** Hostile input must not exhaust authoring or endpoint hosts.

**Acceptance.** `USK-AT-BUNDLE-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^USR-DISKED], [^USR-SYSPANE].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
