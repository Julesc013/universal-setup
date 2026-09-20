---
type: "Engineering Specification"
title: "Portability profiles and early compatibility canaries"
description: "Separate portable semantics, source standards, loader floors and actual target execution."
tags: ["universal-setup","build"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "USR-SYSPANE","resource": "urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879","title": "User-supplied SysPane setup integration review"},{"id": "USR-DISKED","resource": "urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0","title": "User-supplied DiskEd setup integration review"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-PORT","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-CAPS","USK-S-SDK"]}
---

# Portability profiles and early compatibility canaries

## Dimensions
Each profile identifies data representation, API/ABI, compiler/runtime, loader imports, OS capabilities, filesystem, frontend, delivery and assurance. A public C ABI does not establish Windows XP, classic Mac, DOS, old glibc or every Unix support. C++17 remains the hosted implementation strategy; small compatibility implementations can use another language subset where a proven target requires it.

## Development sequence
Keep modern local profiles moving while running an early read-only downlevel canary before public API freeze. The canary discovers integer/encoding/thread/runtime assumptions cheaply. It does not enable unqualified mutation. Historical target support is a separately versioned implementation/profile programme, not an excuse to constrain every modern shell to old APIs.

## Binary gates
Windows: machine/subsystem/imports/CRT/exports/manifest/ISA. macOS: architectures, deployment target, strong/weak imports, framework/dylib closure, bundle signing behavior. ELF: interpreter, DT_NEEDED, GLIBC/GLIBCXX/CXXABI versions, RPATH/RUNPATH and ISA. Cross-build success must be recorded separately from loader/run proof.

## Filesystems and metadata
Qualify NTFS/FAT/exFAT, APFS/HFS+, ext4/XFS/btrfs and selected network/removable profiles as needed rather than declaring all variants mandatory. Each profile names exact operation guarantees and loss behavior. A legacy client may inspect a modern plan and truthfully report local executor unavailable.

## Verifiable requirements

### USK-R-PORT-001 — No build-only support claim

**Requirement.** A supported target claim MUST include required loader/runtime/behavior evidence, not merely a cross-compile.

**Rationale.** Source portability and runtime compatibility differ.

**Acceptance.** `USK-AT-PORT-001` in the acceptance catalogue.

### USK-R-PORT-002 — Explicit platform floors

**Requirement.** Each binary release MUST declare and audit its OS/runtime/architecture/ISA floor and selected provider closure.

**Rationale.** Modern dependencies can silently raise support floor.

**Acceptance.** `USK-AT-PORT-002` in the acceptance catalogue.

### USK-R-PORT-003 — Reduced profiles retain semantics

**Requirement.** A reduced compatibility profile MUST preserve recognized data and refuse unavailable operations without pretending modern guarantees.

**Rationale.** Legacy can be useful without equal capability.

**Acceptance.** `USK-AT-PORT-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^USR-SYSPANE], [^USR-DISKED], [^CONVERSATION].

[^USR-SYSPANE]: User-supplied SysPane setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:0bb15977ef76559f166352751b0043060ff240a844d97d6a7b74a41e95185879`.
[^USR-DISKED]: User-supplied DiskEd setup integration review. [Source registry](../provenance/sources.json); identity `urn:sha256:9299eec8bc1709009beb0500c99382483b63c8a34fa74adf2e473ceabd5de0b0`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
