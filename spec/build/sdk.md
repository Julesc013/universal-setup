---
type: "Engineering Specification"
title: "SDK packaging, build graph and development dependencies"
description: "Make component use reproducible without exposing private implementation or mandatory authoring machinery."
tags: ["universal-setup","build"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "REPO-README","resource": "https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md","title": "Universal Setup pinned README"},{"id": "USR-REVIEW","resource": "urn:sha256:093e0aac0c7dc6e344967a1433b2517f2f5cfcaf5be4e566cccb6b38f24a0bfa","title": "User-supplied June provider architecture review; historical"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-SDK","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-API","USK-S-AUTHOR"]}
---

# SDK packaging, build graph and development dependencies

## Consumption modes
Source subdirectory/vendor snapshot, installed static SDK, installed shared SDK, process host and contracts-only package are separately tested. Existing CMake targets Headers/CoreStatic/CoreShared remain valid. Additional components are additive and clearly classified as experimental until callable and qualified.

Shared ABI consumers do not include private C++ headers. Static consumers still require compatible compiler/linker/CRT/standard-library closure. Publish that closure. Do not claim language independence at the static linker merely because exported headers are C.

## Build graph
Use domain-owned private libraries or object targets. Share object compilation only across matching PIC, export, runtime, warning, sanitizer and configuration settings; separate genuinely incompatible variants. One canonical source list feeds static/shared targets where appropriate. Compilers/languages are implementation choices within target profiles; public ABI behavior is stable.

Developer tools, generators, Python and CMake belong to build-host requirements, not installed product runtime requirements. Prepared source releases should include generated inputs needed for ordinary SDK builds, with hashes and regeneration commands. Installed SDK consumption should not require the whole development checkout or AIDE.

## Conformance
Test C and C++ includes, exact version discovery, relocation, static/shared link/run, old supported callers, package manifests, licence closure and symbols. CMake compatibility convenience never replaces exact product release locks. All build outputs use declared external/marker-owned roots consistent with repository workspace policy.

## Verifiable requirements

### USK-R-SDK-001 — Installed SDK independent

**Requirement.** An installed SDK consumer MUST build without private headers, repository-local generators or AIDE.

**Rationale.** External developers need a real package.

**Acceptance.** `USK-AT-SDK-001` in the acceptance catalogue.

### USK-R-SDK-002 — Matched object sharing

**Requirement.** Build deduplication MUST preserve configuration-specific runtime, PIC, exports and instrumentation semantics.

**Rationale.** Blind OBJECT reuse can produce broken binaries.

**Acceptance.** `USK-AT-SDK-002` in the acceptance catalogue.

### USK-R-SDK-003 — Prepared source closure

**Requirement.** A source release MUST identify required build tools and generated inputs and avoid hidden developer-machine state.

**Rationale.** Reconstruction should not depend on a home cache.

**Acceptance.** `USK-AT-SDK-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^REPO-README], [^USR-REVIEW], [^CONVERSATION].

[^REPO-README]: [Universal Setup pinned README](https://github.com/Julesc013/universal-setup/blob/0ca648a2c4fa8a37bb78a22639578093aecf6254/README.md).
[^USR-REVIEW]: User-supplied June provider architecture review; historical. [Source registry](../provenance/sources.json); identity `urn:sha256:093e0aac0c7dc6e344967a1433b2517f2f5cfcaf5be4e566cccb6b38f24a0bfa`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
