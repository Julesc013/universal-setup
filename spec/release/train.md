---
type: "Engineering Specification"
title: "Release trains, exact locks and maintenance"
description: "Version contracts independently and ship bounded support promises through evidence gates."
tags: ["universal-setup","release"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "OWNER-DECISION-20260922","resource": "urn:sha256:ed6bab5a72716c8f03e58248c97ff1d69e600e4a14808e3192d7c0b4f92ec9bb","title": "Owner selection of initial platform, compatibility policy and 1.1 release train"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-REL","revision": "2","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-SDK","USK-S-MIG","USK-S-TRUST"]}
---

# Release trains, exact locks and maintenance

## Version axes
Track release SemVer, CMake compatibility version, C ABI, provider SPI, command protocol, bundle schema, plan schema, installed state, journal format, TCK and target profile separately. The current 1.0.0 CMake SDK is a baseline identity, not proof of a stable complete setup platform.

## Proposed release stages
Core preview: existing bounded kernel. Lifecycle alpha: qualified local install/update/recovery subset. Application-kit alpha: no-code authoring, CLI/TUI and first native shell. Beta: frozen supported profile with complete lifecycle and different consumers. RC: source/contracts/package scope frozen, only release corrections. Supported 1.x: explicit compatibility, migration and servicing guarantees. Exact future minor allocations require a release decision; do not spend the same version on incompatible meanings.

## Selected 1.1 direction
The selected development train is Universal Setup 1.1, targeting `1.1.0 — Local Setup Foundation` through Alpha, Beta, RC and supported-release gates.[^OWNER-DECISION-20260922] The release objective is a complete local authoring-to-maintenance product: qualified safety core, local lifecycle, declarative authoring, shared application service, SDK, CLI/machine mode, both TUI modes, first native OEM+ shell, independent recovery, exact distribution inventory and consumer/accessibility qualification.

This allocation does not establish release readiness, allocate an Alpha, or grant signing, tagging or publication. Production signing identity, key custody, publisher trust, publication approval and qualification of exact candidate bytes remain outstanding under OD-008. If implementation requires a breaking public contract, use an explicit breaking boundary rather than conceal incompatibility under `1.1.0`.

## Branch law
Respect current task -> dev -> reviewed main promotion -> dev ancestry synchronization. Stable consumers pin accepted main source/tree plus exact package manifest and artifact identities. Canary task/dev inputs remain marked noncanonical and never silently update tracked consumer locks. This spec does not activate protected integration or publication.

## Releases
Build fresh, finalize payload, construct carrier, reopen/compare, attest, approve per channel, publish immutable assets. Withdraw through a new record referencing affected digests; do not retarget tags. Snapshot and alpha cadence follows release-significant changes, not every prose edit.

## Maintenance
Patch releases preserve supported data and automation behavior. Deprecations identify replacement and overlap period; removals occur at an explicit breaking boundary. Retain recovery readers and known-good packages as needed. Support and EOL policy must include security response, key loss, incident handling and user recovery guidance.

## Verifiable requirements

### USK-R-REL-001 — Exact consumer locks

**Requirement.** A deployed consumer MUST bind provider source/tree, package version, artifact identity, ABI and contract set rather than a floating branch.

**Rationale.** Packages with same labels may contain different implementations.

**Acceptance.** `USK-AT-REL-001` in the acceptance catalogue.

### USK-R-REL-002 — Immutable publication

**Requirement.** Published release tags and assets MUST NOT be replaced to hide defects.

**Rationale.** Users need stable provenance and withdrawal records.

**Acceptance.** `USK-AT-REL-002` in the acceptance catalogue.

### USK-R-REL-003 — Separate maturity

**Requirement.** Package/API version MUST NOT automatically set stable support or qualification.

**Rationale.** Existing version labels are not evidence.

**Acceptance.** `USK-AT-REL-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^OWNER-DECISION-20260922].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^OWNER-DECISION-20260922]: Owner selection of initial platform, compatibility policy and 1.1 release train. [Source registry](../provenance/sources.json); identity `urn:sha256:ed6bab5a72716c8f03e58248c97ff1d69e600e4a14808e3192d7c0b4f92ec9bb`.
