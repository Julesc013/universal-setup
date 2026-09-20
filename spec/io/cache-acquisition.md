---
type: "Engineering Specification"
title: "Acquisition, verified cache and offline media"
description: "Separate obtaining trusted material from installed-state mutation and selection."
tags: ["universal-setup","io"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-CACHE","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-STREAM","USK-S-OWN"]}
---

# Acquisition, verified cache and offline media

## Boundaries
Product policy chooses candidate artifacts and rights/entitlement posture. A source/trust adapter acquires and verifies material into quarantine/cache. USK planning consumes an exact acceptable source. Successful download is not installation, authenticity or permission to execute.

Start with local directory/archive/offline media. Optional networking implements bounded redirects, explicit credential providers, domain policy, proxy handling, resume, deadlines and bandwidth/space budgets. Resume must bind the same object identity and reverify final bytes; an HTTP range success cannot establish stable content by itself.

## Cache
Content-addressed objects are immutable verified blobs keyed by named digest algorithm and length. Temporary/unverified data uses a separate namespace. Atomically publish only after verification. Maintain references for packages, repair sources, active operations and retention policy. Cache presence does not select product content or establish installation ownership.

Deduplication across trust scopes is permitted only when privacy, access controls, licensing and verification policy allow it. Avoid exposing whether another user has cached a sensitive artifact. Do not hardlink writable installed files to cache objects. Offline bundles include required manifests, packages, trust metadata and compatibility information, not credentials.

## Optimization
Delta transfer is an optional acquisition optimization. Reconstruct the full exact artifact, verify its digest, then feed the same installation pipeline. Do not create a second delta-specific mutation engine. GC is reviewed and reachability-aware, not a recursive age-based cleanup of unknown directories.

## Verifiable requirements

### USK-R-CACHE-001 — Acquisition cannot install

**Requirement.** A source connector MUST NOT mutate installation roots or authoritative setup state.

**Rationale.** Network compromise should not become installation authority.

**Acceptance.** `USK-AT-CACHE-001` in the acceptance catalogue.

### USK-R-CACHE-002 — Resume verifies final identity

**Requirement.** A resumed download MUST verify the complete final artifact identity before cache admission.

**Rationale.** Remote object can change between ranges.

**Acceptance.** `USK-AT-CACHE-002` in the acceptance catalogue.

### USK-R-CACHE-003 — Offline self-sufficiency

**Requirement.** An offline profile MUST enumerate all required payload, trust and runtime dependencies before deployment.

**Rationale.** Air gaps expose hidden prerequisites.

**Acceptance.** `USK-AT-CACHE-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
