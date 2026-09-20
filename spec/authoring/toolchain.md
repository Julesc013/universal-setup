---
type: "Engineering Specification"
title: "Authoring tools and deterministic bundle compiler"
description: "Turn declarative product data into reproducible payload envelopes and usable setup products."
tags: ["universal-setup","authoring"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-AUTHOR","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-BUNDLE","USK-S-ARCHIVE","USK-S-TRUST"]}
---

# Authoring tools and deterministic bundle compiler

## Developer flow
A minimal producer points a product definition at an already finalized payload. Validate identity/paths/ownership, resolve components and target variants, inventory exact bytes, bind licences/trust/runtime requirements, select a qualified setup runtime/shell profile, compile the Product Setup Bundle and construct the carrier. Reopen every produced carrier and compare it with the resolved graph.

The authoring compiler may expose init, validate, inspect, resolve, build, bundle, test and release-verify commands. These names are proposed until implementation. A generic host can load a verified adjacent bundle; a prefab compiler can embed the bundle and assets into a target-specific executable. Both obey the same machine-planning contract.

## Signing and reproducibility
Finalize application signing before its immutable payload inventory. Finalize prefab resources before final installer signing. Signing/notarization/timestamping are distinct authorized transformations; unsigned reproducibility does not imply independent reproduction of the publisher's timestamped signature. Record exact pre/post transformation inputs and outputs.

## Build safety
Never execute arbitrary product manifest strings as shell. Compiler plugins follow the same explicit provider/trust constraints. Paths are rooted and normalized relative to the authored project; build outputs go to an explicitly owned external staging root. No developer home path, cache or private credentials may enter distribution. A packaging adapter may wrap/compress/project declared metadata but not invent product contents or support claims.

## Verifiable requirements

### USK-R-AUTHOR-001 — Deterministic bundle

**Requirement.** The same declared source, toolchain and profile inputs MUST produce the same specified unsigned bundle artifacts.

**Rationale.** Release composition must be inspectable.

**Acceptance.** `USK-AT-AUTHOR-001` in the acceptance catalogue.

### USK-R-AUTHOR-002 — Adapter fidelity

**Requirement.** Package adapters MUST NOT change product selections, ownership, preservation or runtime requirements beyond the resolved graph.

**Rationale.** MSI/ZIP/pkg scripts must not define different products.

**Acceptance.** `USK-AT-AUTHOR-002` in the acceptance catalogue.

### USK-R-AUTHOR-003 — No-code consumer

**Requirement.** The minimal authoring template MUST remain usable without copying or editing engine source.

**Rationale.** This is the prefab product promise.

**Acceptance.** `USK-AT-AUTHOR-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
