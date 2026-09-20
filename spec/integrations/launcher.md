---
type: "Engineering Specification"
title: "Universal Launcher handoff and optional quiescence"
description: "Coordinate installed generations and runnable references without a circular mandatory dependency."
tags: ["universal-setup","integrations"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "USR-REVIEW","resource": "urn:sha256:093e0aac0c7dc6e344967a1433b2517f2f5cfcaf5be4e566cccb6b38f24a0bfa","title": "User-supplied June provider architecture review; historical"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-ULK","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-GEN","USK-S-REL"]}
---

# Universal Launcher handoff and optional quiescence

USK produces exact plan/result/installed-state/generation/audit references. ULK consumes those to refresh install references, invalidate launch plans and hold generation-use leases. ULK does not mutate installed software; USK does not interpret product launch intent, game profiles or Last Run.

A setup operation may require product quiescence or safe retained-generation behavior. The product supplies a bounded coordination protocol or an admitted ULK adapter. No kill-by-name or broad process termination is inferred. A bare CLI application installation can operate without ULK by using the profile's conservative no-active-use/precondition strategy.

## Joint compatibility
Pin the handoff schema/ABI, owning source revision and consumer adapter. Cross-repo tests create a USK result, project it into an ULK install reference, verify stale launch-plan handling, retain active-generation leases and release them only on terminal session/recovery rules. Native package-manager ownership remains visible in the reference.

Keep package version, ABI, handoff schema and implementation digest separate. An ULK canary using a provider task head is exploratory; stable consumption uses an accepted exact provider package. No atomic three-repository merge or floating branch pin is required.

## Verifiable requirements

### USK-R-ULK-001 — One-way mutation boundary

**Requirement.** ULK integration MUST NOT implement USK file/state mutation or require USK to understand product launch semantics.

**Rationale.** Ownership separation enables independent releases.

**Acceptance.** `USK-AT-ULK-001` in the acceptance catalogue.

### USK-R-ULK-002 — Lease-aware setup

**Requirement.** When a profile permits updating beside active sessions, it MUST retain used generations until their leases are safely released.

**Rationale.** Running processes may depend on old files.

**Acceptance.** `USK-AT-ULK-002` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^USR-REVIEW], [^CONVERSATION].

[^USR-REVIEW]: User-supplied June provider architecture review; historical. [Source registry](../provenance/sources.json); identity `urn:sha256:093e0aac0c7dc6e344967a1433b2517f2f5cfcaf5be4e566cccb6b38f24a0bfa`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
