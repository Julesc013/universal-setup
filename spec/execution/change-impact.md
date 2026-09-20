---
type: "Engineering Specification"
title: "Change impact and selective requalification"
description: "Reduce repeated work using explicit invalidation rather than optimistic omission."
tags: ["universal-setup","execution"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-IMPACT","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-CONTEXT","USK-S-TEST"]}
---

# Change impact and selective requalification

## Inputs
Use changed paths, semantic requirement IDs, contract IDs, component ownership, target providers, toolchain and fixture changes. Map them to affected tasks/acceptance cases and documentation. Reverse dependencies propagate changes through plans, ABI, state and consumer boundaries.

## Conservative default
Unmapped paths, missing base, stale inventory, changed test harness, ambiguous generated output or unknown semantic impact select broader review. A positive file-name match is an optimization hint, not a proof that unselected tests cannot fail. Release qualification retains its required full matrix even if PR checks are selective.

## Evidence cache
A result cache key includes command/test revision, relevant source/dependency closure, toolchain, target, fixture, policy and harness. Failed/skipped results remain visible. Cached success is not copied into a new receipt pretending rerun. Cache hits record original evidence reference and why it remains valid.

## Change classes
Prose clarification may require only spec/tool checks. Semantic requirement changes require contract/model tests and decision review. ABI/state/publisher changes require downstream integration, migration/recovery and target qualification. Packaging/signing changes invalidate artifact receipts even when runtime code is unchanged. Human evidence is re-evaluated for changed user journeys, package identities and rendering/input behavior.

## Verifiable requirements

### USK-R-IMPACT-001 — Unknown impact broadens

**Requirement.** Unclassified changes MUST select conservative review rather than an empty test list.

**Rationale.** Coverage maps are incomplete.

**Acceptance.** `USK-AT-IMPACT-001` in the acceptance catalogue.

### USK-R-IMPACT-002 — Cached evidence provenance

**Requirement.** Reused evidence MUST retain its original execution identity and explicit validity justification.

**Rationale.** Reuse is not rerun.

**Acceptance.** `USK-AT-IMPACT-002` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
