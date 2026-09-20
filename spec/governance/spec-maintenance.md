---
type: "Engineering Specification"
title: "Specification maintenance and documentation generation"
description: "Keep requirements, operational records and published documentation synchronized without duplicate authority."
tags: ["universal-setup","governance"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "AIDE-README","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/README.md","title": "AIDE README; inspect contracts and source when implementation claims conflict"},{"id": "USR-FACMAN","resource": "urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4","title": "User-supplied September 6 FacMan and native-interface programme; historical"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-MAINT","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-OKF"]}
---

# Specification maintenance and documentation generation

## Pull-request change bundle
A nontrivial implementation PR records requirement IDs, task ID, source base, changed files, tests, limitations and expected compatibility. If implementation reveals a flawed requirement, amend the requirement and its decision before claiming conformance; never weaken a test merely to match a bug.

A semantic spec PR supplies a decision/change record, old/new requirement mapping, affected consumers and a validation plan. It need not execute a full native suite when only prose clarification changes, but it must say why no behavior is affected. Unknown impact selects broader review.

## Publication
`docs/` contains curated tutorials, task guides, architecture explanations and generated references. Generated blocks/pages carry origin IDs and generator version. Human-authored tutorials may interpret the specification but reference its stable IDs rather than duplicating normative lists. `specctl render-docs` produces review output in an explicitly selected external directory; it does not overwrite the root README or existing documentation.

## Progress and freshness
Source observations identify exact Git commit/tree and checked paths. Refresh them when starting an implementation task or making a release claim. A previous successful CI run is not transferred to a new source tree. No auto-generated current-state page should require a perpetual source-commit self-reference: evidence binds the input tree, and subsequent truth-only projections identify the covered input separately.

## Recovery from context loss
A completed worker emits an immutable handoff with task, inputs, changes, tests/results, failed attempts, unresolved blockers, next admissible action and permission ceiling. The next worker verifies those identities before continuing. A summary is a retrieval aid, not a substitute for referenced evidence.

## Verifiable requirements

### USK-R-MAINT-001 — Documentation impact

**Requirement.** A semantic implementation change MUST identify affected specification and publication pages or justify no documentation impact.

**Rationale.** Prevents stale architecture claims.

**Acceptance.** `USK-AT-MAINT-001` in the acceptance catalogue.

### USK-R-MAINT-002 — No fabricated freshness

**Requirement.** Generated current-state records MUST distinguish their input revision from the commit containing the generated record.

**Rationale.** Avoids self-reference loops and stale truth.

**Acceptance.** `USK-AT-MAINT-002` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^AIDE-README], [^USR-FACMAN], [^CONVERSATION].

[^AIDE-README]: [AIDE README; inspect contracts and source when implementation claims conflict](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/README.md).
[^USR-FACMAN]: User-supplied September 6 FacMan and native-interface programme; historical. [Source registry](../provenance/sources.json); identity `urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
