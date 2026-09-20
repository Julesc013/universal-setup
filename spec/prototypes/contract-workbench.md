---
type: "Contract Workbench"
title: "Prototype contract workbench"
description: "Review draft JSON schemas and examples without replacing the installed contracts."
tags: ["universal-setup","prototypes"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-PROTO","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "prototype","depends_on": ["USK-S-BUNDLE","USK-S-PLAN","USK-S-AUTH"]}
---

# Prototype contract workbench

The adjacent schemas are deliberately versioned `usk.draft.*` proposals. They demonstrate field boundaries and executable syntax for bundle, plan, receipt, provider, presentation, unattended response, evidence and handoff records. They are not the existing `usk.*.v1` contracts.

Examples use zero SHA-256 sentinel values and fixture identities. Their schema validity is not content identity, trust, execution or authorization. Real consumers must reject unresolved sentinel identities. Semantic validators additionally enforce graph integrity, native path projection, total resource budgets, policy, identity binding and state-machine rules. JSON Schema alone cannot prove those properties.

Promotion requires the contract WorkUnit: map existing producers/readers, make version/compatibility decisions, implement converters when needed, move the selected authoritative schema into `contracts/`, update this page to reference it and remove independent editability of the draft. Do not silently publish these schemas under old v1 IDs.

Run `python spec/tools/specctl.py schema-check` in an environment with `jsonschema` installed. The dependency is a development check, not an endpoint requirement. If unavailable, the command reports unavailable rather than PASS.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
