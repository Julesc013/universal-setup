---
type: "Engineering Specification"
title: "AIDE integration without a mandatory runtime dependency"
description: "Export bounded WorkUnit and ContextPack records against pinned actual AIDE contracts."
tags: ["universal-setup","execution"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"},{"id": "AIDE-CONTEXT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-context-pack-v2.schema.json","title": "Pinned AIDE ContextPack v2 schema"},{"id": "AIDE-README","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/README.md","title": "AIDE README; inspect contracts and source when implementation claims conflict"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-AIDE","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-WORK"]}
---

# AIDE integration without a mandatory runtime dependency

## Role
AIDE is the engineering control plane. It can maintain queue, attempts, test jobs, evidence and knowledge projections. It is not installed on customer machines and is not a prerequisite for ordinary building/testing. Its own current source and schemas distinguish proposed protocol surfaces, reviewed worker foundations and still-unqualified live capabilities.

## Pinned mapping
The archive pins AIDE main, its WorkUnit schema path and Git blob identity, and its ContextPack v2 schema path/blob. The provided exporter maps specification task definitions to WorkUnit-shaped records: metadata identity/producer/compatibility; task scope/prerequisites; explicit no-activation fields; NOT_RUN validation commands; planned status. It never writes a live `.aide/queue`, changes grants or invokes a scheduler.

When an exact AIDE checkout is supplied, validate the exported object against that schema and record the checker version/result. Without the schema, report unverified compatibility. A permissive schema validation is only shape proof, not queue acceptance, adapter admission or worker capability. The checked-in AIDE README may lag implemented schemas; source observations are preserved instead of repeating old blanket pre-runtime descriptions.

## Authority split
`spec/` defines intended engineering semantics after adoption. AIDE queue/protocol/evidence owns operational task state. `.aide/knowledge/okf` is a generated explanation of actual work/evidence, not a second normative spec. A spec index can be a knowledge input but must retain origin/status. Do not make two independently editable queues.

## Model/budget policy
Root model and reasoning choice remain user/deployment-controlled. Descendant models, effort, tokens/money, wall time, tool capabilities, network domains and filesystem scope are separate axes. Quality is established through tests/evaluation, not a claim that every task used the largest model. Version/provider strings are observations, never permanently hard-coded role identities.

## Verifiable requirements

### USK-R-AIDE-001 — Export is not admission

**Requirement.** AIDE exports MUST remain proposed with authorizes_implementation=false unless an actual separately authorized queue/grant workflow changes them.

**Rationale.** A spec package cannot self-authorize.

**Acceptance.** `USK-AT-AIDE-001` in the acceptance catalogue.

### USK-R-AIDE-002 — Pinned schema validation

**Requirement.** AIDE compatibility claims MUST name the exact schema identity and validation result.

**Rationale.** A familiar JSON shape is not interoperability proof.

**Acceptance.** `USK-AT-AIDE-002` in the acceptance catalogue.

### USK-R-AIDE-003 — AIDE optional build dependency

**Requirement.** Product building, tests and customer setup MUST remain executable without AIDE or model access.

**Rationale.** The control plane must not trap the product.

**Acceptance.** `USK-AT-AIDE-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^AIDE-WORKUNIT], [^AIDE-CONTEXT], [^AIDE-README], [^CONVERSATION].

[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
[^AIDE-CONTEXT]: [Pinned AIDE ContextPack v2 schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-context-pack-v2.schema.json).
[^AIDE-README]: [AIDE README; inspect contracts and source when implementation claims conflict](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/README.md).
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
