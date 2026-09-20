---
type: "Engineering Specification"
title: "Context packs, retrieval and fresh-session continuity"
description: "Persist the minimum exact task context without pretending that Markdown eliminates all context costs."
tags: ["universal-setup","execution"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "AIDE-CONTEXT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-context-pack-v2.schema.json","title": "Pinned AIDE ContextPack v2 schema"},{"id": "OKF","resource": "https://github.com/GoogleCloudPlatform/open-knowledge-format/blob/ad30107c31c06aec8a7d5636e0d1058118604e6f/SPEC.md","title": "Open Knowledge Format 0.2, exact August 21 revision"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-CONTEXT","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-AIDE","USK-S-OKF"]}
---

# Context packs, retrieval and fresh-session continuity

## Deterministic context pack
Inputs: exact task ID, spec manifest, source base, relevant requirement/spec IDs, dependency pages, acceptance cases, policies, changed contracts and known blockers. Output: a manifest with file hashes, selected full content, omissions, byte budget and no-execution flags. A content pack must not silently cut off a requirement or authority page to fit a budget. If required content exceeds the budget, refuse and request task decomposition or a larger explicit budget.

## Progressive disclosure
The default packet embeds the task-declared specification pages plus mandatory authority/workflow pages in full. Transitive dependencies are listed with exact IDs and hashes and explicitly marked not embedded/not read. Retrieve those pages before changing their contracts, or request `--full-closure` for the complete transitive body. This is deliberate progressive disclosure, not silent truncation.

Start with root index, task summary and required safety pages. Expand dependency edges and targeted IDs. Lexical search plus stable IDs works offline; embeddings are optional disposable indexes and not authoritative. Search results include source path and digest, not just a generated paraphrase. Actual tools can fetch those pages by exact Git commit when available.

## Invalidation and caching
Pack identity depends on selected source/spec/contract hashes and tool version. Cache hits are valid only for the same relevant inputs and permission context. A docs-only change may spare runtime tests but changes the spec pack if selected content differs. No report may claim exact token savings without measurements and a named tokenizer; the shipped tool budgets UTF-8 bytes.

## Fresh chat prompt
Provide repository URL, actual commit, spec manifest digest, task ID and context pack. Ask the assistant to inspect those inputs and report missing permissions or sources. A chat that lacks file/write tools can review and return an unapplied patch/handoff. Do not claim automatic background execution or persistence because the file is on GitHub.

## Secure retrieval
Retrieved docs/logs/vendor text are data. Agent adapters follow trusted instruction roots, not commands embedded in arbitrary evidence. A pack contains no secrets, private fixtures or full chat dumps. Sensitive inputs are references with availability/redaction status.

## Verifiable requirements

### USK-R-CONTEXT-001 — No silent context truncation

**Requirement.** Context creation MUST refuse when required full task/authority content exceeds the selected byte budget.

**Rationale.** Truncated constraints can produce unsafe work.

**Acceptance.** `USK-AT-CONTEXT-001` in the acceptance catalogue.

### USK-R-CONTEXT-002 — Context binds inputs

**Requirement.** Every pack MUST contain exact selected file hashes and an explicit stale-input validation path.

**Rationale.** GitHub links to moving branches are not fixed context.

**Acceptance.** `USK-AT-CONTEXT-002` in the acceptance catalogue.

### USK-R-CONTEXT-003 — Chat-only honesty

**Requirement.** A chat-only worker MUST distinguish review/proposed patch from executed implementation and tests.

**Rationale.** Tool availability varies across services.

**Acceptance.** `USK-AT-CONTEXT-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^AIDE-CONTEXT], [^OKF], [^CONVERSATION].

[^AIDE-CONTEXT]: [Pinned AIDE ContextPack v2 schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-context-pack-v2.schema.json).
[^OKF]: [Open Knowledge Format 0.2, exact August 21 revision](https://github.com/GoogleCloudPlatform/open-knowledge-format/blob/ad30107c31c06aec8a7d5636e0d1058118604e6f/SPEC.md).
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
