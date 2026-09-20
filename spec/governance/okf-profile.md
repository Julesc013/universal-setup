---
type: "Engineering Specification"
title: "OKF engineering profile and authoring rules"
description: "Use pinned OKF 0.2 Markdown with a small namespaced engineering extension."
tags: ["universal-setup","governance"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "OKF","resource": "https://github.com/GoogleCloudPlatform/open-knowledge-format/blob/ad30107c31c06aec8a7d5636e0d1058118604e6f/SPEC.md","title": "Open Knowledge Format 0.2, exact August 21 revision"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-OKF","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-AUTH"]}
---

# OKF engineering profile and authoring rules

## Wire format for knowledge
This bundle targets OKF 0.2 at the pinned upstream commit recorded in `provenance/pins.json`. Pin the commit as well as the version label. OKF is Markdown plus YAML frontmatter; it does not replace JSON Schema, a scheduler, an authorization system or an evidence verifier.

Each concept has `type`, `title`, `description`, `tags`, `generated`, `sources` and the producer extension `usk_spec`. The bundled producer uses one YAML key per line and JSON values, a YAML-compatible subset parsed by the dependency-free tooling. Generic OKF permits more YAML; the local parser deliberately validates this producer subset rather than claiming to parse every possible OKF document.

`index.md` and `log.md` are reserved listing/history files, not ordinary concepts. The root index declares `okf_version: "0.2"`. All other Markdown concepts have frontmatter. Concept IDs are relative paths without `.md`; `usk_spec.id` is a separate durable engineering ID used across path changes. A redirect/alias entry preserves old logical references when a page moves.

## Metadata discipline
`usk_spec` holds profile, stable ID, document revision, proposal status, owner, layer and dependency IDs. `generated` records authorship, not verification. Do not add `verified` because lint or a schema check passes. Machine confirmation of a source-derived claim and human review are separate events, each with exact scope and references.

Dates are ISO 8601 timestamps with explicit UTC offset. Sources use stable IDs and URI/digest references. Footnote keys join to those source IDs. Unknown generic OKF keys and unknown types are preserved by consumers; a producer may validate the semantics of its own namespaced extension without pretending all other extensions are invalid.

## Writing granularity
One page owns one coherent contract or implementation boundary. Use purpose, semantics, algorithms/state transitions, failure behavior, verifiable requirements and examples. Split a page when independent tasks repeatedly need disjoint halves, not to meet an arbitrary line count. Prefer ordinary Markdown links, tables, JSON examples and text diagrams. Diagrams supplement rather than replace textual invariants.

## No hidden second specification
Requirements are authored once in Markdown. The catalogue is an extracted projection. Acceptance scenarios are authored as test designs, not outcomes. Task definitions reference requirements and scenarios; their live progress belongs in the selected queue after admission.

## Verifiable requirements

### USK-R-OKF-001 — Stable logical identities

**Requirement.** Every normative concept and requirement MUST have a unique stable engineering ID independent of filename.

**Rationale.** Links survive reorganization.

**Acceptance.** `USK-AT-OKF-001` in the acceptance catalogue.

### USK-R-OKF-002 — Preserve unknown metadata

**Requirement.** The knowledge reader MUST preserve unknown OKF fields and MUST NOT treat unknown concept types as executable instructions.

**Rationale.** Portability includes future extensions.

**Acceptance.** `USK-AT-OKF-002` in the acceptance catalogue.

### USK-R-OKF-003 — Correct provenance

**Requirement.** Source-derived claims MUST identify the source and its temporal scope; proposed extensions MUST be labelled as proposals.

**Rationale.** Historical audits are not live truth.

**Acceptance.** `USK-AT-OKF-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^OKF], [^CONVERSATION].

[^OKF]: [Open Knowledge Format 0.2, exact August 21 revision](https://github.com/GoogleCloudPlatform/open-knowledge-format/blob/ad30107c31c06aec8a7d5636e0d1058118604e6f/SPEC.md).
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
