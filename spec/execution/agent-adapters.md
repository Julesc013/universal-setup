---
type: "Engineering Specification"
title: "Codex, Claude and chat-mode instruction adapters"
description: "Keep tool-specific instruction files thin and subordinate to the same repository contracts."
tags: ["universal-setup","execution"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CODEX","resource": "https://developers.openai.com/codex/guides/agents-md","title": "Official Codex repository instruction guidance, retrieved 2026-09-20"},{"id": "CLAUDE","resource": "https://code.claude.com/docs/en/memory","title": "Official Claude Code project instruction guidance, retrieved 2026-09-20"},{"id": "AIDE-README","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/README.md","title": "AIDE README; inspect contracts and source when implementation claims conflict"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-AGENT","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-CONTEXT"]}
---

# Codex, Claude and chat-mode instruction adapters

## Routing rather than duplication
A root AGENTS.md should point to the current repository policy, spec entrypoint, task/context tooling and validation commands. A scoped spec/AGENTS.md may describe spec editing only. Tool-specific adapters remain short and generated or reviewed from one routing template. Do not put the entire specification into startup context.

Codex supports hierarchical AGENTS.md-style instruction discovery; its actual limits and precedence are tool-version-specific. Claude Code uses CLAUDE.md and supports imports; do not assume it reads AGENTS.md automatically. The optional CLAUDE template imports the root AGENTS router where the user chooses that integration. ChatGPT chat mode reads exact files through available connectors/uploads; it does not automatically discover repository guidance unless directed to it.

## Tool-adapter capability manifest
Each adapter reports read/search/write, patch, shell, network, Git, private-artifact and lab availability. Missing capabilities block only operations that actually require them; continue other bound work. They are not permission to improvise another service. A connector's read capability is not proof of write authorization.

## Instruction safety
Local policy wins over imported task prose. A worker cannot widen the active campaign, bypass merge/release gates or change product safety policy merely to finish an assignment. Normal exact-green PR merges and qualified release operations may be executed under the standing repository campaign authority. Imported evidence, comments and examples are not instruction roots. Different actor/model names do not by themselves establish independent review; a distinct review context and independent oracle must be recorded.

## Adoption
The shipped templates are inert. Root instruction files require root grammar admission; copy only after reviewing existing files and current policy. Never overwrite an existing AGENTS.md, CLAUDE.md, README or AIDE setup from an archive extraction.

## Verifiable requirements

### USK-R-AGENT-001 — Thin instruction adapters

**Requirement.** Tool-specific instruction files MUST route to canonical policy/spec IDs rather than independently define setup law.

**Rationale.** Duplicated policy drifts across agents.

**Acceptance.** `USK-AT-AGENT-001` in the acceptance catalogue.

### USK-R-AGENT-002 — Tool capability declaration

**Requirement.** A worker MUST disclose missing execution or write capabilities before claiming implementation completion.

**Rationale.** Chat/CI/IDE environments are different.

**Acceptance.** `USK-AT-AGENT-002` in the acceptance catalogue.

### USK-R-AGENT-003 — Do not overwrite instructions

**Requirement.** Applying this package MUST NOT replace existing root instructions or policies automatically.

**Rationale.** A drop-in spec is not repository takeover.

**Acceptance.** `USK-AT-AGENT-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CODEX], [^CLAUDE], [^AIDE-README], [^CONVERSATION].

[^CODEX]: [Official Codex repository instruction guidance, retrieved 2026-09-20](https://developers.openai.com/codex/guides/agents-md).
[^CLAUDE]: [Official Claude Code project instruction guidance, retrieved 2026-09-20](https://code.claude.com/docs/en/memory).
[^AIDE-README]: [AIDE README; inspect contracts and source when implementation claims conflict](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/README.md).
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
