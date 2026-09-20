---
type: "Engineering Specification"
title: "Human and agent engineering workflow"
description: "Use one bounded, evidence-producing workflow for every worker and tool."
tags: ["universal-setup","execution"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"},{"id": "AIDE-README","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/README.md","title": "AIDE README; inspect contracts and source when implementation claims conflict"},{"id": "USR-FACMAN","resource": "urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4","title": "User-supplied September 6 FacMan and native-interface programme; historical"},{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-WORK","revision": "1","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "design","depends_on": ["USK-S-AUTH","USK-S-TEST"]}
---

# Human and agent engineering workflow

## One loop
```text
read exact context -> inspect -> propose bounded change -> implement
-> run declared checks -> independent review -> handoff
-> admitted integration -> revalidate -> update knowledge projections
```
Humans, Codex, Claude, ChatGPT with connectors, local models and CI use the same repository commands and contracts. Model/tool-specific instructions are small generated routers, not alternate policy sources. A coding model choice is independent of execution privileges, budgets, descendant model permissions and review role.

## WorkUnit content
Every task has stable ID, goal, requirements, input base/spec digest, prerequisites, allowed/read-only/forbidden paths, affected contracts, implementation steps, test plan, expected outputs, authority ceiling, stop conditions and rollback/cleanup. Templates in this archive are proposed and not live queue items. Materialize one into the actual queue only through its supported admitted adapter.

## WIP and independence
Prefer one kernel safety migration, one application/authoring slice and one release/evidence task. Avoid concurrent writers to the same authority records. Worktrees organize changes but do not isolate unsafe effects. Independent review means another execution/review context with access to original source and evidence, not a self-approved label or mandatory fixed model percentages.

## Stop rules
Stop on missing grants, stale base, unknown ownership, conflicting authority, unsupported contract, altered private fixtures, incomplete negative-control proof or unavailable target. Record a blocker and continue unrelated admitted work. Never erase a failing test or broaden a sandbox root to make the task pass.

## Completion
A handoff identifies files/digests changed, commands actually run, outputs/results, failed attempts, unresolved issues, current branch/tree and next safe action. Only an accepted queue transition changes operational completion. Committing a prose report does not make a lifecycle capability release-qualified.

## Verifiable requirements

### USK-R-WORK-001 — Bound task authority

**Requirement.** Every nontrivial implementation task MUST bind scope, exact inputs, acceptance and an independently established execution grant.

**Rationale.** Tasks must survive context/model changes safely.

**Acceptance.** `USK-AT-WORK-001` in the acceptance catalogue.

### USK-R-WORK-002 — Truthful completion

**Requirement.** A task MUST NOT be accepted solely because code exists or its spec-tool validation passes.

**Rationale.** Scaffolds and metadata checks are not product behavior.

**Acceptance.** `USK-AT-WORK-002` in the acceptance catalogue.

### USK-R-WORK-003 — Independent review

**Requirement.** High-risk changes MUST receive independent technical review in addition to mechanical checks under the repository policy.

**Rationale.** Self-certification misses semantic safety errors.

**Acceptance.** `USK-AT-WORK-003` in the acceptance catalogue.


## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^AIDE-WORKUNIT], [^AIDE-README], [^USR-FACMAN], [^CONVERSATION].

[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
[^AIDE-README]: [AIDE README; inspect contracts and source when implementation claims conflict](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/README.md).
[^USR-FACMAN]: User-supplied September 6 FacMan and native-interface programme; historical. [Source registry](../provenance/sources.json); identity `urn:sha256:1a9b48f9aa23e01f88739d70a2394438e33c2a48d8e6f0ccc9204cfe40e649a4`.
[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
