---
type: "WorkUnit Definition"
title: "Qualify spec tooling and context export"
description: "Proposed M0 WorkUnit; no implementation authority is granted."
tags: ["universal-setup","plan"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-TASK-003","revision": "2","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "plan","depends_on": ["USK-S-WORK","USK-S-AIDE","USK-S-CONTEXT","USK-S-AGENT","USK-S-IMPACT","USK-S-ROADMAP"]}
usk_task: {"id": "USK-WU-003","title": "Qualify spec tooling and context export","phase": "M0","status": "proposed","depends_on": ["USK-WU-001"],"spec_ids": ["USK-S-WORK","USK-S-AIDE","USK-S-CONTEXT","USK-S-AGENT","USK-S-IMPACT","USK-S-ROADMAP"],"requirement_ids": ["USK-R-WORK-001","USK-R-WORK-002","USK-R-WORK-003","USK-R-AIDE-001","USK-R-AIDE-002","USK-R-AIDE-003","USK-R-CONTEXT-001","USK-R-CONTEXT-002","USK-R-CONTEXT-003","USK-R-AGENT-001","USK-R-AGENT-002","USK-R-AGENT-003","USK-R-IMPACT-001","USK-R-IMPACT-002","USK-R-ROADMAP-001","USK-R-ROADMAP-002"],"acceptance_ids": ["USK-AT-WORK-001","USK-AT-WORK-002","USK-AT-WORK-003","USK-AT-AIDE-001","USK-AT-AIDE-002","USK-AT-AIDE-003","USK-AT-CONTEXT-001","USK-AT-CONTEXT-002","USK-AT-CONTEXT-003","USK-AT-AGENT-001","USK-AT-AGENT-002","USK-AT-AGENT-003","USK-AT-IMPACT-001","USK-AT-IMPACT-002","USK-AT-ROADMAP-001","USK-AT-ROADMAP-002"],"context_paths": ["README.md","contracts/**","release/**","docs/**","spec/**"],"allowed_paths": ["spec/**","tools/**","tests/**"],"read_only_paths": ["contracts/**","release/**","docs/**"],"forbidden_paths": ["README.md",".git/**","external/**"],"forbidden_operations": ["protected-ref-write","force-push","sign","publish","operate-on-user-state","activate-own-authority"],"steps": ["Run toolkit self-tests and adversarial metadata/path fixtures.","Validate optional AIDE exports against the pinned schema checkout.","Prove fresh-session handoff with a second reader and bounded context pack.","Admit root instruction/CI routers separately; leave active queues unchanged."],"deliverables": ["Tool qualification report","Validated inactive export","Fresh-reader finding log"],"risks": ["Schema shape is not AIDE runtime admission."],"checks": [{"argv": ["python","spec/tools/specctl.py","validate"],"status": "NOT_RUN","scope": "specification-integrity-only"},{"argv": ["python","tools/structure_policy_check.py"],"status": "NOT_RUN","scope": "existing-repository-policy"},{"argv": ["python","-m","unittest","discover","-s","tests","-v"],"status": "NOT_RUN","scope": "existing-repository-tests; qualify relevance and dependencies before execution"}],"required_binding": "active USK-SPEC-TO-RELEASE-01 campaign authority plus an exact task binding; exact target/environment receipt additionally required for endpoint or user-state effects","authorizes_implementation": false,"base_binding": "derive exact accepted source commit/tree, task-definition digest, current spec aggregate, non-widened scope and predecessor receipts","stop_conditions": ["required source/spec inputs changed","active campaign authority or exact task binding unavailable","affected contract decision unresolved","unexplained failure or required skip","possible user-state or protected-ref effect"],"completion": "implementation plus specified evidence and independent technical review under active campaign policy; document count is insufficient"}
---

# Qualify spec tooling and context export

## Goal
Qualify spec tooling and context export.

## Preconditions
Pair this definition with an exact campaign task binding for the actual repository commit/tree, current spec manifest, non-widened scope and accepted predecessor receipts. This file is not a live AIDE task and cannot mint its own binding.

## Implementation steps
1. Run toolkit self-tests and adversarial metadata/path fixtures.
2. Validate optional AIDE exports against the pinned schema checkout.
3. Prove fresh-session handoff with a second reader and bounded context pack.
4. Admit root instruction/CI routers separately; leave active queues unchanged.

## Deliverables
- Tool qualification report
- Validated inactive export
- Fresh-reader finding log

## Risks and review
- Schema shape is not AIDE runtime admission.

## Qualification
Implement the linked acceptance designs as actual tests. Bind source, dependency, target, fixtures, commands, results and skips. No designed scenario has run merely because it appears here. The first listed check validates this specification only. Use existing repository build/test tooling and an external build root.

## Handoff
Record exact changes, evidence, unresolved blockers, changed contract IDs, next task, binding identity and any binding expiry. Do not mark operational progress by editing this template.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^AIDE-WORKUNIT].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
