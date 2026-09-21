---
type: "WorkUnit Definition"
title: "Add owned operation API and progress/cancellation"
description: "Proposed M3 WorkUnit; no implementation authority is granted."
tags: ["universal-setup","plan"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-TASK-015","revision": "2","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "plan","depends_on": ["USK-S-API","USK-S-TXN"]}
usk_task: {"id": "USK-WU-015","title": "Add owned operation API and progress/cancellation","phase": "M3","status": "proposed","depends_on": ["USK-WU-008","USK-WU-013"],"spec_ids": ["USK-S-API","USK-S-TXN"],"requirement_ids": ["USK-R-TXN-001","USK-R-TXN-002","USK-R-TXN-003","USK-R-API-001","USK-R-API-002","USK-R-API-003"],"acceptance_ids": ["USK-AT-TXN-001","USK-AT-TXN-002","USK-AT-TXN-003","USK-AT-API-001","USK-AT-API-002","USK-AT-API-003"],"context_paths": ["README.md","contracts/**","release/**","docs/**","spec/**"],"allowed_paths": ["include/usk/**","runtime/setup/kernel/**","runtime/command/**","runtime/setup/lifecycle/**","contracts/abi/**","tests/**"],"read_only_paths": ["release/**","docs/**","spec/**"],"forbidden_paths": ["README.md",".git/**","external/**"],"forbidden_operations": ["protected-ref-write","force-push","sign","publish","operate-on-user-state","activate-own-authority"],"steps": ["Add owned results without changing ABI1 layouts.","Introduce operation IDs, inspect and cancellation request.","Emit bounded progress with durable terminal outcomes.","Qualify allocator and FFI callback lifetimes."],"deliverables": ["Additive API","Old-client ABI proof","Cancellation-race test matrix"],"risks": ["Borrowed API remains supported; callbacks cannot reenter accidentally."],"checks": [{"argv": ["python","spec/tools/specctl.py","validate"],"status": "NOT_RUN","scope": "specification-integrity-only"},{"argv": ["python","tools/structure_policy_check.py"],"status": "NOT_RUN","scope": "existing-repository-policy"},{"argv": ["python","-m","unittest","discover","-s","tests","-v"],"status": "NOT_RUN","scope": "existing-repository-tests; qualify relevance and dependencies before execution"}],"required_grant": "separate-admitted-D1; D3 required for endpoint effects; no implicit D2/D4","authorizes_implementation": false,"base_binding": "bind actual repository commit/tree and current spec manifest at admission","stop_conditions": ["required source/spec inputs changed","required grant unavailable","affected contract decision unresolved","unexplained failure or required skip","possible user-state or protected-ref effect"],"completion": "implementation plus specified evidence and independent acceptance under actual queue policy; document count is insufficient"}
---

# Add owned operation API and progress/cancellation

## Goal
Add owned operation API and progress/cancellation.

## Preconditions
bind actual repository commit/tree and current spec manifest at admission. Complete dependencies or record a separate approved scope adjustment. This file is not a live AIDE task.

## Implementation steps
1. Add owned results without changing ABI1 layouts.
2. Introduce operation IDs, inspect and cancellation request.
3. Emit bounded progress with durable terminal outcomes.
4. Qualify allocator and FFI callback lifetimes.

## Deliverables
- Additive API
- Old-client ABI proof
- Cancellation-race test matrix

## Risks and review
- Borrowed API remains supported; callbacks cannot reenter accidentally.

## Qualification
Implement the linked acceptance designs as actual tests. Bind source, dependency, target, fixtures, commands, results and skips. No designed scenario has run merely because it appears here. The first listed check validates this specification only. Use existing repository build/test tooling and an external build root.

## Handoff
Record exact changes, evidence, unresolved blockers, changed contract IDs, next task and applicable grant expiry. Do not mark operational progress by editing this template.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^AIDE-WORKUNIT].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
