---
type: "WorkUnit Definition"
title: "Qualify neutral and demanding product consumers"
description: "Proposed M4 WorkUnit; no implementation authority is granted."
tags: ["universal-setup","plan"]
generated: {"by": "chatgpt/gpt-6-astra-pro","at": "2026-09-20T12:23:08Z"}
sources: [{"id": "CONVERSATION","resource": "urn:usk:input:current-conversation-design","title": "Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export"},{"id": "AIDE-WORKUNIT","resource": "https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json","title": "Pinned AIDE WorkUnit schema"}]
usk_spec: {"profile": "usk-engineering/0.1.0-draft.1","id": "USK-S-TASK-021","revision": "2","status": "proposed","authority": "engineering-intent-only-after-adoption","owner": "universal-setup","layer": "plan","depends_on": ["USK-S-CONSUMER","USK-S-TEST","USK-S-ULK","USK-S-MODULES","USK-S-VISION"]}
usk_task: {"id": "USK-WU-021","title": "Qualify neutral and demanding product consumers","phase": "M4","status": "proposed","depends_on": ["USK-WU-011","USK-WU-014","USK-WU-017","USK-WU-018"],"spec_ids": ["USK-S-CONSUMER","USK-S-TEST","USK-S-ULK","USK-S-MODULES","USK-S-VISION"],"requirement_ids": ["USK-R-TEST-001","USK-R-TEST-002","USK-R-TEST-003","USK-R-CONSUMER-001","USK-R-CONSUMER-002","USK-R-CONSUMER-003","USK-R-ULK-001","USK-R-ULK-002","USK-R-MODULES-001","USK-R-MODULES-002","USK-R-MODULES-003","USK-R-VISION-001","USK-R-VISION-002","USK-R-VISION-003"],"acceptance_ids": ["USK-AT-TEST-001","USK-AT-TEST-002","USK-AT-TEST-003","USK-AT-CONSUMER-001","USK-AT-CONSUMER-002","USK-AT-CONSUMER-003","USK-AT-ULK-001","USK-AT-ULK-002","USK-AT-MODULES-001","USK-AT-MODULES-002","USK-AT-MODULES-003","USK-AT-VISION-001","USK-AT-VISION-002","USK-AT-VISION-003"],"context_paths": ["README.md","contracts/**","release/**","docs/**","spec/**"],"allowed_paths": ["tests/**","content/templates/**","docs/**","release/index/**"],"read_only_paths": ["contracts/**","spec/**"],"forbidden_paths": ["README.md",".git/**","external/**"],"forbidden_operations": ["protected-ref-write","force-push","sign","publish","operate-on-user-state","activate-own-authority"],"steps": ["Run a tiny neutral app without internal tooling.","Run a demanding component/preservation fixture.","Coordinate designated Dominium proof and optional real consumers through exact pins.","Document each product boundary and missing evidence."],"deliverables": ["At least two distinct consumer evidence classes","No-fork onboarding report","Consumer qualification matrix"],"risks": ["Do not claim actual external product runs from synthetic stand-ins."],"checks": [{"argv": ["python","spec/tools/specctl.py","validate"],"status": "NOT_RUN","scope": "specification-integrity-only"},{"argv": ["python","tools/structure_policy_check.py"],"status": "NOT_RUN","scope": "existing-repository-policy"},{"argv": ["python","-m","unittest","discover","-s","tests","-v"],"status": "NOT_RUN","scope": "existing-repository-tests; qualify relevance and dependencies before execution"}],"required_grant": "separate-admitted-D1; D3 required for endpoint effects; no implicit D2/D4","authorizes_implementation": false,"base_binding": "bind actual repository commit/tree and current spec manifest at admission","stop_conditions": ["required source/spec inputs changed","required grant unavailable","affected contract decision unresolved","unexplained failure or required skip","possible user-state or protected-ref effect"],"completion": "implementation plus specified evidence and independent acceptance under actual queue policy; document count is insufficient"}
---

# Qualify neutral and demanding product consumers

## Goal
Qualify neutral and demanding product consumers.

## Preconditions
bind actual repository commit/tree and current spec manifest at admission. Complete dependencies or record a separate approved scope adjustment. This file is not a live AIDE task.

## Implementation steps
1. Run a tiny neutral app without internal tooling.
2. Run a demanding component/preservation fixture.
3. Coordinate designated Dominium proof and optional real consumers through exact pins.
4. Document each product boundary and missing evidence.

## Deliverables
- At least two distinct consumer evidence classes
- No-fork onboarding report
- Consumer qualification matrix

## Risks and review
- Do not claim actual external product runs from synthetic stand-ins.

## Qualification
Implement the linked acceptance designs as actual tests. Bind source, dependency, target, fixtures, commands, results and skips. No designed scenario has run merely because it appears here. The first listed check validates this specification only. Use existing repository build/test tooling and an external build root.

## Handoff
Record exact changes, evidence, unresolved blockers, changed contract IDs, next task and applicable grant expiry. Do not mark operational progress by editing this template.

## Provenance and status

This is authored engineering intent, not an implementation or runtime qualification claim. Source-derived constraints and the proposed extensions above are separated by the package authority policy. Sources: [^CONVERSATION], [^AIDE-WORKUNIT].

[^CONVERSATION]: Current conversation: enterprise synthesis and specification-authoring request; not a full transcript export. [Source registry](../../provenance/sources.json); identity `urn:usk:input:current-conversation-design`.
[^AIDE-WORKUNIT]: [Pinned AIDE WorkUnit schema](https://github.com/Julesc013/aide/blob/aec53b1d3675f02e2fdd17cc718fdcff6cd4e9f3/.aide/protocol/aide-workunit.schema.json).
